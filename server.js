// =====================
// IMPORTS & CONFIG
// =====================
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const sqlite3 = require("sqlite3").verbose();
const multer = require("multer");
const nodemailer = require("nodemailer");
const path = require("path");
const fs = require("fs");
const http = require("http");
const { Server } = require("socket.io");
const { google } = require("googleapis");
const fetch = (...args) => import("node-fetch").then(({ default: fetch }) => fetch(...args));
require("dotenv").config();

// =====================
// CONFIGURATION
// =====================
const DB_PATH = path.join(__dirname, "devices.db");
const UPLOAD_DIR = path.join(__dirname, "uploads");
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret";
const PORT = process.env.PORT || 5000;
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || "finditn83@gmail.com";

const ALLOWED = new Set([
  "http://localhost:5173",
  "http://localhost:3000",
  "https://pasearch-frontend.vercel.app",
  ...(process.env.CORS_EXTRA_ORIGINS || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean),
]);
app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin) return cb(null, true); // allow Postman & same-origin
      const ok =
        ALLOWED.has(origin) ||
        /\.vercel\.app$/.test(new URL(origin).hostname); // ✅ any Vercel preview domain
      cb(ok ? null : new Error("CORS blocked"), ok);
    },
    credentials: true,
  })
);
app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin) return cb(null, true);
      const ok = ALLOWED.has(origin) || /\.vercel\.app$/.test(new URL(origin).hostname);
      cb(ok ? null : new Error("CORS blocked"), ok);
    },
    credentials: true,
  })
);

// =====================
// HEALTH CHECK
// =====================
app.get("/api/health", (_, res) => {
  res.json({
    ok: true,
    message: "Backend reachable ✅",
    time: new Date().toISOString(),
  });
});

// =====================
// FILE UPLOAD (MULTER)
// =====================
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR);
const storage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, UPLOAD_DIR),
  filename: (_, file, cb) =>
    cb(null, Date.now() + "-" + file.originalname.replace(/\s+/g, "_")),
});
const upload = multer({ storage });

// =====================
// SQLITE DATABASE
// =====================
const db = new sqlite3.Database(DB_PATH, (err) => {
  if (err) console.error("❌ DB error:", err.message);
  else console.log("✅ Connected to SQLite database.");
});
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    email TEXT UNIQUE,
    phone TEXT,
    password TEXT,
    role TEXT,
    verified INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    device_category TEXT,
    device_type TEXT,
    imei TEXT,
    color TEXT,
    location_area TEXT,
    lost_type TEXT,
    proof_path TEXT,
    police_report_path TEXT,
    lost_datetime TEXT,
    other_details TEXT,
    status TEXT DEFAULT 'reported',
    recovered_at TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS tracking (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    imei TEXT,
    latitude TEXT,
    longitude TEXT,
    address TEXT,
    trackerName TEXT,
    trackedAt TEXT
  )`);
});

// =====================
// GOOGLE SHEETS LOGGING
// =====================
async function logToGoogleSheet(dataRow) {
  try {
    const keyFile = process.env.GOOGLE_SERVICE_ACCOUNT_PATH || "./service-account.json";
    if (!fs.existsSync(keyFile)) throw new Error("Missing service account file");

    const auth = new google.auth.GoogleAuth({
      keyFile,
      scopes: ["https://www.googleapis.com/auth/spreadsheets"],
    });
    const sheets = google.sheets({ version: "v4", auth });
    const timestamp = new Date().toISOString().replace("T", " ").split(".")[0];
    const row = [...dataRow, timestamp];

    await sheets.spreadsheets.values.append({
      spreadsheetId: process.env.GOOGLE_SHEET_ID,
      range: "Sheet1!A1",
      valueInputOption: "USER_ENTERED",
      requestBody: { values: [row] },
    });
    console.log("✅ Logged to Google Sheets:", row);
  } catch (err) {
    console.warn("⚠️ Sheets logging skipped:", err.message);
  }
}

// =====================
// AUTH MIDDLEWARE
// =====================
function auth(req, res, next) {
  const hdr = req.headers.authorization || "";
  const token = hdr.startsWith("Bearer ") ? hdr.slice(7) : null;
  if (!token) return res.status(401).json({ error: "No token" });
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ error: "Invalid token" });
    req.user = decoded;
    next();
  });
}
const requireRole = (...roles) => (req, res, next) => {
  if (!req.user || !roles.includes(req.user.role))
    return res.status(403).json({ error: "Forbidden" });
  next();
};

// =====================
// REGISTER
// =====================
app.post("/auth/register", async (req, res) => {
  try {
    const { username, email, phone, password, role } = req.body;
    if (!username || !email || !password)
      return res.status(400).json({ error: "All fields required" });

    const userRole = email === ADMIN_EMAIL ? "admin" : role || "reporter";
    const hashed = await bcrypt.hash(password, 10);

    db.run(
      "INSERT INTO users (username, email, phone, password, role) VALUES (?, ?, ?, ?, ?)",
      [username, email, phone, hashed, userRole],
      async function (err) {
        if (err) return res.status(409).json({ error: "User already exists" });
        const token = jwt.sign(
          { id: this.lastID, username, email, role: userRole },
          JWT_SECRET,
          { expiresIn: "7d" }
        );
        await logToGoogleSheet([username, email, phone || "N/A", userRole, "Registered"]);
        res.json({ success: true, token, message: "Account created successfully" });
      }
    );
  } catch (err) {
    res.status(500).json({ error: "Register error" });
  }
});

// =====================
// LOGIN
// =====================
app.post("/auth/login", async (req, res) => {
  try {
    const { email, username, password } = req.body;
    const identifier = email || username;
    if (!identifier || !password)
      return res.status(400).json({ error: "Missing credentials" });

    db.get(
      "SELECT * FROM users WHERE email = ? OR username = ?",
      [identifier, identifier],
      async (err, user) => {
        if (err || !user) return res.status(401).json({ error: "Invalid credentials" });
        const match = await bcrypt.compare(password, user.password);
        if (!match) return res.status(401).json({ error: "Invalid credentials" });

        const token = jwt.sign(
          { id: user.id, role: user.role, email: user.email },
          JWT_SECRET,
          { expiresIn: "7d" }
        );
        res.json({ success: true, token, user });
      }
    );
  } catch (err) {
    res.status(500).json({ error: "Login error" });
  }
});

// =====================
// UPDATE PASSWORD
// =====================
app.post("/auth/update-password", async (req, res) => {
  try {
    const { email, currentPassword, newPassword } = req.body;
    if (!email || !currentPassword || !newPassword)
      return res.status(400).json({ error: "All fields required" });

    db.get("SELECT * FROM users WHERE email=?", [email], async (err, user) => {
      if (err || !user) return res.status(404).json({ error: "User not found" });
      const match = await bcrypt.compare(currentPassword, user.password);
      if (!match) return res.status(400).json({ error: "Incorrect password" });

      const hashed = await bcrypt.hash(newPassword, 10);
      db.run("UPDATE users SET password=? WHERE email=?", [hashed, email], async (e2) => {
        if (e2) return res.status(500).json({ error: "Update failed" });
        await logToGoogleSheet([user.username, user.email, "Password Updated"]);
        res.json({ message: "Password updated successfully" });
      });
    });
  } catch (err) {
    res.status(500).json({ error: "Update-password error" });
  }
});

// =====================
// REPORT DEVICE
// =====================
app.post("/report-device", upload.any(), async (req, res) => {
  try {
    const {
      user_id,
      device_category,
      device_type,
      imei,
      color,
      location_area,
      lost_type,
      lost_datetime,
      other_details,
      reporter_email,
    } = req.body;
    const proof = req.files?.find(f => f.fieldname === "proof_path")?.path || null;
    const police = req.files?.find(f => f.fieldname === "police_report_path")?.path || null;

    db.run(
      `INSERT INTO devices (user_id, device_category, device_type, imei, color, location_area, lost_type, proof_path, police_report_path, lost_datetime, other_details)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        user_id || null,
        device_category,
        device_type,
        imei,
        color,
        location_area,
        lost_type,
        proof,
        police,
        lost_datetime,
        other_details,
      ],
      async function (err) {
        if (err) return res.status(500).json({ error: "DB error" });
        await logToGoogleSheet([
          imei,
          device_type,
          color,
          location_area,
          reporter_email || "N/A",
          lost_type || "N/A",
        ]);
        res.json({ success: true, id: this.lastID });
      }
    );
  } catch (err) {
    res.status(500).json({ error: "Report error" });
  }
});

// =====================
// TRACK DEVICE
// =====================
app.post("/track-device", async (req, res) => {
  try {
    const { imei, latitude, longitude, address, trackerName } = req.body;
    const trackedAt = new Date().toISOString().replace("T", " ").split(".")[0];

    db.run(
      `INSERT INTO tracking (imei, latitude, longitude, address, trackerName, trackedAt)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [imei, latitude, longitude, address, trackerName, trackedAt],
      async (err) => {
        if (err) return res.status(500).json({ error: "DB error" });
        await logToGoogleSheet([
          imei,
          trackerName || "Unknown",
          latitude,
          longitude,
          address,
        ]);
        if (global.io)
          global.io.emit("deviceTracked", { imei, latitude, longitude, address, trackerName, trackedAt });
        res.json({ success: true, message: "Device tracked successfully" });
      }
    );
  } catch (err) {
    res.status(500).json({ error: "Track error" });
  }
});

// =====================
// AI ASSISTANT
// =====================
app.post("/api/ask-ai", async (req, res) => {
  try {
    const { prompt } = req.body;
    const apiKey = process.env.OPENAI_API_KEY;
    if (!apiKey) return res.status(500).json({ error: "Missing API key" });

    const r = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model: "gpt-4o-mini",
        messages: [
          {
            role: "system",
            content: "You are PasearchAI, a privacy-focused assistant for device recovery.",
          },
          { role: "user", content: prompt || "" },
        ],
        max_tokens: 300,
      }),
    });

    const data = await r.json();
    const reply = data?.choices?.[0]?.message?.content || "No response.";
    res.json({ reply });
  } catch (err) {
    res.status(500).json({ error: "AI request failed" });
  }
});

// =====================
// FRONTEND REDEPLOY
// =====================
app.post("/trigger-frontend", async (req, res) => {
  try {
    const hook = process.env.VERCEL_DEPLOY_HOOK_URL;
    if (!hook) return res.status(400).json({ error: "Hook not set" });
    await fetch(hook, { method: "POST" });
    res.json({ success: true, message: "Frontend redeploy triggered" });
  } catch (err) {
    res.status(500).json({ error: "Trigger error" });
  }
});

// =====================
// 404 HANDLER
// =====================
app.use((_, res) => res.status(404).json({ error: "Route not found" }));

// =====================
// SOCKET.IO
// =====================
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: ["http://localhost:5173", "https://pasearch-frontend.vercel.app"],
    methods: ["GET", "POST"],
  },
});
global.io = io;

io.on("connection", (socket) => {
  console.log("Client connected:", socket.id);
  socket.on("disconnect", () => console.log("Disconnected:", socket.id));
});

// =====================
// START SERVER
// =====================
server.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 PASEARCH backend + WebSocket running on port ${PORT}`);
});
