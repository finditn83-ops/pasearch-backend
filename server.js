// =============================================================
// 🚀 PASEARCH BACKEND (Express + SQLite + Google Sheets + Render/Vercel)
// =============================================================

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
const fetch = (...args) =>
  import("node-fetch").then(({ default: fetch }) => fetch(...args));
require("dotenv").config();

// =====================
// EXPRESS + CORS
// =====================
const app = express();
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));

// ✅ Safe CORS origin list
const extraOriginsEnv = process.env.CORS_EXTRA_ORIGINS || "";
const extraOrigins = extraOriginsEnv
  ? extraOriginsEnv.split(",").map((s) => s.trim()).filter(Boolean)
  : [];

const allowedOrigins = [
  "http://localhost:5173",
  "http://localhost:3000",
  "https://pasearch-frontend.vercel.app",
  ...extraOrigins,
];

const ALLOWED = new Set(allowedOrigins);

app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin) return cb(null, true);
      const ok =
        ALLOWED.has(origin) ||
        /\.vercel\.app$/.test(new URL(origin).hostname);
      cb(ok ? null : new Error("CORS blocked"), ok);
    },
    credentials: true,
  })
);

// =====================
// CONFIG
// =====================
const DB_PATH = path.join(__dirname, "devices.db");
const UPLOAD_DIR = path.join(__dirname, "uploads");
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret";
const PORT = process.env.PORT || 5000;
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || "finditn83@gmail.com";

// =====================
// DB INITIALIZATION
// =====================
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

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
    reset_token TEXT,
    reset_expires INTEGER,
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

  db.run(`CREATE TABLE IF NOT EXISTS system_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action TEXT,
    timestamp TEXT
  )`);
});

// =====================
// GOOGLE SHEETS HELPER
// =====================
async function logToGoogleSheet(dataRow) {
  try {
    const keyFile =
      process.env.GOOGLE_SERVICE_ACCOUNT_PATH || "./service-account.json";
    if (!fs.existsSync(keyFile))
      throw new Error(`Missing service account file: ${keyFile}`);

    const auth = new google.auth.GoogleAuth({
      keyFile,
      scopes: ["https://www.googleapis.com/auth/spreadsheets"],
    });

    const sheets = google.sheets({ version: "v4", auth });
    const timestamp = new Date().toISOString().replace("T", " ").split(".")[0];
    const fullRow = [...dataRow, timestamp];

    await sheets.spreadsheets.values.append({
      spreadsheetId: process.env.GOOGLE_SHEET_ID,
      range: "Sheet1!A1",
      valueInputOption: "USER_ENTERED",
      requestBody: { values: [fullRow] },
    });

    console.log("✅ Logged to Google Sheets:", fullRow);
  } catch (err) {
    console.error("⚠️ Sheets log error:", err.message);
  }
}

// =====================
// MULTER FILE UPLOADS
// =====================
const storage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, UPLOAD_DIR),
  filename: (_, file, cb) =>
    cb(null, Date.now() + "-" + file.originalname.replace(/\s+/g, "_")),
});
const upload = multer({ storage });

// =====================
// AUTH MIDDLEWARE
// =====================
function auth(req, res, next) {
  const hdr = req.headers.authorization || "";
  const token = hdr.startsWith("Bearer ") ? hdr.slice(7) : null;
  if (!token) return res.status(401).json({ error: "No token provided" });
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err && err.name === "TokenExpiredError")
      return res.status(401).json({ error: "Token expired" });
    if (err) return res.status(401).json({ error: "Invalid token" });
    req.user = decoded;
    next();
  });
}

const requireRole =
  (...roles) =>
  (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role))
      return res.status(403).json({ error: "Forbidden" });
    next();
  };

// =====================
// ROUTES
// =====================

// Health check
app.get("/api/health", (_, res) =>
  res.json({
    ok: true,
    message: "Backend reachable ✅",
    service: "PASEARCH Backend",
    time: new Date().toISOString(),
  })
);

// Register user
app.post("/auth/register", async (req, res) => {
  try {
    const { username, email, phone, password, role } = req.body;
    if (!username || !email || !password)
      return res.status(400).json({ error: "All fields required" });

    const userRole = email === ADMIN_EMAIL ? "admin" : role || "reporter";
    const hashed = await bcrypt.hash(password, 10);

    db.run(
      "INSERT INTO users (username, email, phone, password, role, verified) VALUES (?, ?, ?, ?, ?, 0)",
      [username, email, phone, hashed, userRole],
      async function (err) {
        if (err)
          return res
            .status(409)
            .json({ error: "Username or email already exists" });

        const token = jwt.sign(
          { id: this.lastID, username, email, role: userRole },
          JWT_SECRET,
          { expiresIn: "7d" }
        );

        await logToGoogleSheet([
          username,
          email,
          phone || "N/A",
          userRole,
          "New Registration",
        ]);

        res.json({
          success: true,
          message: "Account created successfully",
          token,
        });
      }
    );
  } catch (error) {
    console.error("Register error:", error);
    res.status(500).json({ error: "Server error during registration" });
  }
});

// Login user
app.post("/auth/login", async (req, res) => {
  try {
    const { email, username, password } = req.body;
    const identifier = email || username;
    if (!identifier || !password)
      return res
        .status(400)
        .json({ error: "Email/Username and password required" });

    db.get(
      "SELECT * FROM users WHERE email = ? OR username = ?",
      [identifier, identifier],
      async (err, user) => {
        if (err) return res.status(500).json({ error: "Database error" });
        if (!user)
          return res.status(401).json({ error: "Invalid credentials" });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch)
          return res.status(401).json({ error: "Invalid credentials" });

        const token = jwt.sign(
          { id: user.id, email: user.email, role: user.role },
          JWT_SECRET,
          { expiresIn: "7d" }
        );

        res.json({
          success: true,
          message: "Login successful",
          token,
          user,
        });
      }
    );
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Server error during login" });
  }
});

// Report device
app.post(
  "/report-device",
  upload.fields([{ name: "proof_path" }, { name: "police_report_path" }]),
  async (req, res) => {
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

      const proof_path = req.files?.proof_path?.[0]?.path || null;
      const police_path = req.files?.police_report_path?.[0]?.path || null;

      db.run(
        `INSERT INTO devices (user_id, device_category, device_type, imei, color, location_area,
          lost_type, proof_path, police_report_path, lost_datetime, other_details)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          user_id,
          device_category,
          device_type,
          imei,
          color,
          location_area,
          lost_type,
          proof_path,
          police_path,
          lost_datetime,
          other_details,
        ],
        async function (err) {
          if (err)
            return res.status(500).json({ error: "Failed to report device" });

          await logToGoogleSheet([
            imei,
            device_type,
            color,
            location_area,
            reporter_email || "N/A",
            lost_type,
          ]);

          res.json({ success: true, id: this.lastID });
        }
      );
    } catch (error) {
      console.error("Report-device error:", error.message);
      res.status(500).json({ error: "Server error while reporting device" });
    }
  }
);

// Track device
app.post("/track-device", async (req, res) => {
  try {
    const { imei, latitude, longitude, address, trackerName } = req.body;
    const trackedAt = new Date().toISOString().replace("T", " ").split(".")[0];

    db.run(
      `INSERT INTO tracking (imei, latitude, longitude, address, trackerName, trackedAt)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [imei, latitude, longitude, address, trackerName, trackedAt],
      async function (err) {
        if (err)
          return res.status(500).json({ error: "Database insert failed" });

        await logToGoogleSheet([
          imei,
          trackerName || "Unknown",
          latitude,
          longitude,
          address,
        ]);

        res.json({
          success: true,
          message: "Device tracked successfully",
        });
      }
    );
  } catch (err) {
    console.error("Track-device error:", err.message);
    res.status(500).json({ error: "Failed to track device" });
  }
});

// =====================
// FRONTEND DEPLOY TRIGGER
// =====================
app.post("/trigger-frontend", async (req, res) => {
  try {
    const hook = process.env.VERCEL_DEPLOY_HOOK_URL;
    if (!hook)
      return res.status(400).json({ error: "VERCEL_DEPLOY_HOOK_URL not set" });

    const response = await fetch(hook, { method: "POST" });
    if (!response.ok)
      throw new Error(`Vercel trigger failed: ${response.statusText}`);

    res.json({ success: true, message: "Frontend redeploy triggered" });
  } catch (error) {
    console.error("Trigger-frontend error:", error.message);
    res.status(500).json({ error: "Failed to trigger frontend redeploy" });
  }
});

// =====================
// DEFAULT ROUTE
// =====================
app.get("/", (_, res) => res.send("Welcome to PASEARCH Backend ✅"));

// =====================
// SOCKET.IO + SERVER START
// =====================
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: Array.from(ALLOWED),
    methods: ["GET", "POST"],
  },
});

io.on("connection", (socket) => {
  console.log("Connected:", socket.id);
  socket.on("disconnect", () => console.log("Disconnected:", socket.id));
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 PASEARCH backend + WebSocket running on port ${PORT}`);
});
