require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const sqlite3 = require("sqlite3").verbose();
const path = require("path");
const fs = require("fs");
const http = require("http");
const { Server } = require("socket.io");
const { google } = require("googleapis");
const nodemailer = require("nodemailer");
const { Configuration, OpenAIApi } = require("openai");

const PORT = process.env.PORT || 5000;
const DB_PATH = path.join(__dirname, "devices.db");
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret";
const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:5173";

// ---------------- Express Setup ----------------
const app = express();
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(
  cors({
    origin: FRONTEND_URL,
    credentials: true,
  })
);

// ---------------- SQLite ----------------
const db = new sqlite3.Database(DB_PATH, (err) => {
  if (err) console.error("❌ DB error:", err.message);
  else console.log("📁 SQLite DB connected.");
});

db.serialize(() => {
  db.run(
    `CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      email TEXT UNIQUE,
      phone TEXT,
      password TEXT,
      role TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`
  );

  db.run(
    `CREATE TABLE IF NOT EXISTS devices (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      device_type TEXT,
      imei TEXT,
      brand TEXT,
      model TEXT,
      color TEXT,
      location_area TEXT,
      lost_type TEXT,
      lost_datetime TEXT,
      reporter_email TEXT,
      reporter_name TEXT,
      police_case_number TEXT,
      status TEXT DEFAULT 'reported',
      frozen INTEGER DEFAULT 0,
      last_seen DATETIME,
      google_account_email TEXT,
      apple_id_email TEXT,
      contact_hint TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`
  );

  db.run(
    `CREATE TABLE IF NOT EXISTS tracking (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      imei TEXT,
      latitude TEXT,
      longitude TEXT,
      address TEXT,
      trackerName TEXT,
      trackedAt TEXT
    )`
  );

  db.run(
    `CREATE TABLE IF NOT EXISTS device_locations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      device_id INTEGER,
      lat REAL,
      lng REAL,
      accuracy REAL,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(device_id) REFERENCES devices(id)
    )`
  );
});

// ---------------- Google Sheets Helper ----------------
async function getSheetsClient() {
  if (!process.env.GOOGLE_SERVICE_ACCOUNT_JSON) return null;
  const creds = JSON.parse(process.env.GOOGLE_SERVICE_ACCOUNT_JSON);
  return new google.auth.GoogleAuth({
    credentials: creds,
    scopes: ["https://www.googleapis.com/auth/spreadsheets"],
  });
}

async function logToSheet(values, range = "Logs!A1") {
  try {
    if (!process.env.GOOGLE_SHEET_ID) return;
    const auth = await getSheetsClient();
    if (!auth) return;
    const sheets = google.sheets({ version: "v4", auth });
    await sheets.spreadsheets.values.append({
      spreadsheetId: process.env.GOOGLE_SHEET_ID,
      range,
      valueInputOption: "USER_ENTERED",
      requestBody: { values: [values] },
    });
  } catch (e) {
    console.warn("logToSheet error:", e.message);
  }
}

// ---------------- Helpers ----------------
function requireAuth(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No token" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    return res.status(403).json({ error: "Invalid token" });
  }
}

function allowRoles(...roles) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: "No user" });
    if (!roles.includes(req.user.role))
      return res.status(403).json({ error: "Forbidden" });
    next();
  };
}

// ---------------- Nodemailer for Password Reset ----------------
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: parseInt(process.env.SMTP_PORT),
  secure: false,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

// ---------------- OpenAI Setup ----------------
let openai;
if (process.env.OPENAI_API_KEY) {
  const configuration = new Configuration({ apiKey: process.env.OPENAI_API_KEY });
  openai = new OpenAIApi(configuration);
}

// ---------------- Health ----------------
app.get("/", (_, res) => res.json({ ok: true, service: "PASEARCH Backend MVP" }));

// ---------------- AUTH ----------------
app.post("/auth/register", async (req, res) => {
  const { username, email, password, role, phone } = req.body;
  if (!username || !email || !password) return res.status(400).json({ error: "Missing fields" });
  try {
    const hash = await bcrypt.hash(password, 10);
    const finalRole = role || "reporter";
    db.run(
      `INSERT INTO users (username,email,phone,password,role) VALUES (?,?,?,?,?)`,
      [username, email, phone || null, hash, finalRole],
      async function (err) {
        if (err) return res.status(400).json({ error: "User exists or DB error" });
        const token = jwt.sign({ id: this.lastID, username, role: finalRole }, JWT_SECRET);
        await logToSheet(["REGISTER", username, email, finalRole, new Date().toISOString()]);
        res.json({ success: true, token });
      }
    );
  } catch (e) {
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/auth/login", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Missing credentials" });
  db.get("SELECT * FROM users WHERE username = ?", [username], async (err, u) => {
    if (err) return res.status(500).json({ error: "DB error" });
    if (!u) return res.status(400).json({ error: "Invalid credentials" });
    const ok = await bcrypt.compare(password, u.password);
    if (!ok) return res.status(400).json({ error: "Invalid credentials" });
    const token = jwt.sign({ id: u.id, username: u.username, role: u.role }, JWT_SECRET);
    await logToSheet(["LOGIN", username, u.role, new Date().toISOString()]);
    res.json({ success: true, token });
  });
});

// ---------------- Forgot Password ----------------
app.post("/auth/forgot-password", (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: "Email required" });
  db.get("SELECT * FROM users WHERE email = ?", [email], async (err, user) => {
    if (err || !user) return res.status(400).json({ error: "User not found" });
    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: "1h" });
    const link = `${FRONTEND_URL}/reset-password?token=${token}`;
    await transporter.sendMail({
      from: process.env.SMTP_FROM,
      to: user.email,
      subject: "PASEARCH Password Reset",
      text: `Reset your password here: ${link}`,
    });
    res.json({ success: true, message: "Password reset email sent" });
  });
});

app.post("/auth/reset-password", (req, res) => {
  const { token, password } = req.body;
  if (!token || !password) return res.status(400).json({ error: "Missing fields" });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    bcrypt.hash(password, 10, (err, hash) => {
      if (err) return res.status(500).json({ error: "Hashing failed" });
      db.run("UPDATE users SET password = ? WHERE id = ?", [hash, payload.id], function (err2) {
        if (err2) return res.status(500).json({ error: "DB update failed" });
        res.json({ success: true, message: "Password updated" });
      });
    });
  } catch (e) {
    res.status(403).json({ error: "Invalid or expired token" });
  }
});

// ---------------- Admin / Police / Devices ----------------
// Similar routes as previous server.js
// /admin/users, /admin/devices, /police/reports, /report-device, /gps/update, /gps/latest, /gps/history, /pasearch-ai/match
// ... (Use same routes from your last complete server.js)

// ---------------- Socket.IO ----------------
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*", methods: ["GET", "POST"] } });
io.on("connection", (socket) => {
  console.log("Socket connected:", socket.id);
  socket.on("subscribe_device", (deviceId) => socket.join(`device_${deviceId}`));
  socket.on("disconnect", () => {});
});
global.io = io;

// ---------------- Start Server ----------------
server.listen(PORT, () => console.log(`🚀 PASEARCH Backend running on port ${PORT}`));
