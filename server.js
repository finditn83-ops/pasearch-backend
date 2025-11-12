// =============================================================
// 🚀 PASEARCH BACKEND — Locate, Track & Recover Devices
// Includes: AI Assistant (OpenAI), Cyber Intel Feed, Socket.IO Tracking
// =============================================================

// ----------------------------
// 1️⃣ Imports
// ----------------------------
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
const RSSParser = require("rss-parser");
const OpenAI = require("openai");
require("dotenv").config();

// ----------------------------
// 2️⃣ Configuration
// ----------------------------
const PORT = process.env.PORT || 5000;
const DB_PATH = path.join(__dirname, "devices.db");
const UPLOAD_DIR = path.join(__dirname, "uploads");
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret";
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || "admin@example.com";
const TELEMETRY_API_KEY = process.env.TELEMETRY_API_KEY || "telemetry_key";
const OPENAI_KEY = process.env.OPENAI_API_KEY || "";
const AI_MODEL = process.env.AI_MODEL || "gpt-4o-mini";
const EMBED_MODEL = process.env.EMBED_MODEL || "text-embedding-3-small";
const INTEL_REFRESH_MINUTES = Number(process.env.INTEL_REFRESH_MINUTES || 180);
const INTEL_SOURCES = (
  process.env.INTEL_SOURCES ||
  [
    "https://krebsonsecurity.com/feed/",
    "https://www.bleepingcomputer.com/feed/",
    "https://www.schneier.com/feed/atom/",
    "https://feeds.feedburner.com/TheHackersNews",
  ].join(",")
)
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

// ----------------------------
// 3️⃣ Initialize Express App
// ----------------------------
const app = express();
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));

// =============================================================
// 🌐 CORS CONFIGURATION — Local + Render + Vercel
// =============================================================
const allowedOrigins = [
  "http://localhost:5173",
  "http://localhost:3000",
  "https://pasearch-frontend.vercel.app",
];

if (process.env.CORS_EXTRA_ORIGINS) {
  const extras = process.env.CORS_EXTRA_ORIGINS.split(",").map((o) => o.trim());
  allowedOrigins.push(...extras);
}

const ALLOWED = new Set(allowedOrigins);

app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin) return cb(null, true);
      try {
        const hostname = new URL(origin).hostname;
        const ok =
          ALLOWED.has(origin) ||
          /\.vercel\.app$/.test(hostname) ||
          hostname.endsWith(".onrender.com");
        if (ok) return cb(null, true);
        console.warn("🚫 Blocked CORS origin:", origin);
        cb(new Error("CORS blocked"));
      } catch {
        cb(new Error("Invalid CORS origin"));
      }
    },
    credentials: true,
  })
);

// ----------------------------
// 5️⃣ File Uploads + DB Init
// ----------------------------
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const db = new sqlite3.Database(DB_PATH);
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    email TEXT UNIQUE,
    phone TEXT,
    password TEXT,
    role TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    device_type TEXT,
    imei TEXT,
    color TEXT,
    location_area TEXT,
    lost_type TEXT,
    lost_datetime TEXT,
    reporter_email TEXT,
    police_case_number TEXT,
    status TEXT DEFAULT 'reported',
    frozen INTEGER DEFAULT 0,
    last_seen DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
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

  db.run(`CREATE TABLE IF NOT EXISTS cyber_intel (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT,
    url TEXT UNIQUE,
    source TEXT,
    published_at TEXT,
    summary TEXT,
    embedding TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
});

// ----------------------------
// 6️⃣ Email + Google Sheets
// ----------------------------
let transporter = null;
if (process.env.SMTP_USER && process.env.SMTP_PASS && process.env.SMTP_HOST) {
  transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT) || 465,
    secure: Number(process.env.SMTP_PORT || 465) === 465,
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
  });
}

async function sendEmail(to, subject, html) {
  if (!transporter) return;
  try {
    await transporter.sendMail({ from: process.env.SMTP_FROM, to, subject, html });
  } catch (e) {
    console.warn("Email error:", e.message);
  }
}

async function getAuth() {
  let creds;
  if (process.env.GOOGLE_SERVICE_ACCOUNT_JSON)
    creds = JSON.parse(process.env.GOOGLE_SERVICE_ACCOUNT_JSON);
  else if (process.env.GOOGLE_SERVICE_ACCOUNT_PATH)
    creds = require(process.env.GOOGLE_SERVICE_ACCOUNT_PATH);
  if (!creds) return null;
  return new google.auth.GoogleAuth({
    credentials: creds,
    scopes: ["https://www.googleapis.com/auth/spreadsheets"],
  });
}
async function logToSheet(values, range = "Sheet1!A1") {
  if (!process.env.GOOGLE_SHEET_ID) return;
  const auth = await getAuth();
  if (!auth) return;
  const sheets = google.sheets({ version: "v4", auth });
  await sheets.spreadsheets.values.append({
    spreadsheetId: process.env.GOOGLE_SHEET_ID,
    range,
    valueInputOption: "USER_ENTERED",
    requestBody: { values: [values] },
  });
}

// ----------------------------
// 7️⃣ Helpers
// ----------------------------
function verifyToken(req, res, next) {
  const t = req.headers.authorization?.split(" ")[1];
  if (!t) return res.status(401).json({ error: "No token" });
  try {
    req.user = jwt.verify(t, JWT_SECRET);
    next();
  } catch {
    res.status(403).json({ error: "Invalid token" });
  }
}
function requireTelemetryKey(req, res, next) {
  const key = req.headers["x-pasearch-key"];
  if (key !== TELEMETRY_API_KEY)
    return res.status(401).json({ error: "Invalid API key" });
  next();
}

// ----------------------------
// 8️⃣ OpenAI + RSS Setup
// ----------------------------
const openai = OPENAI_KEY ? new OpenAI({ apiKey: OPENAI_KEY }) : null;
const rss = new RSSParser();
function cosine(a, b) {
  if (!a || !b || a.length !== b.length) return 0;
  let dot = 0,
    na = 0,
    nb = 0;
  for (let i = 0; i < a.length; i++) {
    dot += a[i] * b[i];
    na += a[i] * a[i];
    nb += b[i] * b[i];
  }
  return dot / (Math.sqrt(na) * Math.sqrt(nb) + 1e-9);
}

// ----------------------------
// 9️⃣ Core Routes
// ----------------------------

// ✅ Health check
app.get("/", (_, res) =>
  res.json({
    ok: true,
    service: "PASEARCH Backend",
    mission: "Locate, track & recover devices (IMEI-change resilient)",
    time: new Date().toISOString(),
  })
);

// ✅ Frontend redeploy (native fetch)
app.post("/trigger-frontend", async (req, res) => {
  try {
    const hook = process.env.VERCEL_DEPLOY_HOOK_URL;
    if (!hook)
      return res.status(400).json({ error: "VERCEL_DEPLOY_HOOK_URL not set" });
    const response = await fetch(hook, { method: "POST" });
    if (!response.ok)
      throw new Error(`Vercel trigger failed: ${response.statusText}`);
    console.log("✅ Frontend redeploy triggered");
    res.json({ success: true, message: "Frontend redeploy triggered" });
  } catch (error) {
    console.error("❌ Trigger error:", error.message);
    res.status(500).json({ error: "Failed to trigger frontend redeploy" });
  }
});

// 🔐 Auth
app.post("/auth/register", async (req, res) => {
  const { username, email, password, role, phone } = req.body;
  if (!username || !email || !password)
    return res.status(400).json({ error: "Missing fields" });
  const hash = await bcrypt.hash(password, 10);
  const r = email === ADMIN_EMAIL ? "admin" : role || "reporter";
  db.run(
    "INSERT INTO users (username,email,phone,password,role) VALUES (?,?,?,?,?)",
    [username, email, phone || null, hash, r],
    async function (err) {
      if (err) return res.status(400).json({ error: "User exists" });
      const token = jwt.sign({ id: this.lastID, username, role: r }, JWT_SECRET, {
        expiresIn: "7d",
      });
      await logToSheet(["REGISTER", username, email, r, new Date().toLocaleString()]);
      res.json({ success: true, token });
    }
  );
});

app.post("/auth/login", (req, res) => {
  const { username, password } = req.body;
  db.get("SELECT * FROM users WHERE username=?", [username], async (err, u) => {
    if (err || !u) return res.status(400).json({ error: "Invalid credentials" });
    const ok = await bcrypt.compare(password, u.password);
    if (!ok) return res.status(400).json({ error: "Invalid credentials" });
    const t = jwt.sign({ id: u.id, username, role: u.role }, JWT_SECRET, {
      expiresIn: "7d",
    });
    await logToSheet(["LOGIN", username, u.role, new Date().toLocaleString()], "Logins!A1");
    res.json({ success: true, token: t });
  });
});

// 🛰️ Device tracking
app.post("/report-device", (req, res) => {
  const { user_id, device_type, imei, reporter_email } = req.body;
  db.run(
    "INSERT INTO devices (user_id,device_type,imei,reporter_email) VALUES (?,?,?,?)",
    [user_id || null, device_type || null, imei || null, reporter_email || null],
    async function (err) {
      if (err) return res.status(500).json({ error: "Failed" });
      await logToSheet(["REPORT", imei, device_type, reporter_email, new Date().toLocaleString()]);
      res.json({ success: true, id: this.lastID });
    }
  );
});

app.post("/track-device", async (req, res) => {
  const { imei, latitude, longitude, address, trackerName } = req.body;
  db.run(
    "INSERT INTO tracking (imei,latitude,longitude,address,trackerName,trackedAt) VALUES (?,?,?,?,?,datetime('now'))",
    [imei, latitude, longitude, address, trackerName],
    async (err) => {
      if (err) return res.status(500).json({ error: err.message });
      io.emit("tracking_update", { imei, latitude, longitude, address, trackerName });
      await logToSheet(["TRACK", imei, latitude, longitude, address, new Date().toLocaleString()]);
      res.json({ success: true });
    }
  );
});

// 📰 Admin News Feed
app.get("/admin/news", async (req, res) => {
  db.all(
    `SELECT title,url,source,summary,published_at
     FROM cyber_intel
     ORDER BY COALESCE(published_at, created_at) DESC
     LIMIT 20`,
    [],
    (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ updated: new Date().toISOString(), articles: rows });
    }
  );
});

// ----------------------------
// 🔟 Server + Socket.IO
// ----------------------------
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

server.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 PASEARCH Backend running on port ${PORT}`);
});
