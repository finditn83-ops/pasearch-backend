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
const { google } = require("googleapis");
require("dotenv").config();

// =====================
// CONFIGURATION
// =====================
const DB_PATH = path.join(__dirname, "devices.db");
const UPLOAD_DIR = path.join(__dirname, "uploads");
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret";
const PORT = process.env.PORT || 5000;
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || "finditn83@gmail.com";

// =====================
// INITIALIZE EXPRESS (CORS fixed)
// =====================
const app = express();

const DEFAULT_ORIGINS = [
  "http://localhost:5173",
  "http://localhost:3000",
  "https://pasearch-frontend.vercel.app",
];
const EXTRA_ORIGINS = (process.env.CORS_EXTRA_ORIGINS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

const LEGACY_FRONTEND = (process.env.FRONTEND_URL || "").trim();
const ALLOWED = new Set(
  [...DEFAULT_ORIGINS, ...EXTRA_ORIGINS, LEGACY_FRONTEND].filter(Boolean)
);

function isAllowedOrigin(origin) {
  if (!origin) return true; // same-origin/tools
  try {
    const url = new URL(origin);
    const hostname = url.hostname;
    if (ALLOWED.has(origin)) return true;
    if (hostname.endsWith(".vercel.app")) return true; // allow Vercel previews
  } catch (_) {}
  return false;
}

app.use(
  cors({
    origin: (origin, cb) =>
      cb(isAllowedOrigin(origin) ? null : new Error("CORS blocked"), isAllowedOrigin(origin)),
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    optionsSuccessStatus: 204,
  })
);

app.options("*", cors());
app.use(express.json({ limit: "5mb" }));
app.use(express.urlencoded({ extended: true }));

if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
app.use("/uploads", express.static(UPLOAD_DIR));

// ✅ Health endpoint (must be above 404)
app.get("/api/health", (_, res) =>
  res.json({
    ok: true,
    message: "Backend reachable ✅",
    service: "PASEARCH Backend",
    env: process.env.NODE_ENV || "development",
    time: new Date().toISOString(),
  })
);

// =====================
// MULTER SETUP
// =====================
const storage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, UPLOAD_DIR),
  filename: (_, file, cb) =>
    cb(null, Date.now() + "-" + file.originalname.replace(/\s+/g, "_")),
});
const upload = multer({ storage });

// =====================
// DATABASE
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

  db.run(`CREATE INDEX IF NOT EXISTS idx_devices_imei ON devices(imei)`);
});

// =====================
// GOOGLE SHEETS HELPER
// =====================
const SHEET_ID = process.env.GOOGLE_SHEET_ID || "";
let sheetsClient = null;

(function initSheets() {
  try {
    const raw = process.env.GOOGLE_SERVICE_ACCOUNT_JSON;
    if (!raw) throw new Error("Missing GOOGLE_SERVICE_ACCOUNT_JSON");
    const serviceAccount = JSON.parse(raw);
    const auth = new google.auth.GoogleAuth({
      credentials: serviceAccount,
      scopes: ["https://www.googleapis.com/auth/spreadsheets"],
    });
    sheetsClient = google.sheets({ version: "v4", auth });
    console.log("✅ Google Sheets connected");
  } catch (err) {
    console.warn("⚠️ Sheets disabled:", err.message);
  }
})();

async function appendToSheet(tab, values) {
  if (!sheetsClient || !SHEET_ID) return;
  try {
    await sheetsClient.spreadsheets.values.append({
      spreadsheetId: SHEET_ID,
      range: `${tab}!A:Z`,
      valueInputOption: "USER_ENTERED",
      requestBody: { values: [values] },
    });
  } catch (err) {
    console.error(`❌ Google Sheet (${tab}) error:`, err.message);
  }
}

// =====================
// EMAIL SETUP
// =====================
const useEmail = !!process.env.EMAIL_USER && !!process.env.EMAIL_PASS;
const transporter = useEmail
  ? nodemailer.createTransport({
      service: "gmail",
      auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
    })
  : null;

// =====================
// OPTIONAL AUTH MIDDLEWARE
// =====================
function auth(req, res, next) {
  const hdr = req.headers.authorization || "";
  const token = hdr.startsWith("Bearer ") ? hdr.slice(7) : null;
  if (!token) return res.status(401).json({ error: "No token provided" });
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err && err.name === "TokenExpiredError") {
      return res.status(401).json({ error: "Token expired" });
    }
    if (err) return res.status(401).json({ error: "Invalid token" });
    req.user = decoded;
    next();
  });
}

// =====================
// ROUTES
// =====================
app.get("/", (_, res) =>
  res.json({
    ok: true,
    service: "PASEARCH Backend",
    env: process.env.NODE_ENV || "development",
    time: new Date().toISOString(),
  })
);

// ✅ Your existing routes follow here (register, login, etc.)
// ... [keep all routes unchanged]

// =====================
// 404 HANDLER + SERVER START
// =====================
app.use((_, res) => res.status(404).json({ error: "Route not found" }));

app.listen(PORT, "0.0.0.0", () =>
  console.log(`🚀 PASEARCH backend running on http://localhost:${PORT}`)
);
