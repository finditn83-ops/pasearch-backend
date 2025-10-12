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
const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:5173";
const ADMIN_EMAIL = "finditn83@gmail.com";

// =====================
// INITIALIZE EXPRESS
// =====================
const app = express();
app.use(
  cors({
    origin: (origin, cb) => {
      const allowed = [FRONTEND_URL];
      if (!origin) return cb(null, true);
      const ok =
        allowed.includes(origin) ||
        /\.vercel\.app$/.test(new URL(origin).hostname);
      return cb(ok ? null : new Error("CORS blocked"), ok);
    },
    credentials: true,
  })
);
app.use(express.json({ limit: "5mb" }));
app.use(express.urlencoded({ extended: true }));
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
app.use("/uploads", express.static(UPLOAD_DIR));

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

async function logUser({ username, email, phone, role }) {
  await appendToSheet("Users", [
    username,
    email,
    phone || "N/A",
    role,
    new Date().toLocaleString(),
  ]);
}
async function logDevice(d) {
  await appendToSheet("Devices", [
    d.device_category || "N/A",
    d.device_type || "N/A",
    d.imei || "N/A",
    d.color || "N/A",
    d.location_area || "N/A",
    d.reporter_email || "N/A",
    new Date().toLocaleString(),
  ]);
}
async function logPasswordEvent({ email, action, actor }) {
  await appendToSheet("PasswordLogs", [
    email,
    action,
    actor,
    new Date().toLocaleString(),
  ]);
}
async function logSystemEvent({ email, role, event }) {
  await appendToSheet("SystemLogs", [
    email,
    role,
    event,
    new Date().toLocaleString(),
  ]);
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
// ROUTES
// =====================

// Health Check
app.get("/", (_, res) =>
  res.json({
    ok: true,
    service: "PASEARCH Backend",
    env: process.env.NODE_ENV || "development",
    time: new Date().toISOString(),
  })
);

// ==============================
// ✅ REGISTER
// ==============================
app.post("/auth/register", (req, res) => {
  const { username, email, phone, password, role } = req.body;
  if (!username || !email || !password)
    return res.status(400).json({ error: "All fields required" });

  const userRole = email === ADMIN_EMAIL ? "admin" : role || "reporter";
  const hashed = bcrypt.hashSync(password, 10);

  db.run(
    "INSERT INTO users (username, email, phone, password, role, verified) VALUES (?, ?, ?, ?, ?, 1)",
    [username, email, phone, hashed, userRole],
    function (err) {
      if (err) {
        if (err.message.includes("UNIQUE"))
          return res.status(409).json({ error: "Username or email exists" });
        return res.status(500).json({ error: "DB error" });
      }

      const token = jwt.sign(
        { id: this.lastID, username, email, role: userRole },
        JWT_SECRET,
        { expiresIn: "7d" }
      );

      logUser({ username, email, phone, role: userRole });

      if (useEmail) {
        transporter
          .sendMail({
            from: process.env.EMAIL_USER,
            to: ADMIN_EMAIL,
            subject: "New Account Registered - PASEARCH",
            html: `<h3>New Account Registered</h3><p>${email}</p>`,
          })
          .catch((e) => console.warn("Email send failed:", e.message));
      }

      res.json({
        message: "Account created successfully",
        token,
        user: { id: this.lastID, username, email, role: userRole },
      });
    }
  );
});

// ==============================
// ✅ LOGIN (fixed & cleaned)
// ==============================
app.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ error: "Email and password required" });

    db.get("SELECT * FROM users WHERE email = ?", [email], async (err, user) => {
      if (err) return res.status(500).json({ error: "Database error" });
      if (!user) return res.status(401).json({ error: "Invalid credentials" });

      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch)
        return res.status(401).json({ error: "Invalid credentials" });

      if (user.email === ADMIN_EMAIL && user.role !== "admin") {
        db.run("UPDATE users SET role='admin' WHERE email=?", [email]);
        user.role = "admin";
      }

      const token = jwt.sign(
        { id: user.id, role: user.role, email: user.email },
        JWT_SECRET,
        { expiresIn: "7d" }
      );

      const timestamp = new Date().toISOString();
      db.run(
        "INSERT INTO system_logs (user_id, action, timestamp) VALUES (?, ?, ?)",
        [user.id, "User Login", timestamp],
        (logErr) => {
          if (logErr) console.error("System log error:", logErr);
        }
      );

      await logSystemEvent({
        email: user.email,
        role: user.role,
        event: "Login Successful",
      });

      res.json({
        message: "Login successful",
        token,
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          role: user.role,
        },
      });
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ error: "Server error" });
  }
});

// ==============================
// ✅ UPDATE PASSWORD
// ==============================
app.post("/auth/update-password", (req, res) => {
  const { email, currentPassword, newPassword } = req.body;
  if (!email || !currentPassword || !newPassword)
    return res.status(400).json({ error: "All fields required" });

  db.get("SELECT * FROM users WHERE email=?", [email], (err, u) => {
    if (err || !u) return res.status(404).json({ error: "User not found" });
    if (!bcrypt.compareSync(currentPassword, u.password))
      return res.status(400).json({ error: "Incorrect password" });

    const hashed = bcrypt.hashSync(newPassword, 10);
    db.run("UPDATE users SET password=? WHERE email=?", [hashed, email], (e2) => {
      if (e2) return res.status(500).json({ error: "Update failed" });

      logPasswordEvent({
        email,
        action: "User changed own password",
        actor: email,
      });

      res.json({ message: "Password updated successfully" });
    });
  });
});

// ==============================
// ✅ REPORT DEVICE
// ==============================
app.post(
  "/report-device",
  upload.fields([{ name: "proof_path" }, { name: "police_report_path" }]),
  (req, res) => {
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

    const proof_path = req.files?.proof_path
      ? req.files.proof_path[0].path
      : null;
    const police_path = req.files?.police_report_path
      ? req.files.police_report_path[0].path
      : null;

    db.run(
      `INSERT INTO devices 
       (user_id, device_category, device_type, imei, color, location_area, lost_type, proof_path, police_report_path, lost_datetime, other_details)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        user_id || null,
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
      function (err) {
        if (err) {
          console.error("Device insert error:", err.message);
          return res.status(500).json({ error: "Failed to report device" });
        }
        logDevice({
          device_category,
          device_type,
          imei,
          color,
          location_area,
          reporter_email,
        });
        res.json({ message: "Device reported successfully" });
      }
    );
  }
);

// ==============================
// ✅ TRACK DEVICE
// ==============================
app.post("/track-device", async (req, res) => {
  const { imei, latitude, longitude, address, trackerName } = req.body;
  const trackedAt = new Date().toLocaleString();

  db.run(
    `INSERT INTO tracking (imei, latitude, longitude, address, trackerName, trackedAt)
     VALUES (?, ?, ?, ?, ?, ?)`,
    [imei, latitude, longitude, address, trackerName, trackedAt],
    async function (err) {
      if (err) {
        console.error("DB insert error:", err);
        return res.status(500).json({ error: "Database error" });
      }
      await appendToSheet("Tracking", [
        imei,
        latitude,
        longitude,
        address,
        trackerName,
        trackedAt,
      ]);
      res.json({ success: true, message: "Device location updated successfully" });
    }
  );
});

// =====================
// 🧠 OPENAI ASSISTANT
// =====================
app.post("/api/ask-ai", async (req, res) => {
  try {
    const { prompt, memory } = req.body;
    const apiKey = process.env.OPENAI_API_KEY;
    if (!apiKey) {
      return res.status(500).json({ error: "OpenAI API key not configured" });
    }

    const body = {
      model: "gpt-4o-mini",
      messages: [
        {
          role: "system",
          content: `You are PasearchAI — a privacy-focused assistant integrated into the Pasearch platform. Help users report, track and recover devices responsibly.`,
        },
        { role: "user", content: prompt || "" },
      ],
      max_tokens: 250,
    };

    const r = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify(body),
    });

    if (!r.ok) {
      const t = await r.text();
      console.error("OpenAI error:", r.status, t);
      return res.status(502).json({ error: "OpenAI upstream error" });
    }

    const data = await r.json();
    const reply =
      data?.choices?.[0]?.message?.content ||
      "Sorry — I couldn’t generate a response.";
    res.json({ reply });
  } catch (err) {
    console.error("AI route error:", err);
    res.status(500).json({ error: "AI request failed" });
  }
});

// =====================
// 404 HANDLER + SERVER START
// =====================
app.use((_, res) => res.status(404).json({ error: "Route not found" }));

app.listen(PORT, "0.0.0.0", () =>
  console.log(`🚀 PASEARCH backend running on http://localhost:${PORT}`)
);
