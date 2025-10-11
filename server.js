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
// GOOGLE SHEETS HELPER
// =====================
async function logToGoogleSheet(dataRow) {
  try {
    const auth = new google.auth.GoogleAuth({
      keyFile: process.env.GOOGLE_SERVICE_ACCOUNT_PATH,
      scopes: ["https://www.googleapis.com/auth/spreadsheets"],
    });

    const sheets = google.sheets({ version: "v4", auth });

    await sheets.spreadsheets.values.append({
      spreadsheetId: process.env.GOOGLE_SHEET_ID,
      range: "Sheet1!A1", // Make sure your first sheet is named 'Sheet1'
      valueInputOption: "USER_ENTERED",
      resource: {
        values: [dataRow],
      },
    });

    console.log("✅ Logged to Google Sheet:", dataRow);
  } catch (err) {
    console.error("❌ Failed to log to Google Sheet:", err.message);
  }
}
// === CONFIG ===
const DB_PATH = path.join(__dirname, "devices.db");
const UPLOAD_DIR = path.join(__dirname, "uploads");
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret";
const PORT = process.env.PORT || 5000;

// Allow local dev + your Vercel domain(s)
const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:5173";
const ADDITIONAL_ORIGINS = (process.env.CORS_EXTRA_ORIGINS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);
// e.g. set CORS_EXTRA_ORIGINS="https://pasearch-frontend.vercel.app,https://*.vercel.app"

const ADMIN_EMAIL = "finditn83@gmail.com";

// === APP INIT ===
const app = express();
app.use(
  cors({
    origin: (origin, cb) => {
      const allowed = [FRONTEND_URL, ...ADDITIONAL_ORIGINS];
      // allow same-origin tools like curl/postman with no Origin
      if (!origin) return cb(null, true);
      const ok =
        allowed.includes(origin) ||
        // allow vercel previews like https://pasearch-frontend-git-main-...vercel.app
        /\.vercel\.app$/.test(new URL(origin).hostname);
      return cb(ok ? null : new Error("CORS blocked"), ok);
    },
    credentials: true,
  })
);
app.use(express.json({ limit: "5mb" }));
app.use(express.urlencoded({ extended: true }));
app.use("/uploads", express.static(UPLOAD_DIR));
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// =====================
// MULTER (uploads)
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

  db.run(`CREATE INDEX IF NOT EXISTS idx_devices_imei ON devices(imei)`);
});

// =====================
// GOOGLE SHEETS (SAFE)
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
    console.log("✅ Google Sheets connected (env-based credentials)");
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
async function logToGoogleSheet(dataRow) {
  try {
    const auth = new google.auth.GoogleAuth({
      keyFile: process.env.GOOGLE_SERVICE_ACCOUNT_PATH,
      scopes: ["https://www.googleapis.com/auth/spreadsheets"],
    });

    const sheets = google.sheets({ version: "v4", auth });

    await sheets.spreadsheets.values.append({
      spreadsheetId: process.env.GOOGLE_SHEET_ID,
      range: "Sheet1!A1", // your first sheet name
      valueInputOption: "USER_ENTERED",
      resource: {
        values: [dataRow],
      },
    });

    console.log("✅ Logged to Google Sheet:", dataRow);
  } catch (err) {
    console.error("❌ Failed to log to Google Sheet:", err.message);
  }
}
// =====================
// EMAIL (optional)
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

// Health
app.get("/", (_, res) =>
  res.json({
    ok: true,
    service: "PASEARCH Backend",
    env: process.env.NODE_ENV || "development",
    time: new Date().toISOString(),
  })
);

app.get("/healthz", (_, res) => {
  db.get("SELECT 1 as ok", [], (err) => {
    if (err) return res.status(500).json({ ok: false, db: "down" });
    res.json({ ok: true, db: "up", time: new Date().toISOString() });
  });
});

// Register
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

      // Logs
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

// Login + SystemLog
app.post("/auth/login", (req, res) => {
  const { email, password } = req.body;
  db.get("SELECT * FROM users WHERE email = ?", [email], async (err, user) => {
    if (err || !user || !bcrypt.compareSync(password, user.password))
      return res.status(400).json({ error: "Invalid credentials" });

    // auto-upgrade admin
    if (user.email === ADMIN_EMAIL && user.role !== "admin") {
      db.run("UPDATE users SET role='admin' WHERE email=?", [email]);
      user.role = "admin";
    }

    const token = jwt.sign({ id: rows[0].id }, JWT_SECRET, { expiresIn: "30d" });
    );

    await logSystemEvent({
      email,
      role: user.role,
      event: "Login Successful",
    });

    res.json({ message: "Login successful", token, user });
  });
});

// Update Password
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

// Forgot Password (email reset link)
app.post("/auth/forgot-password", (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: "Email required" });

  const token = Math.random().toString(36).slice(2);
  const expires = Date.now() + 15 * 60 * 1000;

  db.run(
    "UPDATE users SET reset_token=?, reset_expires=? WHERE email=?",
    [token, expires, email],
    (err) => {
      if (err) return res.status(500).json({ error: "DB error" });

      const link = `${FRONTEND_URL}/reset-password?token=${token}`;
      if (useEmail) {
        transporter
          .sendMail({
            from: process.env.EMAIL_USER,
            to: email,
            subject: "Reset Password - PASEARCH",
            html: `<a href="${link}">${link}</a>`,
          })
          .catch((e) => console.warn("Email send failed:", e.message));
      } else {
        console.log("ℹ️ Email disabled, reset link:", link);
      }

      res.json({ ok: true, message: "Password reset link sent." });
    }
  );
});

// Reset Password Confirm
app.post("/auth/reset-password", (req, res) => {
  const { token, new_password } = req.body;
  if (!token || !new_password)
    return res.status(400).json({ error: "Token and new_password required" });

  const hashed = bcrypt.hashSync(new_password, 10);
  db.get("SELECT * FROM users WHERE reset_token=?", [token], (err, row) => {
    if (err || !row || Date.now() > row.reset_expires)
      return res.status(400).json({ error: "Invalid or expired token" });

    db.run(
      "UPDATE users SET password=?, reset_token=NULL, reset_expires=NULL WHERE id=?",
      [hashed, row.id],
      (uErr) => {
        if (uErr) return res.status(500).json({ error: "DB error" });
        logPasswordEvent({
          email: row.email,
          action: "Password reset via token",
          actor: row.email,
        });
        res.json({ ok: true, message: "Password reset successful" });
      }
    );
  });
});

// Admin Reset Password
app.post("/admin/reset-user", (req, res) => {
  const { email, new_password } = req.body;
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: "Missing token" });

  try {
    const decoded = jwt.verify(authHeader.split(" ")[1], JWT_SECRET);
    if (decoded.role !== "admin")
      return res.status(403).json({ error: "Admins only" });

    const hashed = bcrypt.hashSync(new_password, 10);
    db.run("UPDATE users SET password=? WHERE email=?", [hashed, email], (err) => {
      if (err) return res.status(500).json({ error: "DB error" });
      logPasswordEvent({
        email,
        action: "Admin reset user password",
        actor: decoded.email,
      });
      res.json({ ok: true, message: "User password reset by admin." });
    });
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
});

// Report Device (uploads + Sheets)
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

    const proof_path = req.files?.proof_path ? req.files.proof_path[0].path : null;
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

// Lookup device by IMEI (useful for police/admin)
app.get("/device/:imei", (req, res) => {
  const { imei } = req.params;
  db.get("SELECT * FROM devices WHERE imei = ?", [imei], (err, row) => {
    if (err) return res.status(500).json({ error: "DB error" });
    if (!row) return res.status(404).json({ error: "Device not found" });
    res.json({ device: row });
  });
});

// =====================
// REPORT DEVICE ENDPOINT
// =====================
app.post("/report-device", async (req, res) => {
  const { imei, name, color, storage, location, reporterName, reporterEmail } = req.body;
  const dateReported = new Date().toLocaleString();

  try {
    // Save to SQLite database
    const db = new sqlite3.Database(DB_PATH);
    db.run(
      `INSERT INTO devices (imei, name, color, storage, location, reporterName, reporterEmail, dateReported)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [imei, name, color, storage, location, reporterName, reporterEmail, dateReported],
      async function (err) {
        if (err) {
          console.error("DB insert error:", err);
          res.status(500).json({ error: "Database error" });
        } else {
          // ✅ Log the new device report to Google Sheets
          await logToGoogleSheet([
            imei,
            name,
            color,
            storage,
            location,
            reporterName,
            reporterEmail,
            dateReported,
          ]);

          res.json({ success: true, message: "Device reported successfully" });
        }
      }
    );
    db.close();
  } catch (err) {
    console.error("Report error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// =====================
// TRACK DEVICE ENDPOINT
// =====================
app.post("/track-device", async (req, res) => {
  const { imei, latitude, longitude, address, trackerName } = req.body;
  const trackedAt = new Date().toLocaleString();

  try {
    // Save the location to the database
    const db = new sqlite3.Database(DB_PATH);
    db.run(
      `INSERT INTO tracking (imei, latitude, longitude, address, trackerName, trackedAt)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [imei, latitude, longitude, address, trackerName, trackedAt],
      async function (err) {
        if (err) {
          console.error("DB insert error:", err);
          res.status(500).json({ error: "Database error" });
        } else {
          // ✅ Log the tracking event to Google Sheets
          await logToGoogleSheet([
            "TRACK", // event type
            imei,
            latitude,
            longitude,
            address,
            trackerName,
            trackedAt,
          ]);

          res.json({ success: true, message: "Device location updated successfully" });
        }
      }
    );
    db.close();
  } catch (err) {
    console.error("Track error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// =====================
// 🧠 OpenAI ASSISTANT (secure backend call)
// =====================
// No SDK import needed; Node 18+ has global fetch. Set OPENAI_API_KEY in Render.
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
          content: `
You are PasearchAI — a privacy-focused assistant integrated into the Pasearch platform.
Help users report, track  and recover devices responsibly.
NEVER reveal private data or violate cyber laws.
Be concise, friendly and helpful.
Use provided memory only for personalization:\n${JSON.stringify(memory || {}, null, 2)}
          `,
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

// 404 Handler
app.use((_, res) => res.status(404).json({ error: "Route not found" }));

// Start Server
app.listen(PORT, "0.0.0.0", () =>
  console.log(`🚀 PASEARCH backend running on http://localhost:${PORT}`)
);
