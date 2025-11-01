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
// GOOGLE SHEETS HELPER (modern credentials)
// =====================
async function logToGoogleSheet(dataRow) {
  try {
    const auth = new google.auth.GoogleAuth({
      credentials: JSON.parse(process.env.GOOGLE_SERVICE_ACCOUNT_JSON),
      scopes: ["https://www.googleapis.com/auth/spreadsheets"],
    });

    const sheets = google.sheets({ version: "v4", auth });
    await sheets.spreadsheets.values.append({
      spreadsheetId: process.env.GOOGLE_SHEET_ID,
      range: "Sheet1!A1",
      valueInputOption: "USER_ENTERED",
      requestBody: { values: [dataRow] },
    });

    console.log("✅ Logged to Google Sheets:", dataRow);
  } catch (err) {
    console.error("❌ Sheets logging error:", err.message);
  }
}

// =====================
// CONFIGURATION
// =====================
const DB_PATH = path.join(__dirname, "devices.db");
const UPLOAD_DIR = path.join(__dirname, "uploads");
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret";
const PORT = process.env.PORT || 5000;
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || "finditn83@gmail.com";

// =====================
// INITIALIZE EXPRESS & CORS
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

// ✅ Apply CORS middleware (final step)
app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin) return cb(null, true); // allow Postman / same-origin
      const ok =
        ALLOWED.has(origin) ||
        /\.vercel\.app$/.test(new URL(origin).hostname);
      cb(ok ? null : new Error("CORS blocked"), ok);
    },
    credentials: true,
  })
);


function isAllowedOrigin(origin) {
  if (!origin) return true;
  try {
    const url = new URL(origin);
    const hostname = url.hostname;
    if (ALLOWED.has(origin)) return true;
    if (hostname.endsWith(".vercel.app")) return true;
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

app.use(express.json({ limit: "5mb" }));
app.use(express.urlencoded({ extended: true }));

if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
app.use("/uploads", express.static(UPLOAD_DIR));

app.get("/", (_, res) =>
  res.json({
    ok: true,
    service: "PASEARCH Backend",
    env: process.env.NODE_ENV || "development",
    time: new Date().toISOString(),
  })
);

app.get("/api/health", (_, res) =>
  res.json({
    ok: true,
    message: "Backend reachable ✅",
    service: "PASEARCH Backend",
    env: process.env.NODE_ENV || "development",
    time: new Date().toISOString(),
  })
);

// Multer
const storage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, UPLOAD_DIR),
  filename: (_, file, cb) =>
    cb(null, Date.now() + "-" + file.originalname.replace(/\s+/g, "_")),
});
const upload = multer({ storage });

// DB
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

  db.run(`CREATE INDEX IF NOT EXISTS idx_devices_imei ON devices(imei)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_tracking_imei ON tracking(imei)`);
});

// =====================
// GOOGLE SHEETS LOGGER (auto timestamp)
// =====================
async function logToGoogleSheet(dataRow) {
  try {
    const keyFile = process.env.GOOGLE_SERVICE_ACCOUNT_PATH || "./service-account.json";
    if (!fs.existsSync(keyFile)) throw new Error(`Missing service account file: ${keyFile}`);

    const auth = new google.auth.GoogleAuth({
      keyFile,
      scopes: ["https://www.googleapis.com/auth/spreadsheets"],
    });

    const sheets = google.sheets({ version: "v4", auth });

    // 🕒 Add current timestamp
    const timestamp = new Date().toISOString().replace("T", " ").split(".")[0];
    const fullRow = [...dataRow, timestamp];

    await sheets.spreadsheets.values.append({
      spreadsheetId: process.env.GOOGLE_SHEET_ID,
      range: "Sheet1!A1",
      valueInputOption: "RAW",
      requestBody: { values: [fullRow] },
    });

    console.log("✅ Logged to Google Sheets:", fullRow);
  } catch (err) {
    console.error("⚠️ Sheets log error:", err.message);
  }
}

// Light migration for status/recovered_at (ignore if already exist)
db.run(`ALTER TABLE devices ADD COLUMN status TEXT DEFAULT 'reported'`, (e) => {});
db.run(`ALTER TABLE devices ADD COLUMN recovered_at TEXT`, (e) => {});

// Google Sheets helper (fixed)
const SHEET_ID = process.env.GOOGLE_SHEET_ID || "";
let sheetsClient = null;

(function initSheets() {
  try {
    const keyFile = process.env.GOOGLE_SERVICE_ACCOUNT_PATH || "./service-account.json";

    if (!fs.existsSync(keyFile)) throw new Error(`Missing service account file: ${keyFile}`);

    const auth = new google.auth.GoogleAuth({
      keyFile,
      scopes: ["https://www.googleapis.com/auth/spreadsheets"],
    });

    sheetsClient = google.sheets({ version: "v4", auth });
    console.log("✅ Google Sheets connected (file path)");
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

// Email
const useEmail = !!process.env.EMAIL_USER && !!process.env.EMAIL_PASS;
const transporter = useEmail
  ? nodemailer.createTransport({
      service: "gmail",
      auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
    })
  : null;

// Auth helpers
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
const requireRole =
  (...roles) =>
  (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role))
      return res.status(403).json({ error: "Forbidden" });
    next();
  };

// =====================
// AUTH ROUTES
// =====================

// =====================
// REGISTER USER (with Google Sheets logging)
// =====================
app.post("/auth/register", async (req, res) => {
  try {
    const { username, email, phone, password, role } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ error: "All fields required" });
    }

    const userRole = email === ADMIN_EMAIL ? "admin" : role || "reporter";
    const hashed = await bcrypt.hash(password, 10);

    db.run(
      "INSERT INTO users (username, email, phone, password, role, verified) VALUES (?, ?, ?, ?, ?, 0)",
      [username, email, phone, hashed, userRole],
      async function (err) {
        if (err) {
          if (err.message.includes("UNIQUE")) {
            return res
              .status(409)
              .json({ error: "Username or email already exists" });
          }
          console.error("Database error:", err);
          return res.status(500).json({ error: "Database error" });
        }

        // ✅ Generate token
        const token = jwt.sign(
          { id: this.lastID, username, email, role: userRole },
          JWT_SECRET,
          { expiresIn: "7d" }
        );

        // ✅ Log registration to Google Sheets
        await logToGoogleSheet([
          username,
          email,
          phone || "N/A",
          userRole,
          "New Registration",
          new Date().toLocaleString(),
        ]);

        console.log("✅ New user registered:", username);
        res.json({
          success: true,
          token,
          message: "Account created successfully",
        });
      }
    );
  } catch (error) {
    console.error("Register error:", error);
    res.status(500).json({ error: "Server error during registration" });
  }
});
        // ✅ Optional: email notification (only if EMAIL_USER is set)
        if (process.env.EMAIL_USER) {
          transporter
            .sendMail({
              from: process.env.EMAIL_USER,
              to: ADMIN_EMAIL,
              subject: "New Account Registered - PASEARCH",
              html: `<h3>New Account Registered</h3><p>Email: ${email}</p><p>Role: ${userRole}</p>`,
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
  } catch (err) {
    console.error("Register error:", err);
    res.status(500).json({ error: "Server error during registration" });
  }
});

// Login
app.post("/auth/login", async (req, res) => {
  try {
    const { email, username, password } = req.body;
    const identifier = email || username; // ✅ allow login by email OR username

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

        // ✅ Ensure admin role if logging in with admin email
        if (user.email === ADMIN_EMAIL && user.role !== "admin") {
          db.run("UPDATE users SET role='admin' WHERE email=?", [user.email]);
          user.role = "admin";
        }

        const token = jwt.sign(
          { id: user.id, role: user.role, email: user.email },
          JWT_SECRET,
          { expiresIn: "7d" }
        );

        // Log login action
        const timestamp = new Date().toISOString();
        db.run(
          "INSERT INTO system_logs (user_id, action, timestamp) VALUES (?, ?, ?)",
          [user.id, "User Login", timestamp]
        );

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
      }
    );
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Server error during login" });
  }
});

// =====================
// LOGIN (already handled above)
// =====================
app.post("/login", async (req, res) => {
  try {
    // ... your login logic here ...
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ error: "Server error during login" });
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
      if (err) return res.status(500).json({ error: "Database error" });
      if (!user) return res.status(404).json({ error: "User not found" });

      const match = await bcrypt.compare(currentPassword, user.password);
      if (!match)
        return res.status(400).json({ error: "Incorrect current password" });

      const hashed = await bcrypt.hash(newPassword, 10);
      db.run("UPDATE users SET password=? WHERE email=?", [hashed, email], async (e2) => {
        if (e2) return res.status(500).json({ error: "Update failed" });

        // ✅ Log password update to Google Sheet
        await logToGoogleSheet([
          user.username,
          user.email,
          "Password Updated",
          new Date().toISOString().replace("T", " ").split(".")[0],
        ]);

        res.json({ message: "Password updated successfully" });
      });
    });
  } catch (err) {
    console.error("Update-password error:", err.message);
    res.status(500).json({ error: "Server error during password update" });
  }
});

// =====================
// REPORT DEVICE
// =====================
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
        `INSERT INTO devices
         (user_id, device_category, device_type, imei, color, location_area, lost_type,
          proof_path, police_report_path, lost_datetime, other_details)
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
        async function (err) {
          if (err) {
            console.error("Device insert error:", err.message);
            return res.status(500).json({ error: "Failed to report device" });
          }

          // ✅ Log new report to Google Sheet
          await logToGoogleSheet([
            imei,
            device_type,
            color,
            location_area,
            reporter_email || "N/A",
            lost_type || "N/A",
            new Date().toISOString().replace("T", " ").split(".")[0],
          ]);

          res.json({
            message: "Device reported successfully",
            id: this.lastID,
          });
        }
      );
    } catch (error) {
      console.error("Report-device error:", error.message);
      res.status(500).json({ error: "Server error while reporting device" });
    }
  }
);

// ==============================
// ✅ TRACK DEVICE (with live emit + Google Sheets logging)
// ==============================
app.post("/track-device", async (req, res) => {
  try {
    const { imei, latitude, longitude, address, trackerName } = req.body;
    const trackedAt = new Date().toISOString().replace("T", " ").split(".")[0];

    // ✅ Save tracking info in local database
    db.run(
      `INSERT INTO tracking (imei, latitude, longitude, address, trackerName, trackedAt)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [imei, latitude, longitude, address, trackerName, trackedAt],
      async function (err) {
        if (err) {
          console.error("DB insert error:", err.message);
          return res.status(500).json({ error: "Database error" });
        }

        // ✅ Log tracking event to Google Sheets
        try {
          await logToGoogleSheet([
            imei,
            trackerName || "Unknown Tracker",
            latitude || "N/A",
            longitude || "N/A",
            address || "N/A",
            trackedAt,
          ]);
          console.log("✅ Logged tracking data to Google Sheets");
        } catch (sheetErr) {
          console.error("❌ Sheets logging error:", sheetErr.message);
        }

        // ✅ Optional: emit to connected clients (real-time tracking)
        if (global.io) {
          global.io.emit("deviceTracked", {
            imei,
            latitude,
            longitude,
            address,
            trackerName,
            trackedAt,
          });
        }

        // ✅ Success response
        res.json({
          success: true,
          message: "Device tracked successfully",
          data: { imei, latitude, longitude, address, trackerName, trackedAt },
        });
      }
    );
  } catch (error) {
    console.error("Track-device error:", error.message);
    res.status(500).json({ error: "Server error during device tracking" });
  }
});

// ==============================
// 🔁 TRIGGER FRONTEND DEPLOY FROM BACKEND
// ==============================
app.post("/trigger-frontend", async (req, res) => {
  try {
    const deployUrl = process.env.VERCEL_DEPLOY_HOOK_URL;
    if (!deployUrl)
      return res.status(400).json({ error: "Missing deploy hook URL" });

    const response = await fetch(deployUrl, { method: "POST" });
    if (!response.ok)
      throw new Error(`Failed to trigger frontend: ${response.statusText}`);

    console.log("✅ Frontend deploy triggered successfully");
    res.json({ success: true, message: "Frontend redeploy triggered" });
  } catch (error) {
    console.error("❌ Frontend trigger error:", error.message);
    res.status(500).json({ error: "Failed to trigger frontend" });
  }
});

        // ✅ Log to Google Sheets (Tracking tab)
        await logToGoogleSheet([
          imei,
          latitude,
          longitude,
          address,
          trackerName,
          trackedAt,
        ]);

        // ✅ Broadcast real-time updates to police dashboards
        emitTrackingUpdate({ imei, latitude, longitude, address, trackerName, trackedAt });

        res.json({ success: true, message: "Device location updated successfully" });
      }
    );
  } catch (err) {
    console.error("Track-device error:", err);
    res.status(500).json({ error: "Server error while tracking device" });
  }
});

// ==============================
// ✅ DEVICE LOOKUP BY IMEI (+ optional history)
// ==============================
app.get("/device/:imei", (req, res) => {
  const { imei } = req.params;
  const history = req.query.history === "1" || req.query.history === "true";

  db.get(
    `SELECT d.*, u.username, u.email
     FROM devices d LEFT JOIN users u ON u.id = d.user_id
     WHERE d.imei = ?`,
    [imei],
    (err, device) => {
      if (err) return res.status(500).json({ error: "DB error" });
      if (!device) return res.status(404).json({ error: "Device not found" });

      const trackingQuery = history
        ? `SELECT * FROM tracking WHERE imei = ? ORDER BY id DESC LIMIT 100`
        : `SELECT * FROM tracking WHERE imei = ? ORDER BY id DESC LIMIT 1`;

      db.all(trackingQuery, [imei], (tErr, tRows) => {
        if (tErr) return res.status(500).json({ error: "DB error (tracking)" });
        res.json({
          success: true,
          device,
          last_location: tRows[0] || null,
          history: history ? tRows : undefined,
        });
      });
    }
  );
});

// ==============================
// ✅ ADMIN: USERS LIST (paginated)
// ==============================
app.get("/admin/users", auth, requireRole("admin"), (req, res) => {
  const page = Math.max(parseInt(req.query.page || "1", 10), 1);
  const limit = Math.min(Math.max(parseInt(req.query.limit || "20", 10), 1), 100);
  const q = (req.query.q || "").trim();
  const offset = (page - 1) * limit;

  const where = q ? `WHERE username LIKE ? OR email LIKE ?` : "";
  const params = q ? [`%${q}%`, `%${q}%`] : [];

  db.all(
    `SELECT id, username, email, phone, role, verified, created_at
     FROM users ${where} ORDER BY id DESC LIMIT ? OFFSET ?`,
    [...params, limit, offset],
    (err, rows) => {
      if (err) return res.status(500).json({ error: "DB error" });
      db.get(
        `SELECT COUNT(*) as total FROM users ${where}`,
        params,
        (cErr, cRow) => {
          if (cErr) return res.status(500).json({ error: "DB error" });
          res.json({ page, limit, total: cRow.total, users: rows });
        }
      );
    }
  );
});

// ==============================
// ✅ ADMIN: DEVICES LIST + SEARCH
// ==============================
app.get("/admin/devices", auth, requireRole("admin"), (req, res) => {
  const page = Math.max(parseInt(req.query.page || "1", 10), 1);
  const limit = Math.min(Math.max(parseInt(req.query.limit || "20", 10), 1), 100);
  const offset = (page - 1) * limit;

  const imei = (req.query.imei || "").trim();
  const email = (req.query.email || "").trim();
  const location = (req.query.location || "").trim();
  const status = (req.query.status || "").trim();

  const filters = [];
  const params = [];

  if (imei) { filters.push("d.imei LIKE ?"); params.push(`%${imei}%`); }
  if (email) { filters.push("u.email LIKE ?"); params.push(`%${email}%`); }
  if (location) { filters.push("d.location_area LIKE ?"); params.push(`%${location}%`); }
  if (status) { filters.push("d.status = ?"); params.push(status); }

  const where = filters.length ? `WHERE ${filters.join(" AND ")}` : "";

  db.all(
    `SELECT d.*, u.username, u.email
     FROM devices d LEFT JOIN users u ON u.id = d.user_id
     ${where} ORDER BY d.id DESC LIMIT ? OFFSET ?`,
    [...params, limit, offset],
    (err, rows) => {
      if (err) return res.status(500).json({ error: "DB error" });
      db.get(
        `SELECT COUNT(*) as total FROM devices d LEFT JOIN users u ON u.id = d.user_id ${where}`,
        params,
        (cErr, cRow) => {
          if (cErr) return res.status(500).json({ error: "DB error" });
          res.json({ page, limit, total: cRow.total, devices: rows });
        }
      );
    }
  );
});

// ==============================
// ✅ ADMIN: UPDATE DEVICE STATUS
// ==============================
app.patch("/admin/devices/:id/status", auth, requireRole("admin"), (req, res) => {
  const id = parseInt(req.params.id, 10);
  const { status } = req.body;
  const allowed = new Set(["reported", "investigating", "recovered"]);
  if (!allowed.has(status)) return res.status(400).json({ error: "Invalid status" });

  const recoveredAt = status === "recovered" ? new Date().toISOString() : null;
  db.run(
    `UPDATE devices SET status = ?, recovered_at = ? WHERE id = ?`,
    [status, recoveredAt, id],
    function (err) {
      if (err) return res.status(500).json({ error: "DB error" });
      if (this.changes === 0) return res.status(404).json({ error: "Device not found" });
      res.json({ success: true, id, status, recovered_at: recoveredAt });
    }
  );
});

// ==============================
// ✅ POLICE: SEARCH DEVICES
// ==============================
app.get("/police/devices/search", auth, requireRole("police", "admin"), (req, res) => {
  const imei = (req.query.imei || "").trim();
  const email = (req.query.email || "").trim();
  const location = (req.query.location || "").trim();
  const status = (req.query.status || "").trim();

  const filters = [];
  const params = [];
  if (imei) { filters.push("d.imei LIKE ?"); params.push(`%${imei}%`); }
  if (email) { filters.push("u.email LIKE ?"); params.push(`%${email}%`); }
  if (location) { filters.push("d.location_area LIKE ?"); params.push(`%${location}%`); }
  if (status) { filters.push("d.status = ?"); params.push(status); }

  const where = filters.length ? `WHERE ${filters.join(" AND ")}` : "";

  db.all(
    `SELECT d.id, d.device_category, d.device_type, d.imei, d.color, d.location_area, d.status, d.recovered_at, d.created_at,
            u.username, u.email
     FROM devices d LEFT JOIN users u ON u.id = d.user_id
     ${where} ORDER BY d.id DESC LIMIT 50`,
    params,
    (err, rows) => {
      if (err) return res.status(500).json({ error: "DB error" });
      res.json({ results: rows });
    }
  );
});

// ==============================
// ✅ POLICE: GET TRACKING EVENTS
// ==============================
app.get("/police/tracking", (req, res) => {
  const { imei } = req.query;
  if (!imei) return res.status(400).json({ error: "IMEI query parameter required" });

  db.all(
    "SELECT imei, latitude, longitude, address, trackerName, trackedAt FROM tracking WHERE imei = ? ORDER BY trackedAt DESC LIMIT 20",
    [imei],
    (err, rows) => {
      if (err) return res.status(500).json({ error: "Database error" });
      res.json({ ok: true, imei, tracks: rows });
    }
  );
});

// ==============================
// ✅ ADMIN DASHBOARD METRICS
// ==============================
app.get("/admin/metrics", async (req, res) => {
  try {
    const result = { total_users: 0, total_devices: 0, recovered: 0, investigating: 0 };

    const queries = [
      ["SELECT COUNT(*) as count FROM users", "total_users"],
      ["SELECT COUNT(*) as count FROM devices", "total_devices"],
      ["SELECT COUNT(*) as count FROM devices WHERE status='recovered'", "recovered"],
      ["SELECT COUNT(*) as count FROM devices WHERE status='investigating'", "investigating"],
    ];

    for (const [sql, key] of queries) {
      await new Promise((resolve) => {
        db.all(sql, [], (err, rows) => {
          if (!err && rows?.[0]) result[key] = rows[0].count;
          resolve();
        });
      });
    }

    res.json({ ok: true, metrics: result });
  } catch (err) {
    console.error("Metrics error:", err);
    res.status(500).json({ ok: false, error: "Failed to load metrics" });
  }
});

// ==============================
// ✅ ADMIN RECENT ACTIVITY
// ==============================
app.get("/admin/activity", (req, res) => {
  try {
    const activity = {};

    db.all(
      "SELECT u.username, u.email, s.action, s.timestamp FROM system_logs s JOIN users u ON s.user_id = u.id ORDER BY s.timestamp DESC LIMIT 10",
      [],
      (err, logs) => {
        if (err) return res.status(500).json({ error: "Failed to load system logs" });
        activity.system_logs = logs || [];

        db.all(
          "SELECT id, imei, device_type, status, created_at FROM devices ORDER BY created_at DESC LIMIT 10",
          [],
          (err2, reports) => {
            if (err2) return res.status(500).json({ error: "Failed to load device logs" });
            activity.device_reports = reports || [];
            res.json({ ok: true, activity });
          }
        );
      }
    );
  } catch (err) {
    console.error("Activity route error:", err);
    res.status(500).json({ error: "Server error while fetching activity logs" });
  }
});

// ==============================
// ✅ ASK-AI (Pasearch Assistant)
// ==============================
app.post("/api/ask-ai", async (req, res) => {
  try {
    const { prompt } = req.body;
    const apiKey = process.env.OPENAI_API_KEY;
    if (!apiKey) return res.status(500).json({ error: "OpenAI API key not configured" });

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
            content: "You are PasearchAI — a privacy-focused assistant integrated into the Pasearch platform. Help users report and recover devices safely.",
          },
          { role: "user", content: prompt || "" },
        ],
        max_tokens: 300,
      }),
    });

    if (!r.ok) {
      const t = await r.text();
      console.error("OpenAI error:", r.status, t);
      return res.status(502).json({ error: "OpenAI upstream error" });
    }

    const data = await r.json();
    const reply = data?.choices?.[0]?.message?.content || "Sorry — I couldn’t generate a response.";
    res.json({ reply });
  } catch (err) {
    console.error("AI route error:", err);
    res.status(500).json({ error: "AI request failed" });
  }
});

// ==============================
// 🔁 MANUAL FRONTEND REDEPLOY TRIGGER
// ==============================
app.post("/trigger-frontend", async (req, res) => {
  try {
    const hookUrl = process.env.VERCEL_DEPLOY_HOOK;
    if (!hookUrl) {
      return res.status(500).json({ error: "VERCEL_DEPLOY_HOOK not configured in environment" });
    }

    const r = await fetch(hookUrl, { method: "POST" });
    if (!r.ok) {
      const text = await r.text();
      console.error("Vercel redeploy failed:", r.status, text);
      return res.status(502).json({ error: "Failed to trigger Vercel redeploy" });
    }

    console.log("✅ Triggered Vercel frontend redeploy");
    res.json({ success: true, message: "Frontend redeploy triggered successfully!" });
  } catch (err) {
    console.error("Trigger-frontend error:", err.message);
    res.status(500).json({ error: "Server error while triggering frontend redeploy" });
  }
});

// ==============================
// ✅ 404 HANDLER
// ==============================
app.use((_, res) => res.status(404).json({ error: "Route not found" }));

// ==============================
// ⚡ REAL-TIME SERVER (Socket.IO)
// ==============================
const http = require("http");
const { Server } = require("socket.io");

const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: ["http://localhost:5173", "https://pasearch-frontend.vercel.app"],
    methods: ["GET", "POST"],
  },
});

io.on("connection", (socket) => {
  console.log("Police or Tracker connected:", socket.id);
  socket.on("disconnect", () => console.log("Disconnected:", socket.id));
});

function emitTrackingUpdate(data) {
  io.emit("tracking_update", data);
}
// ==============================
// 🏠 DEFAULT HOME ROUTE
// ==============================
app.get("/", (req, res) => {
  res.send("Welcome to Pasearch");
});

// ==============================
// 🏁 START COMBINED SERVER
// ==============================
server.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 PASEARCH backend + WebSocket running on port ${PORT}`);
});
