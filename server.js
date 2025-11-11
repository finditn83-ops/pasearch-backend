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
// ✅ MULTER FILE UPLOAD HANDLER
// =====================
const multer = require("multer");
const path = require("path");
const fs = require("fs");

const UPLOAD_DIR = path.join(__dirname, "uploads");
if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
  console.log("📁 Created uploads folder at:", UPLOAD_DIR);
}

const storage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, UPLOAD_DIR),
  filename: (_, file, cb) => {
    const safeName = Date.now() + "-" + file.originalname.replace(/\s+/g, "_");
    cb(null, safeName);
  },
});

const upload = multer({ storage });

// ==========================
// ✅ GOOGLE SHEETS CONNECTION CHECK
// ==========================
if (
  process.env.GOOGLE_SHEET_ID &&
  (process.env.GOOGLE_SERVICE_ACCOUNT_PATH || process.env.GOOGLE_SERVICE_ACCOUNT_JSON)
) {
  console.log(`✅ Google Sheets logging enabled (Sheet ID: ${process.env.GOOGLE_SHEET_ID})`);
} else {
  console.warn("⚠️ Google Sheets disabled: Missing credentials or sheet ID");
}

// ==========================
// ✅ GOOGLE SHEETS UNIVERSAL AUTH
// ==========================
async function getGoogleAuth() {
  try {
    if (process.env.GOOGLE_SERVICE_ACCOUNT_JSON) {
      const creds = JSON.parse(process.env.GOOGLE_SERVICE_ACCOUNT_JSON);
      return new google.auth.GoogleAuth({
        credentials: creds,
        scopes: ["https://www.googleapis.com/auth/spreadsheets"],
      });
    }

    const keyFile = process.env.GOOGLE_SERVICE_ACCOUNT_PATH || "./service-account.json";
    if (!fs.existsSync(keyFile))
      throw new Error(`Missing Google key file at: ${keyFile}`);

    return new google.auth.GoogleAuth({
      keyFile,
      scopes: ["https://www.googleapis.com/auth/spreadsheets"],
    });
  } catch (err) {
    console.error("❌ Google Auth Error:", err.message);
    throw err;
  }
}

// ==========================
// ✅ GENERIC SHEET APPENDER
// ==========================
async function appendToSheet(tabName, dataRow) {
  try {
    const auth = await getGoogleAuth();
    const sheets = google.sheets({ version: "v4", auth });
    const timestamp = new Date().toLocaleString();
    const row = [...dataRow, timestamp];

    await sheets.spreadsheets.values.append({
      spreadsheetId: process.env.GOOGLE_SHEET_ID,
      range: `${tabName}!A1`,
      valueInputOption: "USER_ENTERED",
      requestBody: { values: [row] },
    });

    console.log(`✅ Logged to ${tabName}:`, row);
  } catch (err) {
    console.error(`❌ Failed to log to ${tabName}:`, err.message);
  }
}

// ==========================
// ✅ SPECIFIC LOGGING HELPERS
// ==========================
const logToGoogleSheet = (dataRow) => appendToSheet("Sheet1", dataRow);
const logLoginActivityToSheet = (info) =>
  appendToSheet("LoginActivity", [
    info.username,
    info.role,
    info.city,
    info.country,
    info.ip,
    info.localTime,
    info.utcTime,
  ]);
const logFailedLoginAttempt = (info) =>
  appendToSheet("LoginAttempts", [
    info.username,
    info.ip,
    info.city,
    info.country,
    info.reason,
  ]);
const logToGoogleSheetInAdminTab = (dataRow) => appendToSheet("AdminUpdates", dataRow);
const logToGoogleSheetInPoliceTab = (dataRow) => appendToSheet("PoliceUpdates", dataRow);

// =====================
// EXPRESS + CORS
// =====================
const app = express();
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));

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
// ✅ MULTER FILE UPLOAD HANDLER (Global Export)
// =====================
const multer = require("multer");
const path = require("path");
const fs = require("fs");

// Define uploads folder
const UPLOAD_DIR = path.join(__dirname, "uploads");
if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
  console.log("📁 Created uploads folder at:", UPLOAD_DIR);
}

// Configure storage engine
const storage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, UPLOAD_DIR),
  filename: (_, file, cb) => {
    // Replace spaces with underscores to avoid path issues
    const safeName = Date.now() + "-" + file.originalname.replace(/\s+/g, "_");
    cb(null, safeName);
  },
});

// Initialize multer
const upload = multer({ storage });

// ✅ Export it for other route files to use
module.exports.upload = upload;

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

// =======================================
// ✅ POST /log-login — Log login to Google Sheets
// =======================================
app.post("/log-login", async (req, res) => {
  const { username, role, city, country, ip, localTime, utcTime } = req.body;

  try {
    await logLoginActivityToSheet({
      username,
      role,
      city,
      country,
      ip,
      localTime,
      utcTime,
    });

    res.json({ success: true, message: "Login logged successfully" });
  } catch (err) {
    console.error("❌ Login logging error:", err.message);
    res.status(500).json({ error: "Failed to log login" });
  }
});


// ==============================
// ✅ REGISTER USER
// ==============================
app.post("/auth/register", async (req, res) => {
  try {
    const { username, email, phone, password, role } = req.body;

    // 🔒 Basic validation
    if (!username || !email || !phone || !password) {
      return res.status(400).json({
        error: "Username, email, phone, and password are required.",
      });
    }

    // 👑 Auto-assign admin role if email matches ENV admin email
    const userRole = email === process.env.ADMIN_EMAIL ? "admin" : role || "reporter";

    // 🔑 Hash password
    const hashed = await bcrypt.hash(password, 10);

    // 🗄️ Insert user into database
    const sql =
      "INSERT INTO users (username, email, phone, password, role, verified, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)";
    const params = [
      username,
      email,
      phone,
      hashed,
      userRole,
      0, // not verified by default
      new Date().toLocaleString(),
    ];

    db.run(sql, params, async function (err) {
      if (err) {
        console.error("Registration error:", err.message);
        return res
          .status(409)
          .json({ error: "Username, email, or phone already exists." });
      }

      // ✅ Create JWT token
      const token = jwt.sign(
        { id: this.lastID, username, email, role: userRole },
        JWT_SECRET,
        { expiresIn: "7d" }
      );

      // ✅ Log signup to Google Sheets
      await logToGoogleSheet([
        "🆕 New Registration",
        username,
        email,
        phone || "N/A",
        userRole,
        new Date().toLocaleString(),
      ]);

      // ✅ Response
      res.json({
        success: true,
        message: "Account created successfully.",
        token,
      });
    });
  } catch (error) {
    console.error("Register error:", error);
    res.status(500).json({ error: "Server error during registration." });
  }
});

// ======================================
// ⚙️ Helper to log failed login attempts (with IP)
// ======================================
async function logFailedLogin(username, reason) {
  try {
    // Import node-fetch dynamically (works even on Render)
    const fetch = (await import("node-fetch")).default;

    // 🌍 Get IP + location info
    const ipRes = await fetch("https://ipapi.co/json/");
    const ipData = await ipRes.json();

    const city = ipData.city || "Unknown";
    const country = ipData.country_name || "Unknown";
    const ip = ipData.ip || "N/A";

    // 🚫 Send the data to Google Sheet
    await logFailedLoginAttempt({ username, ip, city, country, reason });

    console.log(`🚫 Logged failed login for ${username} (${reason})`);
  } catch (err) {
    console.warn("⚠️ Failed login logging skipped:", err.message);
  }
}

// ==========================
// 🔐 LOGIN USER (Final Version)
// ==========================
app.post("/auth/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
      if (err) {
        console.error("❌ DB error during login:", err.message);
        return res.status(500).json({ error: "Database error" });
      }

      // 🚫 User not found
      if (!user) {
        await logFailedLogin(username, "User not found");
        return res.status(400).json({ error: "Invalid username or password." });
      }

      // 2️⃣ Verify password
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        await logFailedLogin(username, "Incorrect password");
        return res.status(400).json({ error: "Invalid username or password." });
      }

      // 3️⃣ Generate JWT token
      const token = jwt.sign(
        { id: user.id, role: user.role, username: user.username },
        JWT_SECRET,
        { expiresIn: "7d" }
      );

      // 4️⃣ Log successful login to Google Sheets
      try {
        const fetch = (await import("node-fetch")).default;
        const ipRes = await fetch("https://ipapi.co/json/");
        const ipData = await ipRes.json();

        const city = ipData.city || "Unknown";
        const country = ipData.country_name || "Unknown";
        const ip = ipData.ip || "N/A";
        const now = new Date();
        const localTime = now.toLocaleString();
        const utcTime = now.toUTCString();

        await logLoginActivityToSheet({
          username: user.username,
          role: user.role,
          city,
          country,
          ip,
          localTime,
          utcTime,
        });
      } catch (err) {
        console.warn("⚠️ Login activity logging skipped:", err.message);
      }

      // 5️⃣ Return success
      res.json({
        token,
        user: {
          id: user.id,
          username: user.username,
          name: user.name,
          email: user.email,
          role: user.role,
        },
      });

      console.log(`✅ ${user.username} (${user.role}) logged in successfully`);
    });
  } catch (error) {
    console.error("❌ Login route error:", error);
    res.status(500).json({ error: "Server error during login" });
  }
});

// ==============================
// ✅ REPORT DEVICE (Logs to Google Sheet)
// ==============================
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
        storage, // optional
        location_area,
        lost_type,
        lost_datetime,
        other_details,
        reporter_name,
        reporter_email,
        police_case_number, // optional
      } = req.body;

      // file paths
      const proof_path = req.files?.proof_path?.[0]?.path || null;
      const police_path = req.files?.police_report_path?.[0]?.path || null;

      // Basic validation
      if (!imei || !device_type || !reporter_email) {
        return res.status(400).json({
          error: "IMEI, device type, and reporter email are required.",
        });
      }

      // Save to database
      db.run(
        `INSERT INTO devices 
          (user_id, device_category, device_type, imei, color, storage, location_area, lost_type, proof_path, police_report_path, lost_datetime, other_details, reporter_email, police_case_number, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
        [
          user_id,
          device_category,
          device_type,
          imei,
          color,
          storage,
          location_area,
          lost_type,
          proof_path,
          police_path,
          lost_datetime,
          other_details,
          reporter_email,
          police_case_number,
        ],
        async function (err) {
          if (err) {
            console.error("❌ DB Insert Error:", err.message);
            return res.status(500).json({ error: "Failed to report device." });
          }

          const reportedAt = new Date().toLocaleString();

          // ✅ Log to Google Sheets — match your columns exactly
          await logToGoogleSheet([
            imei,
            device_type,              // Device Name column
            color || "N/A",
            storage || "N/A",
            location_area || "N/A",
            reporter_name || "N/A",
            reporter_email,
            reportedAt,
            police_case_number || "N/A",
          ]);

          res.json({
            success: true,
            message: "Device reported successfully.",
            id: this.lastID,
          });
        }
      );
    } catch (error) {
      console.error("❌ Report-device error:", error.message);
      res.status(500).json({ error: "Server error while reporting device." });
    }
  }
);

// ==============================
// ✅ TRACK DEVICE (with live socket + Google Sheets log)
// ==============================
app.post("/track-device", async (req, res) => {
  try {
    const { imei, latitude, longitude, address, trackerName } = req.body;
    const trackedAt = new Date().toISOString().replace("T", " ").split(".")[0];

    db.run(
      `INSERT INTO tracking (imei, latitude, longitude, address, trackerName, trackedAt)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [imei, latitude, longitude, address, trackerName, trackedAt],
      async function (err) {
        if (err) {
          console.error("❌ Database insert failed:", err);
          return res.status(500).json({ error: "Database insert failed" });
        }

        // ✅ Log to Google Sheet (optional)
        await logToGoogleSheet([
          "TRACK",
          imei,
          trackerName || "Unknown",
          latitude,
          longitude,
          address,
          trackedAt,
        ]);

        // ✅ Emit live tracking update to Police/Admin dashboards
        io.emit("tracking_update", {
          imei,
          latitude,
          longitude,
          address,
          trackerName,
          trackedAt,
        });

        console.log("📡 Live tracking update emitted:", imei);

        res.json({
          success: true,
          message: "Device tracked successfully",
        });
      }
    );
  } catch (err) {
    console.error("❌ Track-device error:", err.message);
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
// IMPORT ROUTES
// =====================
const adminRoutes = require("./routes/admin");
app.use("/admin", adminRoutes);

const authRoutes = require("./routes/auth");
app.use("/auth", authRoutes);

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

// ======================================
// ✅ JWT verification middleware
// ======================================
function verifyToken(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: "No token provided" });

  const token = header.split(" ")[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded; // { id, email, role }
    next();
  } catch (err) {
    return res.status(403).json({ error: "Invalid token" });
  }
}

// ======================================
// ✅ Import and Attach Admin Routes
// ======================================
app.use("/admin", verifyToken, adminRoutes);

// ======================================
// ✅ Start HTTP + WebSocket Server
// ======================================
server.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 PASEARCH backend + WebSocket running on port ${PORT}`);
});
