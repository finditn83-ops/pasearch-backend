/**
 * PASEARCH Backend — Integrated server.js
 * - SQLite (users, devices, tracking, device_locations)
 * - Auth (register/login)
 * - Role-based access (admin / police / reporter)
 * - GPS endpoints: /gps/update, /gps/latest, /gps/history
 * - Socket.IO realtime: gps_update, tracking_update, police_alert
 * - PasearchAI matching
 * - Admin & police routes
 *
 * Requirements:
 * - .env: PORT, JWT_SECRET, FRONTEND_URL, GOOGLE_SERVICE_ACCOUNT_JSON (optional), GOOGLE_SHEET_ID (optional)
 */

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

const PORT = process.env.PORT || 5000;
const DB_PATH = path.join(__dirname, "devices.db");
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret";
const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:5173";

console.log("🔥 FRONTEND_URL:", FRONTEND_URL);

// Express setup
const app = express();
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin) return cb(null, true);
      if (origin === FRONTEND_URL || origin.endsWith(".vercel.app")) return cb(null, true);
      return cb(new Error("CORS blocked"), false);
    },
    credentials: true,
  })
);

// ---- SQLite init ----
const db = new sqlite3.Database(DB_PATH, (err) => {
  if (err) console.error("❌ DB error:", err.message);
  else console.log("📁 SQLite DB connected.");
});

db.serialize(() => {
  // users table
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    email TEXT UNIQUE,
    phone TEXT,
    password TEXT,
    role TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // devices (reports)
  db.run(`CREATE TABLE IF NOT EXISTS devices (
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
  )`);

  // legacy tracking table (for quick trackers)
  db.run(`CREATE TABLE IF NOT EXISTS tracking (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    imei TEXT,
    latitude TEXT,
    longitude TEXT,
    address TEXT,
    trackerName TEXT,
    trackedAt TEXT
  )`);

  // per-device GPS points
  db.run(`CREATE TABLE IF NOT EXISTS device_locations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER,
    lat REAL,
    lng REAL,
    accuracy REAL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(device_id) REFERENCES devices(id)
  )`);
});

// ---- Google Sheets helper (optional) ----
async function getSheetsClient() {
  try {
    if (!process.env.GOOGLE_SERVICE_ACCOUNT_JSON) return null;
    const creds = JSON.parse(process.env.GOOGLE_SERVICE_ACCOUNT_JSON);
    return new google.auth.GoogleAuth({
      credentials: creds,
      scopes: ["https://www.googleapis.com/auth/spreadsheets"],
    });
  } catch (e) {
    console.warn("Google Sheets auth parse error:", e.message);
    return null;
  }
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

// ---- Helpers (auth / roles) ----
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
    if (!roles.includes(req.user.role)) return res.status(403).json({ error: "Forbidden" });
    next();
  };
}

// ---- Health ----
app.get("/", (_, res) =>
  res.json({ ok: true, service: "PASEARCH Backend MVP", time: new Date().toISOString() })
);

// ---- AUTH ----
app.post("/auth/register", async (req, res) => {
  const { username, email, password, role, phone } = req.body;
  if (!username || !email || !password) return res.status(400).json({ error: "Missing fields" });

  try {
    const hash = await bcrypt.hash(password, 10);
    const finalRole = role || "reporter";

    db.run(
      "INSERT INTO users (username,email,phone,password,role) VALUES (?,?,?,?,?)",
      [username, email, phone || null, hash, finalRole],
      async function (err) {
        if (err) {
          console.error("Register DB error:", err.message);
          return res.status(400).json({ error: "User exists or DB error" });
        }

        const token = jwt.sign({ id: this.lastID, username, role: finalRole }, JWT_SECRET, { expiresIn: "7d" });
        await logToSheet(["REGISTER", username, email, finalRole, new Date().toLocaleString()]);
        return res.json({ success: true, token });
      }
    );
  } catch (e) {
    console.error("Register error:", e.message);
    return res.status(500).json({ error: "Server error" });
  }
});

app.post("/auth/login", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Missing" });

  db.get("SELECT * FROM users WHERE username=?", [username], async (err, u) => {
    if (err) {
      console.error("Login DB error:", err.message);
      return res.status(500).json({ error: "DB error" });
    }
    if (!u) return res.status(400).json({ error: "Invalid credentials" });

    const ok = await bcrypt.compare(password, u.password);
    if (!ok) return res.status(400).json({ error: "Invalid credentials" });

    const token = jwt.sign({ id: u.id, username: u.username, role: u.role }, JWT_SECRET, { expiresIn: "7d" });
    await logToSheet(["LOGIN", username, u.role, new Date().toLocaleString()]);
    res.json({ success: true, token });
  });
});

// ---- Admin routes ----
app.get("/admin/users", requireAuth, allowRoles("admin"), (req, res) => {
  db.all("SELECT id, username, email, role FROM users", [], (err, rows) => {
    if (err) return res.status(500).json({ error: "DB error" });
    res.json({ users: rows });
  });
});

app.get("/admin/devices", requireAuth, allowRoles("admin"), (req, res) => {
  db.all("SELECT id, imei, device_type, status, reporter_email, created_at FROM devices ORDER BY created_at DESC LIMIT 200", [], (err, rows) => {
    if (err) return res.status(500).json({ error: "DB error" });
    res.json({ devices: rows });
  });
});

// ---- Police reports (police/admin) ----
app.get("/police/reports", requireAuth, (req, res) => {
  const role = req.user?.role;
  if (!["police", "admin"].includes(role)) return res.status(403).json({ error: "Forbidden" });

  const type = (req.query.type || "all").toLowerCase();
  let sql = "SELECT * FROM devices ORDER BY id DESC LIMIT 200";
  let params = [];
  if (type && type !== "all") {
    sql = "SELECT * FROM devices WHERE device_type = ? ORDER BY id DESC LIMIT 200";
    params = [type];
  }
  db.all(sql, params, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// ---- Report a device ----
app.post("/report-device", requireAuth, (req, res) => {
  const {
    device_type, imei, brand, model, color, location_area,
    lost_type, lost_datetime, reporter_email, reporter_name,
    google_account_email, apple_id_email, contact_hint,
  } = req.body;

  db.run(
    `INSERT INTO devices (user_id, device_type, imei, brand, model, color, location_area, lost_type, lost_datetime, reporter_email, reporter_name, google_account_email, apple_id_email, contact_hint)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
    [
      req.user.id,
      device_type, imei, brand || null, model || null, color || null, location_area || null,
      lost_type || null, lost_datetime || null, reporter_email || null, reporter_name || null,
      google_account_email || null, apple_id_email || null, contact_hint || null
    ],
    async function (err) {
      if (err) {
        console.error("report-device error:", err.message);
        return res.status(500).json({ error: "Failed to save" });
      }
      await logToSheet(["REPORT", imei, device_type, reporter_email || reporter_name, new Date().toLocaleString()]);
      res.json({ success: true, id: this.lastID });
    }
  );
});

// ---- Legacy quick tracker endpoint (track-device) ----
app.post("/track-device", (req, res) => {
  const { imei, latitude, longitude, address, trackerName } = req.body;
  if (!imei || !latitude || !longitude) return res.status(400).json({ error: "Missing fields" });

  db.run(
    `INSERT INTO tracking (imei, latitude, longitude, address, trackerName, trackedAt) VALUES (?,?,?,?,?,?)`,
    [imei, String(latitude), String(longitude), address || null, trackerName || null, new Date().toISOString()],
    async function (err) {
      if (err) return res.status(500).json({ error: err.message });

      if (io) io.emit("tracking_update", { imei, latitude, longitude, address, trackerName });
      await logToSheet(["TRACK", imei, latitude, longitude, address || "", new Date().toLocaleString()]);
      res.json({ success: true });
    }
  );
});

// ---- GPS per-device: store and emit ----
app.post("/gps/update", requireAuth, (req, res) => {
  const { device_id, lat, lng, accuracy } = req.body;
  if (!device_id || lat === undefined || lng === undefined) return res.status(400).json({ error: "Missing required fields." });

  const sql = `INSERT INTO device_locations (device_id, lat, lng, accuracy) VALUES (?, ?, ?, ?)`;
  db.run(sql, [device_id, lat, lng, accuracy || null], function (err) {
    if (err) {
      console.error("gps/update error:", err.message);
      return res.status(500).json({ error: err.message });
    }

    // update devices.last_seen
    db.run("UPDATE devices SET last_seen = ? WHERE id = ?", [new Date().toISOString(), device_id], (uerr) => {
      if (uerr) console.warn("failed to update last_seen:", uerr.message);
    });

    // fetch device info to include in emit and alerts
    db.get("SELECT id, imei, device_type, status, reporter_email FROM devices WHERE id = ?", [device_id], (derr, deviceRow) => {
      const payload = {
        device_id,
        lat,
        lng,
        accuracy: accuracy || null,
        timestamp: new Date().toISOString(),
        device: deviceRow || null,
      };

      // emit realtime update
      if (io) io.emit("gps_update", payload);

      // police-alert logic: if device is reported (status === 'reported'), emit police_alert
      if (deviceRow && deviceRow.status === "reported") {
        const alert = {
          device_id: deviceRow.id,
          imei: deviceRow.imei,
          device_type: deviceRow.device_type,
          reporter_email: deviceRow.reporter_email,
          lat,
          lng,
          timestamp: payload.timestamp,
        };
        if (io) io.emit("police_alert", alert);
      }

      logToSheet(["GPS_UPDATE", deviceRow?.imei || "", device_id, lat, lng, new Date().toLocaleString()]).catch(() => {});

      res.json({ success: true, id: this.lastID });
    });
  });
});

// ---- GET latest location(s) ----
// Supports: ?imei=xxxx or ?device_id=NNN  OR no param -> returns latest for all devices with location
app.get("/gps/latest", requireAuth, (req, res) => {
  const { imei, device_id } = req.query;

  if (imei) {
    // find device by imei
    db.get("SELECT id FROM devices WHERE imei = ? LIMIT 1", [imei], (err, row) => {
      if (err) return res.status(500).json({ error: err.message });
      if (!row) return res.json({ success: true, device: null });

      const did = row.id;
      db.get("SELECT * FROM device_locations WHERE device_id = ? ORDER BY timestamp DESC LIMIT 1", [did], (lerr, loc) => {
        if (lerr) return res.status(500).json({ error: lerr.message });
        return res.json({ success: true, device: loc || null });
      });
    });
    return;
  }

  if (device_id) {
    db.get("SELECT * FROM device_locations WHERE device_id = ? ORDER BY timestamp DESC LIMIT 1", [device_id], (err, loc) => {
      if (err) return res.status(500).json({ error: err.message });
      return res.json({ success: true, device: loc || null });
    });
    return;
  }

  // default: latest location per device (join)
  const sql = `
    SELECT d.id as device_id, d.imei, d.device_type,
           l.lat, l.lng, l.accuracy, l.timestamp
    FROM devices d
    LEFT JOIN (
      SELECT device_id, lat, lng, accuracy, MAX(timestamp) as timestamp
      FROM device_locations
      GROUP BY device_id
    ) l ON d.id = l.device_id
    WHERE l.lat IS NOT NULL AND l.lng IS NOT NULL
  `;
  db.all(sql, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true, devices: rows });
  });
});

// ---- GPS history (supports imei or device_id, & limit) ----
app.get("/gps/history", requireAuth, (req, res) => {
  const { imei, device_id, limit } = req.query;
  const lim = Math.min(parseInt(limit || "200", 10), 2000);

  if (imei) {
    db.get("SELECT id FROM devices WHERE imei = ? LIMIT 1", [imei], (err, row) => {
      if (err) return res.status(500).json({ error: err.message });
      if (!row) return res.json({ success: true, data: [] });
      db.all("SELECT * FROM device_locations WHERE device_id = ? ORDER BY timestamp DESC LIMIT ?", [row.id, lim], (lerr, rows) => {
        if (lerr) return res.status(500).json({ error: lerr.message });
        return res.json({ success: true, data: rows });
      });
    });
    return;
  }

  if (device_id) {
    db.all("SELECT * FROM device_locations WHERE device_id = ? ORDER BY timestamp DESC LIMIT ?", [device_id, lim], (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      return res.json({ success: true, data: rows });
    });
    return;
  }

  // fallback: all recent points (capped)
  db.all("SELECT * FROM device_locations ORDER BY timestamp DESC LIMIT ?", [lim], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    return res.json({ success: true, data: rows });
  });
});

// ---- PasearchAI matching (requires auth) ----
app.post("/pasearch-ai/match", requireAuth, (req, res) => {
  const { imei, google_account_email, apple_id_email, owner_phone } = req.body;

  db.all("SELECT * FROM devices", [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });

    const results = rows
      .map((d) => {
        let score = 0;
        if (imei && d.imei && d.imei === imei) score += 60;
        if (google_account_email && d.google_account_email && d.google_account_email.toLowerCase() === google_account_email.toLowerCase()) score += 40;
        if (apple_id_email && d.apple_id_email && d.apple_id_email.toLowerCase() === apple_id_email.toLowerCase()) score += 40;
        if (owner_phone && d.contact_hint && d.contact_hint.includes(owner_phone.replace(/[^0-9]/g, "").slice(-7))) score += 20;
        return { score, device: d };
      })
      .filter((m) => m.score > 0)
      .sort((a, b) => b.score - a.score);

    res.json({ success: true, matches: results });
  });
});

// ---- Quick IMEI lookup ----
app.get("/devices/by-imei/:imei", requireAuth, (req, res) => {
  const imei = req.params.imei;
  db.get("SELECT * FROM devices WHERE imei = ? LIMIT 1", [imei], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ device: row || null });
  });
});

// ---- Socket.IO + Server start ----
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"],
  },
});

io.on("connection", (socket) => {
  console.log("Socket connected:", socket.id);

  // allow clients to subscribe to a specific device room
  socket.on("subscribe_device", (deviceId) => {
    try {
      socket.join(`device_${deviceId}`);
    } catch (e) {}
  });

  socket.on("disconnect", () => {
    // console.log("Socket disconnected:", socket.id);
  });
});

// keep io global for route handlers
global.io = io;

server.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 PASEARCH Backend MVP running on port ${PORT}`);
});
