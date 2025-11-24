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
const OPENAI_KEY = process.env.OPENAI_API_KEY;

console.log("🔥 FRONTEND_URL:", FRONTEND_URL);

// ---------- EXPRESS SETUP ----------
const app = express();
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(cors({ origin: FRONTEND_URL, credentials: true }));

// ---------- SQLITE INIT ----------
const db = new sqlite3.Database(DB_PATH, (err) => {
  if (err) console.error("❌ DB error:", err.message);
  else console.log("📁 SQLite DB connected.");
});

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
  db.run(`CREATE TABLE IF NOT EXISTS tracking (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    imei TEXT,
    latitude TEXT,
    longitude TEXT,
    address TEXT,
    trackerName TEXT,
    trackedAt TEXT
  )`);
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

// ---------- GOOGLE SHEETS ----------
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

// ---------- OPENAI ----------
const configuration = new Configuration({ apiKey: OPENAI_KEY });
const openai = new OpenAIApi(configuration);

// ---------- EMAIL (Nodemailer) ----------
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: parseInt(process.env.SMTP_PORT || "587"),
  secure: false,
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
});

// ---------- HELPERS ----------
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

// ---------- HEALTH ----------
app.get("/", (_, res) => res.json({ ok: true, service: "PASEARCH Backend MVP" }));

// ---------- AUTH ----------
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
        await logToSheet(["REGISTER", username, email, finalRole, new Date().toLocaleString()]);
        res.json({ success: true, token });
      }
    );
  } catch (e) {
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/auth/login", (req, res) => {
  const { username, password } = req.body;
  db.get(`SELECT * FROM users WHERE username = ? LIMIT 1`, [username], async (err, u) => {
    if (err) return res.status(500).json({ error: "DB error" });
    if (!u) return res.status(400).json({ error: "Invalid credentials" });
    const ok = await bcrypt.compare(password, u.password);
    if (!ok) return res.status(400).json({ error: "Invalid credentials" });
    const token = jwt.sign({ id: u.id, username: u.username, role: u.role }, JWT_SECRET);
    await logToSheet(["LOGIN", username, u.role, new Date().toLocaleString()]);
    res.json({ success: true, token });
  });
});

// ---------- FORGOT / RESET PASSWORD ----------
app.post("/auth/forgot-password", (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: "Email required" });
  db.get(`SELECT * FROM users WHERE email = ?`, [email], async (err, u) => {
    if (err) return res.status(500).json({ error: "DB error" });
    if (!u) return res.status(400).json({ error: "No user found" });
    const resetToken = jwt.sign({ id: u.id }, JWT_SECRET, { expiresIn: "1h" });
    const resetLink = `${FRONTEND_URL}/reset-password/${resetToken}`;
    try {
      await transporter.sendMail({
        from: process.env.SMTP_FROM,
        to: email,
        subject: "PASEARCH Password Reset",
        text: `Click to reset your password: ${resetLink}`,
      });
      res.json({ success: true, message: "Reset email sent" });
    } catch (e) {
      console.error(e);
      res.status(500).json({ error: "Failed to send email" });
    }
  });
});

app.post("/auth/reset-password", (req, res) => {
  const { token, newPassword } = req.body;
  if (!token || !newPassword) return res.status(400).json({ error: "Missing fields" });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    bcrypt.hash(newPassword, 10, (err, hash) => {
      if (err) return res.status(500).json({ error: "Hashing error" });
      db.run(`UPDATE users SET password = ? WHERE id = ?`, [hash, decoded.id], (e) => {
        if (e) return res.status(500).json({ error: "DB update error" });
        res.json({ success: true });
      });
    });
  } catch (e) {
    return res.status(400).json({ error: "Invalid or expired token" });
  }
});

// ---------- ADMIN ----------
app.get("/admin/users", requireAuth, allowRoles("admin"), (req, res) => {
  db.all("SELECT id, username, email, role FROM users", [], (err, rows) => {
    if (err) return res.status(500).json({ error: "DB error" });
    res.json({ users: rows });
  });
});

app.delete("/admin/users/:id", requireAuth, allowRoles("admin"), (req, res) => {
  const { id } = req.params;
  db.run("DELETE FROM users WHERE id = ?", [id], (err) => {
    if (err) return res.status(500).json({ error: "DB error" });
    res.json({ success: true });
  });
});

app.get("/admin/devices", requireAuth, allowRoles("admin"), (req, res) => {
  db.all(
    "SELECT id, imei, device_type, status, reporter_email, created_at FROM devices",
    [],
    (err, rows) => {
      if (err) return res.status(500).json({ error: "DB error" });
      res.json({ devices: rows });
    }
  );
});

app.delete("/admin/devices/:id", requireAuth, allowRoles("admin"), (req, res) => {
  const { id } = req.params;
  db.run("DELETE FROM devices WHERE id = ?", [id], (err) => {
    if (err) return res.status(500).json({ error: "DB error" });
    res.json({ success: true });
  });
});

// ---------- POLICE / REPORTS ----------
app.get("/police/reports", requireAuth, (req, res) => {
  if (!["police", "admin"].includes(req.user.role))
    return res.status(403).json({ error: "Forbidden" });

  const type = (req.query.type || "all").toLowerCase();
  let sql = "SELECT * FROM devices ORDER BY id DESC LIMIT 200";
  let params = [];
  if (type !== "all") {
    sql = "SELECT * FROM devices WHERE device_type = ? ORDER BY id DESC LIMIT 200";
    params = [type];
  }

  db.all(sql, params, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// ---------- REPORT DEVICE ----------
app.post("/report-device", requireAuth, (req, res) => {
  const {
    device_type,
    imei,
    brand,
    model,
    color,
    location_area,
    lost_type,
    lost_datetime,
    reporter_email,
    reporter_name,
    google_account_email,
    apple_id_email,
    contact_hint,
  } = req.body;

  db.run(
    `INSERT INTO devices (user_id, device_type, imei, brand, model, color, location_area, lost_type, lost_datetime, reporter_email, reporter_name, google_account_email, apple_id_email, contact_hint)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
    [
      req.user.id,
      device_type,
      imei,
      brand || null,
      model || null,
      color || null,
      location_area || null,
      lost_type || null,
      lost_datetime || null,
      reporter_email || null,
      reporter_name || null,
      google_account_email || null,
      apple_id_email || null,
      contact_hint || null,
    ],
    async function (err) {
      if (err) return res.status(500).json({ error: err.message });
      await logToSheet(["REPORT", imei, device_type, reporter_email || "", new Date().toLocaleString()]);
      res.json({ success: true, id: this.lastID });
    }
  );
});

// ---------- GPS ----------
app.post("/gps/update", requireAuth, (req, res) => {
  const { device_id, lat, lng, accuracy } = req.body;
  if (!device_id || lat === undefined || lng === undefined) return res.status(400).json({ error: "Missing fields" });

  db.run(
    "INSERT INTO device_locations (device_id, lat, lng, accuracy) VALUES (?,?,?,?)",
    [device_id, lat, lng, accuracy || null],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });

      db.run("UPDATE devices SET last_seen = ? WHERE id = ?", [new Date().toISOString(), device_id]);

      db.get("SELECT id, imei, device_type, status, reporter_email FROM devices WHERE id = ?", [device_id], (err2, deviceRow) => {
        if (io) io.emit("gps_update", { device_id, lat, lng, accuracy, timestamp: new Date().toISOString(), device: deviceRow });
        if (deviceRow?.status === "reported" && io) {
          io.emit("police_alert", {
            device_id: deviceRow.id,
            imei: deviceRow.imei,
            device_type: deviceRow.device_type,
            reporter_email: deviceRow.reporter_email,
            lat,
            lng,
            timestamp: new Date().toISOString(),
          });
        }
      });

      logToSheet(["GPS_UPDATE", device_id, lat, lng, new Date().toLocaleString()]);
      res.json({ success: true, id: this.lastID });
    }
  );
});

// ---------- PASEARCH AI ----------
app.post("/pasearch-ai/match", requireAuth, async (req, res) => {
  const { imei, google_account_email, apple_id_email, owner_phone } = req.body;
  db.all("SELECT * FROM devices", [], async (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });

    const results = rows
      .map((d) => {
        let score = 0;
        if (imei && d.imei && d.imei === imei) score += 60;
        if (google_account_email && d.google_account_email && d.google_account_email === google_account_email) score += 20;
        if (apple_id_email && d.apple_id_email && d.apple_id_email.toLowerCase() === apple_id_email.toLowerCase()) score += 20;
        if (owner_phone && d.contact_hint?.includes(owner_phone)) score += 10;
        return { score, device: d };
      })
      .filter((m) => m.score > 0)
      .sort((a, b) => b.score - a.score);

    res.json(results);
  });
});

// ---------- SOCKET.IO ----------
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*", methods: ["GET", "POST"] } });
io.on("connection", (socket) => {
  console.log("Socket connected:", socket.id);
  socket.on("subscribe_device", (deviceId) => {
    try { socket.join(`device_${deviceId}`); } catch (e) {}
  });
  socket.on("disconnect", () => {});
});
global.io = io;

// ---------- START SERVER ----------
server.listen(PORT, "0.0.0.0", () => console.log(`🚀 PASEARCH Backend running on port ${PORT}`));
