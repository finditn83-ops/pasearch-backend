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
const crypto = require("crypto");
const { Configuration, OpenAIApi } = require("openai");

const PORT = process.env.PORT || 5000;
const DB_PATH = path.join(__dirname, "devices.db");
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret";
const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:5173";
console.log("🔥 FRONTEND_URL:", FRONTEND_URL);

// --- Express setup ---
const app = express();
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(cors({ origin: FRONTEND_URL, credentials: true }));

// --- SQLite DB ---
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
    resetToken TEXT,
    resetExpires INTEGER,
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

// --- Google Sheets helper ---
async function getSheetsClient() {
  if (!process.env.GOOGLE_SERVICE_ACCOUNT_JSON) return null;
  const creds = JSON.parse(process.env.GOOGLE_SERVICE_ACCOUNT_JSON);
  return new google.auth.GoogleAuth({
    credentials: creds,
    scopes: ["https://www.googleapis.com/auth/spreadsheets"],
  });
}

async function logToSheet(values, range = "Logs!A1") {
  if (!process.env.GOOGLE_SHEET_ID) return;
  const auth = await getSheetsClient();
  if (!auth) return;
  const sheets = google.sheets({ version: "v4", auth });
  try {
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

// --- OpenAI / PasearchAI setup ---
let openai = null;
if (process.env.OPENAI_API_KEY) {
  const configuration = new Configuration({ apiKey: process.env.OPENAI_API_KEY });
  openai = new OpenAIApi(configuration);
}

// --- SMTP transporter ---
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: parseInt(process.env.SMTP_PORT || "587"),
  secure: false,
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
});

// --- Helpers ---
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

// --- Health check ---
app.get("/", (_, res) => res.json({ ok: true, service: "PASEARCH Backend MVP", time: new Date().toISOString() }));

// --- Auth routes ---
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
        const token = jwt.sign({ id: this.lastID, username, role: finalRole }, JWT_SECRET, { expiresIn: "7d" });
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
  db.get("SELECT * FROM users WHERE username = ?", [username], async (err, u) => {
    if (err) return res.status(500).json({ error: "DB error" });
    if (!u) return res.status(400).json({ error: "Invalid credentials" });
    const ok = await bcrypt.compare(password, u.password);
    if (!ok) return res.status(400).json({ error: "Invalid credentials" });
    const token = jwt.sign({ id: u.id, username: u.username, role: u.role }, JWT_SECRET, { expiresIn: "7d" });
    await logToSheet(["LOGIN", username, u.role, new Date().toLocaleString()]);
    res.json({ success: true, token });
  });
});

// --- Forgot / Reset Password ---
app.post("/auth/forgot-password", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: "Email required" });
  db.get("SELECT * FROM users WHERE email = ?", [email], async (err, user) => {
    if (err) return res.status(500).json({ error: "DB error" });
    if (!user) return res.status(404).json({ error: "User not found" });
    const token = crypto.randomBytes(32).toString("hex");
    const expires = Date.now() + 3600 * 1000;
    user.resetToken = token;
    user.resetExpires = expires;
    const resetLink = `${FRONTEND_URL}/reset-password?token=${token}&email=${email}`;
    try {
      await transporter.sendMail({
        from: process.env.SMTP_FROM,
        to: email,
        subject: "PASEARCH Password Reset",
        text: `Click the link to reset: ${resetLink}`,
        html: `<p>Click the link to reset your password:</p><p><a href="${resetLink}">${resetLink}</a></p>`
      });
      res.json({ success: true, message: "Password reset email sent" });
    } catch (e) {
      res.status(500).json({ error: "Failed to send email" });
    }
  });
});

app.post("/auth/reset-password", async (req, res) => {
  const { email, token, newPassword } = req.body;
  if (!email || !token || !newPassword) return res.status(400).json({ error: "Missing fields" });
  db.get("SELECT * FROM users WHERE email = ?", [email], async (err, user) => {
    if (err) return res.status(500).json({ error: "DB error" });
    if (!user || user.resetToken !== token || Date.now() > user.resetExpires) return res.status(400).json({ error: "Invalid or expired token" });
    const hash = await bcrypt.hash(newPassword, 10);
    db.run("UPDATE users SET password = ?, resetToken=NULL, resetExpires=NULL WHERE email=?", [hash, email], function (err2) {
      if (err2) return res.status(500).json({ error: "DB error" });
      res.json({ success: true, message: "Password has been reset" });
    });
  });
});

// --- Admin routes ---
app.get("/admin/users", requireAuth, allowRoles("admin"), (req, res) => {
  db.all("SELECT id, username, email, role FROM users", [], (err, rows) => {
    if (err) return res.status(500).json({ error: "DB error" });
    res.json({ users: rows });
  });
});

app.delete("/admin/users/:id", requireAuth, allowRoles("admin"), (req, res) => {
  const id = req.params.id;
  db.run("DELETE FROM users WHERE id=?", [id], function (err) {
    if (err) return res.status(500).json({ error: "DB error" });
    res.json({ success: true });
  });
});

app.get("/admin/devices", requireAuth, allowRoles("admin"), (req, res) => {
  db.all("SELECT id, imei, device_type, status, reporter_email, created_at FROM devices", [], (err, rows) => {
    if (err) return res.status(500).json({ error: "DB error" });
    res.json({ devices: rows });
  });
});

// --- Police reports ---
app.get("/police/reports", requireAuth, (req, res) => {
  if (!["police","admin"].includes(req.user.role)) return res.status(403).json({ error: "Forbidden" });
  db.all("SELECT * FROM devices ORDER BY id DESC LIMIT 200", [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// --- Device reporting ---
app.post("/report-device", requireAuth, (req, res) => {
  const { device_type, imei, brand, model, color, location_area, lost_type, lost_datetime, reporter_email, reporter_name, google_account_email, apple_id_email, contact_hint } = req.body;
  db.run(
    `INSERT INTO devices (user_id, device_type, imei, brand, model, color, location_area, lost_type, lost_datetime, reporter_email, reporter_name, google_account_email, apple_id_email, contact_hint)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
    [req.user.id, device_type, imei, brand||null, model||null, color||null, location_area||null, lost_type||null, lost_datetime||null, reporter_email||null, reporter_name||null, google_account_email||null, apple_id_email||null, contact_hint||null],
    async function(err){
      if(err) return res.status(500).json({error:"Failed to save"});
      await logToSheet(["REPORT", imei, device_type, reporter_email||"", new Date().toLocaleString()]);
      res.json({success:true, id:this.lastID});
    }
  );
});

// --- Tracking & GPS ---
app.post("/track-device", (req,res)=>{
  const { imei, latitude, longitude, address, trackerName } = req.body;
  if(!imei||!latitude||!longitude) return res.status(400).json({error:"Missing fields"});
  db.run("INSERT INTO tracking (imei, latitude, longitude, address, trackerName, trackedAt) VALUES (?,?,?,?,?,?)",
    [imei,String(latitude),String(longitude),address||null,trackerName||null,new Date().toISOString()],
    async function(err){
      if(err) return res.status(500).json({error:err.message});
      if(io) io.emit("tracking_update",{imei,latitude,longitude,address,trackerName});
      await logToSheet(["TRACK", imei, latitude, longitude, address||"", new Date().toLocaleString()]);
      res.json({success:true});
    }
  );
});

app.post("/gps/update", requireAuth, (req,res)=>{
  const { device_id, lat, lng, accuracy } = req.body;
  if(!device_id||lat===undefined||lng===undefined) return res.status(400).json({error:"Missing fields"});
  db.run("INSERT INTO device_locations (device_id, lat, lng, accuracy) VALUES (?,?,?,?)",[device_id,lat,lng,accuracy||null], function(err){
    if(err) return res.status(500).json({error:err.message});
    db.run("UPDATE devices SET last_seen=? WHERE id=?",[new Date().toISOString(),device_id]);
    db.get("SELECT id, imei, device_type, status, reporter_email FROM devices WHERE id=?",[device_id], (err2,row)=>{
      const payload={device_id,lat,lng,accuracy:accuracy||null,timestamp:new Date().toISOString(),device:row||null};
      if(io) io.emit("gps_update",payload);
      if(row && row.status==="reported" && io) io.emit("police_alert", {
        device_id: row.id, imei: row.imei, device_type: row.device_type, reporter_email: row.reporter_email, lat, lng, timestamp:payload.timestamp
      });
      logToSheet(["GPS_UPDATE", row?.imei||"", device_id, lat, lng, new Date().toLocaleString()]);
      res.json({success:true,id:this.lastID});
    });
  });
});

app.get("/gps/latest", requireAuth, (req,res)=>{
  const { imei, device_id } = req.query;
  if(imei){
    db.get("SELECT id FROM devices WHERE imei=? LIMIT 1",[imei],(err,row)=>{
      if(err) return res.status(500).json({error:err.message});
      if(!row) return res.json({success:true,device:null});
      db.get("SELECT * FROM device_locations WHERE device_id=? ORDER BY timestamp DESC LIMIT 1",[row.id],(err2,loc)=>{
        if(err2) return res.status(500).json({error:err2.message});
        res.json({success:true,device:loc||null});
      });
    });
    return;
  }
  if(device_id){
    db.get("SELECT * FROM device_locations WHERE device_id=? ORDER BY timestamp DESC LIMIT 1",[device_id],(err,loc)=>{
      if(err) return res.status(500).json({error:err.message});
      res.json({success:true,device:loc||null});
    });
    return;
  }
  const sql=`SELECT d.id as device_id,d.imei,d.device_type,l.lat,l.lng,l.accuracy,l.timestamp
  FROM devices d
  LEFT JOIN (SELECT device_id,lat,lng,accuracy,MAX(timestamp) as timestamp FROM device_locations GROUP BY device_id) l
  ON d.id=l.device_id WHERE l.lat IS NOT NULL AND l.lng IS NOT NULL`;
  db.all(sql,[],(err,rows)=>{
    if(err) return res.status(500).json({error:err.message});
    res.json({success:true,devices:rows});
  });
});

app.get("/gps/history", requireAuth, (req,res)=>{
  const { imei, device_id, limit } = req.query;
  const lim = Math.min(parseInt(limit||"200",10),2000);
  if(imei){
    db.get("SELECT id FROM devices WHERE imei=? LIMIT 1",[imei],(err,row)=>{
      if(err) return res.status(500).json({error:err.message});
      if(!row) return res.json({success:true,data:[]});
      db.all("SELECT * FROM device_locations WHERE device_id=? ORDER BY timestamp DESC LIMIT ?",[row.id,lim],(err2,rows)=>{
        if(err2) return res.status(500).json({error:err2.message});
        res.json({success:true,data:rows});
      });
    });
    return;
  }
  if(device_id){
    db.all("SELECT * FROM device_locations WHERE device_id=? ORDER BY timestamp DESC LIMIT ?",[device_id,lim],(err,rows)=>{
      if(err) return res.status(500).json({error:err.message});
      res.json({success:true,data:rows});
    });
    return;
  }
  db.all("SELECT * FROM device_locations ORDER BY timestamp DESC LIMIT ?",[lim],(err,rows)=>{
    if(err) return res.status(500).json({error:err.message});
    res.json({success:true,data:rows});
  });
});

// --- PasearchAI matching ---
app.post("/pasearch-ai/match", requireAuth, async (req,res)=>{
  const { imei, google_account_email, apple_id_email, owner_phone } = req.body;
  db.all("SELECT * FROM devices",[], async (err, rows)=>{
    if(err) return res.status(500).json({error:err.message});
    const results = rows.map(d=>{
      let score = 0;
      if(imei && d.imei && d.imei===imei) score+=60;
      if(google_account_email && d.google_account_email && d.google_account_email===google_account_email) score+=20;
      if(apple_id_email && d.apple_id_email && d.apple_id_email.toLowerCase()===apple_id_email.toLowerCase()) score+=20;
      if(owner_phone && d.contact_hint && d.contact_hint.includes(owner_phone)) score+=10;
      return {...d, matchScore:score};
    });
    results.sort((a,b)=>b.matchScore-a.matchScore);
    await logToSheet(["AI_MATCH", imei||"", google_account_email||"", apple_id_email||"", new Date().toLocaleString()]);
    res.json({success:true,results:results.slice(0,50)});
  });
});

// --- Socket.IO server ---
const server = http.createServer(app);
const io = new Server(server,{
  cors:{ origin: FRONTEND_URL, methods:["GET","POST"] }
});
io.on("connection",(socket)=>{
  console.log("⚡ Socket connected:", socket.id);
});

// --- Start server ---
server.listen(PORT, ()=>console.log(`🚀 Server running on port ${PORT}`));
