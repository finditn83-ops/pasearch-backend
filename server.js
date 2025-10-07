// server.js — FINAL BACKEND (OTP + Password Reset + Admin Tools, Render-ready)
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const sqlite3 = require("sqlite3").verbose();
const multer = require("multer");
const nodemailer = require("nodemailer");
const twilio = require("twilio");
const path = require("path");
const fs = require("fs");
require("dotenv").config();

// === CONFIG ===
const DB_PATH = path.join(__dirname, "devices.db");
const UPLOAD_DIR = path.join(__dirname, "uploads");
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret";
const PORT = process.env.PORT || 5000;
const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:5173";

// === APP INIT ===
const app = express();
app.use(cors());
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));
app.use("/uploads", express.static(UPLOAD_DIR));

// Ensure uploads dir exists
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// === MULTER ===
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const safe = Date.now() + "-" + file.originalname.replace(/\s+/g, "_");
    cb(null, safe);
  },
});
const upload = multer({ storage });

// === DATABASE ===
const db = new sqlite3.Database(DB_PATH, (err) => {
  if (err) console.error("❌ DB error:", err.message);
  else console.log("✅ Connected to SQLite DB.");
});

// Create tables
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
  db.run(`CREATE TABLE IF NOT EXISTS otp_codes (
    email TEXT,
    otp TEXT,
    expires_at INTEGER,
    attempts INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
});

// === SERVICES (safe setup) ===
const useTwilio =
  !!process.env.TWILIO_SID &&
  !!process.env.TWILIO_TOKEN &&
  !!process.env.TWILIO_PHONE;

const twilioClient = useTwilio
  ? twilio(process.env.TWILIO_SID, process.env.TWILIO_TOKEN)
  : null;

const useEmail = !!process.env.EMAIL_USER && !!process.env.EMAIL_PASS;

const transporter = useEmail
  ? nodemailer.createTransport({
      service: "gmail",
      auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
    })
  : null;

// === ROOT & HEALTH (fixes "Cannot GET /") ===
app.get("/", (req, res) => {
  res.json({
    ok: true,
    service: "PASEARCH Device Tracker Backend",
    env: process.env.NODE_ENV || "development",
    time: new Date().toISOString(),
    docs: {
      health: "/healthz",
      login: "POST /auth/login",
      register: "POST /auth/register",
      verifyOtp: "POST /auth/verify-otp",
      resendOtp: "POST /auth/resend-otp",
      forgot: "POST /auth/forgot-password",
      reset: "POST /auth/reset-password",
      adminReset: "POST /admin/reset-user",
    },
  });
});

app.get("/healthz", (req, res) => {
  // Simple DB ping
  db.get("SELECT 1 as ok", [], (err, row) => {
    if (err) return res.status(500).json({ ok: false, db: "down" });
    res.json({ ok: true, db: "up", time: new Date().toISOString() });
  });
});

// === REGISTER (with OTP) ===
app.post("/auth/register", async (req, res) => {
  try {
    const { username, email, phone, password, role } = req.body;
    if (!username || !email || !phone || !password) {
      return res.status(400).json({ error: "All fields required" });
    }
    const salt = await bcrypt.genSalt(10);
    const hashed = await bcrypt.hash(password, salt);

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expires = Date.now() + 5 * 60 * 1000; // 5 minutes

    db.run(
      "INSERT INTO users (username,email,phone,password,role,verified) VALUES (?,?,?,?,?,0)",
      [username, email, phone, hashed, role || "reporter"],
      (err) => {
        if (err) {
          if (err.message && err.message.includes("UNIQUE")) {
            return res
              .status(409)
              .json({ error: "Username or email already exists" });
          }
          return res.status(500).json({ error: "DB error" });
        }

        db.run(
          "INSERT INTO otp_codes (email, otp, expires_at, attempts) VALUES (?,?,?,0)",
          [email, otp, expires]
        );

        // Send SMS
        if (useTwilio) {
          twilioClient.messages
            .create({
              body: `Your PASEARCH verification code: ${otp}`,
              from: process.env.TWILIO_PHONE,
              to: phone,
            })
            .catch((e) => console.log("SMS fail:", e.message));
        } else {
          console.log("ℹ️ Twilio disabled, OTP:", otp);
        }

        // Send Email
        if (useEmail) {
          transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: email,
            subject: "Verify your PASEARCH Account",
            html: `<p>Your verification code: <b>${otp}</b> (expires in 5 minutes)</p>`,
          });
        } else {
          console.log("ℹ️ Email disabled, OTP:", otp);
        }

        res.json({ ok: true, message: "OTP sent to phone and/or email." });
      }
    );
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Server error" });
  }
});

// === VERIFY OTP ===
app.post("/auth/verify-otp", (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp)
    return res.status(400).json({ error: "Email and OTP required" });

  db.get(
    "SELECT * FROM otp_codes WHERE email = ? ORDER BY created_at DESC LIMIT 1",
    [email],
    (err, row) => {
      if (err) return res.status(500).json({ error: "DB error" });
      if (!row) return res.status(404).json({ error: "OTP not found" });
      if (Date.now() > row.expires_at)
        return res.status(400).json({ error: "OTP expired" });
      if (row.otp !== otp)
        return res.status(400).json({ error: "Invalid OTP" });

      db.run("UPDATE users SET verified = 1 WHERE email = ?", [email]);
      db.run("DELETE FROM otp_codes WHERE email = ?", [email]);
      res.json({ ok: true, message: "Account verified successfully." });
    }
  );
});

// === RESEND OTP (limited) ===
app.post("/auth/resend-otp", (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: "Email required" });

  db.get("SELECT * FROM users WHERE email = ?", [email], (err, user) => {
    if (err) return res.status(500).json({ error: "DB error" });
    if (!user) return res.status(404).json({ error: "User not found" });
    if (user.verified) return res.json({ message: "Already verified." });

    db.get("SELECT * FROM otp_codes WHERE email = ? ORDER BY created_at DESC LIMIT 1", [email], (err2, row) => {
      if (row && row.attempts >= 3) {
        const last = new Date(row.created_at).getTime();
        if (Date.now() - last < 30 * 60 * 1000) {
          return res.status(429).json({ error: "Too many requests. Try later." });
        }
      }

      const newOTP = Math.floor(100000 + Math.random() * 900000).toString();
      const expires = Date.now() + 5 * 60 * 1000;

      const nextAttempts = row && typeof row.attempts === "number" ? row.attempts + 1 : 1;

      db.run(
        "INSERT INTO otp_codes (email, otp, expires_at, attempts) VALUES (?,?,?,?)",
        [email, newOTP, expires, nextAttempts]
      );

      if (useEmail) {
        transporter.sendMail({
          from: process.env.EMAIL_USER,
          to: email,
          subject: "Resend OTP - PASEARCH",
          html: `<p>Your new OTP is <b>${newOTP}</b> (expires in 5 minutes)</p>`,
        });
      } else {
        console.log("ℹ️ Email disabled, OTP:", newOTP);
      }

      if (useTwilio) {
        twilioClient.messages
          .create({
            body: `New PASEARCH OTP: ${newOTP}`,
            from: process.env.TWILIO_PHONE,
            to: user.phone,
          })
          .catch((e) => console.log("SMS resend fail:", e.message));
      } else {
        console.log("ℹ️ Twilio disabled, OTP:", newOTP);
      }

      res.json({ ok: true, message: "New OTP sent to email/phone." });
    });
  });
});

// === LOGIN ===
app.post("/auth/login", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: "Username and password required" });

  db.get("SELECT * FROM users WHERE username = ?", [username], async (err, u) => {
    if (err) return res.status(500).json({ error: "DB error" });
    if (!u) return res.status(401).json({ error: "Invalid credentials" });
    if (!u.verified)
      return res.status(403).json({ error: "Account not verified" });

    const valid = await bcrypt.compare(password, u.password);
    if (!valid) return res.status(401).json({ error: "Invalid password" });

    const token = jwt.sign(
      { id: u.id, username: u.username, role: u.role },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({
      ok: true,
      token,
      role: u.role,
      user: { id: u.id, username: u.username, email: u.email, phone: u.phone },
    });
  });
});

// === PASSWORD RESET (Email link) ===
app.post("/auth/forgot-password", (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: "Email required" });

  const token = Math.random().toString(36).substring(2, 15);
  const expires = Date.now() + 15 * 60 * 1000;

  db.run("UPDATE users SET reset_token=?, reset_expires=? WHERE email=?", [token, expires, email], function (err) {
    if (err) return res.status(500).json({ error: "DB error" });

    const resetLink = `${FRONTEND_URL}/reset-password?token=${token}`;

    if (useEmail) {
      transporter.sendMail({
        from: process.env.EMAIL_USER,
        to: email,
        subject: "Reset Password - PASEARCH",
        html: `<p>Click to reset your password: 
               <a href="${resetLink}">Reset Password</a> (expires in 15 minutes)</p>`,
      });
    } else {
      console.log("ℹ️ Email disabled, reset link:", resetLink);
    }

    res.json({ ok: true, message: "Password reset link sent to email (or logged to console)." });
  });
});

// === RESET PASSWORD CONFIRM ===
app.post("/auth/reset-password", async (req, res) => {
  const { token, new_password } = req.body;
  if (!token || !new_password)
    return res.status(400).json({ error: "Token and new_password required" });

  const salt = await bcrypt.genSalt(10);
  const hashed = await bcrypt.hash(new_password, salt);

  db.get("SELECT * FROM users WHERE reset_token=?", [token], (err, row) => {
    if (err) return res.status(500).json({ error: "DB error" });
    if (!row || Date.now() > row.reset_expires)
      return res.status(400).json({ error: "Token invalid or expired" });

    db.run(
      "UPDATE users SET password=?, reset_token=NULL, reset_expires=NULL WHERE id=?",
      [hashed, row.id],
      function (uErr) {
        if (uErr) return res.status(500).json({ error: "DB error" });
        res.json({ ok: true, message: "Password reset successfully." });
      }
    );
  });
});

// === ADMIN RESET USER PASSWORD ===
app.post("/admin/reset-user", (req, res) => {
  const { email, new_password } = req.body;
  if (!email || !new_password)
    return res.status(400).json({ error: "Email and new_password required" });

  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: "Missing token" });

  const token = auth.split(" ")[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.role !== "admin")
      return res.status(403).json({ error: "Admins only" });

    bcrypt.hash(new_password, 10).then((hashed) => {
      db.run("UPDATE users SET password=? WHERE email=?", [hashed, email], function (err) {
        if (err) return res.status(500).json({ error: "DB error" });
        res.json({ ok: true, message: "User password reset by admin." });
      });
    });
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
});

// === OPTIONAL: Example file upload for proofs (kept for future)
// app.post("/reporter/proof", upload.single("proof"), (req, res) => {
//   res.json({ ok: true, file: `/uploads/${req.file.filename}` });
// });

// === 404 HANDLER ===
app.use((req, res) => {
  res.status(404).json({ error: "Route not found" });
});

// === START ===
app.listen(PORT, "0.0.0.0", () =>
  console.log(`🚀 PASEARCH backend running on http://localhost:${PORT}`)
);
