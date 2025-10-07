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
const ADMIN_EMAIL = "finditn83@gmail.com"; // ✅ Your master admin email

// === APP INIT ===
const app = express();
app.use(cors());
app.use(express.json({ limit: "5mb" }));
app.use(express.urlencoded({ extended: true }));
app.use("/uploads", express.static(UPLOAD_DIR));

// Ensure uploads dir exists
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// === MULTER (File Upload) ===
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
  else console.log("✅ Connected to SQLite database.");
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

// === SERVICES ===
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

// === HEALTH CHECK ===
app.get("/", (req, res) => {
  res.json({
    ok: true,
    service: "PASEARCH Device Tracker Backend",
    env: process.env.NODE_ENV || "development",
    time: new Date().toISOString(),
  });
});

app.get("/healthz", (req, res) => {
  db.get("SELECT 1 as ok", [], (err) => {
    if (err) return res.status(500).json({ ok: false, db: "down" });
    res.json({ ok: true, db: "up", time: new Date().toISOString() });
  });
});

// === REGISTER (Auto Admin + OTP Optional) ===
app.post("/auth/register", async (req, res) => {
  try {
    const { username, email, phone, password, role } = req.body;
    if (!username || !email || !password)
      return res.status(400).json({ error: "All fields required" });

    const userRole = email === ADMIN_EMAIL ? "admin" : (role || "reporter");
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

        // Notify admin
        if (useEmail) {
          transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: ADMIN_EMAIL,
            subject: "New Account Registered - PASEARCH",
            html: `
              <h3>New Account Registered</h3>
              <p><b>Username:</b> ${username}</p>
              <p><b>Email:</b> ${email}</p>
              <p><b>Role:</b> ${userRole}</p>
              <p>Time: ${new Date().toLocaleString()}</p>
            `,
          });
        }

        res.json({
          message: "Account created successfully",
          token,
          user: { id: this.lastID, username, email, role: userRole },
        });
      }
    );
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Server error" });
  }
});

// === LOGIN (Auto Admin Recognition) ===
app.post("/auth/login", (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ error: "Email and password required" });

  db.get("SELECT * FROM users WHERE email = ?", [email], (err, user) => {
    if (err || !user) return res.status(400).json({ error: "Invalid credentials" });

    if (!bcrypt.compareSync(password, user.password))
      return res.status(400).json({ error: "Invalid credentials" });

    // Auto-admin upgrade
    if (user.email === ADMIN_EMAIL && user.role !== "admin") {
      db.run("UPDATE users SET role='admin' WHERE email=?", [user.email]);
      user.role = "admin";
    }

    const token = jwt.sign(
      { id: user.id, username: user.username, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({
      message: "Login successful",
      token,
      user: { id: user.id, username: user.username, email: user.email, role: user.role },
    });
  });
});

// === UPDATE PASSWORD ===
app.post("/auth/update-password", (req, res) => {
  const { email, currentPassword, newPassword } = req.body;
  if (!email || !currentPassword || !newPassword)
    return res.status(400).json({ error: "All fields required" });

  db.get("SELECT * FROM users WHERE email = ?", [email], (err, user) => {
    if (err || !user) return res.status(400).json({ error: "User not found" });

    if (!bcrypt.compareSync(currentPassword, user.password))
      return res.status(400).json({ error: "Incorrect current password" });

    const hashed = bcrypt.hashSync(newPassword, 10);
    db.run("UPDATE users SET password = ? WHERE email = ?", [hashed, email], (err2) => {
      if (err2) return res.status(500).json({ error: "Failed to update password" });

      // Confirmation email
      if (useEmail) {
        transporter.sendMail({
          from: process.env.EMAIL_USER,
          to: ADMIN_EMAIL,
          subject: "Password Updated - PASEARCH",
          html: `
            <h3>Password Changed</h3>
            <p><b>Email:</b> ${email}</p>
            <p>Your password was changed on ${new Date().toLocaleString()}.</p>
          `,
        });
      }

      res.json({ message: "Password updated successfully" });
    });
  });
});

// === UPDATE EMAIL ===
app.post("/auth/update-email", (req, res) => {
  const { oldEmail, newEmail, password } = req.body;
  if (!oldEmail || !newEmail || !password)
    return res.status(400).json({ error: "All fields required" });

  db.get("SELECT * FROM users WHERE email = ?", [oldEmail], (err, user) => {
    if (err || !user) return res.status(400).json({ error: "User not found" });

    if (!bcrypt.compareSync(password, user.password))
      return res.status(400).json({ error: "Incorrect password" });

    db.run("UPDATE users SET email = ? WHERE email = ?", [newEmail, oldEmail], (err2) => {
      if (err2) return res.status(500).json({ error: "Failed to update email" });

      if (oldEmail === ADMIN_EMAIL) {
        db.run("UPDATE users SET role='admin' WHERE email=?", [newEmail]);
      }

      if (useEmail) {
        transporter.sendMail({
          from: process.env.EMAIL_USER,
          to: ADMIN_EMAIL,
          subject: "Email Updated - PASEARCH",
          html: `
            <h3>Email Changed</h3>
            <p>Your account email was updated from <b>${oldEmail}</b> to <b>${newEmail}</b>.</p>
            <p>Time: ${new Date().toLocaleString()}</p>
          `,
        });
      }

      res.json({ message: "Email updated successfully" });
    });
  });
});

// === PASSWORD RESET (FORGOT) ===
app.post("/auth/forgot-password", (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: "Email required" });

  const token = Math.random().toString(36).substring(2, 15);
  const expires = Date.now() + 15 * 60 * 1000;

  db.run("UPDATE users SET reset_token=?, reset_expires=? WHERE email=?", [token, expires, email], (err) => {
    if (err) return res.status(500).json({ error: "DB error" });
    const resetLink = `${FRONTEND_URL}/reset-password?token=${token}`;

    if (useEmail) {
      transporter.sendMail({
        from: process.env.EMAIL_USER,
        to: email,
        subject: "Reset Password - PASEARCH",
        html: `<p>Click the link to reset password: <a href="${resetLink}">${resetLink}</a></p>`,
      });
    } else {
      console.log("ℹ️ Email disabled, reset link:", resetLink);
    }
    res.json({ ok: true, message: "Password reset link sent." });
  });
});

// === RESET PASSWORD CONFIRM ===
app.post("/auth/reset-password", async (req, res) => {
  const { token, new_password } = req.body;
  if (!token || !new_password)
    return res.status(400).json({ error: "Token and new_password required" });

  const hashed = bcrypt.hashSync(new_password, 10);
  db.get("SELECT * FROM users WHERE reset_token=?", [token], (err, row) => {
    if (err) return res.status(500).json({ error: "DB error" });
    if (!row || Date.now() > row.reset_expires)
      return res.status(400).json({ error: "Token invalid or expired" });

    db.run("UPDATE users SET password=?, reset_token=NULL, reset_expires=NULL WHERE id=?", [hashed, row.id], (uErr) => {
      if (uErr) return res.status(500).json({ error: "DB error" });
      res.json({ ok: true, message: "Password reset successfully." });
    });
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

    const hashed = bcrypt.hashSync(new_password, 10);
    db.run("UPDATE users SET password=? WHERE email=?", [hashed, email], (err) => {
      if (err) return res.status(500).json({ error: "DB error" });
      res.json({ ok: true, message: "User password reset by admin." });
    });
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
});

// === 404 HANDLER ===
app.use((req, res) => {
  res.status(404).json({ error: "Route not found" });
});

// === START SERVER ===
app.listen(PORT, "0.0.0.0", () =>
  console.log(`🚀 PASEARCH backend running on http://localhost:${PORT}`)
);
