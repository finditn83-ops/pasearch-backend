// =============================================================
// 🔐 routes/auth.js — Secure Authentication + OTP + Sheet Logging + Alerts
// =============================================================
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const sqlite3 = require("sqlite3").verbose();
const { logSecurityEvent } = require("../sheetsHelper");
require("dotenv").config();

const router = express.Router();
const db = new sqlite3.Database("devices.db");

// =============================================================
// ✉️ EMAIL TRANSPORT — Gmail SMTP
// =============================================================
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.ADMIN_EMAIL,
    pass: process.env.ADMIN_PASS,
  },
});

// =============================================================
// 🧠 In-memory OTP Tracker (auto resets every 10 min)
// =============================================================
const otpCache = {};
const otpFailCount = {};

// =============================================================
// 🧩 1️⃣ USER REGISTRATION
// =============================================================
router.post("/register", async (req, res) => {
  try {
    const { username, email, phone, password, role } = req.body;
    if (!username || !email || !phone || !password)
      return res.status(400).json({ error: "Missing required fields" });

    const userRole =
      email === process.env.ADMIN_EMAIL ? "admin" : role || "reporter";

    const hashed = await bcrypt.hash(password, 10);

    db.run(
      "INSERT INTO users (username, email, phone, password, role, verified, created_at) VALUES (?, ?, ?, ?, ?, ?, datetime('now'))",
      [username, email, phone, hashed, userRole, 1],
      async function (err) {
        if (err) {
          console.error("❌ Registration error:", err.message);
          return res
            .status(409)
            .json({ error: "Username, email, or phone already exists." });
        }

        const token = jwt.sign(
          { id: this.lastID, username, email, role: userRole },
          process.env.JWT_SECRET,
          { expiresIn: "7d" }
        );

        await logSecurityEvent(email, "REGISTER", "SUCCESS", `Role: ${userRole}`);
        res.json({
          success: true,
          message: "Account created successfully.",
          token,
        });
      }
    );
  } catch (err) {
    console.error("Register error:", err);
    res.status(500).json({ error: "Server error during registration" });
  }
});

// =============================================================
// 🧩 2️⃣ USER LOGIN
// =============================================================
router.post("/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: "Username and password required" });

  db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
    if (err) return res.status(500).json({ error: "Database error" });
    if (!user)
      return res.status(400).json({ error: "Invalid username or password" });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
      await logSecurityEvent(user.email, "LOGIN", "FAILED", "Incorrect password");
      return res.status(400).json({ error: "Invalid username or password" });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    await logSecurityEvent(user.email, "LOGIN", "SUCCESS", `Role: ${user.role}`);
    res.json({
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
      },
    });
  });
});

// =============================================================
// 🧩 3️⃣ FORGOT PASSWORD — Send OTP
// =============================================================
router.post("/forgot-password", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: "Email is required" });

  db.get("SELECT * FROM users WHERE email = ?", [email], async (err, user) => {
    if (err) return res.status(500).json({ error: "Database error" });
    if (!user)
      return res.status(404).json({ error: "No user found with that email" });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = Date.now() + 10 * 60 * 1000;

    otpCache[email] = { otp, expiresAt };

    try {
      await transporter.sendMail({
        from: `"PASEARCH Support" <${process.env.ADMIN_EMAIL}>`,
        to: email,
        subject: "PASEARCH Password Reset Code",
        html: `
          <h3>Your password reset code</h3>
          <p>Use this code to reset your password:</p>
          <h2>${otp}</h2>
          <p>This code expires in <b>10 minutes</b>.</p>
        `,
      });

      await logSecurityEvent(email, "FORGOT PASSWORD", "SUCCESS", `OTP: ${otp}`);
      res.json({ message: "OTP sent successfully to your email." });
    } catch (err) {
      await logSecurityEvent(email, "FORGOT PASSWORD", "FAILED", err.message);
      res.status(500).json({ error: "Failed to send OTP" });
    }
  });
});

// =============================================================
// 🧩 4️⃣ VERIFY OTP
// =============================================================
router.post("/verify-otp", async (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp)
    return res.status(400).json({ error: "Email and OTP are required" });

  const record = otpCache[email];
  if (!record)
    return res.status(400).json({ error: "No OTP request found for this email" });

  if (Date.now() > record.expiresAt)
    return res.status(400).json({ error: "OTP expired" });

  if (record.otp !== otp) {
    otpFailCount[email] = (otpFailCount[email] || 0) + 1;
    await logSecurityEvent(email, "VERIFY OTP", "FAILED", `Attempt ${otpFailCount[email]}`);

    // ⚠️ Send admin alert if 3+ failures
    if (otpFailCount[email] >= 3) {
      try {
        await transporter.sendMail({
          from: `"PASEARCH Security" <${process.env.ADMIN_EMAIL}>`,
          to: process.env.ADMIN_EMAIL,
          subject: `🚨 ALERT: Multiple OTP failures for ${email}`,
          html: `<p>${email} has failed OTP verification ${otpFailCount[email]} times.</p>`,
        });
      } catch {}
    }
    return res.status(400).json({ error: "Invalid OTP" });
  }

  await logSecurityEvent(email, "VERIFY OTP", "SUCCESS");
  delete otpCache[email];
  res.json({ message: "OTP verified successfully" });
});

// =============================================================
// 🧩 5️⃣ RESET PASSWORD
// =============================================================
router.post("/reset-password", async (req, res) => {
  const { email, newPassword } = req.body;
  if (!email || !newPassword)
    return res.status(400).json({ error: "Email and new password required" });

  const hashed = await bcrypt.hash(newPassword, 10);
  db.run("UPDATE users SET password = ? WHERE email = ?", [hashed, email], async (err) => {
    if (err) {
      await logSecurityEvent(email, "RESET PASSWORD", "FAILED", err.message);
      return res.status(500).json({ error: "Failed to reset password" });
    }

    await logSecurityEvent(email, "RESET PASSWORD", "SUCCESS");
    res.json({ message: "Password reset successfully. You can now log in." });
  });
});

module.exports = router;
