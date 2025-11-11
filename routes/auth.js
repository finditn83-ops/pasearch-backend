// =============================================================
// 🧑‍💻 routes/auth.js — Authentication (Forgot Password + OTP)
// =============================================================
const express = require("express");
const bcrypt = require("bcryptjs");
const nodemailer = require("nodemailer");
const sqlite3 = require("sqlite3").verbose();
const path = require("path");
require("dotenv").config();

const router = express.Router();
const db = new sqlite3.Database("devices.db");

// =============================================================
// ✉️ Nodemailer Transport
// =============================================================
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.ADMIN_EMAIL,
    pass: process.env.ADMIN_PASS,
  },
});

// =============================================================
// 🧩 1️⃣  Forgot Password — Send OTP
// =============================================================
router.post("/forgot-password", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: "Email is required" });

  db.get("SELECT * FROM users WHERE email = ?", [email], async (err, user) => {
    if (err) return res.status(500).json({ error: "Database error" });
    if (!user) return res.status(404).json({ error: "No user found with that email" });

    // Generate a 6-digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000);
    const expiresAt = Date.now() + 10 * 60 * 1000; // 10 min expiry

    // Save OTP to DB
    db.run(
      "CREATE TABLE IF NOT EXISTS otps (email TEXT, otp TEXT, expires_at INTEGER)"
    );
    db.run("DELETE FROM otps WHERE email = ?", [email]); // remove old OTPs
    db.run("INSERT INTO otps (email, otp, expires_at) VALUES (?, ?, ?)", [
      email,
      otp,
      expiresAt,
    ]);

    // Send Email
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

      console.log(`✅ OTP ${otp} sent to ${email}`);
      res.json({ message: "OTP sent successfully to your email." });
    } catch (mailErr) {
      console.error("❌ Email send failed:", mailErr.message);
      res.status(500).json({ error: "Failed to send OTP email." });
    }
  });
});

// =============================================================
// 🧩 2️⃣  Verify OTP
// =============================================================
router.post("/verify-otp", async (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp)
    return res.status(400).json({ error: "Email and OTP are required" });

  db.get("SELECT * FROM otps WHERE email = ? AND otp = ?", [email, otp], (err, row) => {
    if (err) return res.status(500).json({ error: "Database error" });
    if (!row) return res.status(400).json({ error: "Invalid OTP" });
    if (Date.now() > row.expires_at)
      return res.status(400).json({ error: "OTP expired" });

    res.json({ message: "OTP verified successfully" });
  });
});

// =============================================================
// 🧩 3️⃣  Reset Password
// =============================================================
router.post("/reset-password", async (req, res) => {
  const { email, newPassword } = req.body;
  if (!email || !newPassword)
    return res.status(400).json({ error: "Email and new password are required" });

  const hashed = await bcrypt.hash(newPassword, 10);

  db.run("UPDATE users SET password = ? WHERE email = ?", [hashed, email], (err) => {
    if (err) return res.status(500).json({ error: "Database update failed" });
    res.json({ message: "Password reset successfully! You can now log in." });
  });
});

module.exports = router;
