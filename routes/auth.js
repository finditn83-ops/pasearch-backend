// =============================================================
// 🧑‍💻 routes/auth.js — Authentication + OTP + Google Sheet Logging + Admin Alerts + Live Feed
// =============================================================
const express = require("express");
const bcrypt = require("bcryptjs");
const nodemailer = require("nodemailer");
const sqlite3 = require("sqlite3").verbose();
const { google } = require("googleapis");
require("dotenv").config();

// ✅ Access global Socket.IO instance (exported from server.js)
const { io } = require("../socket") || { io: null };

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
// 📊 Google Sheets Logging Helper
// =============================================================
async function logPasswordResetEvent(action, email, status, details = "") {
  try {
    if (!process.env.GOOGLE_SERVICE_ACCOUNT_JSON || !process.env.GOOGLE_SHEET_ID) {
      console.warn("⚠️ Skipping Google Sheet log: missing credentials or sheet ID");
      return;
    }

    const serviceAccount = JSON.parse(process.env.GOOGLE_SERVICE_ACCOUNT_JSON);
    const auth = new google.auth.GoogleAuth({
      credentials: serviceAccount,
      scopes: ["https://www.googleapis.com/auth/spreadsheets"],
    });

    const sheets = google.sheets({ version: "v4", auth });
    const timestamp = new Date().toLocaleString();
    const values = [[action, email, status, details, timestamp]];

    await sheets.spreadsheets.values.append({
      spreadsheetId: process.env.GOOGLE_SHEET_ID,
      range: "PasswordResets!A1",
      valueInputOption: "USER_ENTERED",
      requestBody: { values },
    });

    console.log(`✅ Logged ${action} for ${email} (${status})`);
  } catch (err) {
    console.error("❌ Failed to log password reset event:", err.message);
  }
}

// =============================================================
// 🧠 Local memory tracker for failed OTP attempts
// =============================================================
const otpFailures = {}; // { email: [timestamps] }

function recordOtpFailure(email) {
  const now = Date.now();
  if (!otpFailures[email]) otpFailures[email] = [];
  otpFailures[email].push(now);

  // Keep only failures within last 5 minutes
  otpFailures[email] = otpFailures[email].filter((t) => now - t < 5 * 60 * 1000);

  return otpFailures[email].length;
}

// =============================================================
// 🚨 Admin Alert Email + Socket.IO Broadcast
// =============================================================
async function sendAdminAlert(email, failCount) {
  try {
    await transporter.sendMail({
      from: `"PASEARCH Security" <${process.env.ADMIN_EMAIL}>`,
      to: process.env.ADMIN_EMAIL,
      subject: "🚨 ALERT: Multiple OTP Failures Detected",
      html: `
        <h3>Suspicious Activity Detected</h3>
        <p>User <b>${email}</b> failed OTP verification <b>${failCount}</b> times within 5 minutes.</p>
        <p>This could indicate a brute-force or phishing attempt.</p>
        <p><b>Time:</b> ${new Date().toLocaleString()}</p>
        <hr />
        <p><i>Automated alert from PASEARCH Cyber-Intel System</i></p>
      `,
    });

    console.log(`🚨 Admin alert sent for ${email} (${failCount} failed attempts)`);

    // 🟢 Emit live alert to all connected admin dashboards
    if (io) {
      io.emit("security_alert", {
        type: "OTP_FAILURE",
        email,
        failCount,
        time: new Date().toLocaleString(),
      });
    }
  } catch (err) {
    console.error("❌ Failed to send admin alert:", err.message);
  }
}

// =============================================================
// 🧩 1️⃣ Forgot Password — Send OTP
// =============================================================
router.post("/forgot-password", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: "Email is required" });

  db.get("SELECT * FROM users WHERE email = ?", [email], async (err, user) => {
    if (err) return res.status(500).json({ error: "Database error" });
    if (!user) {
      await logPasswordResetEvent("Forgot Password", email, "FAILED", "User not found");
      return res.status(404).json({ error: "No user found with that email." });
    }

    const otp = Math.floor(100000 + Math.random() * 900000);
    const expiresAt = Date.now() + 10 * 60 * 1000;

    db.run("CREATE TABLE IF NOT EXISTS otps (email TEXT, otp TEXT, expires_at INTEGER)");
    db.run("DELETE FROM otps WHERE email = ?", [email]);
    db.run("INSERT INTO otps (email, otp, expires_at) VALUES (?, ?, ?)", [
      email,
      otp.toString(),
      expiresAt,
    ]);

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

      await logPasswordResetEvent("Forgot Password", email, "SUCCESS", `OTP ${otp} sent`);
      res.json({ message: "OTP sent successfully to your email." });
    } catch (mailErr) {
      await logPasswordResetEvent("Forgot Password", email, "FAILED", mailErr.message);
      res.status(500).json({ error: "Failed to send OTP email." });
    }
  });
});

// =============================================================
// 🧩 2️⃣ Verify OTP — with live alert broadcast
// =============================================================
router.post("/verify-otp", async (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp)
    return res.status(400).json({ error: "Email and OTP are required" });

  db.get(
    "SELECT * FROM otps WHERE email = ? AND otp = ?",
    [email, otp.toString()],
    async (err, row) => {
      if (err) return res.status(500).json({ error: "Database error" });
      if (!row) {
        const failCount = recordOtpFailure(email);
        await logPasswordResetEvent("Verify OTP", email, "FAILED", `Invalid OTP (${failCount}x)`);

        // 🚨 Trigger admin alert for 3+ failures
        if (failCount >= 3) await sendAdminAlert(email, failCount);

        return res.status(400).json({ error: "Invalid OTP" });
      }

      if (Date.now() > row.expires_at) {
        await logPasswordResetEvent("Verify OTP", email, "FAILED", "OTP expired");
        return res.status(400).json({ error: "OTP expired" });
      }

      await logPasswordResetEvent("Verify OTP", email, "SUCCESS");
      res.json({ message: "OTP verified successfully" });
    }
  );
});

// =============================================================
// 🧩 3️⃣ Reset Password
// =============================================================
router.post("/reset-password", async (req, res) => {
  const { email, newPassword } = req.body;
  if (!email || !newPassword)
    return res.status(400).json({ error: "Email and new password are required" });

  const hashed = await bcrypt.hash(newPassword, 10);

  db.run(
    "UPDATE users SET password = ? WHERE email = ?",
    [hashed, email],
    async (err) => {
      if (err) {
        await logPasswordResetEvent("Reset Password", email, "FAILED", err.message);
        return res.status(500).json({ error: "Database update failed" });
      }

      await logPasswordResetEvent("Reset Password", email, "SUCCESS");
      res.json({ message: "Password reset successfully! You can now log in." });
    }
  );
});

module.exports = router;
