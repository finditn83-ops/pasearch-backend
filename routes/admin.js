// =====================
// 📂 ADMIN ROUTES (with file upload support)
// =====================
const express = require("express");
const router = express.Router();
const sqlite3 = require("sqlite3").verbose();

// ✅ Connect to SQLite database
const db = new sqlite3.Database("devices.db", (err) => {
  if (err) console.error("❌ DB error:", err.message);
  else console.log("✅ Admin routes connected to SQLite DB.");
});

// ✅ Import global upload from server.js
const { upload } = require("../server"); // 👈 this fixes "upload is not defined"

// Example: handle admin file upload
router.post("/upload-proof", upload.single("proof"), (req, res) => {
  try {
    console.log("File uploaded by admin:", req.file);
    res.json({
      message: "✅ File uploaded successfully!",
      file: req.file.filename,
    });
  } catch (err) {
    console.error("❌ Upload failed:", err.message);
    res.status(500).json({ error: "Upload failed" });
  }
});

// ✅ IMPORT GOOGLE SHEET HELPERS
const { logToGoogleSheetInAdminTab, logToGoogleSheetInPoliceTab } = require("../sheetsHelper");

// ✅ Middleware to verify admin access
function requireAdmin(req, res, next) {
  try {
    const auth = req.user; // assuming req.user is set by JWT middleware
    if (!auth || auth.role !== "admin") {
      return res.status(403).json({ error: "Access denied: admin only" });
    }
    next();
  } catch {
    return res.status(401).json({ error: "Unauthorized" });
  }
}

// =============================
// 1️⃣  GET /admin/metrics
// =============================
router.get("/metrics", requireAdmin, (req, res) => {
  const metrics = {
    totalUsers: 0,
    totalReports: 0,
    recoveredDevices: 0,
    underInvestigation: 0,
  };

  db.get("SELECT COUNT(*) AS total FROM users", (err, row) => {
    if (!err) metrics.totalUsers = row?.total || 0;

    db.get("SELECT COUNT(*) AS total FROM devices", (err2, row2) => {
      if (!err2) metrics.totalReports = row2?.total || 0;

      db.get("SELECT COUNT(*) AS total FROM devices WHERE status='Recovered'", (err3, row3) => {
        if (!err3) metrics.recoveredDevices = row3?.total || 0;

        db.get("SELECT COUNT(*) AS total FROM devices WHERE status='Under Investigation'", (err4, row4) => {
          if (!err4) metrics.underInvestigation = row4?.total || 0;
          res.json(metrics);
        });
      });
    });
  });
});

// =============================
// 2️⃣  GET /admin/reports
// =============================
router.get("/reports", requireAdmin, (req, res) => {
  db.all("SELECT * FROM devices ORDER BY created_at DESC", (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// =============================
// 3️⃣  GET /admin/users
// =============================
router.get("/users", requireAdmin, (req, res) => {
  db.all("SELECT id, username, email, role, created_at FROM users ORDER BY created_at DESC", (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// =============================
// 4️⃣  GET /admin/activity
// =============================
router.get("/activity", requireAdmin, (req, res) => {
  const activity = { system_logs: [], device_reports: [] };

  db.all("SELECT * FROM logs ORDER BY timestamp DESC LIMIT 20", (err, logs) => {
    if (!err && logs) activity.system_logs = logs;

    db.all("SELECT * FROM devices ORDER BY created_at DESC LIMIT 20", (err2, reports) => {
      if (!err2 && reports) activity.device_reports = reports;
      res.json(activity);
    });
  });
});

// =============================
// ✅ 5️⃣ PUT /admin/update-device/:id
// Logs to Google Sheets tab "AdminUpdates"
// =============================
router.put("/update-device/:id", requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { status, updated_by } = req.body;

  try {
    // 1️⃣ Update device in DB
    db.run("UPDATE devices SET status=? WHERE id=?", [status, id], async function (err) {
      if (err) {
        console.error("❌ DB update error:", err.message);
        return res.status(500).json({ error: err.message });
      }
      if (this.changes === 0) return res.status(404).json({ error: "Device not found" });

      // 2️⃣ Fetch device details for Google Sheet logging
      db.get("SELECT imei, device_type AS device_name FROM devices WHERE id=?", [id], async (fetchErr, device) => {
        if (fetchErr || !device) {
          console.warn("⚠️ Could not fetch device details for Sheets log.");
          return res.json({ success: true, updated: this.changes });
        }

        // 3️⃣ Log to "AdminUpdates" tab
        const updatedAt = new Date().toLocaleString();
        await logToGoogleSheetInAdminTab([
          device.imei,
          device.device_name || "Unknown",
          "Updated Status",
          updated_by || "Admin",
          status,
          updatedAt,
        ]);

        console.log(`✅ Admin update logged for device ${device.imei}: ${status}`);

        res.json({
          success: true,
          message: "Device status updated successfully",
          updated: this.changes,
        });
      });
    });
  } catch (error) {
    console.error("❌ Admin update error:", error.message);
    res.status(500).json({ error: "Server error while updating device status" });
  }
});

// =============================
// ✅ 6️⃣ PUT /admin/update-case/:id
// Logs police case updates to "PoliceUpdates" tab
// =============================
router.put("/update-case/:id", requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { police_case_number, update_type, officer_name } = req.body;

  try {
    db.run("UPDATE devices SET police_case_number=? WHERE id=?", [police_case_number, id], async function (err) {
      if (err) {
        console.error("❌ DB case update error:", err.message);
        return res.status(500).json({ error: "Failed to update police case number." });
      }
      if (this.changes === 0) return res.status(404).json({ error: "Device not found" });

      db.get("SELECT imei, device_type AS device_name FROM devices WHERE id=?", [id], async (fetchErr, device) => {
        if (fetchErr || !device) {
          console.warn("⚠️ Could not fetch device details for PoliceUpdates log.");
          return res.json({ success: true, updated: this.changes });
        }

        const updatedAt = new Date().toLocaleString();

        await logToGoogleSheetInPoliceTab([
          device.imei,
          device.device_name || "Unknown",
          "Police Case Update",
          officer_name || "Officer/Police",
          police_case_number || "N/A",
          update_type || "Update",
          updatedAt,
        ]);

        console.log(`✅ Logged Police Update for ${device.imei}: Case #${police_case_number}`);

        res.json({
          success: true,
          message: "Police case updated successfully.",
          updated: this.changes,
        });
      });
    });
  } catch (error) {
    console.error("❌ Police update error:", error.message);
    res.status(500).json({ error: "Server error while updating police case." });
  }
});

// =============================
// ✅ 7️⃣ GET /admin/police-updates
// Returns the latest police case updates
// =============================
router.get("/police-updates", requireAdmin, (req, res) => {
  db.all(
    "SELECT imei, device_type AS device_name, police_case_number, status, updated_at FROM devices WHERE police_case_number IS NOT NULL ORDER BY updated_at DESC LIMIT 10",
    (err, rows) => {
      if (err) {
        console.error("❌ Failed to fetch police updates:", err.message);
        return res.status(500).json({ error: "Failed to fetch updates" });
      }
      res.json(rows);
    }
  );
});

// Export router
module.exports = router;
