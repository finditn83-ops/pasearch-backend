// =============================================================
// 🧠 routes/aiIntel.js — Smart AI Assistant + Cyber Intel Crawler
// =============================================================
const express = require("express");
const router = express.Router();
const sqlite3 = require("sqlite3").verbose();
const RSSParser = require("rss-parser");
const { google } = require("googleapis");
require("dotenv").config();

let OpenAI;
try {
  OpenAI = require("openai");
} catch {
  console.warn("⚠️ OpenAI module missing — AI will run in offline fallback mode");
}

const openai = process.env.OPENAI_API_KEY
  ? new OpenAI({ apiKey: process.env.OPENAI_API_KEY })
  : null;

const parser = new RSSParser();
const db = new sqlite3.Database("devices.db");

// =============================================================
// 🧾 Google Sheets Helper (Intel Logging)
// =============================================================
async function logAIIntelEvent(source, question, answer) {
  try {
    const auth = new google.auth.GoogleAuth({
      keyFile: process.env.GOOGLE_SERVICE_ACCOUNT_PATH || "service-account.json",
      scopes: ["https://www.googleapis.com/auth/spreadsheets"],
    });
    const sheets = google.sheets({ version: "v4", auth });

    await sheets.spreadsheets.values.append({
      spreadsheetId: process.env.GOOGLE_SHEET_ID,
      range: "IntelFeed!A1",
      valueInputOption: "USER_ENTERED",
      requestBody: {
        values: [
          [new Date().toLocaleString(), source, question, answer],
        ],
      },
    });
  } catch (err) {
    console.warn("⚠️ Google Sheets intel log failed:", err.message);
  }
}

// =============================================================
// 🧠 Offline AI Fallback Logic
// =============================================================
function fallbackAI(question) {
  const q = question.toLowerCase();

  if (q.includes("imei")) {
    return "If IMEI is changed, PASEARCH detects cloned devices by analyzing SIM swaps, Wi-Fi MACs, Bluetooth IDs, and phonebook sync patterns. Try also checking your last login and app telemetry data.";
  }
  if (q.includes("laptop") || q.includes("computer")) {
    return "Use the PASEARCH Laptop Agent to gather the latest IP, SSID, and login timestamps. Even if BIOS is locked, network metadata remains traceable.";
  }
  if (q.includes("tv") || q.includes("smart")) {
    return "Smart TVs sync via Wi-Fi. Check your router logs or ISP account — PASEARCH can automatically scan for your device’s MAC fingerprint.";
  }
  if (q.includes("cyber") || q.includes("law")) {
    return "Under cyber laws, every telecom and ISP maintains device IMEI-MAC linkage logs for 180 days. PASEARCH partners with these entities to enhance lawful recovery.";
  }
  if (q.includes("password") || q.includes("email")) {
    return "Reset your password immediately, enable 2FA, and log suspicious attempts under SecurityLogs. PASEARCH AI monitors repeated credential reuse patterns.";
  }
  return "PASEARCH AI (offline mode): Use your last synced GPS, Wi-Fi, or contact data. I’ll refine this once online intel access resumes.";
}

// =============================================================
// 🌐 /ai/news — Get Latest Cybersecurity Intel
// =============================================================
router.get("/news", async (req, res) => {
  try {
    const feeds = [
      "https://feeds.feedburner.com/TheHackersNews",
      "https://www.bleepingcomputer.com/feed/",
      "https://cyware.com/feed/news.xml",
    ];

    let articles = [];
    for (const url of feeds) {
      const data = await parser.parseURL(url);
      articles = articles.concat(
        data.items.slice(0, 5).map((item) => ({
          title: item.title,
          link: item.link,
          date: item.pubDate,
          source: data.title,
        }))
      );
    }

    res.json({ success: true, articles });
  } catch (err) {
    console.error("❌ RSS Fetch Error:", err.message);
    res.status(500).json({ error: "Failed to fetch cyber news" });
  }
});

// =============================================================
// 🔍 /ai/lookup — IMEI or Device Lookup in Database
// =============================================================
router.post("/lookup", async (req, res) => {
  const { imei } = req.body;
  if (!imei) return res.status(400).json({ error: "IMEI is required" });

  db.get(
    "SELECT * FROM devices WHERE imei = ? OR police_case_number = ?",
    [imei, imei],
    (err, row) => {
      if (err) return res.status(500).json({ error: err.message });
      if (!row)
        return res.status(404).json({ error: "No matching device found" });
      res.json({ success: true, device: row });
    }
  );
});

// =============================================================
// 🧠 /ai/ask — Smart AI Assistant (Online + Fallback)
// =============================================================
router.post("/ask", async (req, res) => {
  const { question } = req.body;
  if (!question)
    return res.status(400).json({ error: "Missing question parameter" });

  try {
    let answer;

    if (openai) {
      try {
        const completion = await openai.chat.completions.create({
          model: "gpt-4o-mini",
          messages: [
            {
              role: "system",
              content:
                "You are PASEARCH AI, an advanced assistant helping track and recover stolen or lost devices, laptops, and TVs using lawful and technical intelligence.",
            },
            { role: "user", content: question },
          ],
        });
        answer = completion.choices[0].message.content;
      } catch (apiErr) {
        console.warn("⚠️ OpenAI API error:", apiErr.message);
        answer = fallbackAI(question);
      }
    } else {
      answer = fallbackAI(question);
    }

    await logAIIntelEvent("AI", question, answer);
    res.json({ success: true, source: openai ? "openai" : "offline", answer });
  } catch (err) {
    console.error("❌ /ai/ask failed:", err.message);
    res.status(500).json({ error: "AI processing error" });
  }
});

module.exports = router;
