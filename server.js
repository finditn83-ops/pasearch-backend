// =============================================================
// 🚀 PASEARCH BACKEND — Locate, Track & Recover Devices
// + PASEARCH AI (RAG + Voice) + Cyber Intel Crawler + Admin News Feed
// =============================================================

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const sqlite3 = require("sqlite3").verbose();
const multer = require("multer");
const nodemailer = require("nodemailer");
const path = require("path");
const fs = require("fs");
const http = require("http");
const { Server } = require("socket.io");
const { google } = require("googleapis");
// ✅ Using native fetch (Node 18+)
const OpenAI = require("openai");
const RSSParser = require("rss-parser");
require("dotenv").config();

// =============================================================
// ⚙️ CONFIG
// =============================================================
const PORT = process.env.PORT || 5000;
const DB_PATH = path.join(__dirname, "devices.db");
const UPLOAD_DIR = path.join(__dirname, "uploads");
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret";
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || "admin@example.com";
const TELEMETRY_API_KEY = process.env.TELEMETRY_API_KEY || "telemetry_key";
const OPENAI_KEY = process.env.OPENAI_API_KEY || "";
const AI_MODEL = process.env.AI_MODEL || "gpt-4o-mini";
const EMBED_MODEL = process.env.EMBED_MODEL || "text-embedding-3-small";
const INTEL_REFRESH_MINUTES = Number(process.env.INTEL_REFRESH_MINUTES || 180);
const INTEL_SOURCES = (process.env.INTEL_SOURCES ||
  [
    "https://krebsonsecurity.com/feed/",
    "https://www.bleepingcomputer.com/feed/",
    "https://www.schneier.com/feed/atom/",
    "https://feeds.feedburner.com/TheHackersNews",
  ].join(","))
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

// =============================================================
// APP INIT
// =============================================================
const app = express();
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));

// =============================================================
// 🌐 CORS CONFIGURATION — Local + Render + Vercel
// =============================================================
const allowedOrigins = [
  "http://localhost:5173",
  "http://localhost:3000",
  "https://pasearch-frontend.vercel.app", // ✅ your live frontend
];

// 👇 Allow extra preview domains (optional)
if (process.env.CORS_EXTRA_ORIGINS) {
  const extras = process.env.CORS_EXTRA_ORIGINS.split(",").map((o) => o.trim());
  allowedOrigins.push(...extras);
}

const ALLOWED = new Set(allowedOrigins);

app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin) return cb(null, true);

      try {
        const hostname = new URL(origin).hostname;
        const ok =
          ALLOWED.has(origin) ||
          /\.vercel\.app$/.test(hostname) ||
          hostname.endsWith(".onrender.com");

        if (ok) return cb(null, true);
        console.warn("🚫 Blocked CORS origin:", origin);
        cb(new Error("CORS blocked"));
      } catch (err) {
        cb(new Error("Invalid CORS origin"));
      }
    },
    credentials: true,
  })
);

// ✅ Ensure upload folder exists
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// =============================================================
// DB
// =============================================================
const db = new sqlite3.Database(DB_PATH);
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
    color TEXT,
    location_area TEXT,
    lost_type TEXT,
    lost_datetime TEXT,
    reporter_email TEXT,
    police_case_number TEXT,
    status TEXT DEFAULT 'reported',
    frozen INTEGER DEFAULT 0,
    last_seen DATETIME,
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

  db.run(`CREATE TABLE IF NOT EXISTS device_aliases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER,
    alias_type TEXT,
    alias_value TEXT,
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS cyber_intel (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT,
    url TEXT UNIQUE,
    source TEXT,
    published_at TEXT,
    summary TEXT,
    embedding TEXT,             -- JSON array string
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
});

// =============================================================
// UPLOADS
// =============================================================
const storage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, UPLOAD_DIR),
  filename: (_, file, cb) => cb(null, Date.now() + "-" + file.originalname.replace(/\s+/g, "_")),
});
const upload = multer({ storage });

// =============================================================
// EMAIL
// =============================================================
let transporter = null;
if (process.env.SMTP_USER && process.env.SMTP_PASS && process.env.SMTP_HOST) {
  transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT) || 465,
    secure: Number(process.env.SMTP_PORT || 465) === 465,
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
  });
}
async function sendEmail(to, subject, html) {
  if (!transporter) return;
  try {
    await transporter.sendMail({ from: process.env.SMTP_FROM, to, subject, html });
  } catch (e) {
    console.warn("Email error:", e.message);
  }
}

// =============================================================
// GOOGLE SHEETS
// =============================================================
async function getAuth() {
  let creds;
  if (process.env.GOOGLE_SERVICE_ACCOUNT_JSON)
    creds = JSON.parse(process.env.GOOGLE_SERVICE_ACCOUNT_JSON);
  else if (process.env.GOOGLE_SERVICE_ACCOUNT_PATH)
    creds = require(process.env.GOOGLE_SERVICE_ACCOUNT_PATH);
  if (!creds) return null;
  return new google.auth.GoogleAuth({
    credentials: creds,
    scopes: ["https://www.googleapis.com/auth/spreadsheets"],
  });
}
async function logToSheet(values, range = "Sheet1!A1") {
  if (!process.env.GOOGLE_SHEET_ID) return;
  const auth = await getAuth();
  if (!auth) return;
  const sheets = google.sheets({ version: "v4", auth });
  await sheets.spreadsheets.values.append({
    spreadsheetId: process.env.GOOGLE_SHEET_ID,
    range,
    valueInputOption: "USER_ENTERED",
    requestBody: { values: [values] },
  });
}

// =============================================================
// HELPERS (AUTH + TELEMETRY KEY)
// =============================================================
function verifyToken(req, res, next) {
  const t = req.headers.authorization?.split(" ")[1];
  if (!t) return res.status(401).json({ error: "No token" });
  try {
    req.user = jwt.verify(t, JWT_SECRET);
    next();
  } catch {
    res.status(403).json({ error: "Invalid token" });
  }
}
function requireTelemetryKey(req, res, next) {
  const key = req.headers["x-pasearch-key"];
  if (key !== TELEMETRY_API_KEY) return res.status(401).json({ error: "Invalid API key" });
  next();
}

// =============================================================
// OpenAI (AI + Embeddings + TTS)
// =============================================================
const openai = OPENAI_KEY ? new OpenAI({ apiKey: OPENAI_KEY }) : null;

async function embedText(text) {
  if (!openai) return null;
  const r = await openai.embeddings.create({
    model: EMBED_MODEL,
    input: text.slice(0, 3000),
  });
  return r.data[0].embedding;
}
function cosine(a, b) {
  if (!a || !b || a.length !== b.length) return 0;
  let dot = 0,
    na = 0,
    nb = 0;
  for (let i = 0; i < a.length; i++) {
    dot += a[i] * b[i];
    na += a[i] * a[i];
    nb += b[i] * b[i];
  }
  return dot / (Math.sqrt(na) * Math.sqrt(nb) + 1e-9);
}

// =============================================================
// SERVER + SOCKET.IO
// =============================================================
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*"} });

// =============================================================
// 🧠 CORE ROUTES — PASEARCH Backend Identity
// =============================================================
app.get("/", (_, res) => {
  res.json({
    service: "PASEARCH Backend API ✅",
    status: "online",
    version: "2.0",
    mission: "Locate, track and recover devices — even if IMEI is changed.",
    description:
      "PASEARCH integrates AI, cyber-intel crawling, Google Sheets logging and real-time WebSocket tracking to help users and authorities recover stolen or lost devices.",
    components: {
      database: "SQLite (devices, tracking, users)",
      ai_assistant: "PASEARCH AI with OpenAI + NewsAPI",
      live_tracking: "Socket.IO real-time updates",
      sheets_logging: "Google Sheets API logging",
    },
    ai_ready: typeof openai !== "undefined",
    time: new Date().toISOString(),
  });
});

// Auth: register/login
app.post("/auth/register", async (req, res) => {
  const { username, email, password, role, phone } = req.body;
  if (!username || !email || !password) return res.status(400).json({ error: "Missing fields" });
  const hash = await bcrypt.hash(password, 10);
  const r = email === ADMIN_EMAIL ? "admin" : role || "reporter";
  db.run(
    "INSERT INTO users (username,email,phone,password,role) VALUES (?,?,?,?,?)",
    [username, email, phone || null, hash, r],
    async function (err) {
      if (err) return res.status(400).json({ error: "User exists" });
      const token = jwt.sign({ id: this.lastID, username, role: r }, JWT_SECRET, { expiresIn: "7d" });
      await logToSheet(["REGISTER", username, email, r, new Date().toLocaleString()]);
      res.json({ success: true, token });
    }
  );
});
app.post("/auth/login", (req, res) => {
  const { username, password } = req.body;
  db.get("SELECT * FROM users WHERE username=?", [username], async (err, u) => {
    if (err || !u) return res.status(400).json({ error: "Invalid credentials" });
    const ok = await bcrypt.compare(password, u.password);
    if (!ok) return res.status(400).json({ error: "Invalid credentials" });
    const t = jwt.sign({ id: u.id, username, role: u.role }, JWT_SECRET, { expiresIn: "7d" });
    await logToSheet(["LOGIN", username, u.role, new Date().toLocaleString()], "Logins!A1");
    res.json({ success: true, token: t });
  });
});

// Report device
app.post("/report-device", upload.any(), (req, res) => {
  const { user_id, device_type, imei, reporter_email } = req.body;
  db.run(
    "INSERT INTO devices (user_id,device_type,imei,reporter_email) VALUES (?,?,?,?)",
    [user_id || null, device_type || null, imei || null, reporter_email || null],
    async function (err) {
      if (err) return res.status(500).json({ error: "Failed" });
      await logToSheet(["REPORT", imei, device_type, reporter_email, new Date().toLocaleString()]);
      res.json({ success: true, id: this.lastID });
    }
  );
});

// Track device (with live push)
app.post("/track-device", async (req, res) => {
  const { imei, latitude, longitude, address, trackerName } = req.body;
  db.run(
    "INSERT INTO tracking (imei,latitude,longitude,address,trackerName,trackedAt) VALUES (?,?,?,?,?,datetime('now'))",
    [imei, latitude, longitude, address, trackerName],
    async (err) => {
      if (err) return res.status(500).json({ error: err.message });
      io.emit("tracking_update", { imei, latitude, longitude, address, trackerName });
      await logToSheet(["TRACK", imei, latitude, longitude, address, new Date().toLocaleString()]);
      res.json({ success: true });
    }
  );
});

// Telemetry (API key; IMEI-change resilience via alias graph)
app.post("/ingest/telemetry", requireTelemetryKey, async (req, res) => {
  const { alias_map = {}, extras = {}, device_id_hint } = req.body;
  const entries = Object.entries(alias_map).filter(([_, v]) => !!v);
  for (const [type, value] of entries) {
    db.run(
      "INSERT INTO device_aliases (device_id,alias_type,alias_value) VALUES (?,?,?)",
      [device_id_hint || null, String(type).toLowerCase(), String(value).toLowerCase()]
    );
  }
  // If we know specific device_id, mark last_seen
  if (device_id_hint) db.run(`UPDATE devices SET last_seen=CURRENT_TIMESTAMP, frozen=0 WHERE id=?`, [device_id_hint]);
  await logToSheet(["TELEMETRY", JSON.stringify(alias_map), new Date().toLocaleString()]);
  res.json({ success: true, received: entries.length });
});

// =============================================================
// AI: Ask (RAG) + TTS
// =============================================================
const rss = new RSSParser();

async function summarize(title, content) {
  if (!openai) return (content || title || "").slice(0, 400);
  const r = await openai.chat.completions.create({
    model: AI_MODEL,
    messages: [
      {
        role: "user",
        content: `Summarize in 3 concise bullets (focus: cyberlaw, anti-theft, forensics, tracking):\n\n${title}\n\n${content || ""}`,
      },
    ],
    temperature: 0.3,
  });
  return r.choices?.[0]?.message?.content?.trim() || "";
}

async function upsertIntel(item, src) {
  const url = item.link || item.guid;
  if (!url) return;
  db.get("SELECT id FROM cyber_intel WHERE url=?", [url], async (err, row) => {
    if (row) return;
    const raw = item.contentSnippet || item.content || "";
    const sum = await summarize(item.title || "(untitled)", raw);
    const emb = await embedText(`${item.title || ""}\n${sum}`);
    db.run(
      "INSERT INTO cyber_intel (title,url,source,published_at,summary,embedding) VALUES (?,?,?,?,?,?)",
      [item.title || "(untitled)", url, src, item.isoDate || item.pubDate || null, sum, emb ? JSON.stringify(emb) : null]
    );
  });
}

async function refreshIntel() {
  for (const src of INTEL_SOURCES) {
    try {
      const feed = await rss.parseURL(src);
      for (const item of feed.items || []) await upsertIntel(item, feed.title || src);
    } catch (e) {
      console.warn("RSS fetch failed:", src, e.message);
    }
  }
  await logToSheet(["INTEL_REFRESH", `${INTEL_SOURCES.length} sources`, new Date().toLocaleString()], "Intel!A1");
}

if (openai && INTEL_SOURCES.length) {
  setInterval(() => refreshIntel().catch(() => {}), Math.max(60_000, INTEL_REFRESH_MINUTES * 60_000));
  setTimeout(() => refreshIntel().catch(() => {}), 10_000);
}

// Manual refresh
app.post("/intel/refresh", verifyToken, async (req, res) => {
  try {
    await refreshIntel();
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: "Refresh failed" });
  }
});

// AI Q&A with RAG
app.post("/ai/ask", async (req, res) => {
  try {
    if (!openai) return res.status(503).json({ error: "AI not configured" });
    const { question } = req.body || {};
    if (!question) return res.status(400).json({ error: "Missing question" });

    const qvec = await embedText(question);
    db.all("SELECT * FROM cyber_intel ORDER BY id DESC LIMIT 400", [], async (err, rows) => {
      if (err || !rows || !rows.length) {
        const fallback = await openai.chat.completions.create({
          model: AI_MODEL,
          messages: [
            { role: "system", content: "You are PASEARCH AI (cybersecurity/anti-theft)." },
            { role: "user", content: question },
          ],
        });
        return res.json({ answer: fallback.choices[0].message.content.trim(), usedIntel: [] });
      }
      const scored = [];
      for (const r of rows) {
        if (!r.embedding) continue;
        try {
          const e = JSON.parse(r.embedding);
          scored.push({ ...r, score: cosine(qvec, e) });
        } catch {}
      }
      scored.sort((a, b) => b.score - a.score);
      const top = scored.slice(0, 5);
      const ctx = top.map((t, i) => `#${i + 1} ${t.title}\n${t.summary}`).join("\n\n");

      const resp = await openai.chat.completions.create({
        model: AI_MODEL,
        messages: [
          { role: "system", content: "You are PASEARCH AI—device recovery & cyberlaw assistant." },
          { role: "user", content: `${question}\n\nContext:\n${ctx}` },
        ],
        temperature: 0.2,
      });

      res.json({
        answer: resp.choices[0].message.content.trim(),
        usedIntel: top.map((t) => ({ title: t.title, url: t.url, source: t.source, score: t.score })),
      });
    });
  } catch (e) {
    console.error("AI ask error:", e);
    res.status(500).json({ error: "AI failed to respond" });
  }
});

// Text-to-Speech
app.post("/ai/tts", async (req, res) => {
  try {
    if (!openai) return res.status(503).json({ error: "AI not configured" });
    const { text } = req.body || {};
    if (!text) return res.status(400).json({ error: "Missing text" });
    const speech = await openai.audio.speech.create({
      model: "gpt-4o-mini-tts",
      voice: "alloy",
      input: text.slice(0, 2000),
      format: "mp3",
    });
    const b64 = Buffer.from(await speech.arrayBuffer()).toString("base64");
    res.json({ audio: `data:audio/mpeg;base64,${b64}` });
  } catch (e) {
    console.error("TTS error:", e);
    res.status(500).json({ error: "TTS failed" });
  }
});

// =============================================================
// ADMIN NEWS FEED (Cyberlaw / theft / PASEARCH-related)
// =============================================================
app.get("/admin/news", async (req, res) => {
  db.all(
    `SELECT title,url,source,summary,published_at
     FROM cyber_intel
     WHERE title LIKE '%law%' OR title LIKE '%cyber%' OR title LIKE '%theft%' OR title LIKE '%pasearch%'
     ORDER BY COALESCE(published_at, created_at) DESC
     LIMIT 20`,
    [],
    (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({
        updated: new Date().toISOString(),
        articles: rows.map((r) => ({
          title: r.title,
          url: r.url,
          source: r.source,
          summary: r.summary,
          published_at: r.published_at,
        })),
      });
    }
  );
});

// =============================================================
// FROZEN DEVICE DETECTOR (silent >30m)
// =============================================================
setInterval(() => {
  const cutoff = Date.now() - 30 * 60 * 1000;
  const iso = new Date(cutoff).toISOString();
  db.all(
    "SELECT id, imei, device_type FROM devices WHERE (last_seen IS NULL OR last_seen < ?) AND frozen=0",
    [iso],
    (err, rows) => {
      if (!rows || !rows.length) return;
      for (const d of rows) {
        db.run("UPDATE devices SET frozen=1 WHERE id=?", [d.id]);
        io.emit("device_frozen", { id: d.id, imei: d.imei });
        logToSheet(["FROZEN", d.imei || "N/A", d.device_type || "Unknown", new Date().toLocaleString()]);
        if (ADMIN_EMAIL) {
          sendEmail(
            ADMIN_EMAIL,
            "PASEARCH — Device Frozen",
            `<p>Device <b>${d.device_type || "Unknown"}</b> (IMEI: ${d.imei || "N/A"}) is marked <b>FROZEN</b>.</p>`
          );
        }
      }
    }
  );
}, 5 * 60 * 1000);

// ======================================================
// 🤖 PASEARCH AI — Enhanced /ai/ask route
// ======================================================
import fetch from "node-fetch"; // if you're using ES modules; otherwise use require() below

// If your server.js uses require() syntax (most do), then use this instead:
const fetch = (...args) => import("node-fetch").then(({ default: fetch }) => fetch(...args));

app.post("/ai/ask", async (req, res) => {
  const { query } = req.body;
  if (!query) return res.status(400).json({ answer: "No question provided." });

  try {
    let answer = "";

    // 1️⃣ IMEI lookup in database
    const imeiMatch = query.match(/\b\d{10,17}\b/);
    if (imeiMatch) {
      const imei = imeiMatch[0];
      answer += `🔎 Checking device IMEI ${imei} in database...\n\n`;

      const row = await new Promise((resolve, reject) => {
        db.get("SELECT * FROM devices WHERE imei = ?", [imei], (err, r) =>
          err ? reject(err) : resolve(r)
        );
      });

      if (row) {
        answer += `✅ Device found: ${row.device_type || "Unknown"} (${row.color || "No color"})\n`;
        answer += `Status: ${row.status}\nReported Area: ${row.location_area || "N/A"}\n\n`;
      } else {
        answer += "❌ This IMEI isn’t yet registered in the PASEARCH system.\n\n";
      }
    }

    // 2️⃣ Cyber-Intel lookup (latest news)
    const newsURL =
      "https://newsapi.org/v2/everything?q=cybercrime+OR+hacking+law&language=en&sortBy=publishedAt&pageSize=3&apiKey=" +
      process.env.NEWS_API_KEY;

    let intelText = "";
    try {
      const newsRes = await fetch(newsURL);
      const newsData = await newsRes.json();
      if (newsData?.articles?.length) {
        intelText =
          "📰 Latest Cyber-Intel:\n" +
          newsData.articles
            .map((a) => `• ${a.title} — ${a.source.name}`)
            .join("\n") +
          "\n\n";
      }
    } catch (e) {
      intelText = "⚠️ Could not load cyber-intel feed right now.\n\n";
    }
    answer += intelText;

    // 3️⃣ Personalized recovery advice
    if (/lost|stolen|recover|track/i.test(query)) {
      answer +=
        "🧭 Recovery Advice:\n" +
        "- Ensure your device is reported in PASEARCH and marked 'Under Investigation'.\n" +
        "- Keep your IMEI ready and only share it with verified police/telecom partners.\n" +
        "- Check your dashboard for GPS or tracking updates.\n" +
        "- File or follow up your police report as needed.\n\n";
    }

    // 4️⃣ Optional OpenAI summary
    try {
      const OpenAI = (await import("openai")).default;
      const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
      const completion = await openai.chat.completions.create({
        model: "gpt-4o-mini",
        messages: [
          { role: "system", content: "You are PASEARCH AI, a cybersecurity recovery assistant." },
          { role: "user", content: answer + "\n\nUser question: " + query },
        ],
        max_tokens: 300,
      });
      answer = completion.choices[0].message.content;
    } catch (err) {
      console.log("OpenAI summarizer skipped:", err.message);
    }

    res.json({ answer });
  } catch (err) {
    console.error("AI route error:", err);
    res.status(500).json({
      answer: "⚠️ Internal error while processing your request. Please try again later.",
    });
  }
});

// =============================================================
// START SERVER
// =============================================================
server.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 PASEARCH Backend + AI running on port ${PORT}`);
});
