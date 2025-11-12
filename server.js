// =============================================================
// 🚀 PASEARCH BACKEND — Locate, Track & Recover Devices
// + PASEARCH AI (RAG + TTS) + Cyber Intel Crawler + Admin News Feed
// =============================================================

/* ------------------------ 1) IMPORTS & CONFIG ------------------------ */
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
const RSSParser = require("rss-parser");
const OpenAI = require("openai");
require("dotenv").config();

/* ------------------------ 2) ENV / CONSTANTS ------------------------ */
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

/* ------------------------ 3) APP INIT & CORS ------------------------ */
const app = express();
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));

const allowedOrigins = [
  "http://localhost:5173",
  "http://localhost:3000",
  "https://pasearch-frontend.vercel.app",
];
if (process.env.CORS_EXTRA_ORIGINS) {
  allowedOrigins.push(
    ...process.env.CORS_EXTRA_ORIGINS.split(",").map((s) => s.trim())
  );
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
        return cb(ok ? null : new Error("CORS blocked"), ok);
      } catch {
        return cb(new Error("Invalid origin"));
      }
    },
    credentials: true,
  })
);

/* ------------------------ 4) HEALTH & UTIL ROUTES ------------------------ */
// Health
app.get("/", (_, res) =>
  res.json({
    ok: true,
    service: "PASEARCH Backend",
    mission: "Locate, track & recover devices (IMEI-change resilient)",
    time: new Date().toISOString(),
  })
);

// Frontend redeploy trigger (Vercel) — uses native global fetch (Node 18+)
app.post("/trigger-frontend", async (req, res) => {
  try {
    const hook = process.env.VERCEL_DEPLOY_HOOK_URL;
    if (!hook) return res.status(400).json({ error: "VERCEL_DEPLOY_HOOK_URL not set" });

    const response = await fetch(hook, { method: "POST" });
    if (!response.ok) throw new Error(`Vercel trigger failed: ${response.statusText}`);

    console.log("✅ Frontend redeploy triggered");
    res.json({ success: true, message: "Frontend redeploy triggered" });
  } catch (error) {
    console.error("❌ Trigger error:", error.message);
    res.status(500).json({ error: "Failed to trigger frontend redeploy" });
  }
});

/* ------------------------ 5) FILE UPLOADS (multer) ------------------------ */
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const storage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, UPLOAD_DIR),
  filename: (_, file, cb) =>
    cb(null, Date.now() + "-" + file.originalname.replace(/\s+/g, "_")),
});
const upload = multer({ storage });

/* ------------------------ 6) DATABASE ------------------------ */
const db = new sqlite3.Database(DB_PATH, (err) => {
  if (err) console.error("❌ DB error:", err.message);
  else console.log("✅ Connected to SQLite DB");
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

  // IMEI-change resilience (alias graph)
  db.run(`CREATE TABLE IF NOT EXISTS device_aliases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER,
    alias_type TEXT,      -- e.g. android_id, wifi_mac, bt_mac, serial, sim_iccid
    alias_value TEXT,
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Cyber intel cache
  db.run(`CREATE TABLE IF NOT EXISTS cyber_intel (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT,
    url TEXT UNIQUE,
    source TEXT,
    published_at TEXT,
    summary TEXT,
    embedding TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
});

/* ------------------------ 7) EMAIL (optional) ------------------------ */
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
  try { await transporter.sendMail({ from: process.env.SMTP_FROM, to, subject, html }); }
  catch (e) { console.warn("Email error:", e.message); }
}

/* ------------------------ 8) GOOGLE SHEETS HELPERS (optional) ------------------------ */
async function getSheetsAuth() {
  try {
    let creds = null;
    if (process.env.GOOGLE_SERVICE_ACCOUNT_JSON) {
      creds = JSON.parse(process.env.GOOGLE_SERVICE_ACCOUNT_JSON);
    } else if (process.env.GOOGLE_SERVICE_ACCOUNT_PATH) {
      creds = require(process.env.GOOGLE_SERVICE_ACCOUNT_PATH);
    }
    if (!creds) return null;
    return new google.auth.GoogleAuth({
      credentials: creds,
      scopes: ["https://www.googleapis.com/auth/spreadsheets"],
    });
  } catch {
    return null;
  }
}

async function logToSheet(values, range = "Sheet1!A1") {
  if (!process.env.GOOGLE_SHEET_ID) return;
  const auth = await getSheetsAuth();
  if (!auth) return;
  const sheets = google.sheets({ version: "v4", auth });
  await sheets.spreadsheets.values.append({
    spreadsheetId: process.env.GOOGLE_SHEET_ID,
    range,
    valueInputOption: "USER_ENTERED",
    requestBody: { values: [values] },
  });
}

/* ------------------------ 9) AUTH HELPERS ------------------------ */
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

/* ------------------------ 10) OPENAI (optional, guarded) ------------------------ */
const openai = OPENAI_KEY ? new OpenAI({ apiKey: OPENAI_KEY }) : null;

async function embedText(text) {
  if (!openai) return null;
  const r = await openai.embeddings.create({
    model: EMBED_MODEL,
    input: String(text || "").slice(0, 3000),
  });
  return r.data[0].embedding;
}
function cosine(a, b) {
  if (!a || !b || a.length !== b.length) return 0;
  let dot = 0, na = 0, nb = 0;
  for (let i = 0; i < a.length; i++) {
    dot += a[i] * b[i];
    na += a[i] * a[i];
    nb += b[i] * b[i];
  }
  return dot / (Math.sqrt(na) * Math.sqrt(nb) + 1e-9);
}

/* ------------------------ 11) CORE AUTH ROUTES ------------------------ */
app.post("/auth/register", async (req, res) => {
  try {
    const { username, email, password, role, phone } = req.body;
    if (!username || !email || !password)
      return res.status(400).json({ error: "Username, email, password required" });

    const hash = await bcrypt.hash(password, 10);
    const r = email === ADMIN_EMAIL ? "admin" : role || "reporter";

    db.run(
      "INSERT INTO users (username,email,phone,password,role) VALUES (?,?,?,?,?)",
      [username, email, phone || null, hash, r],
      async function (err) {
        if (err) return res.status(409).json({ error: "Username or email exists" });
        const token = jwt.sign({ id: this.lastID, username, role: r }, JWT_SECRET, { expiresIn: "7d" });
        await logToSheet(["REGISTER", username, email, r, new Date().toLocaleString()]);
        res.json({ success: true, token });
      }
    );
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Register failed" });
  }
});

app.post("/auth/login", (req, res) => {
  const { username, password } = req.body;
  db.get("SELECT * FROM users WHERE username=?", [username], async (err, u) => {
    if (err || !u) return res.status(400).json({ error: "Invalid credentials" });
    const ok = await bcrypt.compare(password, u.password);
    if (!ok) return res.status(400).json({ error: "Invalid credentials" });
    const t = jwt.sign({ id: u.id, username, role: u.role }, JWT_SECRET, { expiresIn: "7d" });
    await logToSheet(["LOGIN", username, u.role, new Date().toLocaleString()], "Logins!A1");
    res.json({ success: true, token: t, user: { id: u.id, username, role: u.role, email: u.email } });
  });
});

/* ------------------------ 12) REPORT / TRACK ------------------------ */
app.post(
  "/report-device",
  upload.fields([{ name: "proof_path" }, { name: "police_report_path" }]),
  (req, res) => {
    const {
      user_id,
      device_type,
      imei,
      color,
      location_area,
      lost_type,
      lost_datetime,
      reporter_email,
      police_case_number,
    } = req.body;

    const proof_path = req.files?.proof_path?.[0]?.path || null;
    const police_path = req.files?.police_report_path?.[0]?.path || null;

    if (!imei || !device_type || !reporter_email)
      return res.status(400).json({ error: "imei, device_type, reporter_email required" });

    db.run(
      `INSERT INTO devices (user_id, device_type, imei, color, location_area, lost_type, lost_datetime, reporter_email, police_case_number, status)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'reported')`,
      [
        user_id || null,
        device_type,
        imei,
        color || null,
        location_area || null,
        lost_type || null,
        lost_datetime || null,
        reporter_email,
        police_case_number || null,
      ],
      async function (err) {
        if (err) return res.status(500).json({ error: "Failed to report device" });
        await logToSheet(
          ["REPORT", imei, device_type, reporter_email, proof_path || "no-proof", police_path || "no-police", new Date().toLocaleString()]
        );
        res.json({ success: true, id: this.lastID });
      }
    );
  }
);

app.post("/track-device", async (req, res) => {
  const { imei, latitude, longitude, address, trackerName } = req.body;
  db.run(
    `INSERT INTO tracking (imei, latitude, longitude, address, trackerName, trackedAt)
     VALUES (?, ?, ?, ?, ?, datetime('now'))`,
    [imei, latitude, longitude, address, trackerName],
    async (err) => {
      if (err) return res.status(500).json({ error: "DB insert failed" });

      // update devices last_seen + unfreeze
      db.run("UPDATE devices SET last_seen=datetime('now'), frozen=0 WHERE imei=?", [imei]);

      io.emit("tracking_update", { imei, latitude, longitude, address, trackerName, trackedAt: new Date().toISOString() });
      await logToSheet(["TRACK", imei, latitude, longitude, address, new Date().toLocaleString()]);
      res.json({ success: true });
    }
  );
});

/* ------------------------ 13) TELEMETRY (IMEI-change resilience) ------------------------ */
app.post("/ingest/telemetry", requireTelemetryKey, async (req, res) => {
  const { alias_map = {}, device_id_hint } = req.body;
  const entries = Object.entries(alias_map).filter(([_, v]) => !!v);

  for (const [type, value] of entries) {
    db.run(
      "INSERT INTO device_aliases (device_id, alias_type, alias_value) VALUES (?, ?, ?)",
      [device_id_hint || null, String(type).toLowerCase(), String(value).toLowerCase()]
    );
  }
  if (device_id_hint) db.run("UPDATE devices SET last_seen=datetime('now'), frozen=0 WHERE id=?", [device_id_hint]);

  await logToSheet(["TELEMETRY", JSON.stringify(alias_map), new Date().toLocaleString()]);
  res.json({ success: true, received: entries.length });
});

/* ------------------------ 14) AI: Cyber Intel + RAG Q&A + TTS ------------------------ */
const rss = new RSSParser();

async function summarizeForIntel(title, content) {
  if (!openai) return (content || title || "").slice(0, 400);
  const r = await openai.chat.completions.create({
    model: AI_MODEL,
    messages: [
      {
        role: "user",
        content:
          `Summarize (<=3 bullets) for cyberlaw/anti-theft/forensics tracking:\nTITLE: ${title}\nCONTENT: ${content || ""}`,
      },
    ],
    temperature: 0.3,
  });
  return r.choices?.[0]?.message?.content?.trim() || "";
}

async function upsertIntelItem(item, source) {
  const url = item.link || item.guid;
  if (!url) return;
  db.get("SELECT id FROM cyber_intel WHERE url=?", [url], async (err, row) => {
    if (row) return;
    const raw = item.contentSnippet || item.content || "";
    const sum = await summarizeForIntel(item.title || "(untitled)", raw);
    const emb = await embedText(`${item.title || ""}\n${sum}`);
    db.run(
      "INSERT INTO cyber_intel (title, url, source, published_at, summary, embedding) VALUES (?, ?, ?, ?, ?, ?)",
      [item.title || "(untitled)", url, source, item.isoDate || item.pubDate || null, sum, emb ? JSON.stringify(emb) : null]
    );
  });
}

async function refreshIntel() {
  for (const src of INTEL_SOURCES) {
    try {
      const feed = await rss.parseURL(src);
      for (const item of (feed.items || [])) {
        await upsertIntelItem(item, feed.title || src);
      }
    } catch (e) {
      console.warn("RSS fetch failed:", src, e.message);
    }
  }
  await logToSheet(["INTEL_REFRESH", `${INTEL_SOURCES.length} sources`, new Date().toLocaleString()], "Intel!A1");
}

if (INTEL_SOURCES.length) {
  setInterval(() => refreshIntel().catch(() => {}), Math.max(60_000, INTEL_REFRESH_MINUTES * 60_000));
  setTimeout(() => refreshIntel().catch(() => {}), 10_000);
}

app.post("/intel/refresh", verifyToken, async (req, res) => {
  try {
    await refreshIntel();
    res.json({ success: true });
  } catch {
    res.status(500).json({ error: "Refresh failed" });
  }
});

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
        articles: (rows || []).map((r) => ({
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

// Enhanced AI Ask (RAG + optional News API + personalized hints)
app.post("/ai/ask", async (req, res) => {
  try {
    const { question } = req.body || {};
    if (!question) return res.status(400).json({ answer: "No question provided." });

    let answer = "";

    // IMEI quick lookup
    const imeiMatch = question.match(/\b\d{10,17}\b/);
    if (imeiMatch) {
      const imei = imeiMatch[0];
      const row = await new Promise((resolve, reject) => {
        db.get("SELECT * FROM devices WHERE imei = ?", [imei], (err, r) => (err ? reject(err) : resolve(r)));
      });
      if (row) {
        answer += `🔎 IMEI ${imei} found — ${row.device_type || "Unknown"} (${row.color || "-"})\nStatus: ${row.status}\nArea: ${row.location_area || "N/A"}\n\n`;
      } else {
        answer += `❌ IMEI ${imei} not found in system.\n\n`;
      }
    }

    // Optional cyber news via NewsAPI
    if (process.env.NEWS_API_KEY) {
      try {
        const url =
          "https://newsapi.org/v2/everything?q=cybercrime%20OR%20hacking%20law&language=en&sortBy=publishedAt&pageSize=3&apiKey=" +
          process.env.NEWS_API_KEY;
        const r = await fetch(url);
        const j = await r.json();
        if (j?.articles?.length) {
          answer += "📰 Latest Cyber-Intel:\n" + j.articles.map((a) => `• ${a.title} — ${a.source?.name}`).join("\n") + "\n\n";
        }
      } catch {
        // silent
      }
    }

    // Personalized recovery advice
    if (/lost|stolen|recover|track/i.test(question)) {
      answer +=
        "🧭 Recovery Advice:\n" +
        "- Ensure the device report is filed in PASEARCH and marked 'Under Investigation'.\n" +
        "- Keep IMEI & proofs ready; only share with verified police/telecom partners.\n" +
        "- Monitor the dashboard for GPS/telemetry updates.\n" +
        "- Follow up your police report with any new locations.\n\n";
    }

    // RAG over cached intel (if OpenAI available)
    if (openai) {
      const qvec = await embedText(question);
      db.all("SELECT * FROM cyber_intel ORDER BY id DESC LIMIT 400", [], async (err, rows) => {
        if (err || !rows || !rows.length || !qvec) {
          const fb = await openai.chat.completions.create({
            model: AI_MODEL,
            messages: [
              { role: "system", content: "You are PASEARCH AI (cybersecurity & device recovery)." },
              { role: "user", content: question + "\n\n" + answer },
            ],
          });
          return res.json({ answer: (fb.choices?.[0]?.message?.content || "").trim(), usedIntel: [] });
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
            { role: "system", content: "You are PASEARCH AI — device recovery & cyberlaw assistant." },
            { role: "user", content: `${question}\n\nExisting info:\n${answer}\n\nContext:\n${ctx}` },
          ],
          temperature: 0.2,
        });
        res.json({
          answer: (resp.choices?.[0]?.message?.content || "").trim(),
          usedIntel: top.map((t) => ({ title: t.title, url: t.url, source: t.source, score: t.score })),
        });
      });
    } else {
      res.json({ answer: (answer || "AI is not configured (set OPENAI_API_KEY).").trim(), usedIntel: [] });
    }
  } catch (e) {
    console.error("AI ask error:", e);
    res.status(500).json({ answer: "Internal AI error." });
  }
});

// TTS (optional)
app.post("/ai/tts", async (req, res) => {
  try {
    if (!openai) return res.status(503).json({ error: "AI not configured" });
    const { text } = req.body || {};
    if (!text) return res.status(400).json({ error: "Missing text" });
    const speech = await openai.audio.speech.create({
      model: "gpt-4o-mini-tts",
      voice: "alloy",
      input: String(text).slice(0, 2000),
      format: "mp3",
    });
    const b64 = Buffer.from(await speech.arrayBuffer()).toString("base64");
    res.json({ audio: `data:audio/mpeg;base64,${b64}` });
  } catch (e) {
    console.error("TTS error:", e);
    res.status(500).json({ error: "TTS failed" });
  }
});

/* ------------------------ 15) FROZEN DETECTOR ------------------------ */
setInterval(() => {
  const cutoffIso = new Date(Date.now() - 30 * 60 * 1000).toISOString(); // 30 mins
  db.all(
    "SELECT id, imei, device_type FROM devices WHERE (last_seen IS NULL OR last_seen < ?) AND frozen=0",
    [cutoffIso],
    (err, rows) => {
      if (err || !rows || !rows.length) return;
      for (const d of rows) {
        db.run("UPDATE devices SET frozen=1 WHERE id=?", [d.id]);
        io.emit("device_frozen", { id: d.id, imei: d.imei, device_type: d.device_type });
        logToSheet(["FROZEN", d.imei || "N/A", d.device_type || "Unknown", new Date().toLocaleString()]);
        if (ADMIN_EMAIL) {
          sendEmail(
            ADMIN_EMAIL,
            "PASEARCH — Device Frozen",
            `<p>Device <b>${d.device_type || "Unknown"}</b> (IMEI: ${d.imei || "N/A"}) marked <b>FROZEN</b>.</p>`
          );
        }
      }
    }
  );
}, 5 * 60 * 1000);

/* ------------------------ 16) (OPTIONAL) MOUNT EXTRA ROUTERS ------------------------ */
/* 
   If you still have separate files:
   const adminRoutes = require("./routes/admin");
   app.use("/admin", adminRoutes);

   const authRoutes = require("./routes/auth");
   app.use("/auth", authRoutes);

   const aiRoutes = require("./routes/aiIntel");
   app.use("/ai", aiRoutes);
   // ⚠️ Make sure you DO NOT duplicate these lines elsewhere.
*/

/* ------------------------ 17) SERVER + SOCKET.IO START ------------------------ */
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

io.on("connection", (socket) => {
  console.log("🧩 Socket connected:", socket.id);
  socket.on("disconnect", () => console.log("❌ Socket disconnected:", socket.id));
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 PASEARCH Backend running on port ${PORT}`);
  if (process.env.GOOGLE_SHEET_ID) console.log("✅ Google Sheets logging enabled");
});
