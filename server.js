// Simple backend for verifying the portfolio "owner key".
//
// Why this exists:
// A frontend-only site can never truly hide a password — anyone can read
// the JavaScript. This tiny server checks the password instead, so the
// real secret never leaves the server, and it rate-limits guesses so
// brute-forcing isn't realistic.
//
// How it works:
// 1. The browser sends the password the user typed to POST /api/verify
// 2. The server hashes it (scrypt) and compares to the stored hash
// 3. If correct, it returns a short-lived signed token
// 4. If wrong too many times from the same IP, it temporarily blocks further attempts

const express = require("express");
const cors = require("cors");
const crypto = require("crypto");

const app = express();
app.use(express.json());

// Allow requests from your GitHub Pages site (and localhost for testing).
// Replace with your actual GitHub Pages URL once deployed.
const ALLOWED_ORIGINS = [
  "http://localhost:5500",
  "http://127.0.0.1:5500",
  "https://AkihiroZayar.github.io",
];
app.use(
  cors({
    origin: ALLOWED_ORIGINS,
  }),
);

// --- Secret configuration ---
// In production, set these via environment variables (Render/Railway "Environment" tab)
// instead of hardcoding them, so the values aren't in your git history.
const PASSWORD_SALT = process.env.PASSWORD_SALT || "zayar-portfolio-salt-2026";
const PASSWORD_HASH =
  process.env.PASSWORD_HASH ||
  "14fb0576ebcdd04ef2fa1e21cf55ef36de8fcecd8926871df1e92c6cf6dcebf5a3ed6ddc086ea728e6214c1b340f22ac3692cd276c845f69d446250f58c20d24"; // hash of "200479"
const TOKEN_SECRET = process.env.TOKEN_SECRET || "change-this-to-something-random";

function hashPassword(input) {
  return crypto.scryptSync(input, PASSWORD_SALT, 64).toString("hex");
}

function makeToken() {
  const expires = Date.now() + 1000 * 60 * 60 * 2; // valid for 2 hours
  const payload = `${expires}`;
  const sig = crypto.createHmac("sha256", TOKEN_SECRET).update(payload).digest("hex");
  return `${payload}.${sig}`;
}

function verifyToken(token) {
  if (!token || typeof token !== "string") return false;
  const [payload, sig] = token.split(".");
  if (!payload || !sig) return false;
  const expectedSig = crypto.createHmac("sha256", TOKEN_SECRET).update(payload).digest("hex");
  if (sig !== expectedSig) return false;
  return Date.now() < Number(payload);
}

// --- Simple in-memory rate limiting ---
// Max 5 attempts per IP per 15 minutes. Good enough for a small personal site.
const attempts = new Map(); // ip -> { count, resetAt }
const MAX_ATTEMPTS = 5;
const WINDOW_MS = 15 * 60 * 1000;

function isRateLimited(ip) {
  const now = Date.now();
  const record = attempts.get(ip);
  if (!record || now > record.resetAt) {
    attempts.set(ip, { count: 0, resetAt: now + WINDOW_MS });
    return false;
  }
  return record.count >= MAX_ATTEMPTS;
}

function recordAttempt(ip) {
  const record = attempts.get(ip);
  if (record) record.count += 1;
}

// --- Routes ---

app.post("/api/verify", (req, res) => {
  const ip = req.ip;

  if (isRateLimited(ip)) {
    return res.status(429).json({ ok: false, error: "Too many attempts. Try again later." });
  }

  const { password } = req.body || {};
  if (typeof password !== "string" || !password) {
    return res.status(400).json({ ok: false, error: "Missing password." });
  }

  recordAttempt(ip);

  const candidateHash = hashPassword(password.trim());
  // Constant-time comparison to avoid timing attacks
  const match =
    candidateHash.length === PASSWORD_HASH.length &&
    crypto.timingSafeEqual(Buffer.from(candidateHash), Buffer.from(PASSWORD_HASH));

  if (!match) {
    return res.status(401).json({ ok: false, error: "Wrong key." });
  }

  // Reset attempts on success
  attempts.delete(ip);

  return res.json({ ok: true, token: makeToken() });
});

app.post("/api/check-token", (req, res) => {
  const { token } = req.body || {};
  return res.json({ ok: verifyToken(token) });
});

// --- Small database for site content ---
// Stores editable homepage text (hero, about, contact, etc.) as a JSON file.
// This is intentionally simple (a "flat file database") — enough for a
// single-owner portfolio site. GET is public so your homepage can load it;
// POST requires a valid owner token (from /api/verify) to make changes.
const fs = require("fs");
const path = require("path");
const CONTENT_FILE = path.join(__dirname, "content.json");

const DEFAULT_CONTENT = {}; // empty = homepage uses its own built-in default text

function loadContent() {
  try {
    return JSON.parse(fs.readFileSync(CONTENT_FILE, "utf-8"));
  } catch {
    return { ...DEFAULT_CONTENT };
  }
}

function saveContent(data) {
  fs.writeFileSync(CONTENT_FILE, JSON.stringify(data, null, 2));
}

// Only these keys can be stored — keeps the data predictable and safe.
const ALLOWED_CONTENT_KEYS = [
  "profile_photo_url",
  "hero_h1", "hero_text", "status_label", "status_tech",
  "fact1_title", "fact1_text",
  "fact2_title", "fact2_text",
  "fact3_title", "fact3_text",
  "contact_h2", "contact_p",
  "contact_email_href", "contact_github_href", "contact_social_href",
];

app.get("/api/content", (req, res) => {
  res.json(loadContent());
});

app.post("/api/content", (req, res) => {
  const token = req.headers["x-auth-token"];
  if (!verifyToken(token)) {
    return res.status(401).json({ ok: false, error: "Not authorized." });
  }

  const updates = req.body || {};
  const current = loadContent();
  const merged = { ...current };

  for (const key of ALLOWED_CONTENT_KEYS) {
    if (typeof updates[key] === "string") {
      if (updates[key].trim() === "") {
        delete merged[key]; // empty field = remove override, fall back to default text
      } else {
        merged[key] = updates[key];
      }
    }
  }

  saveContent(merged);
  res.json({ ok: true, content: merged });
});

app.get("/", (req, res) => {
  res.send("Portfolio auth backend is running.");
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Auth server running on port ${PORT}`);
});
