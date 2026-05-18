import dotenv from "dotenv";
import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import { mkdirSync, readFileSync, writeFileSync, existsSync } from "fs";
import crypto from "crypto";
import bcrypt from "bcrypt";
import session from "express-session";
import Stripe from "stripe";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
dotenv.config({ path: path.join(__dirname, ".env") });
const app = express();
const port = process.env.PORT || 3000;
const publicBase =
  process.env.PUBLIC_BASE_URL?.replace(/\/$/, "") || `http://localhost:${port}`;

const DATA_DIR = path.join(__dirname, "data");
const STORE_PATH = path.join(DATA_DIR, "auth-store.json");

function loadStore() {
  if (!existsSync(STORE_PATH)) {
    return { users: [], pending: {} };
  }
  try {
    return JSON.parse(readFileSync(STORE_PATH, "utf8"));
  } catch {
    return { users: [], pending: {} };
  }
}

function saveStore(store) {
  mkdirSync(DATA_DIR, { recursive: true });
  writeFileSync(STORE_PATH, JSON.stringify(store, null, 2));
}

const sendCodeHits = new Map();

function rateLimitSendCode(ip) {
  const now = Date.now();
  const windowMs = 60_000;
  const max = 5;
  let arr = sendCodeHits.get(ip) || [];
  arr = arr.filter((t) => now - t < windowMs);
  if (arr.length >= max) return false;
  arr.push(now);
  sendCodeHits.set(ip, arr);
  return true;
}

function looksLikeEmail(s) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s);
}

function looksLikePhone(s) {
  const digits = String(s).replace(/\D/g, "");
  return digits.length >= 10 && digits.length <= 15;
}

function validateIdentifier(raw) {
  const t = String(raw || "").trim();
  if (!t) return { error: "Enter your email or phone number." };
  if (looksLikeEmail(t) || looksLikePhone(t)) return { value: t };
  return {
    error:
      "Enter a valid email address or a phone number with at least 10 digits.",
  };
}

function normalizeIdentifier(t) {
  const v = t.trim();
  if (looksLikeEmail(v)) return v.toLowerCase();
  return v.replace(/\D/g, "");
}

function validatePassword(pw) {
  if (typeof pw !== "string" || pw.length < 6) {
    return "Password must be at least 6 characters.";
  }
  if (
    !/[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?`~]/.test(pw)
  ) {
    return "Password must include at least one special character.";
  }
  return null;
}

function randomUserId() {
  return crypto.randomBytes(12).toString("hex");
}

function displayNameFromUser(u) {
  const id = u.identifierDisplay || u.identifierNorm;
  if (looksLikeEmail(id)) {
    const local = id.split("@")[0] || "you";
    return local.charAt(0).toUpperCase() + local.slice(1);
  }
  const d = id.replace(/\D/g, "");
  if (d.length >= 4) {
    return `Member ···${d.slice(-4)}`;
  }
  return "Member";
}

function handleFromNorm(norm) {
  if (norm.includes("@")) {
    const local = norm.split("@")[0] || "you";
    const clean = local.replace(/[^a-z0-9_]/gi, "");
    return `@${clean || "you"}`;
  }
  return `@member${norm.slice(-4)}`;
}

const stripeSecret = process.env.STRIPE_SECRET_KEY;
const stripe = stripeSecret ? new Stripe(stripeSecret) : null;
const stripePublishableKey = process.env.STRIPE_PUBLISHABLE_KEY || "";

const priceMatching = process.env.STRIPE_PRICE_MATCHING;
const priceByProduct = {
  abundant: process.env.STRIPE_PRICE_ABUNDANT || priceMatching,
  "matching-set": priceMatching,
  "love-letter": process.env.STRIPE_PRICE_LOVE_LETTER,
  "date-night": process.env.STRIPE_PRICE_DATE_NIGHT,
  "memory-journal": process.env.STRIPE_PRICE_MEMORY,
};

app.use(express.json());

app.use(
  session({
    name: "fmn.sid",
    secret:
      process.env.SESSION_SECRET ||
      "forget-me-not-dev-session-secret-change-me",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    },
  })
);

/** Step 1: validate form, hash password, email “verification” code (logged in dev), open modal next. */
app.post("/api/auth/start-signup", async (req, res) => {
  const ip = req.ip || req.socket.remoteAddress || "unknown";
  if (!rateLimitSendCode(ip)) {
    return res
      .status(429)
      .json({ error: "Too many attempts. Try again in a minute." });
  }

  const { identifier, password, agreePrivacy, notRobot, company, website } =
    req.body || {};
  if (company || website) {
    return res.status(400).json({ error: "Could not create account." });
  }
  if (!agreePrivacy) {
    return res.status(400).json({ error: "Please agree to the privacy policy." });
  }
  if (!notRobot) {
    return res.status(400).json({ error: "Please confirm you are not a robot." });
  }

  const v = validateIdentifier(identifier);
  if (v.error) return res.status(400).json({ error: v.error });

  const pwErr = validatePassword(password);
  if (pwErr) return res.status(400).json({ error: pwErr });

  const norm = normalizeIdentifier(v.value);
  const store = loadStore();
  if (store.users.some((u) => u.identifierNorm === norm)) {
    return res.status(400).json({ error: "An account already exists for this email or phone." });
  }

  const passwordHash = await bcrypt.hash(password, 10);
  const code = String(Math.floor(1000 + Math.random() * 9000));
  const codeHash = await bcrypt.hash(code, 8);

  store.pending[norm] = {
    codeHash,
    expires: Date.now() + 10 * 60 * 1000,
    passwordHash,
    identifierDisplay: v.value.trim(),
  };
  saveStore(store);

  req.session.pendingSignupNorm = norm;
  console.info(`[signup verification email] ${norm} → ${code}`);

  const payload = {
    ok: true,
    message:
      "Check your email (or SMS when configured) for a 4-digit code. Until then, see the server terminal in development.",
  };
  if (process.env.NODE_ENV !== "production") {
    payload.devCode = code;
  }
  res.json(payload);
});

/** Step 2: after correct code, account is created and session is logged in. */
app.post("/api/auth/verify-signup", async (req, res) => {
  const norm = req.session.pendingSignupNorm;
  if (!norm) {
    return res.status(400).json({
      error: "No signup in progress. Press Create account again.",
    });
  }

  const codeStr = String(req.body?.code || "").replace(/\D/g, "").slice(0, 4);
  if (codeStr.length !== 4) {
    return res.status(400).json({ error: "Enter the 4-digit verification code." });
  }

  const store = loadStore();
  const pending = store.pending[norm];
  if (!pending?.passwordHash) {
    delete req.session.pendingSignupNorm;
    return res.status(400).json({ error: "Signup expired. Start again with Create account." });
  }
  if (pending.expires < Date.now()) {
    delete store.pending[norm];
    saveStore(store);
    delete req.session.pendingSignupNorm;
    return res.status(400).json({ error: "Code expired. Press Create account again." });
  }

  const ok = await bcrypt.compare(codeStr, pending.codeHash);
  if (!ok) {
    return res.status(400).json({ error: "Incorrect verification code." });
  }

  if (store.users.some((u) => u.identifierNorm === norm)) {
    delete store.pending[norm];
    saveStore(store);
    delete req.session.pendingSignupNorm;
    return res.status(400).json({ error: "An account already exists for this email or phone." });
  }

  const user = {
    id: randomUserId(),
    identifierDisplay: pending.identifierDisplay,
    identifierNorm: norm,
    passwordHash: pending.passwordHash,
    createdAt: Date.now(),
  };
  store.users.push(user);
  delete store.pending[norm];
  saveStore(store);
  delete req.session.pendingSignupNorm;
  req.session.userId = user.id;

  res.json({
    ok: true,
    user: {
      id: user.id,
      identifierDisplay: user.identifierDisplay,
      identifierNorm: user.identifierNorm,
      displayName: displayNameFromUser(user),
      handle: handleFromNorm(norm),
      createdAt: user.createdAt,
    },
  });
});

app.post("/api/auth/resend-signup-code", async (req, res) => {
  const ip = req.ip || req.socket.remoteAddress || "unknown";
  if (!rateLimitSendCode(ip)) {
    return res
      .status(429)
      .json({ error: "Too many attempts. Try again in a minute." });
  }

  const norm = req.session.pendingSignupNorm;
  if (!norm) {
    return res.status(400).json({ error: "No signup in progress." });
  }

  const store = loadStore();
  const pending = store.pending[norm];
  if (!pending?.passwordHash) {
    return res.status(400).json({ error: "Start signup again with Create account." });
  }

  const code = String(Math.floor(1000 + Math.random() * 9000));
  const codeHash = await bcrypt.hash(code, 8);
  store.pending[norm] = {
    ...pending,
    codeHash,
    expires: Date.now() + 10 * 60 * 1000,
  };
  saveStore(store);
  console.info(`[resend signup verification] ${norm} → ${code}`);

  const payload = { ok: true, message: "A new code was sent." };
  if (process.env.NODE_ENV !== "production") {
    payload.devCode = code;
  }
  res.json(payload);
});

app.post("/api/auth/cancel-signup", (req, res) => {
  const norm = req.session.pendingSignupNorm;
  if (norm) {
    const store = loadStore();
    delete store.pending[norm];
    saveStore(store);
  }
  delete req.session.pendingSignupNorm;
  res.json({ ok: true });
});

app.post("/api/auth/login", async (req, res) => {
  const { identifier, password } = req.body || {};
  const v = validateIdentifier(identifier);
  if (v.error) return res.status(400).json({ error: v.error });

  const norm = normalizeIdentifier(v.value);
  const store = loadStore();
  const user = store.users.find((u) => u.identifierNorm === norm);
  if (!user) {
    return res.status(400).json({ error: "No account found for that email or phone." });
  }

  const match = await bcrypt.compare(password, user.passwordHash);
  if (!match) {
    return res.status(400).json({ error: "Incorrect password." });
  }

  req.session.userId = user.id;
  res.json({
    ok: true,
    user: {
      id: user.id,
      identifierDisplay: user.identifierDisplay,
      identifierNorm: user.identifierNorm,
      displayName: displayNameFromUser(user),
      handle: handleFromNorm(norm),
      createdAt: user.createdAt,
    },
  });
});

app.post("/api/auth/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("fmn.sid");
    res.json({ ok: true });
  });
});

app.get("/api/auth/me", (req, res) => {
  const id = req.session.userId;
  if (!id) return res.status(401).json({ user: null });

  const store = loadStore();
  const user = store.users.find((u) => u.id === id);
  if (!user) {
    req.session.destroy(() => {});
    return res.status(401).json({ user: null });
  }

  res.json({
    user: {
      id: user.id,
      identifierDisplay: user.identifierDisplay,
      identifierNorm: user.identifierNorm,
      displayName: displayNameFromUser(user),
      handle: handleFromNorm(user.identifierNorm),
      createdAt: user.createdAt,
    },
  });
});

function mergeCheckoutItems(body) {
  const raw = body?.items;
  if (Array.isArray(raw) && raw.length) {
    const map = new Map();
    for (const row of raw) {
      const id = String(row?.productId || "").trim();
      if (!id) continue;
      const q = Math.min(99, Math.max(1, parseInt(row?.quantity, 10) || 1));
      map.set(id, (map.get(id) || 0) + q);
    }
    return [...map.entries()].map(([productId, quantity]) => ({
      productId,
      quantity,
    }));
  }
  const single = String(body?.productId || "").trim();
  if (single) return [{ productId: single, quantity: 1 }];
  return [];
}

app.post("/api/create-checkout-session", async (req, res) => {
  try {
    if (!stripe) {
      return res.status(503).json({
        error:
          "Stripe is not configured. Add STRIPE_SECRET_KEY to your .env file.",
      });
    }

    const merged = mergeCheckoutItems(req.body || {});
    if (!merged.length) {
      return res.status(400).json({
        error: "Send productId or a non-empty items array with productId and quantity.",
      });
    }

    const line_items = [];
    for (const { productId, quantity } of merged) {
      const priceId = priceByProduct[productId];
      if (!priceId) {
        return res.status(400).json({
          error: `Unknown or unpriced product: ${productId}. Check Stripe price env vars.`,
        });
      }
      line_items.push({ price: priceId, quantity });
    }

    const session = await stripe.checkout.sessions.create({
      mode: "payment",
      line_items,
      success_url: `${publicBase}/success.html?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${publicBase}/`,
      allow_promotion_codes: true,
    });

    return res.json({ url: session.url });
  } catch (err) {
    console.error(err);
    const stripeMsg =
      err?.raw?.message ||
      err?.message ||
      "Could not start checkout";
    const code = err?.raw?.code;
    const hint =
      code === "resource_missing" && String(err?.raw?.param || "").includes("price")
        ? " Check that each STRIPE_PRICE_* in .env is a real Price ID from the same Stripe account and mode (Live vs Test) as your secret key."
        : "";
    return res.status(500).json({
      error: stripeMsg + hint,
    });
  }
});

app.get("/api/health", (_req, res) => {
  res.json({
    ok: true,
    stripe: Boolean(stripe),
    stripePublishableKeyConfigured: Boolean(stripePublishableKey),
    pricesConfigured: Object.fromEntries(
      Object.entries(priceByProduct).map(([k, v]) => [k, Boolean(v)])
    ),
  });
});

/** Publishable key (pk_...) for browser Stripe.js; safe to expose. Set STRIPE_PUBLISHABLE_KEY in .env */
app.get("/api/stripe-config", (_req, res) => {
  res.json({ publishableKey: stripePublishableKey || null });
});

app.use(express.static(path.join(__dirname, "public")));

app.listen(port, () => {
  console.log(`Forget Me Not at ${publicBase}`);
  if (!stripe) console.warn("Stripe: missing STRIPE_SECRET_KEY");
  if (!stripePublishableKey) console.warn("Stripe: missing STRIPE_PUBLISHABLE_KEY (optional for Checkout redirect; needed for Stripe.js)");
});
