
'use strict';

const express = require('express');
const { Pool } = require('pg');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const API_KEY = process.env.API_KEY;
const DATABASE_URL = process.env.DATABASE_URL;
const PORT = process.env.PORT || 3000;

if (!API_KEY || !DATABASE_URL) {
  console.error('API_KEY and DATABASE_URL environment variables are required.');
  process.exit(1);
}

const isProduction =
  process.env.NODE_ENV === 'production' ||
  Boolean(process.env.RENDER);

const SESSION_COOKIE = 'clinic_session';
const SESSION_DURATION_MS = 8 * 60 * 60 * 1000; // 8 hours

const isLocalDb = /localhost|127\.0\.0\.1/.test(DATABASE_URL);

const pool = new Pool({
  connectionString: DATABASE_URL,
  max: Number(process.env.PG_POOL_MAX || 15),
  ssl: isLocalDb ? false : { rejectUnauthorized: false },
});

pool.on('error', (err) => {
  console.error('Idle pg client error:', err.message);
});

const RATE_LIMIT = 5;
const RATE_WINDOW_MS = 60 * 1000;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// Login rate limiting: 10 failed attempts per IP per 15 minutes.
const loginAttempts = new Map();
const LOGIN_MAX_ATTEMPTS = 10;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;

// ---------------------------------------------------------------------------
// Load the original appointment interface
// IMPORTANT: indexHtml must be declared before authenticatedHtml.
// ---------------------------------------------------------------------------

const indexHtml = fs.readFileSync(
  path.join(__dirname, 'public', 'index.html'),
  'utf8'
);

// ---------------------------------------------------------------------------
// Authentication helpers
// ---------------------------------------------------------------------------

function safeEqual(a, b) {
  const ab = Buffer.from(String(a));
  const bb = Buffer.from(String(b));

  return (
    ab.length === bb.length &&
    crypto.timingSafeEqual(ab, bb)
  );
}

function createSessionToken() {
  const issuedAt = Date.now().toString();

  const signature = crypto
    .createHmac('sha256', API_KEY)
    .update(issuedAt)
    .digest('hex');

  return `${issuedAt}.${signature}`;
}

function verifySessionToken(token) {
  if (typeof token !== 'string') {
    return false;
  }

  const parts = token.split('.');

  if (parts.length !== 2) {
    return false;
  }

  const [issuedAt, suppliedSignature] = parts;

  if (
    !/^\d+$/.test(issuedAt) ||
    !/^[a-f0-9]{64}$/i.test(suppliedSignature)
  ) {
    return false;
  }

  const timestamp = Number(issuedAt);
  const age = Date.now() - timestamp;

  if (
    !Number.isSafeInteger(timestamp) ||
    age < 0 ||
    age > SESSION_DURATION_MS
  ) {
    return false;
  }

  const expectedSignature = crypto
    .createHmac('sha256', API_KEY)
    .update(issuedAt)
    .digest('hex');

  return safeEqual(suppliedSignature, expectedSignature);
}

function getCookie(req, cookieName) {
  const header = req.headers.cookie;

  if (!header) {
    return null;
  }

  const cookies = header.split(';');

  for (const item of cookies) {
    const separator = item.indexOf('=');

    if (separator === -1) continue;

    const name = item.slice(0, separator).trim();
    const value = item.slice(separator + 1).trim();

    if (name === cookieName) {
      try {
        return decodeURIComponent(value);
      } catch {
        return value;
      }
    }
  }

  return null;
}

function hasValidSession(req) {
  const token = getCookie(req, SESSION_COOKIE);

  if (verifySessionToken(token)) {
    return true;
  }

  // Also support authenticated API clients using X-API-Key.
  const headerKey = req.get('X-API-Key');

  return Boolean(headerKey && safeEqual(headerKey, API_KEY));
}

function setSessionCookie(res) {
  const token = createSessionToken();

  const cookieParts = [
    `${SESSION_COOKIE}=${encodeURIComponent(token)}`,
    'Path=/',
    `Max-Age=${Math.floor(SESSION_DURATION_MS / 1000)}`,
    'HttpOnly',
    'SameSite=Strict',
  ];

  if (isProduction) {
    cookieParts.push('Secure');
  }

  res.setHeader('Set-Cookie', cookieParts.join('; '));
}

function clearSessionCookie(res) {
  const cookieParts = [
    `${SESSION_COOKIE}=`,
    'Path=/',
    'Max-Age=0',
    'HttpOnly',
    'SameSite=Strict',
  ];

  if (isProduction) {
    cookieParts.push('Secure');
  }

  res.setHeader('Set-Cookie', cookieParts.join('; '));
}

function sendError(res, status, message) {
  return res.status(status).json({ error: message });
}

// ---------------------------------------------------------------------------
// Login rate limiting
// ---------------------------------------------------------------------------

function checkLoginRateLimit(ip) {
  const now = Date.now();
  const record = loginAttempts.get(ip);

  if (!record || now - record.startedAt >= LOGIN_WINDOW_MS) {
    loginAttempts.set(ip, {
      count: 0,
      startedAt: now,
    });

    return true;
  }

  return record.count < LOGIN_MAX_ATTEMPTS;
}

function recordFailedLogin(ip) {
  const now = Date.now();
  let record = loginAttempts.get(ip);

  if (!record || now - record.startedAt >= LOGIN_WINDOW_MS) {
    record = {
      count: 0,
      startedAt: now,
    };
  }

  record.count += 1;
  loginAttempts.set(ip, record);
}

// Periodically remove expired login-rate-limit records.
const loginCleanup = setInterval(() => {
  const now = Date.now();

  for (const [ip, record] of loginAttempts.entries()) {
    if (now - record.startedAt >= LOGIN_WINDOW_MS) {
      loginAttempts.delete(ip);
    }
  }
}, 10 * 60 * 1000);

loginCleanup.unref();

// ---------------------------------------------------------------------------
// API authentication middleware
// ---------------------------------------------------------------------------

function requireApiKey(req, res, next) {
  if (!hasValidSession(req)) {
    return sendError(res, 401, 'unauthorized');
  }

  next();
}

// ---------------------------------------------------------------------------
// Login page
// ---------------------------------------------------------------------------

const loginHtml = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="robots" content="noindex, nofollow">
  <title>Secure Login | Medical Care</title>

  <style>
    * {
      box-sizing: border-box;
    }

    body {
      margin: 0;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 24px;
      background: #f3f8fb;
      font-family: Arial, Helvetica, sans-serif;
      color: #183247;
    }

    .login-card {
      width: 100%;
      max-width: 420px;
      padding: 42px 34px;
      background: #ffffff;
      border-radius: 16px;
      box-shadow: 0 12px 40px rgba(20, 65, 90, 0.10);
      text-align: center;
    }

    .logo {
      width: 58px;
      height: 58px;
      margin: 0 auto 20px;
      display: flex;
      align-items: center;
      justify-content: center;
      border-radius: 15px;
      background: #e4f5f5;
      color: #078b91;
      font-size: 27px;
      font-weight: bold;
    }

    h1 {
      margin: 0 0 10px;
      font-size: 25px;
      color: #17394e;
    }

    .description {
      margin: 0 0 28px;
      color: #718392;
      font-size: 14px;
      line-height: 1.6;
    }

    label {
      display: block;
      margin-bottom: 9px;
      text-align: left;
      font-size: 13px;
      font-weight: 600;
      color: #344d60;
    }

    input {
      display: block;
      width: 100%;
      padding: 14px 15px;
      border: 1px solid #d6e2e9;
      border-radius: 8px;
      outline: none;
      font-size: 15px;
      color: #183247;
      background: #ffffff;
    }

    input:focus {
      border-color: #078b91;
      box-shadow: 0 0 0 3px rgba(7, 139, 145, 0.10);
    }

    button {
      width: 100%;
      margin-top: 19px;
      padding: 14px;
      border: 0;
      border-radius: 8px;
      background: #078b91;
      color: white;
      font-size: 15px;
      font-weight: 600;
      cursor: pointer;
    }

    button:hover {
      background: #06767c;
    }

    button:disabled {
      opacity: 0.65;
      cursor: not-allowed;
    }

    #message {
      min-height: 20px;
      margin: 15px 0 0;
      font-size: 13px;
      color: #c0392b;
    }

    .footer {
      margin-top: 26px;
      color: #93a2ad;
      font-size: 12px;
    }

    @media (max-width: 480px) {
      .login-card {
        padding: 35px 23px;
      }
    }
  </style>
</head>

<body>
  <main class="login-card">
    <div class="logo">+</div>

    <h1>Medical Care</h1>

    <p class="description">
      Secure access to the Clinic Booking application.
      Enter your authorised API key to continue.
    </p>

    <form id="loginForm">
      <label for="apiKey">API Authentication Key</label>

      <input
        id="apiKey"
        name="apiKey"
        type="password"
        placeholder="Enter your API key"
        autocomplete="current-password"
        required
        autofocus
      >

      <button id="loginButton" type="submit">
        Sign In
      </button>

      <p id="message" role="alert" aria-live="polite"></p>
    </form>

    <div class="footer">
      Protected Clinic Booking System
    </div>
  </main>

  <script>
    const form = document.getElementById('loginForm');
    const input = document.getElementById('apiKey');
    const button = document.getElementById('loginButton');
    const message = document.getElementById('message');

    form.addEventListener('submit', async function(event) {
      event.preventDefault();

      const apiKey = input.value.trim();

      if (!apiKey) {
        message.textContent = 'Please enter your API key.';
        return;
      }

      button.disabled = true;
      button.textContent = 'Authenticating...';
      message.textContent = '';

      try {
        const response = await fetch('/auth/login', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ apiKey })
        });

        const result = await response.json();

        if (!response.ok) {
          message.textContent =
            result.error || 'Authentication failed. Check your API key.';
          return;
        }

        input.value = '';
        window.location.replace('/');

      } catch (error) {
        message.textContent =
          'Unable to connect. Please try again.';
      } finally {
        button.disabled = false;
        button.textContent = 'Sign In';
      }
    });
  </script>
</body>
</html>`;

// ---------------------------------------------------------------------------
// Logout control added to the existing appointment interface.
// The original public/index.html is otherwise preserved.
// ---------------------------------------------------------------------------

const logoutControl = `
<style>
  #clinicLogoutButton {
    position: fixed;
    right: 18px;
    bottom: 18px;
    z-index: 99999;
    padding: 11px 17px;
    border: 0;
    border-radius: 8px;
    background: #078b91;
    color: #fff;
    font-size: 13px;
    font-weight: 600;
    cursor: pointer;
    box-shadow: 0 3px 12px rgba(0,0,0,.15);
  }

  #clinicLogoutButton:hover {
    background: #06767c;
  }
</style>

<button id="clinicLogoutButton" type="button">Log out</button>

<script>
  document.getElementById('clinicLogoutButton')
    .addEventListener('click', async function() {
      this.disabled = true;
      this.textContent = 'Logging out...';

      try {
        await fetch('/auth/logout', {
          method: 'POST',
          credentials: 'same-origin'
        });
      } finally {
        window.location.replace('/');
      }
    });
</script>
`;

const authenticatedHtml = /<\/body>/i.test(indexHtml)
  ? indexHtml.replace(/<\/body>/i, `${logoutControl}</body>`)
  : `${indexHtml}${logoutControl}`;

// ---------------------------------------------------------------------------
// Database schema
// ---------------------------------------------------------------------------

async function initDb() {
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    await client.query(
      "SELECT pg_advisory_xact_lock(hashtextextended('schema-init', 0))"
    );

    await client.query(`
      CREATE TABLE IF NOT EXISTS slots (
        id TEXT PRIMARY KEY,
        provider TEXT NOT NULL,
        start_raw TEXT NOT NULL,
        end_raw TEXT NOT NULL,
        start_ts TIMESTAMPTZ NOT NULL,
        end_ts TIMESTAMPTZ NOT NULL
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS bookings (
        seq BIGSERIAL UNIQUE,
        id TEXT PRIMARY KEY,
        slot_id TEXT NOT NULL REFERENCES slots(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        email TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL
      )
    `);

    await client.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS one_confirmed_booking_per_slot
      ON bookings (slot_id)
      WHERE status = 'confirmed'
    `);

    await client.query(
      'CREATE INDEX IF NOT EXISTS bookings_email_seq ON bookings (email, seq)'
    );

    await client.query(`
      CREATE TABLE IF NOT EXISTS idempotency_keys (
        key TEXT PRIMARY KEY,
        body_hash TEXT NOT NULL,
        status_code INTEGER NOT NULL,
        response JSON NOT NULL
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS booking_attempts (
        email TEXT NOT NULL,
        ts BIGINT NOT NULL
      )
    `);

    await client.query(
      'CREATE INDEX IF NOT EXISTS booking_attempts_email_ts ON booking_attempts (email, ts)'
    );

    // Create demo slots only if the database has no slots.
    const { rows } = await client.query(
      'SELECT COUNT(*)::int AS n FROM slots'
    );

    if (rows[0].n === 0) {
      const providers = ['Dr Ade', 'Dr Okafor'];
      const times = [9, 10, 11, 14];
      const now = new Date();

      let n = 1;

      for (let day = 1; day <= 5; day++) {
        for (const provider of providers) {
          for (const hour of times) {
            const start = new Date(
              Date.UTC(
                now.getUTCFullYear(),
                now.getUTCMonth(),
                now.getUTCDate() + day,
                hour, 0, 0
              )
            );

            const end = new Date(
              start.getTime() + 30 * 60 * 1000
            );

            await client.query(
              `INSERT INTO slots
              (id, provider, start_raw, end_raw, start_ts, end_ts)
              VALUES ($1,$2,$3,$4,$5,$6)`,
              [
                `s${n++}`,
                provider,
                isoNoMs(start),
                isoNoMs(end),
                start,
                end
              ]
            );
          }
        }
      }
    }

    await client.query('COMMIT');

  } catch (err) {
    await client.query('ROLLBACK');
    throw err;

  } finally {
    client.release();
  }
}

function isoNoMs(d) {
  return d.toISOString().replace('.000Z', 'Z');
}

// ---------------------------------------------------------------------------
// General helpers
// ---------------------------------------------------------------------------

function isObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

function stableStringify(v) {
  if (Array.isArray(v)) {
    return '[' + v.map(stableStringify).join(',') + ']';
  }

  if (isObject(v)) {
    return '{' +
      Object.keys(v)
        .sort()
        .map(k => JSON.stringify(k) + ':' + stableStringify(v[k]))
        .join(',') +
      '}';
  }

  return JSON.stringify(v);
}

function sha256(s) {
  return crypto.createHash('sha256').update(s).digest('hex');
}

function formatBooking(row) {
  return {
    id: row.id,
    slot_id: row.slot_id,
    name: row.name,
    email: row.email,
    status: row.status,
    created_at: new Date(row.created_at).toISOString()
  };
}

// ---------------------------------------------------------------------------
// Express application
// ---------------------------------------------------------------------------

const app = express();

app.disable('x-powered-by');

// Render runs behind a proxy. Trust its proxy headers for IP information.
if (isProduction) {
  app.set('trust proxy', 1);
}

app.use(express.json({
  type: () => true,
  strict: false,
  limit: '256kb'
}));

// ---------------------------------------------------------------------------
// Authentication routes
// These routes must appear BEFORE the global authentication middleware.
// ---------------------------------------------------------------------------

// Login.
app.post('/auth/login', (req, res) => {
  res.set('Cache-Control', 'no-store');

  const ip = req.ip || req.socket.remoteAddress || 'unknown';

  if (!checkLoginRateLimit(ip)) {
    return sendError(
      res,
      429,
      'Too many failed login attempts. Try again later.'
    );
  }

  const suppliedKey =
    isObject(req.body) && typeof req.body.apiKey === 'string'
      ? req.body.apiKey
      : '';

  if (!suppliedKey || !safeEqual(suppliedKey, API_KEY)) {
    recordFailedLogin(ip);
    return sendError(res, 401, 'Invalid API key.');
  }

  loginAttempts.delete(ip);

  setSessionCookie(res);

  return res.json({
    ok: true,
    message: 'Authentication successful.'
  });
});

// Check current browser session.
app.get('/auth/session', (req, res) => {
  res.set('Cache-Control', 'no-store');

  return res.json({
    authenticated: hasValidSession(req)
  });
});

// Logout.
app.post('/auth/logout', (req, res) => {
  clearSessionCookie(res);

  return res.json({
    ok: true,
    message: 'Logged out successfully.'
  });
});

// ---------------------------------------------------------------------------
// Health check - PUBLIC OPERATIONAL ENDPOINT
// This is kept public so Render health checks can reach the service.
// ---------------------------------------------------------------------------

app.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ ok: false });
  }
});

// ---------------------------------------------------------------------------
// Main application page
// ---------------------------------------------------------------------------

app.get('/', (req, res) => {
  res.set('Cache-Control', 'no-store');

  if (!hasValidSession(req)) {
    return res.type('html').send(loginHtml);
  }

  return res.type('html').send(authenticatedHtml);
});

// ---------------------------------------------------------------------------
// GLOBAL AUTHENTICATION
// Every application route below this point requires authentication.
// Browser sessions use the signed HttpOnly cookie.
// External API clients can use X-API-Key.
// ---------------------------------------------------------------------------

app.use(requireApiKey);

// ---------------------------------------------------------------------------
// POST /reset - AUTHENTICATED
// ---------------------------------------------------------------------------

app.post('/reset', requireApiKey, async (req, res) => {
  const body = req.body;

  if (!isObject(body) || !Array.isArray(body.slots)) {
    return sendError(res, 400, 'slots must be an array');
  }

  const ids = [];
  const providers = [];
  const startsRaw = [];
  const endsRaw = [];
  const startsTs = [];
  const endsTs = [];
  const seen = new Set();

  for (const s of body.slots) {
    if (!isObject(s)) {
      return sendError(res, 400, 'each slot must be an object');
    }

    for (const f of ['id', 'provider', 'start', 'end']) {
      if (typeof s[f] !== 'string' || s[f].trim() === '') {
        return sendError(res, 400, `slot ${f} is required`);
      }
    }

    const st = new Date(s.start);
    const en = new Date(s.end);

    if (
      Number.isNaN(st.getTime()) ||
      Number.isNaN(en.getTime()) ||
      en <= st
    ) {
      return sendError(res, 400, 'slot start/end must be valid dates');
    }

    if (seen.has(s.id)) {
      return sendError(res, 400, 'duplicate slot id');
    }

    seen.add(s.id);
    ids.push(s.id);
    providers.push(s.provider);
    startsRaw.push(s.start);
    endsRaw.push(s.end);
    startsTs.push(st.toISOString());
    endsTs.push(en.toISOString());
  }

  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    await client.query('DELETE FROM bookings');
    await client.query('DELETE FROM slots');
    await client.query('DELETE FROM idempotency_keys');
    await client.query('DELETE FROM booking_attempts');

    if (ids.length) {
      await client.query(
        `INSERT INTO slots
        (id, provider, start_raw, end_raw, start_ts, end_ts)
        SELECT * FROM unnest(
          $1::text[],
          $2::text[],
          $3::text[],
          $4::text[],
          $5::timestamptz[],
          $6::timestamptz[]
        )`,
        [ids, providers, startsRaw, endsRaw, startsTs, endsTs]
      );
    }

    await client.query('COMMIT');

    res.json({ ok: true, slots: ids.length });

  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    console.error(err);
    sendError(res, 500, 'internal error');

  } finally {
    client.release();
  }
});

// ---------------------------------------------------------------------------
// GET /slots - AUTHENTICATED
// ---------------------------------------------------------------------------

app.get('/slots', async (req, res) => {
  try {
    const params = [];
    let where = '';

    if (typeof req.query.provider === 'string') {
      params.push(req.query.provider);
      where = 'WHERE s.provider = $1';
    }

    const { rows } = await pool.query(
      `SELECT
        s.id,
        s.provider,
        s.start_raw,
        s.end_raw,
        NOT EXISTS (
          SELECT 1
          FROM bookings b
          WHERE b.slot_id = s.id
          AND b.status = 'confirmed'
        ) AS available
       FROM slots s
       ${where}
       ORDER BY s.start_ts ASC, s.id ASC`,
      params
    );

    res.json({
      slots: rows.map(r => ({
        id: r.id,
        provider: r.provider,
        start: r.start_raw,
        end: r.end_raw,
        available: r.available
      }))
    });

  } catch (err) {
    console.error(err);
    sendError(res, 500, 'internal error');
  }
});

// ---------------------------------------------------------------------------
// POST /bookings - AUTHENTICATED
// ---------------------------------------------------------------------------

app.post('/bookings', async (req, res) => {
  const body = req.body;
  const idemKey = (req.get('Idempotency-Key') || '').trim();
  const b = isObject(body) ? body : {};

  const slotId = typeof b.slot_id === 'string'
    ? b.slot_id.trim()
    : '';

  const name = typeof b.name === 'string'
    ? b.name.trim()
    : '';

  const email = typeof b.email === 'string'
    ? b.email.trim().toLowerCase()
    : '';

  const emailValid = EMAIL_RE.test(email);

  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    // Idempotency protection.
    let bodyHash = null;

    if (idemKey) {
      bodyHash = sha256(
        stableStringify(body === undefined ? null : body)
      );

      await client.query(
        'SELECT pg_advisory_xact_lock(hashtextextended($1, 0))',
        ['idem:' + idemKey]
      );

      const prev = await client.query(
        `SELECT body_hash, status_code, response
         FROM idempotency_keys
         WHERE key = $1`,
        [idemKey]
      );

      if (prev.rowCount > 0) {
        await client.query('COMMIT');

        if (prev.rows[0].body_hash !== bodyHash) {
          return sendError(
            res,
            422,
            'Idempotency-Key was already used with a different request body'
          );
        }

        return res
          .status(prev.rows[0].status_code)
          .json(prev.rows[0].response);
      }
    }

    // Limit attempts per email.
    if (emailValid) {
      await client.query(
        'SELECT pg_advisory_xact_lock(hashtextextended($1, 0))',
        ['rate:' + email]
      );

      const now = Date.now();

      await client.query(
        'DELETE FROM booking_attempts WHERE email = $1 AND ts <= $2',
        [email, now - RATE_WINDOW_MS]
      );

      const attempts = await client.query(
        'SELECT ts FROM booking_attempts WHERE email = $1 ORDER BY ts ASC',
        [email]
      );

      if (attempts.rowCount >= RATE_LIMIT) {
        await client.query('COMMIT');

        const oldest = Number(attempts.rows[0].ts);

        const retryAfter = Math.max(
          1,
          Math.ceil((oldest + RATE_WINDOW_MS - now) / 1000)
        );

        res.set('Retry-After', String(retryAfter));

        return sendError(
          res,
          429,
          'too many booking attempts for this email, try again later'
        );
      }

      await client.query(
        'INSERT INTO booking_attempts (email, ts) VALUES ($1, $2)',
        [email, now]
      );
    }

    // Validate booking details.
    let problem = null;

    if (!slotId) problem = 'slot_id is required';
    else if (!name) problem = 'name is required';
    else if (!email) problem = 'email is required';
    else if (!emailValid) problem = 'email is not valid';

    if (problem) {
      await client.query('COMMIT');
      return sendError(res, 400, problem);
    }

    const slot = await client.query(
      `SELECT id, (start_ts <= now()) AS started
       FROM slots
       WHERE id = $1`,
      [slotId]
    );

    if (slot.rowCount === 0) {
      await client.query('COMMIT');
      return sendError(res, 404, 'slot not found');
    }

    if (slot.rows[0].started) {
      await client.query('COMMIT');
      return sendError(res, 400, 'slot has already started');
    }

    // Database unique index prevents double booking.
    const id = crypto.randomUUID();
    const createdAt = new Date();

    await client.query('SAVEPOINT book');

    try {
      await client.query(
        `INSERT INTO bookings
        (id, slot_id, name, email, status, created_at)
        VALUES ($1, $2, $3, $4, 'confirmed', $5)`,
        [id, slotId, name, email, createdAt]
      );

    } catch (err) {
      if (err.code === '23505') {
        await client.query('ROLLBACK TO SAVEPOINT book');
        await client.query('COMMIT');

        return sendError(res, 409, 'slot is already booked');
      }

      throw err;
    }

    const booking = formatBooking({
      id,
      slot_id: slotId,
      name,
      email,
      status: 'confirmed',
      created_at: createdAt
    });

    if (idemKey) {
      await client.query(
        `INSERT INTO idempotency_keys
        (key, body_hash, status_code, response)
        VALUES ($1, $2, $3, $4)`,
        [idemKey, bodyHash, 201, JSON.stringify(booking)]
      );
    }

    await client.query('COMMIT');

    return res.status(201).json(booking);

  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    console.error(err);
    return sendError(res, 500, 'internal error');

  } finally {
    client.release();
  }
});

// ---------------------------------------------------------------------------
// GET /bookings - AUTHENTICATED
// ---------------------------------------------------------------------------

app.get('/bookings', async (req, res) => {
  const email = typeof req.query.email === 'string'
    ? req.query.email.trim().toLowerCase()
    : '';

  if (!email) {
    return sendError(res, 400, 'email is required');
  }

  let limit = 10;

  if (req.query.limit !== undefined) {
    if (
      typeof req.query.limit !== 'string' ||
      !/^\d+$/.test(req.query.limit)
    ) {
      return sendError(res, 400, 'limit must be an integer from 1 to 50');
    }

    limit = Number(req.query.limit);

    if (limit < 1 || limit > 50) {
      return sendError(res, 400, 'limit must be an integer from 1 to 50');
    }
  }

  let after = 0;

  if (req.query.cursor !== undefined && req.query.cursor !== '') {
    try {
      const decoded = Buffer
        .from(String(req.query.cursor), 'base64url')
        .toString('utf8');

      if (!/^\d+$/.test(decoded)) {
        throw new Error('bad cursor');
      }

      after = Number(decoded);

    } catch (e) {
      return sendError(res, 400, 'invalid cursor');
    }
  }

  try {
    const { rows } = await pool.query(
      `SELECT seq, id, slot_id, name, email, status, created_at
       FROM bookings
       WHERE email = $1 AND seq > $2
       ORDER BY seq ASC
       LIMIT $3`,
      [email, after, limit + 1]
    );

    const page = rows.slice(0, limit);
    const hasMore = rows.length > limit;

    res.json({
      bookings: page.map(formatBooking),
      next_cursor: hasMore
        ? Buffer.from(
            String(page[page.length - 1].seq)
          ).toString('base64url')
        : null
    });

  } catch (err) {
    console.error(err);
    sendError(res, 500, 'internal error');
  }
});

// ---------------------------------------------------------------------------
// GET /bookings/:id - AUTHENTICATED
// ---------------------------------------------------------------------------

app.get('/bookings/:id', async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, slot_id, name, email, status, created_at
       FROM bookings
       WHERE id = $1`,
      [req.params.id]
    );

    if (rows.length === 0) {
      return sendError(res, 404, 'booking not found');
    }

    res.json(formatBooking(rows[0]));

  } catch (err) {
    console.error(err);
    sendError(res, 500, 'internal error');
  }
});

// ---------------------------------------------------------------------------
// DELETE /bookings/:id - AUTHENTICATED
// ---------------------------------------------------------------------------

app.delete('/bookings/:id', async (req, res) => {
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    const found = await client.query(
      `SELECT id, slot_id, name, email, status, created_at
       FROM bookings
       WHERE id = $1
       FOR UPDATE`,
      [req.params.id]
    );

    if (found.rowCount === 0) {
      await client.query('COMMIT');
      return sendError(res, 404, 'booking not found');
    }

    if (found.rows[0].status === 'cancelled') {
      await client.query('COMMIT');
      return sendError(res, 409, 'booking is already cancelled');
    }

    await client.query(
      "UPDATE bookings SET status = 'cancelled' WHERE id = $1",
      [req.params.id]
    );

    await client.query('COMMIT');

    res.json(
      formatBooking({
        ...found.rows[0],
        status: 'cancelled'
      })
    );

  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    console.error(err);
    sendError(res, 500, 'internal error');

  } finally {
    client.release();
  }
});

// ---------------------------------------------------------------------------
// Fallbacks
// ---------------------------------------------------------------------------

// Unknown routes are also behind the global authentication middleware.
app.use((req, res) => {
  sendError(res, 404, 'not found');
});

// Error handler.
app.use((err, req, res, next) => {
  if (
    err &&
    (err.type === 'entity.parse.failed' || err instanceof SyntaxError)
  ) {
    return sendError(res, 400, 'invalid JSON');
  }

  if (err && err.type === 'entity.too.large') {
    return sendError(res, 413, 'request too large');
  }

  console.error(err);
  sendError(res, 500, 'internal error');
});

// ---------------------------------------------------------------------------
// Start server
// ---------------------------------------------------------------------------

initDb()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Clinic booking API listening on port ${PORT}`);
      console.log('API-key authentication is enabled.');
    });
  })
  .catch((err) => {
    console.error('Failed to start:', err);
    process.exit(1);
  });
