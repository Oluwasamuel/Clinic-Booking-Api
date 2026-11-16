'use strict';

const express = require('express');
const { Pool } = require('pg');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------
const API_KEY = process.env.API_KEY;
const DATABASE_URL = process.env.DATABASE_URL;
const PORT = process.env.PORT || 3000;

if (!API_KEY || !DATABASE_URL) {
  console.error('API_KEY and DATABASE_URL environment variables are required.');
  process.exit(1);
}

const isLocalDb = /localhost|127\.0\.0\.1/.test(DATABASE_URL);
const pool = new Pool({
  connectionString: DATABASE_URL,
  max: Number(process.env.PG_POOL_MAX || 15),
  ssl: isLocalDb ? false : { rejectUnauthorized: false },
});
pool.on('error', (err) => console.error('Idle pg client error', err.message));

const RATE_LIMIT = 5; // attempts
const RATE_WINDOW_MS = 60 * 1000; // per minute, per email
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// ---------------------------------------------------------------------------
// Database schema
// ---------------------------------------------------------------------------
async function initDb() {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    // Serialise schema creation if several instances start at once.
    await client.query("SELECT pg_advisory_xact_lock(hashtextextended('schema-init', 0))");
    await client.query(`
      CREATE TABLE IF NOT EXISTS slots (
        id        TEXT PRIMARY KEY,
        provider  TEXT NOT NULL,
        start_raw TEXT NOT NULL,
        end_raw   TEXT NOT NULL,
        start_ts  TIMESTAMPTZ NOT NULL,
        end_ts    TIMESTAMPTZ NOT NULL
      )`);
    await client.query(`
      CREATE TABLE IF NOT EXISTS bookings (
        seq        BIGSERIAL UNIQUE,
        id         TEXT PRIMARY KEY,
        slot_id    TEXT NOT NULL REFERENCES slots(id) ON DELETE CASCADE,
        name       TEXT NOT NULL,
        email      TEXT NOT NULL,
        status     TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL
      )`);
    // The database itself guarantees a slot can have only one confirmed
    // booking, no matter how many requests arrive at the same moment.
    await client.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS one_confirmed_booking_per_slot
      ON bookings (slot_id) WHERE status = 'confirmed'`);
    await client.query('CREATE INDEX IF NOT EXISTS bookings_email_seq ON bookings (email, seq)');
    await client.query(`
      CREATE TABLE IF NOT EXISTS idempotency_keys (
        key         TEXT PRIMARY KEY,
        body_hash   TEXT NOT NULL,
        status_code INTEGER NOT NULL,
        response    JSON NOT NULL
      )`);
    await client.query(`
      CREATE TABLE IF NOT EXISTS booking_attempts (
        email TEXT NOT NULL,
        ts    BIGINT NOT NULL
      )`);
    await client.query('CREATE INDEX IF NOT EXISTS booking_attempts_email_ts ON booking_attempts (email, ts)');

    // Demo slots so the web page has something to show on a fresh database.
    const { rows } = await client.query('SELECT COUNT(*)::int AS n FROM slots');
    if (rows[0].n === 0) {
      const providers = ['Dr Ade', 'Dr Okafor'];
      const times = [9, 10, 11, 14];
      const now = new Date();
      let n = 1;
      for (let day = 1; day <= 5; day++) {
        for (const provider of providers) {
          for (const hour of times) {
            const start = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + day, hour, 0, 0));
            const end = new Date(start.getTime() + 30 * 60 * 1000);
            await client.query(
              'INSERT INTO slots (id, provider, start_raw, end_raw, start_ts, end_ts) VALUES ($1,$2,$3,$4,$5,$6)',
              [`s${n++}`, provider, isoNoMs(start), isoNoMs(end), start, end]
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
// Helpers
// ---------------------------------------------------------------------------
function isObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

function stableStringify(v) {
  if (Array.isArray(v)) return '[' + v.map(stableStringify).join(',') + ']';
  if (isObject(v)) {
    return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + stableStringify(v[k])).join(',') + '}';
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
    created_at: new Date(row.created_at).toISOString(),
  };
}

function sendError(res, status, message) {
  return res.status(status).json({ error: message });
}

function safeEqual(a, b) {
  const ab = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  return ab.length === bb.length && crypto.timingSafeEqual(ab, bb);
}

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------
const app = express();
app.disable('x-powered-by');

// The web page and health check are public. Everything else needs the key.
const indexHtml = fs
  .readFileSync(path.join(__dirname, 'public', 'index.html'), 'utf8')
  .replace('__API_KEY__', () => JSON.stringify(API_KEY).slice(1, -1));

app.get('/', (req, res) => {
  res.type('html').send(indexHtml);
});
app.get('/health', async (req, res) => {
  // Touches the database too, so an uptime monitor also keeps the DB awake.
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ ok: false });
  }
});

// Level 2: API key check on every API request.
app.use((req, res, next) => {
  const key = req.get('X-API-Key');
  if (!key || !safeEqual(key, API_KEY)) return sendError(res, 401, 'unauthorized');
  next();
});

app.use(express.json({ type: () => true, strict: false, limit: '256kb' }));

// ---------------------------------------------------------------------------
// POST /reset  (Level 1)
// ---------------------------------------------------------------------------
app.post('/reset', async (req, res) => {
  const body = req.body;
  if (!isObject(body) || !Array.isArray(body.slots)) return sendError(res, 400, 'slots must be an array');

  const ids = [];
  const providers = [];
  const startsRaw = [];
  const endsRaw = [];
  const startsTs = [];
  const endsTs = [];
  const seen = new Set();
  for (const s of body.slots) {
    if (!isObject(s)) return sendError(res, 400, 'each slot must be an object');
    for (const f of ['id', 'provider', 'start', 'end']) {
      if (typeof s[f] !== 'string' || s[f].trim() === '') return sendError(res, 400, `slot ${f} is required`);
    }
    const st = new Date(s.start);
    const en = new Date(s.end);
    if (Number.isNaN(st.getTime()) || Number.isNaN(en.getTime())) return sendError(res, 400, 'slot start/end must be valid dates');
    if (seen.has(s.id)) return sendError(res, 400, 'duplicate slot id');
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
        `INSERT INTO slots (id, provider, start_raw, end_raw, start_ts, end_ts)
         SELECT * FROM unnest($1::text[], $2::text[], $3::text[], $4::text[], $5::timestamptz[], $6::timestamptz[])`,
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
// GET /slots  (Level 1)
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
      `SELECT s.id, s.provider, s.start_raw, s.end_raw,
              NOT EXISTS (SELECT 1 FROM bookings b WHERE b.slot_id = s.id AND b.status = 'confirmed') AS available
       FROM slots s ${where}
       ORDER BY s.start_ts ASC, s.id ASC`,
      params
    );
    res.json({
      slots: rows.map((r) => ({ id: r.id, provider: r.provider, start: r.start_raw, end: r.end_raw, available: r.available })),
    });
  } catch (err) {
    console.error(err);
    sendError(res, 500, 'internal error');
  }
});

// ---------------------------------------------------------------------------
// POST /bookings  (Levels 1-5)
// ---------------------------------------------------------------------------
app.post('/bookings', async (req, res) => {
  const body = req.body;
  const idemKey = (req.get('Idempotency-Key') || '').trim();
  const b = isObject(body) ? body : {};

  const slotId = typeof b.slot_id === 'string' ? b.slot_id.trim() : '';
  const name = typeof b.name === 'string' ? b.name.trim() : '';
  const email = typeof b.email === 'string' ? b.email.trim().toLowerCase() : '';
  const emailValid = EMAIL_RE.test(email);

  const client = await pool.connect();
  // Everything below runs in ONE transaction using transaction-level advisory
  // locks, so it works behind connection poolers (e.g. Neon's pooled URL).
  // The transaction is COMMITTED on every outcome except an unexpected error,
  // so the rate-limit attempt is recorded even when the booking itself fails.
  try {
    await client.query('BEGIN');

    // Level 4: idempotency. Concurrent requests with the same key queue up on
    // this lock, so only the first one does the work; the rest replay it.
    let bodyHash = null;
    if (idemKey) {
      bodyHash = sha256(stableStringify(body === undefined ? null : body));
      await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', ['idem:' + idemKey]);
      const prev = await client.query(
        'SELECT body_hash, status_code, response FROM idempotency_keys WHERE key = $1',
        [idemKey]
      );
      if (prev.rowCount > 0) {
        await client.query('COMMIT');
        if (prev.rows[0].body_hash !== bodyHash) {
          return sendError(res, 422, 'Idempotency-Key was already used with a different request body');
        }
        return res.status(prev.rows[0].status_code).json(prev.rows[0].response);
      }
    }

    // Level 5: at most 5 attempts per email per minute (failed ones count).
    if (emailValid) {
      await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', ['rate:' + email]);
      const now = Date.now();
      await client.query('DELETE FROM booking_attempts WHERE email = $1 AND ts <= $2', [email, now - RATE_WINDOW_MS]);
      const attempts = await client.query(
        'SELECT ts FROM booking_attempts WHERE email = $1 ORDER BY ts ASC',
        [email]
      );
      if (attempts.rowCount >= RATE_LIMIT) {
        await client.query('COMMIT');
        const oldest = Number(attempts.rows[0].ts);
        const retryAfter = Math.max(1, Math.ceil((oldest + RATE_WINDOW_MS - now) / 1000));
        res.set('Retry-After', String(retryAfter));
        return sendError(res, 429, 'too many booking attempts for this email, try again later');
      }
      await client.query('INSERT INTO booking_attempts (email, ts) VALUES ($1, $2)', [email, now]);
    }

    // Level 2: validation.
    let problem = null;
    if (!slotId) problem = 'slot_id is required';
    else if (!name) problem = 'name is required';
    else if (!email) problem = 'email is required';
    else if (!emailValid) problem = 'email is not valid';
    if (problem) {
      await client.query('COMMIT');
      return sendError(res, 400, problem);
    }

    const slot = await client.query('SELECT id, (start_ts <= now()) AS started FROM slots WHERE id = $1', [slotId]);
    if (slot.rowCount === 0) {
      await client.query('COMMIT');
      return sendError(res, 404, 'slot not found');
    }
    if (slot.rows[0].started) {
      await client.query('COMMIT');
      return sendError(res, 400, 'slot has already started');
    }

    // Level 3: the unique partial index rejects a second confirmed booking.
    const id = crypto.randomUUID();
    const createdAt = new Date();
    await client.query('SAVEPOINT book');
    try {
      await client.query(
        `INSERT INTO bookings (id, slot_id, name, email, status, created_at)
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

    const booking = formatBooking({ id, slot_id: slotId, name, email, status: 'confirmed', created_at: createdAt });
    if (idemKey) {
      await client.query(
        'INSERT INTO idempotency_keys (key, body_hash, status_code, response) VALUES ($1, $2, $3, $4)',
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
// GET /bookings?email=&limit=&cursor=  (Level 4)
// ---------------------------------------------------------------------------
app.get('/bookings', async (req, res) => {
  const email = typeof req.query.email === 'string' ? req.query.email.trim().toLowerCase() : '';
  if (!email) return sendError(res, 400, 'email is required');

  let limit = 10;
  if (req.query.limit !== undefined) {
    if (typeof req.query.limit !== 'string' || !/^\d+$/.test(req.query.limit)) return sendError(res, 400, 'limit must be an integer from 1 to 50');
    limit = Number(req.query.limit);
    if (limit < 1 || limit > 50) return sendError(res, 400, 'limit must be an integer from 1 to 50');
  }

  let after = 0;
  if (req.query.cursor !== undefined && req.query.cursor !== '') {
    try {
      const decoded = Buffer.from(String(req.query.cursor), 'base64url').toString('utf8');
      if (!/^\d+$/.test(decoded)) throw new Error('bad cursor');
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
      next_cursor: hasMore ? Buffer.from(String(page[page.length - 1].seq)).toString('base64url') : null,
    });
  } catch (err) {
    console.error(err);
    sendError(res, 500, 'internal error');
  }
});

// ---------------------------------------------------------------------------
// GET /bookings/:id  (Level 1)
// ---------------------------------------------------------------------------
app.get('/bookings/:id', async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT id, slot_id, name, email, status, created_at FROM bookings WHERE id = $1',
      [req.params.id]
    );
    if (rows.length === 0) return sendError(res, 404, 'booking not found');
    res.json(formatBooking(rows[0]));
  } catch (err) {
    console.error(err);
    sendError(res, 500, 'internal error');
  }
});

// ---------------------------------------------------------------------------
// DELETE /bookings/:id  (Level 3)
// ---------------------------------------------------------------------------
app.delete('/bookings/:id', async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const found = await client.query(
      'SELECT id, slot_id, name, email, status, created_at FROM bookings WHERE id = $1 FOR UPDATE',
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
    await client.query("UPDATE bookings SET status = 'cancelled' WHERE id = $1", [req.params.id]);
    await client.query('COMMIT');
    res.json(formatBooking({ ...found.rows[0], status: 'cancelled' }));
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
app.use((req, res) => sendError(res, 404, 'not found'));

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  if (err && (err.type === 'entity.parse.failed' || err instanceof SyntaxError)) return sendError(res, 400, 'invalid JSON');
  if (err && err.type === 'entity.too.large') return sendError(res, 413, 'request too large');
  console.error(err);
  sendError(res, 500, 'internal error');
});

initDb()
  .then(() => app.listen(PORT, () => console.log(`Clinic booking API listening on ${PORT}`)))
  .catch((err) => {
    console.error('Failed to start', err);
    process.exit(1);
  });
