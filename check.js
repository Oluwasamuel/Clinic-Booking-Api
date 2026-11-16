// Run:  BASE=http://localhost:3000 KEY=... node test/check.js
// WARNING: calls /reset, which wipes all bookings and slots.
const BASE = process.env.BASE || 'http://localhost:3000';
const KEY = process.env.KEY;
let pass = 0, fail = 0;
function ok(name, cond, extra) {
  if (cond) { pass++; console.log('PASS', name); }
  else { fail++; console.log('FAIL', name, extra !== undefined ? JSON.stringify(extra) : ''); }
}
async function call(method, path, body, headers = {}, key = KEY) {
  const h = { 'Content-Type': 'application/json', ...headers };
  if (key) h['X-API-Key'] = key;
  const res = await fetch(BASE + path, { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body) });
  let json = null; try { json = await res.json(); } catch (e) {}
  return { status: res.status, json, headers: res.headers };
}
const future = (days, hour) => {
  const d = new Date(Date.now() + days * 864e5); d.setUTCHours(hour, 0, 0, 0);
  const e = new Date(d.getTime() + 30 * 60000);
  const f = (x) => x.toISOString().replace('.000Z', 'Z');
  return { start: f(d), end: f(e) };
};

(async () => {
  const slots = [];
  for (let i = 1; i <= 12; i++) slots.push({ id: 's' + i, provider: i <= 6 ? 'Dr Ade' : 'Dr Bola', ...future(i, 9) });
  slots.push({ id: 'past', provider: 'Dr Ade', start: '2020-01-01T09:00:00Z', end: '2020-01-01T09:30:00Z' });

  // Level 2: auth
  ok('401 without key', (await call('GET', '/slots', undefined, {}, null)).status === 401);
  ok('401 wrong key', (await call('GET', '/slots', undefined, {}, 'nope')).status === 401);
  ok('401 reset without key', (await call('POST', '/reset', { slots }, {}, null)).status === 401);
  const r401 = await call('GET', '/slots', undefined, {}, null);
  ok('401 body shape', typeof r401.json.error === 'string');

  // Level 1
  ok('reset 200', (await call('POST', '/reset', { slots })).status === 200);
  let r = await call('GET', '/slots');
  ok('list slots sorted, past first', r.status === 200 && r.json.slots[0].id === 'past' && r.json.slots.length === 13, r.json.slots && r.json.slots.map(s => s.id));
  ok('slot has fields + available', r.json.slots[1].available === true && r.json.slots[1].start.endsWith('Z'));
  r = await call('GET', '/slots?provider=Dr%20Bola');
  ok('provider filter', r.json.slots.length === 6 && r.json.slots.every(s => s.provider === 'Dr Bola'));

  r = await call('POST', '/bookings', { slot_id: 's1', name: '  Ada Obi ', email: '  ADA@Example.COM ' });
  ok('book 201', r.status === 201 && r.json.status === 'confirmed', r);
  ok('trimmed + lowercased', r.json.name === 'Ada Obi' && r.json.email === 'ada@example.com', r.json);
  const bookingId = r.json.id;
  r = await call('GET', '/bookings/' + bookingId);
  ok('get booking', r.status === 200 && r.json.id === bookingId && r.json.slot_id === 's1');
  ok('get missing booking 404', (await call('GET', '/bookings/nope')).status === 404);
  r = await call('GET', '/slots');
  ok('slot s1 unavailable', r.json.slots.find(s => s.id === 's1').available === false);

  // Level 2 validation
  const bad = [
    [{ name: 'A', email: 'a1@x.com' }, 'missing slot_id'],
    [{ slot_id: 's2', email: 'b2@x.com' }, 'missing name'],
    [{ slot_id: 's2', name: 'A' }, 'missing email'],
    [{ slot_id: '', name: 'A', email: 'c3@x.com' }, 'empty slot_id'],
    [{ slot_id: 's2', name: '   ', email: 'd4@x.com' }, 'blank name'],
    [{ slot_id: 's2', name: 'A', email: 'not-an-email' }, 'invalid email'],
    [{ slot_id: 's2', name: 'A', email: 'a@b' }, 'invalid email no tld'],
    [{ slot_id: 'past', name: 'A', email: 'e5@x.com' }, 'slot already started'],
  ];
  for (const [b, label] of bad) {
    r = await call('POST', '/bookings', b);
    ok('400 ' + label, r.status === 400 && typeof r.json.error === 'string', r);
  }
  r = await call('POST', '/bookings', { slot_id: 'zzz', name: 'A', email: 'f6@x.com' });
  ok('404 unknown slot', r.status === 404);
  r = await fetch(BASE + '/bookings', { method: 'POST', headers: { 'X-API-Key': KEY, 'Content-Type': 'application/json' }, body: '{oops' });
  ok('400 malformed JSON', r.status === 400);

  // Level 3: conflict + cancel + rebook
  r = await call('POST', '/bookings', { slot_id: 's1', name: 'Bob', email: 'bob@example.com' });
  ok('409 already booked', r.status === 409, r);
  r = await call('DELETE', '/bookings/' + bookingId);
  ok('cancel 200', r.status === 200 && r.json.status === 'cancelled', r);
  ok('cancel again 409', (await call('DELETE', '/bookings/' + bookingId)).status === 409);
  ok('cancel unknown 404', (await call('DELETE', '/bookings/nope')).status === 404);
  r = await call('POST', '/bookings', { slot_id: 's1', name: 'Bob', email: 'bob@example.com' });
  ok('rebook cancelled slot 201', r.status === 201, r);

  // Level 3: concurrency, 40 people at once for one slot
  const conc = await Promise.all(Array.from({ length: 40 }, (_, i) =>
    call('POST', '/bookings', { slot_id: 's2', name: 'P' + i, email: `race${i}@example.com` })));
  const wins = conc.filter(x => x.status === 201).length;
  const conflicts = conc.filter(x => x.status === 409).length;
  ok('exactly 1 winner of 40 concurrent', wins === 1 && conflicts === 39, { wins, conflicts, other: conc.map(x => x.status).filter(s => s !== 201 && s !== 409) });

  // Level 3: concurrency, same person many slots at same time is rate limited but not broken
  // Level 4: idempotency
  const body = { slot_id: 's3', name: 'Ida', email: 'ida@example.com' };
  const k = 'key-' + Math.random();
  const a = await call('POST', '/bookings', body, { 'Idempotency-Key': k });
  const b = await call('POST', '/bookings', body, { 'Idempotency-Key': k });
  ok('idempotent replay same id + status', a.status === 201 && b.status === 201 && a.json.id === b.json.id, { a, b });
  ok('idempotent replay identical body', JSON.stringify(a.json) === JSON.stringify(b.json));
  const diff = await call('POST', '/bookings', { ...body, name: 'Other' }, { 'Idempotency-Key': k });
  ok('same key different body 422', diff.status === 422, diff);
  const sameDiffOrder = await call('POST', '/bookings', { email: 'ida@example.com', name: 'Ida', slot_id: 's3' }, { 'Idempotency-Key': k });
  ok('same body, different key order still replays', sameDiffOrder.status === 201 && sameDiffOrder.json.id === a.json.id, sameDiffOrder);
  // concurrent same key
  const k2 = 'key2-' + Math.random();
  const body2 = { slot_id: 's4', name: 'Joy', email: 'joy@example.com' };
  const same = await Promise.all(Array.from({ length: 12 }, () => call('POST', '/bookings', body2, { 'Idempotency-Key': k2 })));
  const ids = new Set(same.map(x => x.json && x.json.id));
  ok('12 concurrent same-key requests -> one booking', same.every(x => x.status === 201) && ids.size === 1, same.map(x => x.status));
  r = await call('GET', '/bookings?email=joy@example.com');
  ok('only one booking stored for that key', r.json.bookings.length === 1, r.json);

  // Level 4: pagination
  const pe = 'pager@example.com';
  for (let i = 5; i <= 12; i++) {
    const x = await call('POST', '/bookings', { slot_id: 's' + i, name: 'Pager', email: pe });
    if (x.status !== 201) console.log('setup pager booking failed', i, x);
    if (i === 9) await new Promise(r => setTimeout(r, 61000)); // stay under the per-minute limit
  }
  let all = [], cursor = null, pages = 0;
  do {
    const q = '/bookings?email=PAGER@example.com&limit=3' + (cursor ? '&cursor=' + encodeURIComponent(cursor) : '');
    const p = await call('GET', q);
    if (p.status !== 200) { ok('page ok', false, p); break; }
    all.push(...p.json.bookings); cursor = p.json.next_cursor; pages++;
  } while (cursor && pages < 10);
  ok('paged through 8 bookings in 3 pages', all.length === 8 && pages === 3, { n: all.length, pages });
  ok('oldest first, no duplicates', new Set(all.map(x => x.id)).size === 8 && all.every((x, i) => i === 0 || all[i - 1].created_at <= x.created_at));
  r = await call('GET', '/bookings?email=nobody@example.com');
  ok('empty page', r.status === 200 && r.json.bookings.length === 0 && r.json.next_cursor === null);
  for (const l of ['0', '51', 'abc', '-1', '2.5']) {
    ok('400 limit=' + l, (await call('GET', '/bookings?email=pager@example.com&limit=' + l)).status === 400);
  }
  r = await call('GET', '/bookings?email=pager@example.com&limit=50');
  ok('limit=50 ok, last page next_cursor null', r.status === 200 && r.json.next_cursor === null);

  // Level 5: rate limit (fresh state)
  await call('POST', '/reset', { slots });
  const spam = [];
  for (let i = 0; i < 6; i++) spam.push(await call('POST', '/bookings', { slot_id: 'zzz', name: 'S', email: 'Spam@Example.com' }));
  ok('first 5 attempts are processed (404s)', spam.slice(0, 5).every(x => x.status === 404), spam.map(x => x.status));
  ok('6th attempt 429', spam[5].status === 429, spam[5]);
  const ra = spam[5].headers.get('Retry-After');
  ok('Retry-After is whole seconds 1..60', /^\d+$/.test(ra) && +ra >= 1 && +ra <= 60, ra);
  r = await call('POST', '/bookings', { slot_id: 's1', name: 'Other', email: 'other@example.com' });
  ok('other email unaffected', r.status === 201);
  r = await call('POST', '/bookings', { slot_id: 's5', name: 'S', email: ' SPAM@example.com ' });
  ok('case/space variants share the limit', r.status === 429);
  // concurrent burst
  const burst = await Promise.all(Array.from({ length: 12 }, () => call('POST', '/bookings', { slot_id: 'zzz', name: 'B', email: 'burst@example.com' })));
  ok('concurrent burst: exactly 5 processed, 7 limited', burst.filter(x => x.status === 404).length === 5 && burst.filter(x => x.status === 429).length === 7, burst.map(x => x.status));

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})();
