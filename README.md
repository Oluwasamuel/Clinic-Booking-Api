# Clinic Booking API

REST API + simple web page for booking clinic appointment slots (Koya Cohort 4, Task 1).
Node.js, Express, PostgreSQL. Implements all five levels of the spec.

## How each level is handled

| Level | Approach |
|---|---|
| 1 | `GET /slots`, `POST /bookings`, `GET /bookings/:id`, `POST /reset` |
| 2 | `X-API-Key` middleware on every API route (401). Validation: required/trimmed fields, email format, lowercase email, 404 unknown slot, 400 slot already started |
| 3 | A **partial unique index** (`one confirmed booking per slot_id`) lets the database reject double bookings, so it holds under concurrency. Cancel sets `status=cancelled`, which frees the slot |
| 4 | `Idempotency-Key`: a transaction-level advisory lock per key serialises concurrent retries; the first response is stored and replayed (same body, same booking id). Same key + different body returns 422. Pagination uses an opaque cursor over a monotonic sequence |
| 5 | Sliding-window limit of 5 attempts per email per 60 s, stored in Postgres (safe across instances), `429` + whole-second `Retry-After`. Failed attempts count; idempotent replays do not |

## Run locally

```bash
npm install
export DATABASE_URL=postgres://user:pass@localhost:5432/clinic
export API_KEY=choose-a-long-random-string
npm start
# in another terminal (this calls /reset and wipes data):
BASE=http://localhost:3000 KEY=$API_KEY node test/check.js
```

## Deploy (Neon + Render)

1. Create a Neon project and copy its connection string.
2. On Render: New > Web Service > this repo. Build command `npm install`, start command `npm start`.
3. Environment variables: `DATABASE_URL`, `API_KEY`.
4. Open the Render URL for the web page. The API lives on the same URL.

The web page is served at `/` and calls the API with the key embedded at serve time.
