# Kisukuti Tents — Backend API

A secure, **zero-dependency** Node.js backend for the Kisukuti Tents booking platform.
Built entirely on Node's built-in modules (`http`, `crypto`, `fs`) — no `npm install` required to run it.

## Quick Start

```bash
cd kisukuti-backend
cp .env.example .env
# Generate secrets and paste into .env:
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
# (run twice — once for JWT_ACCESS_SECRET, once for JWT_REFRESH_SECRET)

node src/server.js
# → 🏕️  Kisukuti Tents API running on http://localhost:5000
```

That's it. No `node_modules`, no build step. SQLite/Postgres can be swapped in later (see *Scaling* below) — out of the box it uses a transactional JSON file at `data/kisukuti.json`.

## Security Measures Implemented

### Authentication & Passwords
- **scrypt** password hashing (memory-hard, GPU/ASIC-resistant) — `N=32768, r=8, p=1`, 64-byte output, unique 32-byte salt per user
- **Timing-safe comparison** (`crypto.timingSafeEqual`) everywhere passwords/tokens are checked, including a dummy-hash path on login so response time doesn't leak whether an email exists
- **Password strength enforced server-side**: 8+ chars, upper+lower+number+special char
- **Account lockout**: 5 failed attempts → 15-minute lock, independent of rate limiting
- **Email enumeration prevention**: register/forgot-password return identical responses whether or not the email exists

### Tokens
- **JWT implemented from scratch** with Node's `crypto.createHmac('sha256', ...)` — no external JWT library, fully auditable
- **Short-lived access tokens** (15 min) + **long-lived refresh tokens** (7 days) with rotation
- Refresh tokens are **hashed (SHA-256) before storage** — the raw token is never persisted, so a database leak alone can't be used to forge sessions
- **Refresh token reuse detection**: if a rotated-out token is presented again, all sessions for that user are flagged and the attempt is audit-logged (signals token theft)
- Refresh tokens delivered via **HttpOnly + Secure + SameSite=Strict** cookies scoped to `/api/auth` — inaccessible to JavaScript/XSS
- "Logout everywhere" endpoint revokes all sessions (used automatically on password change)

### Transport & Headers
- `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `X-XSS-Protection`
- **Content-Security-Policy** restricting scripts/styles/frames to same-origin
- **HSTS** in production
- Strict **CORS allow-list** (only configured frontend origins; credentials only sent to whitelisted origins)
- Request body size capped (10 KB) to mitigate payload-based DoS

### Rate Limiting (in-memory token-bucket, per-IP)
| Endpoint | Limit |
|---|---|
| Login | 5 / 15 min, then temporary IP lockout |
| Register | 3 / hour |
| Forgot/reset password | 3 / hour |
| Payments | 10 / hour |
| Bookings | 20 / hour |
| General API | 200 / 15 min |

### Payments (M-Pesa Daraja STK Push)
- **Server-authoritative pricing** — the amount charged always comes from the server's service price table, never from the client request body, so a tampered `amount` field in the request is silently ignored
- **Idempotency guard**: a second payment attempt on a booking that already has a pending payment from the last 5 minutes is rejected (409), preventing duplicate STK pushes/double charges
- **Booking ownership check**: authenticated users can only pay for bookings linked to their own account
- **Callback signature/IP awareness**: M-Pesa webhook validated against Safaricom's published IP ranges in production
- Payment status transitions are **one-way** (`pending → completed` or `pending → failed`); a completed/failed payment can't be re-processed by a replayed callback
- Phone numbers normalized & validated to the `2547XXXXXXXX` format server-side before being sent to Safaricom

### Input Validation & Sanitization
- All request bodies pass through a schema validator (`src/middleware/validate.js`) — type checks, length limits, enums, regex for email/phone/UUID
- HTML-escaping and basic SQL-injection-pattern stripping applied to all free-text fields
- `express-mongo-sanitize`-style key sanitization concept applied manually (no NoSQL here, but the same prototype-pollution-prevention principle is used in the JSON datastore layer)

### Auditing
- Every security-relevant event (`LOGIN_SUCCESS`, `LOGIN_FAILED`, `PAYMENT_COMPLETED`, `REFRESH_TOKEN_REUSE_ATTEMPT`, `PASSWORD_CHANGED`, etc.) is written to an append-only audit log with IP, timestamp, and metadata — queryable by admins at `GET /api/users/audit-logs`

## API Reference

### Auth — `/api/auth`
| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/register` | — | Create account (rate-limited 3/hr) |
| POST | `/login` | — | Login, returns access token + sets refresh cookie (rate-limited 5/15min) |
| POST | `/refresh` | cookie | Rotate refresh token, get new access token |
| POST | `/logout` | ✓ | Revoke current session |
| POST | `/logout-all` | ✓ | Revoke all sessions |
| POST | `/forgot-password` | — | Request reset email (rate-limited 3/hr) |
| POST | `/reset-password` | — | Complete reset with token |
| PATCH | `/change-password` | ✓ | Change password (revokes other sessions) |
| GET | `/me` | ✓ | Current user profile |
| GET | `/verify/:userId/:token` | — | Verify email link |

### Bookings — `/api/bookings`
| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/` | optional | Create booking (guest or logged-in) |
| GET | `/my` | ✓ | My bookings |
| GET | `/:id` | ✓ (owner/admin) | Booking detail |
| PATCH | `/:id/cancel` | ✓ (owner/admin) | Cancel a pending booking |
| GET | `/` | ✓ admin | All bookings |

### Payments — `/api/payments`
| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/initiate` | optional | Start M-Pesa STK push / bank transfer |
| GET | `/my` | ✓ | My payment history |
| GET | `/:paymentId/status` | optional | Poll payment status (frontend uses this after STK push) |
| GET | `/` | ✓ admin | All payments |

### Webhooks — `/api/webhooks`
| Method | Path | Description |
|---|---|---|
| POST | `/mpesa/callback` | Safaricom calls this when the customer completes/cancels the STK prompt |

### Services — `/api/services`
| Method | Path | Description |
|---|---|---|
| GET | `/` | List all 6 packages with prices |
| GET | `/:id` | One package detail |

## Connecting the Frontend

In the React frontend, point API calls at this server and always send credentials so the refresh-token cookie works:

```js
fetch('http://localhost:5000/api/auth/login', {
  method: 'POST',
  credentials: 'include',          // sends/receives the HttpOnly cookie
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ email, password }),
})
  .then(r => r.json())
  .then(({ data }) => {
    localStorage.removeItem('token');     // never store access tokens in localStorage
    window.__accessToken = data.accessToken; // keep in memory only; refresh on reload via /api/auth/refresh
  });
```

For the payment flow: call `POST /api/payments/initiate` with `{ bookingId, phone, method }`, show the "check your phone" state, then poll `GET /api/payments/:paymentId/status` every 3–4 seconds until `status` becomes `completed` or `failed`.

## Scaling Beyond the JSON File Store

`src/config/database.js` exposes a small repository API (`db.users.*`, `db.bookings.*`, `db.payments.*`, …). To move to PostgreSQL/MySQL in production, reimplement each method in that file against your driver of choice — no controller code needs to change.

## M-Pesa Setup Checklist

1. Register at [developer.safaricom.co.ke](https://developer.safaricom.co.ke), create an app, copy the **Consumer Key/Secret**.
2. For sandbox testing use shortcode `174379` and the published sandbox passkey.
3. Set `MPESA_CALLBACK_URL` to a **publicly reachable HTTPS URL** (use ngrok in development) pointing to `/api/webhooks/mpesa/callback`.
4. Switch `MPESA_ENV=production` and use your real shortcode/passkey when going live.

## Project Structure

```
src/
  server.js              # HTTP server, router, security headers, Express-compat shim
  config/database.js     # Repository pattern over a JSON file datastore
  controllers/
    authController.js    # Register/login/refresh/reset/verify
    bookingController.js # Booking CRUD
    paymentController.js # M-Pesa STK push, callback, status polling
  middleware/
    auth.js               # JWT auth, role guards, CSRF, ownership checks
    rateLimiter.js         # In-memory rate limiting
    validate.js            # Request schema validation
  utils/
    security.js     # Password hashing, JWT, CSRF, sanitization, M-Pesa signing
    envLoader.js     # Minimal .env parser (no dotenv dependency)
    logger.js        # Structured file + console logging
    mailer.js        # Raw SMTP client (no nodemailer dependency) + dev console fallback
```
