'use strict';
/**
 * security.js — All cryptographic operations using Node built-in crypto ONLY.
 * • Password hashing: scrypt (memory-hard, resistant to GPU/ASIC attacks)
 * • JWT: manual HMAC-SHA256 implementation (no jsonwebtoken package needed)
 * • CSRF tokens: cryptographically random
 * • Input sanitization: XSS & SQL injection stripping
 */

const crypto = require('crypto');

// ─── CONFIG ─────────────────────────────────────────────────────────────────
const SCRYPT_N      = 32768;  // CPU/memory cost (2^15)
const SCRYPT_R      = 8;      // Block size
const SCRYPT_P      = 1;      // Parallelization
const KEY_LEN       = 64;     // Output key length in bytes
const SALT_LEN      = 32;     // Salt length in bytes

const ACCESS_SECRET  = process.env.JWT_ACCESS_SECRET  || crypto.randomBytes(64).toString('hex');
const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || crypto.randomBytes(64).toString('hex');
const ACCESS_TTL     = parseInt(process.env.JWT_ACCESS_TTL  || '900');    // 15 minutes
const REFRESH_TTL    = parseInt(process.env.JWT_REFRESH_TTL || '604800'); // 7 days

// ─── PASSWORD HASHING ───────────────────────────────────────────────────────
const password = {
  /**
   * Hash a password using scrypt with a random salt.
   * Returns "salt:hash" as a hex string.
   */
  async hash(plaintext) {
    validatePasswordStrength(plaintext); // Throws if too weak
    const salt = crypto.randomBytes(SALT_LEN);
    return new Promise((resolve, reject) => {
      const maxmem = 128 * SCRYPT_N * SCRYPT_R * 2; // Sufficient headroom for N=32768,r=8
      crypto.scrypt(plaintext, salt, KEY_LEN, { N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P, maxmem }, (err, hash) => {
        if (err) return reject(err);
        resolve(`${salt.toString('hex')}:${hash.toString('hex')}`);
      });
    });
  },

  /**
   * Verify a password against its stored hash.
   * Uses timingSafeEqual to prevent timing attacks.
   */
  async verify(plaintext, stored) {
    const [saltHex, hashHex] = stored.split(':');
    if (!saltHex || !hashHex) return false;
    const salt    = Buffer.from(saltHex, 'hex');
    const storedHash = Buffer.from(hashHex, 'hex');
    const maxmem = 128 * SCRYPT_N * SCRYPT_R * 2;
    return new Promise((resolve, reject) => {
      crypto.scrypt(plaintext, salt, KEY_LEN, { N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P, maxmem }, (err, hash) => {
        if (err) return reject(err);
        try {
          resolve(crypto.timingSafeEqual(hash, storedHash));
        } catch {
          resolve(false);
        }
      });
    });
  },
};

// ─── PASSWORD STRENGTH VALIDATION ───────────────────────────────────────────
function validatePasswordStrength(pwd) {
  const errors = [];
  if (pwd.length < 8)                        errors.push('at least 8 characters');
  if (!/[A-Z]/.test(pwd))                    errors.push('one uppercase letter');
  if (!/[a-z]/.test(pwd))                    errors.push('one lowercase letter');
  if (!/[0-9]/.test(pwd))                    errors.push('one number');
  if (!/[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]/.test(pwd)) errors.push('one special character');
  if (errors.length) {
    const err = new Error(`Password must contain: ${errors.join(', ')}`);
    err.statusCode = 422;
    throw err;
  }
}

// ─── JWT (manual HMAC-SHA256 — no external package) ─────────────────────────
const b64url = {
  encode: (buf) => Buffer.from(buf).toString('base64url'),
  decode: (str) => Buffer.from(str, 'base64url'),
};

const jwt = {
  sign(payload, secret, ttlSeconds) {
    const header  = b64url.encode(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
    const now     = Math.floor(Date.now() / 1000);
    const body    = b64url.encode(JSON.stringify({
      ...payload,
      iat: now,
      exp: now + ttlSeconds,
      jti: crypto.randomBytes(16).toString('hex'), // Unique token ID
    }));
    const sig = crypto.createHmac('sha256', secret)
      .update(`${header}.${body}`)
      .digest('base64url');
    return `${header}.${body}.${sig}`;
  },

  verify(token, secret) {
    if (!token || typeof token !== 'string') throw new Error('Missing token');
    const parts = token.split('.');
    if (parts.length !== 3) throw new Error('Malformed token');
    const [header, body, sig] = parts;

    // Verify signature (timing-safe)
    const expectedSig = crypto.createHmac('sha256', secret)
      .update(`${header}.${body}`)
      .digest('base64url');
    const sigBuf = Buffer.from(sig, 'base64url');
    const expBuf = Buffer.from(expectedSig, 'base64url');
    if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
      throw new Error('Invalid signature');
    }

    // Decode and check expiry
    let payload;
    try { payload = JSON.parse(b64url.decode(body).toString()); }
    catch { throw new Error('Malformed payload'); }

    if (payload.exp < Math.floor(Date.now() / 1000)) {
      throw new Error('Token expired');
    }
    return payload;
  },

  /** Generate access + refresh token pair */
  generatePair(userId, role, email) {
    const access  = jwt.sign({ sub: userId, role, email, type: 'access' },  ACCESS_SECRET,  ACCESS_TTL);
    const refresh = jwt.sign({ sub: userId, role, email, type: 'refresh' }, REFRESH_SECRET, REFRESH_TTL);
    return { access, refresh, expiresIn: ACCESS_TTL };
  },

  verifyAccess(token)  { return jwt.verify(token, ACCESS_SECRET); },
  verifyRefresh(token) { return jwt.verify(token, REFRESH_SECRET); },

  /** Hash a refresh token for storage (don't store raw tokens) */
  hashRefreshToken(token) {
    return crypto.createHash('sha256').update(token).digest('hex');
  },
};

// ─── CSRF TOKENS ────────────────────────────────────────────────────────────
const csrf = {
  generate() {
    return crypto.randomBytes(32).toString('hex');
  },
  verify(provided, stored) {
    if (!provided || !stored) return false;
    try {
      return crypto.timingSafeEqual(
        Buffer.from(provided, 'hex'),
        Buffer.from(stored,   'hex')
      );
    } catch {
      return false;
    }
  },
};

// ─── ADMIN GATE (passphrase wall in front of the staff login) ───────────────
const adminGate = {
  /**
   * Timing-safe check of the supplied passphrase against ADMIN_GATE_PASSPHRASE.
   * The env var is never sent to the client and never logged.
   */
  verifyPassphrase(provided) {
    const expected = process.env.ADMIN_GATE_PASSPHRASE;
    if (!expected) return false; // Misconfigured server — fail closed, not open
    if (!provided || typeof provided !== 'string') return false;
    const a = Buffer.from(provided.padEnd(128, '\0'));
    const b = Buffer.from(expected.padEnd(128, '\0'));
    try {
      return a.length === b.length && crypto.timingSafeEqual(a, b) && provided === expected;
    } catch {
      return false;
    }
  },

  /** Short-lived (10 min) signed token proving the passphrase was correct. */
  issueGateToken() {
    return jwt.sign({ type: 'admin_gate' }, process.env.ADMIN_GATE_SECRET || process.env.JWT_ACCESS_SECRET, 600);
  },

  verifyGateToken(token) {
    try {
      const payload = jwt.verify(token, process.env.ADMIN_GATE_SECRET || process.env.JWT_ACCESS_SECRET);
      return payload.type === 'admin_gate';
    } catch {
      return false;
    }
  },
};

// ─── INPUT SANITIZATION ─────────────────────────────────────────────────────
const sanitize = {
  /** Strip HTML tags and dangerous characters */
  html(str) {
    if (typeof str !== 'string') return str;
    return str
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;')
      .replace(/\//g, '&#x2F;')
      .trim();
  },

  /** Strip SQL injection patterns */
  sql(str) {
    if (typeof str !== 'string') return str;
    const sqlPatterns = /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION|SCRIPT)\b|--|;|\/\*|\*\/|xp_)/gi;
    return str.replace(sqlPatterns, '').trim();
  },

  /** Sanitize an entire object recursively */
  object(obj) {
    if (typeof obj !== 'object' || obj === null) return obj;
    const clean = {};
    for (const [k, v] of Object.entries(obj)) {
      if (typeof v === 'string') {
        clean[k] = sanitize.sql(sanitize.html(v));
      } else if (typeof v === 'object') {
        clean[k] = sanitize.object(v);
      } else {
        clean[k] = v;
      }
    }
    return clean;
  },

  /** Validate and normalize Kenyan phone number → 2547XXXXXXXX or 2541XXXXXXXX */
  phone(phone) {
    const cleaned = phone.replace(/\D/g, '');
    // 07XXXXXXXX or 01XXXXXXXX (10 digits, starting 07 or 01)
    if (/^0[17]\d{8}$/.test(cleaned))  return '254' + cleaned.slice(1);
    // Already in 2547XXXXXXXX or 2541XXXXXXXX format (12 digits)
    if (/^254[17]\d{8}$/.test(cleaned)) return cleaned;
    // Bare 7XXXXXXXX or 1XXXXXXXX (9 digits, no leading 0)
    if (/^[17]\d{8}$/.test(cleaned))    return '254' + cleaned;
    throw Object.assign(new Error('Invalid Kenyan phone number. Use format 07XXXXXXXX or 01XXXXXXXX'), { statusCode: 422 });
  },

  /** Validate email format */
  email(email) {
    const re = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/;
    if (!re.test(email)) throw Object.assign(new Error('Invalid email address'), { statusCode: 422 });
    return email.toLowerCase().trim();
  },
};

// ─── RANDOM TOKEN GENERATION ────────────────────────────────────────────────
// ─── ONE-TIME PASSCODE (OTP) FOR LOGIN ──────────────────────────────────────
const otp = {
  /** Generate a 6-digit numeric OTP using a cryptographically secure RNG */
  generate() {
    // crypto.randomInt is rejection-sampled, so this is uniformly distributed
    return crypto.randomInt(100000, 999999).toString();
  },
  /** Hash an OTP for storage (never store the raw code) */
  hash(code) {
    return crypto.createHash('sha256').update(code).digest('hex');
  },
  /** Timing-safe OTP comparison */
  verify(provided, storedHash) {
    if (!provided || !storedHash) return false;
    const providedHash = otp.hash(provided);
    try {
      return crypto.timingSafeEqual(Buffer.from(providedHash, 'hex'), Buffer.from(storedHash, 'hex'));
    } catch {
      return false;
    }
  },
};

const tokens = {
  /** Generate a cryptographically random reset/verify token */
  generate(bytes = 32) {
    return crypto.randomBytes(bytes).toString('hex');
  },
  /** Hash a token for storage */
  hash(token) {
    return crypto.createHash('sha256').update(token).digest('hex');
  },
};

// ─── M-PESA SIGNATURE VERIFICATION ─────────────────────────────────────────
const mpesa = {
  /** Verify Safaricom callback signature */
  verifyCallbackSignature(body, receivedSig, secret) {
    const expected = crypto.createHmac('sha256', secret)
      .update(JSON.stringify(body))
      .digest('hex');
    try {
      return crypto.timingSafeEqual(
        Buffer.from(receivedSig, 'hex'),
        Buffer.from(expected,    'hex')
      );
    } catch {
      return false;
    }
  },

  /** Generate LipaNaMpesa password (base64 of shortcode+passkey+timestamp) */
  generatePassword(shortcode, passkey, timestamp) {
    return Buffer.from(`${shortcode}${passkey}${timestamp}`).toString('base64');
  },

  /** Get current timestamp in YYYYMMDDHHMMSS format */
  timestamp() {
    return new Date().toISOString().replace(/[-T:.Z]/g, '').slice(0, 14);
  },
};

module.exports = { password, jwt, csrf, sanitize, tokens, mpesa, otp, adminGate, validatePasswordStrength };
