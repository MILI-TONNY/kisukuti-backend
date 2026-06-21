'use strict';
/**
 * rateLimiter.js — In-memory rate limiting using only Node built-ins.
 * Implements token bucket algorithm per IP + endpoint.
 * Replace with Redis-backed rate limiter in multi-server production.
 */

// ─── In-memory stores ───────────────────────────────────────────────────────
const requestStore = new Map(); // ip → { count, resetTime }
const lockoutStore = new Map(); // ip → lockoutUntil

// ─── Cleanup expired entries every 5 minutes ─────────────────────────────────
setInterval(() => {
  const now = Date.now();
  for (const [key, val] of requestStore.entries()) {
    if (val.resetTime < now) requestStore.delete(key);
  }
  for (const [key, until] of lockoutStore.entries()) {
    if (until < now) lockoutStore.delete(key);
  }
}, 5 * 60 * 1000);

/**
 * Create a rate limiter middleware.
 * @param {object} opts
 * @param {number} opts.windowMs   - Time window in ms
 * @param {number} opts.max        - Max requests per window
 * @param {string} opts.message    - Error message
 * @param {boolean} opts.skipSuccessful - Don't count successful responses
 */
function createLimiter({ windowMs = 900000, max = 100, message = 'Too many requests, please try again later.', keyPrefix = 'general', skipSuccessful = false } = {}) {
  return function rateLimiter(req, res, next) {
    const ip  = getClientIP(req);
    const key = `${keyPrefix}:${ip}`;
    const now = Date.now();

    // ── Check hard lockout ────────────────────────────────────────────────
    const lockedUntil = lockoutStore.get(key);
    if (lockedUntil && lockedUntil > now) {
      const retryAfter = Math.ceil((lockedUntil - now) / 1000);
      res.setHeader('Retry-After', retryAfter);
      res.setHeader('X-RateLimit-Limit', max);
      res.setHeader('X-RateLimit-Remaining', 0);
      return sendError(res, 429, `Account temporarily locked. Try again in ${retryAfter} seconds.`);
    }

    // ── Get or init window ────────────────────────────────────────────────
    let entry = requestStore.get(key);
    if (!entry || entry.resetTime <= now) {
      entry = { count: 0, resetTime: now + windowMs };
      requestStore.set(key, entry);
    }

    entry.count++;

    res.setHeader('X-RateLimit-Limit', max);
    res.setHeader('X-RateLimit-Remaining', Math.max(0, max - entry.count));
    res.setHeader('X-RateLimit-Reset', Math.ceil(entry.resetTime / 1000));

    if (entry.count > max) {
      // Escalate to hard lockout after 3× the limit
      if (entry.count >= max * 3) {
        lockoutStore.set(key, now + windowMs * 2);
      }
      const retryAfter = Math.ceil((entry.resetTime - now) / 1000);
      res.setHeader('Retry-After', retryAfter);
      return sendError(res, 429, message);
    }

    if (skipSuccessful) {
      // Intercept response to uncount successful requests
      const originalEnd = res.end.bind(res);
      res.end = (...args) => {
        if (res.statusCode < 400) entry.count--;
        return originalEnd(...args);
      };
    }

    next();
  };
}

// ─── Specific limiters ───────────────────────────────────────────────────────
const generalLimiter = createLimiter({
  windowMs: 15 * 60 * 1000,  // 15 min
  max: 200,
  message: 'Too many requests from this IP. Please wait 15 minutes.',
  keyPrefix: 'general',
});

const authLimiter = createLimiter({
  windowMs: 15 * 60 * 1000,  // 15 min
  max: 5,                     // Only 5 login attempts per 15 min
  message: 'Too many login attempts. Your IP has been blocked for 15 minutes.',
  keyPrefix: 'auth',
});

const adminGateLimiter = createLimiter({
  windowMs: 30 * 60 * 1000,  // 30 min
  max: 5,                     // Only 5 passphrase/admin-login attempts per 30 min — deliberately tight
  message: 'Too many attempts. Try again later.',
  keyPrefix: 'admin_gate',
});

const registerLimiter = createLimiter({
  windowMs: 60 * 60 * 1000,  // 1 hour
  max: 3,                     // Max 3 registrations per hour per IP
  message: 'Too many account registrations from this IP.',
  keyPrefix: 'register',
});

const passwordResetLimiter = createLimiter({
  windowMs: 60 * 60 * 1000,  // 1 hour
  max: 3,
  message: 'Too many password reset requests. Please wait 1 hour.',
  keyPrefix: 'pwreset',
});

const paymentLimiter = createLimiter({
  windowMs: 60 * 60 * 1000,  // 1 hour
  max: 10,                    // Max 10 payment attempts per hour
  message: 'Too many payment attempts. Please contact support.',
  keyPrefix: 'payment',
});

const bookingLimiter = createLimiter({
  windowMs: 60 * 60 * 1000,  // 1 hour
  max: 20,
  message: 'Too many booking requests from this IP.',
  keyPrefix: 'booking',
});

// ─── Helpers ────────────────────────────────────────────────────────────────
function getClientIP(req) {
  return (
    req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
    req.headers['x-real-ip'] ||
    req.socket?.remoteAddress ||
    '0.0.0.0'
  );
}

function sendError(res, status, message) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json');
  res.end(JSON.stringify({ success: false, error: message, statusCode: status }));
}

module.exports = {
  generalLimiter,
  authLimiter,
  registerLimiter,
  passwordResetLimiter,
  paymentLimiter,
  bookingLimiter,
  adminGateLimiter,
  createLimiter,
};
