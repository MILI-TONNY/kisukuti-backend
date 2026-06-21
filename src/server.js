'use strict';
require('./utils/envLoader').load();

const http    = require('http');
const crypto  = require('crypto');
const path    = require('path');
const url     = require('url');
const zlib    = require('zlib');
const db      = require('./config/database');
const logger  = require('./utils/logger');
const { jwt, csrf, sanitize } = require('./utils/security');
const { generalLimiter, authLimiter, registerLimiter, passwordResetLimiter, paymentLimiter, bookingLimiter, adminGateLimiter } = require('./middleware/rateLimiter');
const authCtrl    = require('./controllers/authController');
const bookingCtrl = require('./controllers/bookingController');
const payCtrl     = require('./controllers/paymentController');
const { validate } = require('./middleware/validate');
const { authenticate, authorize, optionalAuth } = require('./middleware/auth');

// ── Init DB ────────────────────────────────────────────────────────────────
db.init();

// ── CORS config ────────────────────────────────────────────────────────────
const ALLOWED_ORIGINS = (process.env.FRONTEND_URL || 'http://localhost:3000,http://localhost:5500,http://127.0.0.1:5500').split(',');

// ── Security headers ────────────────────────────────────────────────────────
function setSecurityHeaders(res, origin) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'same-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self'; object-src 'none'; frame-src 'none'");
  if (process.env.NODE_ENV === 'production') {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  }
  if (origin && ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
  }
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization,X-Requested-With,X-CSRF-Token');
  res.setHeader('Access-Control-Expose-Headers', 'X-RateLimit-Limit,X-RateLimit-Remaining');
  res.setHeader('Access-Control-Max-Age', '86400');
}

// ── Cookie parser (simple, no package) ─────────────────────────────────────
function parseCookies(cookieStr = '') {
  const out = {};
  cookieStr.split(';').forEach(part => {
    const [k, ...v] = part.trim().split('=');
    if (k) out[k.trim()] = decodeURIComponent(v.join('=') || '');
  });
  return out;
}
function setCookie(res, name, value, opts = {}) {
  let cookie = `${name}=${encodeURIComponent(value)}`;
  if (opts.maxAge)   cookie += `; Max-Age=${opts.maxAge}`;
  if (opts.httpOnly) cookie += '; HttpOnly';
  if (opts.secure || process.env.NODE_ENV === 'production') cookie += '; Secure';
  if (opts.sameSite) cookie += `; SameSite=${opts.sameSite}`;
  if (opts.path)     cookie += `; Path=${opts.path}`;
  res.setHeader('Set-Cookie', cookie);
}
function clearCookie(res, name, path = '/') {
  res.setHeader('Set-Cookie', `${name}=; Max-Age=0; Path=${path}; HttpOnly; SameSite=Strict`);
}

// ── Body parser ─────────────────────────────────────────────────────────────
function readBody(req, maxBytes = 10240) {
  return new Promise((resolve, reject) => {
    let data = '';
    let size = 0;
    req.on('data', chunk => {
      size += chunk.length;
      if (size > maxBytes) {
        reject(Object.assign(new Error('Request body too large'), { statusCode: 413 }));
        req.destroy();
        return;
      }
      data += chunk;
    });
    req.on('end', () => {
      try {
        resolve(data ? JSON.parse(data) : {});
      } catch {
        reject(Object.assign(new Error('Invalid JSON body'), { statusCode: 400 }));
      }
    });
    req.on('error', reject);
  });
}

// ── Services list ────────────────────────────────────────────────────────────
const SERVICES = [
  { id:'wedding',name:'Wedding Ceremonies',price:45000,icon:'💒',badge:'Most Popular',depositPercent:30 },
  { id:'birthday',name:'Birthday Celebrations',price:18000,icon:'🎂',badge:'Fan Favourite',depositPercent:50 },
  { id:'meeting',name:'Corporate & Meetings',price:22000,icon:'🤝',badge:'Professional',depositPercent:50 },
  { id:'dinner',name:'Outdoor Dinner Events',price:35000,icon:'🍽️',badge:'Premium',depositPercent:30 },
  { id:'traditional',name:'Traditional Ceremonies',price:30000,icon:'🪢',badge:'Cultural',depositPercent:30 },
  { id:'custom',name:'Custom Bespoke Events',price:25000,icon:'✨',badge:'Bespoke',depositPercent:30 },
];

// ── Send JSON response ──────────────────────────────────────────────────────
function send(res, status, body) {
  const json = JSON.stringify(body);
  res.writeHead(status, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(json) });
  res.end(json);
}

// ── Get client IP ───────────────────────────────────────────────────────────
function getIP(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket?.remoteAddress || 'unknown';
}

// ── Router ──────────────────────────────────────────────────────────────────
const routes = [];
function addRoute(method, pattern, ...handlers) {
  routes.push({ method: method.toUpperCase(), pattern, handlers });
}

function matchRoute(method, pathname) {
  for (const route of routes) {
    if (route.method !== method && route.method !== 'ALL') continue;
    const keys = [];
    const regexStr = route.pattern.replace(/:([^/]+)/g, (_, k) => { keys.push(k); return '([^/]+)'; });
    const match = pathname.match(new RegExp(`^${regexStr}$`));
    if (match) {
      const params = {};
      keys.forEach((k, i) => params[k] = match[i + 1]);
      return { ...route, params };
    }
  }
  return null;
}

// ── Middleware runner (chain) ───────────────────────────────────────────────
async function runHandlers(handlers, req, res) {
  let i = 0;
  const next = async (err) => {
    if (err) throw err;
    if (i < handlers.length) {
      const handler = handlers[i++];
      // Middleware that call next
      if (handler.length >= 3) {
        await new Promise((resolve, reject) => {
          handler(req, res, (e) => e ? reject(e) : resolve());
        });
      } else {
        await handler(req, res);
      }
    }
  };
  // Run first handler
  if (handlers.length > 0) {
    const handler = handlers[i++];
    if (handler.length >= 3) {
      await new Promise((resolve, reject) => {
        handler(req, res, (e) => e ? reject(e) : resolve());
      });
      // Continue chain
      while (i < handlers.length && !res.writableEnded) {
        const h = handlers[i++];
        if (h.length >= 3) {
          await new Promise((resolve, reject) => {
            h(req, res, (e) => e ? reject(e) : resolve());
          });
        } else {
          await h(req, res);
        }
      }
    } else {
      await handler(req, res);
    }
  }
}

// ── HTTP Server ─────────────────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  const startTime = Date.now();
  const origin    = req.headers.origin || '';
  setSecurityHeaders(res, origin);

  // Parse URL
  const parsed   = url.parse(req.url, true);
  const pathname = parsed.pathname;
  const query    = parsed.query;

  // Parse cookies
  req.cookies = parseCookies(req.headers.cookie || '');
  req.signedCookies = req.cookies; // Simplified (use cookie-signature pkg for real HMAC signing)
  req.query = query;
  req.getIP = () => getIP(req);

  // ── Express-compatibility shim on `res` so controllers written for
  //    Express (res.json / res.status / res.cookie) work unchanged on
  //    the raw http.ServerResponse object. ──────────────────────────────
  res.status = function (code) { res.statusCode = code; return res; };
  res.json = function (body) {
    if (res.writableEnded) return res;
    const json = JSON.stringify(body);
    if (!res.headersSent) {
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Content-Length', Buffer.byteLength(json));
    }
    res.end(json);
    return res;
  };
  res.cookie = function (name, value, opts = {}) {
    const existing = res.getHeader('Set-Cookie');
    const cookies = existing ? (Array.isArray(existing) ? existing : [existing]) : [];
    let cookie = `${name}=${encodeURIComponent(value)}`;
    if (opts.maxAge)   cookie += `; Max-Age=${Math.floor(opts.maxAge / 1000)}`;
    if (opts.httpOnly) cookie += '; HttpOnly';
    if (opts.secure || process.env.NODE_ENV === 'production') cookie += '; Secure';
    if (opts.sameSite) cookie += `; SameSite=${opts.sameSite.charAt(0).toUpperCase()}${opts.sameSite.slice(1)}`;
    cookie += `; Path=${opts.path || '/'}`;
    cookies.push(cookie);
    res.setHeader('Set-Cookie', cookies);
    return res;
  };
  res.clearCookie = function (name, opts = {}) {
    return res.cookie(name, '', { ...opts, maxAge: 0 });
  };

  // CORS preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  // Parse body for mutating requests
  if (['POST','PUT','PATCH','DELETE'].includes(req.method)) {
    try {
      req.body = await readBody(req);
    } catch (err) {
      send(res, err.statusCode || 400, { success: false, error: err.message });
      return;
    }
  } else {
    req.body = {};
  }

  // ── ROUTES ────────────────────────────────────────────────────────────────

  // Health check
  if (pathname === '/health' && req.method === 'GET') {
    send(res, 200, { status:'healthy', uptime: process.uptime(), env: process.env.NODE_ENV, timestamp: new Date().toISOString() });
    return;
  }

  // CSRF token endpoint
  if (pathname === '/api/auth/csrf' && req.method === 'GET') {
    const csrfToken = csrf.generate();
    setCookie(res, 'csrfToken', csrfToken, { httpOnly: false, sameSite: 'Strict', path: '/', maxAge: 3600 });
    send(res, 200, { success: true, csrfToken });
    return;
  }

  // ── Auth routes ────────────────────────────────────────────────────────
  if (pathname === '/api/auth/register' && req.method === 'POST') {
    await safeRun(res, () => withMiddleware(req, res, [registerLimiter, validate('register')], () => authCtrl.register(req, res)));
  } else if (pathname === '/api/auth/login' && req.method === 'POST') {
    await safeRun(res, () => withMiddleware(req, res, [authLimiter, validate('login')], () => authCtrl.login(req, res)));
  } else if (pathname === '/api/auth/verify-otp' && req.method === 'POST') {
    await safeRun(res, () => withMiddleware(req, res, [authLimiter, validate('verifyOtp')], () => authCtrl.verifyLoginOtp(req, res)));
  } else if (pathname === '/api/auth/resend-otp' && req.method === 'POST') {
    await safeRun(res, () => withMiddleware(req, res, [passwordResetLimiter, validate('resendOtp')], () => authCtrl.resendLoginOtp(req, res)));
  } else if (pathname === '/api/admin/gate' && req.method === 'POST') {
    await safeRun(res, () => withMiddleware(req, res, [adminGateLimiter], () => authCtrl.adminGateCheck(req, res)));
  } else if (pathname === '/api/admin/login' && req.method === 'POST') {
    await safeRun(res, () => withMiddleware(req, res, [adminGateLimiter], () => authCtrl.adminLogin(req, res)));
  } else if (pathname === '/api/auth/refresh' && req.method === 'POST') {
    await safeRun(res, () => authCtrl.refreshToken(req, res));
  } else if (pathname === '/api/auth/logout' && req.method === 'POST') {
    await safeRun(res, () => withMiddleware(req, res, [authenticate], () => authCtrl.logout(req, res)));
  } else if (pathname === '/api/auth/logout-all' && req.method === 'POST') {
    await safeRun(res, () => withMiddleware(req, res, [authenticate], () => authCtrl.logoutAll(req, res)));
  } else if (pathname === '/api/auth/forgot-password' && req.method === 'POST') {
    await safeRun(res, () => withMiddleware(req, res, [passwordResetLimiter, validate('forgotPassword')], () => authCtrl.forgotPassword(req, res)));
  } else if (pathname === '/api/auth/reset-password' && req.method === 'POST') {
    await safeRun(res, () => withMiddleware(req, res, [passwordResetLimiter, validate('resetPassword')], () => authCtrl.resetPassword(req, res)));
  } else if (pathname === '/api/auth/change-password' && req.method === 'PATCH') {
    await safeRun(res, () => withMiddleware(req, res, [authenticate, validate('changePassword')], () => authCtrl.changePassword(req, res)));
  } else if (pathname === '/api/auth/me' && req.method === 'GET') {
    await safeRun(res, () => withMiddleware(req, res, [authenticate], () => authCtrl.me(req, res)));
  } else if (/^\/api\/auth\/verify\/([^/]+)\/([^/]+)$/.test(pathname) && req.method === 'GET') {
    const [, userId, token] = pathname.match(/^\/api\/auth\/verify\/([^/]+)\/([^/]+)$/);
    req.params = { userId, token };
    await safeRun(res, () => authCtrl.verifyEmail(req, res));

  // ── Booking routes ──────────────────────────────────────────────────────
  } else if (pathname === '/api/bookings' && req.method === 'POST') {
    await safeRun(res, () => withMiddleware(req, res, [bookingLimiter, optionalAuth, validate('booking')], () => bookingCtrl.createBooking(req, res)));
  } else if (pathname === '/api/bookings' && req.method === 'GET') {
    await safeRun(res, () => withMiddleware(req, res, [authenticate, authorize('admin')], () => bookingCtrl.getAllBookings(req, res)));
  } else if (pathname === '/api/bookings/my' && req.method === 'GET') {
    await safeRun(res, () => withMiddleware(req, res, [authenticate], () => bookingCtrl.getMyBookings(req, res)));
  } else if (/^\/api\/bookings\/([^/]+)$/.test(pathname) && req.method === 'GET') {
    req.params = { id: pathname.split('/').pop() };
    await safeRun(res, () => withMiddleware(req, res, [authenticate], () => bookingCtrl.getBooking(req, res)));
  } else if (/^\/api\/bookings\/([^/]+)\/cancel$/.test(pathname) && req.method === 'PATCH') {
    req.params = { id: pathname.split('/')[3] };
    await safeRun(res, () => withMiddleware(req, res, [authenticate], () => bookingCtrl.cancelBooking(req, res)));

  // ── Payment routes ──────────────────────────────────────────────────────
  } else if (pathname === '/api/payments/initiate' && req.method === 'POST') {
    await safeRun(res, () => withMiddleware(req, res, [paymentLimiter, optionalAuth, validate('initiatePayment')], () => payCtrl.initiatePayment(req, res)));
  } else if (pathname === '/api/payments/my' && req.method === 'GET') {
    await safeRun(res, () => withMiddleware(req, res, [authenticate], () => payCtrl.getUserPayments(req, res)));
  } else if (/^\/api\/payments\/([^/]+)\/status$/.test(pathname) && req.method === 'GET') {
    req.params = { paymentId: pathname.split('/')[3] };
    await safeRun(res, () => withMiddleware(req, res, [optionalAuth], () => payCtrl.queryMpesaStatus(req, res)));
  } else if (pathname === '/api/payments' && req.method === 'GET') {
    await safeRun(res, () => withMiddleware(req, res, [authenticate, authorize('admin')], () => payCtrl.getAllPayments(req, res)));

  // ── M-Pesa Webhook ──────────────────────────────────────────────────────
  } else if (pathname === '/api/webhooks/mpesa/callback' && req.method === 'POST') {
    await safeRun(res, () => payCtrl.mpesaCallback(req, res));

  // ── Services ────────────────────────────────────────────────────────────
  } else if (pathname === '/api/services' && req.method === 'GET') {
    send(res, 200, { success: true, data: SERVICES, total: SERVICES.length });
  } else if (/^\/api\/services\/([^/]+)$/.test(pathname) && req.method === 'GET') {
    const id = pathname.split('/').pop();
    const svc = SERVICES.find(s => s.id === id);
    if (!svc) send(res, 404, { success: false, error: 'Service not found.' });
    else send(res, 200, { success: true, data: svc });

  // ── Users ───────────────────────────────────────────────────────────────
  } else if (pathname === '/api/users/me' && req.method === 'GET') {
    await safeRun(res, () => withMiddleware(req, res, [authenticate], () => {
      const user = db.users.findById(req.user.id);
      if (!user) return send(res, 404, { success: false, error: 'Not found.' });
      const { passwordHash, emailVerifyToken, emailVerifyExpires, lockedUntil, loginAttempts, ...safe } = user;
      send(res, 200, { success: true, data: safe });
    }));
  } else if (pathname === '/api/users/me' && req.method === 'PATCH') {
    await safeRun(res, () => withMiddleware(req, res, [authenticate, validate('updateProfile')], () => {
      const updates = {};
      if (req.body.name) updates.name = req.body.name;
      if (req.body.phone) updates.phone = req.body.phone;
      const updated = db.users.update(req.user.id, updates);
      const { passwordHash, ...safe } = updated;
      send(res, 200, { success: true, data: safe });
    }));
  } else if (pathname === '/api/users' && req.method === 'GET') {
    await safeRun(res, () => withMiddleware(req, res, [authenticate, authorize('admin')], () => {
      const users = db.users.findAll().map(({ passwordHash, emailVerifyToken, ...u }) => u);
      send(res, 200, { success: true, data: users, total: users.length });
    }));
  } else if (pathname === '/api/users/audit-logs' && req.method === 'GET') {
    await safeRun(res, () => withMiddleware(req, res, [authenticate, authorize('admin')], () => {
      send(res, 200, { success: true, data: db.audit.recent(500) });
    }));
  } else if (pathname === '/api/users/login-history' && req.method === 'GET') {
    await safeRun(res, () => withMiddleware(req, res, [authenticate, authorize('admin')], () => {
      const logs  = db.audit.recent(2000).filter(l => l.action === 'LOGIN_SUCCESS' || l.action === 'LOGIN_FAILED' || l.action === 'LOGIN_BLOCKED_LOCKED');
      const users = db.users.findAll();
      const userById = Object.fromEntries(users.map(u => [u.id, u]));

      const history = logs.map(l => {
        const u = userById[l.userId];
        let meta = {};
        try { meta = JSON.parse(l.meta || '{}'); } catch {}
        return {
          event:     l.action,
          name:      u ? u.name : '(unknown — account may be deleted)',
          email:     u ? u.email : meta.email || '(unknown)',
          role:      u ? u.role : undefined,
          ip:        l.ip,
          userAgent: l.userAgent || undefined,
          timestamp: l.timestamp,
        };
      });

      send(res, 200, { success: true, data: history, total: history.length });
    }));
  } else if (pathname === '/api/users/online-sessions' && req.method === 'GET') {
    await safeRun(res, () => withMiddleware(req, res, [authenticate, authorize('admin')], () => {
      const fs = require('fs');
      const path = require('path');
      const dbFile = path.join(__dirname, '../data/kisukuti.json');
      const raw = fs.existsSync(dbFile) ? JSON.parse(fs.readFileSync(dbFile, 'utf8')) : { refresh_tokens: [] };
      const users = db.users.findAll();
      const userById = Object.fromEntries(users.map(u => [u.id, u]));
      const now = new Date();

      const sessions = raw.refresh_tokens
        .filter(t => new Date(t.expiresAt) > now)
        .map(t => {
          const u = userById[t.userId];
          return {
            name:      u ? u.name : '(unknown)',
            email:     u ? u.email : '(unknown)',
            sessionStartedAt: t.createdAt,
            expiresAt: t.expiresAt,
          };
        });

      send(res, 200, { success: true, data: sessions, total: sessions.length });
    }));

  // ── 404 ──────────────────────────────────────────────────────────────────
  } else {
    send(res, 404, { success: false, error: `Route ${req.method} ${pathname} not found`, statusCode: 404 });
  }

  // Log request
  const duration = Date.now() - startTime;
  logger.http(`${req.method} ${pathname} ${res.statusCode || 200} ${duration}ms`);
});

// ── safeRun — catches all errors ────────────────────────────────────────────
async function safeRun(res, fn) {
  try {
    await fn();
  } catch (err) {
    const status = err.statusCode || 500;
    if (status >= 500) logger.error('Server error:', err.stack || err.message);
    if (!res.writableEnded) {
      send(res, status, {
        success: false,
        error: status >= 500 && process.env.NODE_ENV === 'production'
          ? 'Internal server error. Our team has been notified.'
          : err.message,
        statusCode: status,
      });
    }
  }
}

// ── withMiddleware — runs an array of middleware then a final handler ───────
async function withMiddleware(req, res, middlewares, final) {
  for (const mw of middlewares) {
    if (res.writableEnded) return;
    await new Promise((resolve, reject) => {
      mw(req, res, (err) => err ? reject(err) : resolve());
    });
  }
  if (!res.writableEnded) await final();
}

// ── Start ───────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  logger.info(`🏕️  Kisukuti Tents API → http://localhost:${PORT}`);
  logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`);
  logger.info(`M-Pesa: ${process.env.MPESA_ENV || 'sandbox'} mode`);
});

// Cleanup every 30 min
setInterval(() => { db.refreshTokens.cleanup(); db.failedLogins.cleanup(); }, 30 * 60 * 1000);

process.on('SIGTERM', () => { server.close(() => { logger.info('Server shut down'); process.exit(0); }); });
process.on('SIGINT',  () => { server.close(() => { logger.info('Server shut down'); process.exit(0); }); });
process.on('uncaughtException',  (err) => { logger.error('Uncaught:', err); process.exit(1); });
process.on('unhandledRejection', (err) => { logger.error('Unhandled:', err); });

module.exports = server;
