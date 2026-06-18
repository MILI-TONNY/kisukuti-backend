'use strict';
/**
 * auth.js middleware — JWT authentication + role-based authorization + CSRF.
 */

const { jwt, csrf } = require('../utils/security');
const db             = require('../config/database');

// ─── Extract Bearer token from Authorization header ──────────────────────────
function extractToken(req) {
  const auth = req.headers['authorization'];
  if (auth && auth.startsWith('Bearer ')) return auth.slice(7);
  return null;
}

// ─── Authenticate ───────────────────────────────────────────────────────────
/**
 * Verifies the JWT access token and attaches user to req.user.
 * Also checks that the user still exists and is still active.
 */
function authenticate(req, res, next) {
  try {
    const token = extractToken(req);
    if (!token) return sendUnauthorized(res, 'Authentication required. Please log in.');

    let payload;
    try {
      payload = jwt.verifyAccess(token);
    } catch (err) {
      if (err.message === 'Token expired') {
        return sendUnauthorized(res, 'Session expired. Please log in again.', 'TOKEN_EXPIRED');
      }
      return sendUnauthorized(res, 'Invalid or tampered token.');
    }

    if (payload.type !== 'access') {
      return sendUnauthorized(res, 'Invalid token type.');
    }

    // Confirm user still exists and is active
    const user = db.users.findById(payload.sub);
    if (!user)            return sendUnauthorized(res, 'User account not found.');
    if (!user.isActive)   return sendUnauthorized(res, 'Your account has been suspended. Contact support.');
    if (user.lockedUntil && new Date(user.lockedUntil) > new Date()) {
      return sendUnauthorized(res, 'Account temporarily locked due to too many failed login attempts.');
    }

    // Attach safe user object (never expose passwordHash)
    req.user = {
      id:        user.id,
      email:     user.email,
      name:      user.name,
      role:      user.role,
      phone:     user.phone,
      isVerified: user.isVerified,
    };

    next();
  } catch (err) {
    next(err);
  }
}

// ─── Optional authentication (doesn't fail if no token) ─────────────────────
function optionalAuth(req, res, next) {
  const token = extractToken(req);
  if (!token) return next();

  try {
    const payload = jwt.verifyAccess(token);
    const user    = db.users.findById(payload.sub);
    if (user && user.isActive) {
      req.user = { id: user.id, email: user.email, name: user.name, role: user.role };
    }
  } catch {
    // Silently ignore invalid tokens for optional auth
  }
  next();
}

// ─── Role-based authorization ────────────────────────────────────────────────
/**
 * Usage: authorize('admin') or authorize('admin', 'manager')
 */
function authorize(...roles) {
  return (req, res, next) => {
    if (!req.user) return sendUnauthorized(res, 'Authentication required.');
    if (!roles.includes(req.user.role)) {
      return sendForbidden(res, `Access denied. Required role: ${roles.join(' or ')}.`);
    }
    next();
  };
}

// ─── CSRF Protection ─────────────────────────────────────────────────────────
/**
 * Validates X-CSRF-Token header against the token stored in the signed cookie.
 * Apply to all state-changing routes (POST, PUT, PATCH, DELETE).
 */
function csrfProtect(req, res, next) {
  // Skip CSRF for API clients that use Bearer tokens (they're not CSRF-vulnerable)
  // Only enforce for cookie-based sessions
  if (extractToken(req)) return next();

  // Skip for safe methods
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();

  // Skip for webhook callbacks (verified by signature instead)
  if (req.path.startsWith('/api/webhooks')) return next();

  const provided = req.headers['x-csrf-token'];
  const stored   = req.signedCookies?.csrfToken;

  if (!csrf.verify(provided, stored)) {
    return res.status(403).json({
      success: false,
      error: 'CSRF token validation failed. Please refresh the page and try again.',
    });
  }
  next();
}

// ─── Ownership guard ─────────────────────────────────────────────────────────
/**
 * Ensures a user can only access their own resources unless they're an admin.
 * Usage: ownerOrAdmin('userId') where 'userId' is the req.params key.
 */
function ownerOrAdmin(paramKey = 'userId') {
  return (req, res, next) => {
    if (!req.user) return sendUnauthorized(res, 'Authentication required.');
    if (req.user.role === 'admin') return next();
    if (req.params[paramKey] === req.user.id) return next();
    return sendForbidden(res, 'You can only access your own resources.');
  };
}

// ─── Verified email guard ────────────────────────────────────────────────────
function requireVerified(req, res, next) {
  if (!req.user) return sendUnauthorized(res, 'Authentication required.');
  if (!req.user.isVerified) {
    return res.status(403).json({
      success: false,
      error: 'Please verify your email address before performing this action.',
      code: 'EMAIL_NOT_VERIFIED',
    });
  }
  next();
}

// ─── Helpers ─────────────────────────────────────────────────────────────────
function sendUnauthorized(res, message, code = 'UNAUTHORIZED') {
  return res.status(401).json({ success: false, error: message, code });
}
function sendForbidden(res, message) {
  return res.status(403).json({ success: false, error: message, code: 'FORBIDDEN' });
}

module.exports = { authenticate, optionalAuth, authorize, csrfProtect, ownerOrAdmin, requireVerified };
