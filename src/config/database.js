'use strict';
/**
 * database.js — File-based JSON database using Node built-ins only.
 * In production swap for PostgreSQL/MySQL using the pg or mysql2 npm package.
 * All writes are atomic (write-to-temp + rename).
 */

const fs   = require('fs');
const path = require('path');
const crypto = require('crypto');

const DB_DIR  = path.join(__dirname, '../../data');
const DB_FILE = path.join(DB_DIR, 'kisukuti.json');

// ─── Default schema ─────────────────────────────────────────────────────────
const DEFAULT_DB = {
  users:            [],
  bookings:         [],
  payments:         [],
  refresh_tokens:   [],
  password_resets:  [],
  audit_logs:       [],
  failed_logins:    [],
};

// ─── Ensure data directory and file exist ───────────────────────────────────
function initDB() {
  if (!fs.existsSync(DB_DIR)) fs.mkdirSync(DB_DIR, { recursive: true });
  if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(DB_FILE, JSON.stringify(DEFAULT_DB, null, 2), 'utf8');
  }
}

// ─── Read entire DB ─────────────────────────────────────────────────────────
function readDB() {
  try {
    return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
  } catch {
    return { ...DEFAULT_DB };
  }
}

// ─── Atomic write (temp file + rename prevents corruption) ──────────────────
function writeDB(data) {
  const tmp = DB_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2), 'utf8');
  fs.renameSync(tmp, DB_FILE);
}

// ─── Generic CRUD helpers ───────────────────────────────────────────────────
const db = {
  init: initDB,

  // ── USERS ──────────────────────────────────────────────────────────────
  users: {
    findById(id) {
      return readDB().users.find(u => u.id === id) || null;
    },
    findByEmail(email) {
      return readDB().users.find(u => u.email.toLowerCase() === email.toLowerCase()) || null;
    },
    create(userData) {
      const store = readDB();
      const user = {
        id:           crypto.randomUUID(),
        ...userData,
        createdAt:    new Date().toISOString(),
        updatedAt:    new Date().toISOString(),
        isVerified:   false,
        isActive:     true,
        role:         userData.role || 'client',
        loginAttempts: 0,
        lockedUntil:  null,
      };
      store.users.push(user);
      writeDB(store);
      return user;
    },
    update(id, updates) {
      const store = readDB();
      const idx = store.users.findIndex(u => u.id === id);
      if (idx === -1) return null;
      store.users[idx] = { ...store.users[idx], ...updates, updatedAt: new Date().toISOString() };
      writeDB(store);
      return store.users[idx];
    },
    delete(id) {
      const store = readDB();
      store.users = store.users.filter(u => u.id !== id);
      writeDB(store);
    },
    findAll() {
      return readDB().users;
    },
  },

  // ── BOOKINGS ────────────────────────────────────────────────────────────
  bookings: {
    findById(id) {
      return readDB().bookings.find(b => b.id === id) || null;
    },
    findByUser(userId) {
      return readDB().bookings.filter(b => b.userId === userId);
    },
    create(data) {
      const store = readDB();
      const booking = {
        id:          crypto.randomUUID(),
        bookingRef:  'KT-' + Date.now().toString(36).toUpperCase(),
        ...data,
        status:      'pending',
        createdAt:   new Date().toISOString(),
        updatedAt:   new Date().toISOString(),
      };
      store.bookings.push(booking);
      writeDB(store);
      return booking;
    },
    update(id, updates) {
      const store = readDB();
      const idx = store.bookings.findIndex(b => b.id === id);
      if (idx === -1) return null;
      store.bookings[idx] = { ...store.bookings[idx], ...updates, updatedAt: new Date().toISOString() };
      writeDB(store);
      return store.bookings[idx];
    },
    findAll(filters = {}) {
      let bookings = readDB().bookings;
      if (filters.status) bookings = bookings.filter(b => b.status === filters.status);
      if (filters.service) bookings = bookings.filter(b => b.service === filters.service);
      return bookings.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    },
  },

  // ── PAYMENTS ────────────────────────────────────────────────────────────
  payments: {
    findById(id) {
      return readDB().payments.find(p => p.id === id) || null;
    },
    findByBooking(bookingId) {
      return readDB().payments.filter(p => p.bookingId === bookingId);
    },
    findByCheckoutId(checkoutRequestId) {
      return readDB().payments.find(p => p.checkoutRequestId === checkoutRequestId) || null;
    },
    create(data) {
      const store = readDB();
      const payment = {
        id:        crypto.randomUUID(),
        payRef:    'PAY-' + crypto.randomBytes(4).toString('hex').toUpperCase(),
        ...data,
        status:    'pending',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };
      store.payments.push(payment);
      writeDB(store);
      return payment;
    },
    update(id, updates) {
      const store = readDB();
      const idx = store.payments.findIndex(p => p.id === id);
      if (idx === -1) return null;
      store.payments[idx] = { ...store.payments[idx], ...updates, updatedAt: new Date().toISOString() };
      writeDB(store);
      return store.payments[idx];
    },
  },

  // ── REFRESH TOKENS ──────────────────────────────────────────────────────
  refreshTokens: {
    save(userId, tokenHash, expiresAt) {
      const store = readDB();
      // Remove old tokens for this user (keep max 5 sessions)
      const userTokens = store.refresh_tokens.filter(t => t.userId === userId);
      if (userTokens.length >= 5) {
        const oldest = userTokens.sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt))[0];
        store.refresh_tokens = store.refresh_tokens.filter(t => t.id !== oldest.id);
      }
      store.refresh_tokens.push({
        id: crypto.randomUUID(), userId, tokenHash, expiresAt,
        createdAt: new Date().toISOString(),
      });
      writeDB(store);
    },
    find(tokenHash) {
      return readDB().refresh_tokens.find(t => t.tokenHash === tokenHash) || null;
    },
    delete(tokenHash) {
      const store = readDB();
      store.refresh_tokens = store.refresh_tokens.filter(t => t.tokenHash !== tokenHash);
      writeDB(store);
    },
    deleteAllForUser(userId) {
      const store = readDB();
      store.refresh_tokens = store.refresh_tokens.filter(t => t.userId !== userId);
      writeDB(store);
    },
    cleanup() {
      const store = readDB();
      const now = new Date();
      store.refresh_tokens = store.refresh_tokens.filter(t => new Date(t.expiresAt) > now);
      writeDB(store);
    },
  },

  // ── PASSWORD RESETS ─────────────────────────────────────────────────────
  passwordResets: {
    create(userId, tokenHash, expiresAt) {
      const store = readDB();
      // Remove existing reset for this user
      store.password_resets = store.password_resets.filter(r => r.userId !== userId);
      store.password_resets.push({
        id: crypto.randomUUID(), userId, tokenHash, expiresAt,
        createdAt: new Date().toISOString(), used: false,
      });
      writeDB(store);
    },
    find(tokenHash) {
      return readDB().password_resets.find(r => r.tokenHash === tokenHash && !r.used) || null;
    },
    markUsed(id) {
      const store = readDB();
      const idx = store.password_resets.findIndex(r => r.id === id);
      if (idx !== -1) { store.password_resets[idx].used = true; writeDB(store); }
    },
  },

  // ── AUDIT LOGS ──────────────────────────────────────────────────────────
  audit: {
    log(action, userId, meta = {}) {
      const store = readDB();
      store.audit_logs.push({
        id: crypto.randomUUID(), action, userId,
        ip: meta.ip || 'unknown',
        userAgent: meta.userAgent || '',
        meta: JSON.stringify(meta),
        timestamp: new Date().toISOString(),
      });
      // Keep last 10,000 audit logs
      if (store.audit_logs.length > 10000) store.audit_logs = store.audit_logs.slice(-10000);
      writeDB(store);
    },
    recent(limit = 100) {
      return readDB().audit_logs.slice(-limit).reverse();
    },
  },

  // ── FAILED LOGINS (brute-force tracking) ────────────────────────────────
  failedLogins: {
    record(ip, email) {
      const store = readDB();
      const key = `${ip}:${email}`;
      const existing = store.failed_logins.find(f => f.key === key);
      if (existing) {
        existing.count++;
        existing.lastAttempt = new Date().toISOString();
      } else {
        store.failed_logins.push({
          key, ip, email, count: 1,
          firstAttempt: new Date().toISOString(),
          lastAttempt: new Date().toISOString(),
        });
      }
      writeDB(store);
    },
    get(ip, email) {
      return readDB().failed_logins.find(f => f.key === `${ip}:${email}`) || null;
    },
    reset(ip, email) {
      const store = readDB();
      store.failed_logins = store.failed_logins.filter(f => f.key !== `${ip}:${email}`);
      writeDB(store);
    },
    cleanup() {
      const store = readDB();
      const cutoff = new Date(Date.now() - 24 * 60 * 60 * 1000);
      store.failed_logins = store.failed_logins.filter(f => new Date(f.lastAttempt) > cutoff);
      writeDB(store);
    },
  },
};

module.exports = db;
