'use strict';
/**
 * logger.js — Structured logger using only Node built-in fs/path.
 * Writes JSON log lines to ./logs/ and also streams to stdout.
 */
const fs   = require('fs');
const path = require('path');

const LOG_DIR = path.join(__dirname, '../../logs');
if (!fs.existsSync(LOG_DIR)) fs.mkdirSync(LOG_DIR, { recursive: true });

const LEVELS = { error: 0, warn: 1, info: 2, http: 3, debug: 4 };
const ENV_LEVEL = LEVELS[process.env.LOG_LEVEL] ?? (process.env.NODE_ENV === 'production' ? 2 : 4);

const COLORS = { error: '\x1b[31m', warn: '\x1b[33m', info: '\x1b[32m', http: '\x1b[36m', debug: '\x1b[90m', reset: '\x1b[0m' };

function write(level, message, meta = {}) {
  if (LEVELS[level] > ENV_LEVEL) return;

  const entry = {
    timestamp: new Date().toISOString(),
    level,
    message: typeof message === 'object' ? JSON.stringify(message) : message,
    ...meta,
  };

  // Colorized console output
  const color = COLORS[level] || '';
  console.log(`${color}[${entry.timestamp}] [${level.toUpperCase()}] ${entry.message}${COLORS.reset}`);

  // Append to daily log file
  try {
    const date = entry.timestamp.split('T')[0];
    const logFile = path.join(LOG_DIR, `${date}-${level === 'error' ? 'error' : 'combined'}.log`);
    fs.appendFileSync(logFile, JSON.stringify(entry) + '\n');
  } catch { /* Don't crash the server if logging fails */ }
}

const logger = {
  error: (msg, meta) => write('error', msg, meta),
  warn:  (msg, meta) => write('warn',  msg, meta),
  info:  (msg, meta) => write('info',  msg, meta),
  http:  (msg, meta) => write('http',  msg, meta),
  debug: (msg, meta) => write('debug', msg, meta),
};

function createLogger(module) {
  return {
    error: (msg, meta) => write('error', msg, { module, ...meta }),
    warn:  (msg, meta) => write('warn',  msg, { module, ...meta }),
    info:  (msg, meta) => write('info',  msg, { module, ...meta }),
    http:  (msg, meta) => write('http',  msg, { module, ...meta }),
    debug: (msg, meta) => write('debug', msg, { module, ...meta }),
  };
}

module.exports = { ...logger, createLogger };
