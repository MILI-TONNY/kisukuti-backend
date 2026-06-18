'use strict';
/**
 * envLoader.js — Minimal .env file loader using only Node built-in fs.
 * Replaces the 'dotenv' package so this backend has ZERO npm dependencies.
 * Usage: require('./utils/envLoader').load();
 */
const fs   = require('fs');
const path = require('path');

function load(envPath) {
  const filePath = envPath || path.join(__dirname, '../../.env');
  if (!fs.existsSync(filePath)) return;

  const content = fs.readFileSync(filePath, 'utf8');
  content.split('\n').forEach(line => {
    line = line.trim();
    if (!line || line.startsWith('#')) return;

    const eqIdx = line.indexOf('=');
    if (eqIdx === -1) return;

    const key = line.slice(0, eqIdx).trim();
    let value = line.slice(eqIdx + 1).trim();

    // Strip surrounding quotes
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }

    // Don't overwrite existing environment variables (allows CLI overrides)
    if (!(key in process.env)) {
      process.env[key] = value;
    }
  });
}

module.exports = { load };
