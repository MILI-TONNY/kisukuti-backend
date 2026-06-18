'use strict';
/**
 * validate.js — Request body/param validation using pure JS.
 * All sanitization runs through security.js utilities.
 */

const { sanitize } = require('../utils/security');

// ─── Validation rule sets ────────────────────────────────────────────────────
const rules = {

  register: {
    name:     { required: true, minLen: 2, maxLen: 80,  type: 'string',  label: 'Full name' },
    email:    { required: true, maxLen: 255, type: 'email',  label: 'Email' },
    password: { required: true, type: 'password', label: 'Password' },
    phone:    { required: true, type: 'phone',   label: 'Phone number' },
  },

  login: {
    email:    { required: true, type: 'email',  label: 'Email' },
    password: { required: true, minLen: 1, maxLen: 128, label: 'Password' },
  },

  forgotPassword: {
    email: { required: true, type: 'email', label: 'Email' },
  },

  resetPassword: {
    token:    { required: true, type: 'hex', label: 'Reset token' },
    password: { required: true, type: 'password', label: 'Password' },
  },

  changePassword: {
    currentPassword: { required: true, minLen: 1, maxLen: 128, label: 'Current password' },
    newPassword:     { required: true, type: 'password', label: 'New password' },
  },

  booking: {
    name:       { required: true, minLen: 2, maxLen: 100, label: 'Full name' },
    email:      { required: false, type: 'email', label: 'Email' },
    phone:      { required: true, type: 'phone', label: 'Phone number' },
    service:    { required: true, enum: ['wedding','birthday','meeting','dinner','traditional','custom'], label: 'Service' },
    eventDate:  { required: true, type: 'futureDate', label: 'Event date' },
    guests:     { required: false, type: 'string', maxLen: 50, label: 'Guest count' },
    venue:      { required: false, maxLen: 200, label: 'Venue' },
    notes:      { required: false, maxLen: 1000, label: 'Notes' },
  },

  initiatePayment: {
    bookingId: { required: true, type: 'uuid', label: 'Booking ID' },
    phone:     { required: true, type: 'phone', label: 'M-Pesa phone number' },
    method:    { required: true, enum: ['mpesa', 'card', 'bank'], label: 'Payment method' },
  },

  updateProfile: {
    name:  { required: false, minLen: 2, maxLen: 80, label: 'Full name' },
    phone: { required: false, type: 'phone', label: 'Phone number' },
  },
};

// ─── Validate function ───────────────────────────────────────────────────────
function validate(ruleName) {
  return (req, res, next) => {
    const schema = rules[ruleName];
    if (!schema) return next();

    const errors = [];
    const cleaned = {};
    const body = req.body || {};

    for (const [field, rule] of Object.entries(schema)) {
      let value = body[field];

      // ── Required check ────────────────────────────────────────────────
      if (rule.required && (value === undefined || value === null || value === '')) {
        errors.push({ field, message: `${rule.label || field} is required` });
        continue;
      }
      if (!rule.required && (value === undefined || value === null || value === '')) {
        cleaned[field] = value || undefined;
        continue;
      }

      // ── Type-specific validation ───────────────────────────────────────
      try {
        switch (rule.type) {
          case 'email':
            cleaned[field] = sanitize.email(value);
            break;

          case 'phone':
            cleaned[field] = sanitize.phone(String(value));
            break;

          case 'password':
            // Don't sanitize passwords — validate only, pass raw
            if (typeof value !== 'string') throw new Error(`${rule.label} must be a string`);
            if (value.length < 8)  throw new Error(`${rule.label} must be at least 8 characters`);
            if (value.length > 128) throw new Error(`${rule.label} is too long`);
            cleaned[field] = value; // Raw — bcrypt/scrypt handles it
            break;

          case 'uuid':
            if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value)) {
              throw new Error(`${rule.label || field} is not a valid ID`);
            }
            cleaned[field] = value;
            break;

          case 'hex':
            if (!/^[0-9a-f]+$/i.test(value)) throw new Error(`${rule.label} is invalid`);
            cleaned[field] = value;
            break;

          case 'futureDate': {
            const d = new Date(value);
            if (isNaN(d.getTime())) throw new Error(`${rule.label} is not a valid date`);
            if (d < new Date()) throw new Error(`${rule.label} must be in the future`);
            cleaned[field] = d.toISOString().split('T')[0];
            break;
          }

          default:
            if (typeof value !== 'string') throw new Error(`${rule.label || field} must be text`);
            if (rule.enum && !rule.enum.includes(value)) {
              throw new Error(`${rule.label || field} must be one of: ${rule.enum.join(', ')}`);
            }
            if (rule.minLen && value.length < rule.minLen) {
              throw new Error(`${rule.label || field} must be at least ${rule.minLen} characters`);
            }
            if (rule.maxLen && value.length > rule.maxLen) {
              throw new Error(`${rule.label || field} must not exceed ${rule.maxLen} characters`);
            }
            cleaned[field] = sanitize.html(sanitize.sql(value));
        }
      } catch (err) {
        errors.push({ field, message: err.message });
      }
    }

    if (errors.length) {
      return res.status(422).json({
        success: false,
        error: 'Validation failed',
        errors,
      });
    }

    // Replace req.body with sanitized version
    req.body = { ...body, ...cleaned };
    next();
  };
}

module.exports = { validate, rules };
