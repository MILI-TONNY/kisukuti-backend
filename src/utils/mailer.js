'use strict';
/**
 * mailer.js — Sends transactional email via the Resend HTTPS API.
 *
 * Why Resend instead of raw SMTP: Render's free tier blocks ALL outbound
 * traffic on SMTP ports 25/465/587 (a platform-wide anti-spam policy since
 * Sept 2025), so any SMTP-based mailer simply cannot connect from a free
 * Render service no matter how correct the SMTP logic is. Resend's API runs
 * over plain HTTPS (port 443), which is never blocked, and it has a
 * permanent free tier (100 emails/day, 3,000/month) — more than enough for
 * registration/OTP/booking emails on a small business site.
 *
 * Uses only Node's built-in https module — no SDK/npm dependency required.
 */
const https  = require('https');
const logger = require('./logger');

async function sendEmail({ to, subject, html, text }) {
  const apiKey = process.env.RESEND_API_KEY;

  // Dev mode / not configured yet: log instead of sending, so local testing
  // and a misconfigured deploy never silently lose the OTP code — it's always
  // visible somewhere.
  if (process.env.NODE_ENV !== 'production' || !apiKey) {
    logger.info(`📧 EMAIL (dev mode — not sent):
  To: ${to}
  Subject: ${subject}
  Body preview: ${(html || text || '').replace(/<[^>]*>/g, '').slice(0, 300)}`);
    return { messageId: `dev-${Date.now()}` };
  }

  const from = process.env.EMAIL_FROM || 'Kisukuti Tents <onboarding@resend.dev>';

  const payload = JSON.stringify({
    from,
    to: [to],
    subject,
    html: html || undefined,
    text: text || undefined,
  });

  try {
    const result = await postJSON({
      hostname: 'api.resend.com',
      path: '/emails',
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload),
      },
    }, payload);

    if (result.statusCode >= 400) {
      const errMsg = result.body?.message || result.body?.name || JSON.stringify(result.body);
      throw new Error(`Resend API error (${result.statusCode}): ${errMsg}`);
    }

    logger.info(`Email sent to ${to}: ${result.body?.id || 'no-id'}`);
    return { messageId: result.body?.id };
  } catch (err) {
    logger.error(`Email failed to ${to}: ${err.message}`);
    throw err;
  }
}

/** Minimal HTTPS POST + JSON-parse helper using only Node built-ins. */
function postJSON({ hostname, path, headers }, body) {
  return new Promise((resolve, reject) => {
    const req = https.request(
      { hostname, path, method: 'POST', headers },
      (res) => {
        let data = '';
        res.on('data', (chunk) => { data += chunk; });
        res.on('end', () => {
          let parsed;
          try { parsed = data ? JSON.parse(data) : {}; }
          catch { parsed = { raw: data }; }
          resolve({ statusCode: res.statusCode, body: parsed });
        });
      }
    );
    req.on('error', reject);
    req.setTimeout(15000, () => { req.destroy(); reject(new Error('Resend API request timed out')); });
    req.write(body);
    req.end();
  });
}

module.exports = { sendEmail };
