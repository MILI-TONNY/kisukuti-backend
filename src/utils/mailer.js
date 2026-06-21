'use strict';
/**
 * mailer.js — Simple SMTP client using Node built-in net/tls.
 * In production: swap for nodemailer, AWS SES, or SendGrid.
 */
const logger = require('./logger');

async function sendEmail({ to, subject, html, text }) {
  // In development: just log the email
  if (process.env.NODE_ENV !== 'production' || !process.env.SMTP_HOST) {
    logger.info(`📧 EMAIL (dev mode — not sent):
  To: ${to}
  Subject: ${subject}
  Body preview: ${(html || text || '').replace(/<[^>]*>/g, '').slice(0, 120)}...`);
    return { messageId: `dev-${Date.now()}` };
  }

  // Production: send via raw SMTP using Node built-in net/tls (no nodemailer needed)
  try {
    const info = await sendViaSMTP({ to, subject, html, text });
    logger.info(`Email sent to ${to}: ${info.messageId}`);
    return info;
  } catch (err) {
    logger.error(`Email failed to ${to}: ${err.message}`);
    throw err;
  }
}

/**
 * Minimal SMTP client using Node's built-in net/tls modules.
 * Supports STARTTLS (port 587) and implicit TLS (port 465) with AUTH LOGIN.
 *
 * This is a proper line-buffered state machine: SMTP responses can span
 * multiple lines (e.g. Gmail's EHLO reply lists ~8 capabilities as
 * "250-STARTTLS\r\n250-AUTH LOGIN PLAIN\r\n...250 SMTPUTF8\r\n"), and only
 * the FINAL line of a multi-line reply has a space after the 3-digit code
 * (250 vs 250-). We must wait for that final line before sending the next
 * command, and we advance through named states rather than inferring
 * position from a command index, since a single state can correspond to
 * several mail commands.
 *
 * For high-volume production use, consider nodemailer or a transactional
 * email API (SES/SendGrid/Postmark) instead — this is intentionally minimal.
 */
function sendViaSMTP({ to, subject, html, text }) {
  const net = require('net');
  const tls = require('tls');

  return new Promise((resolve, reject) => {
    const host   = process.env.SMTP_HOST;
    const port   = parseInt(process.env.SMTP_PORT || '587');
    const secure = process.env.SMTP_SECURE === 'true' || port === 465;
    const user   = process.env.SMTP_USER;
    const pass   = process.env.SMTP_PASS;
    const from   = process.env.EMAIL_FROM || `"Kisukuti Tents" <${user}>`;

    if (!host || !user || !pass) {
      return reject(new Error('SMTP not configured (missing SMTP_HOST/SMTP_USER/SMTP_PASS)'));
    }

    const messageId = `<${Date.now()}.${Math.random().toString(36).slice(2)}@kisukutitents.co.ke>`;
    const body = [
      `From: ${from}`,
      `To: ${to}`,
      `Subject: ${subject}`,
      `Message-ID: ${messageId}`,
      'MIME-Version: 1.0',
      'Content-Type: text/html; charset=UTF-8',
      '',
      (html || text || '').replace(/^\.\s*$/gm, '..'), // escape lone "." lines per SMTP DATA rules
      '',
    ].join('\r\n');

    // ── Named states, advanced explicitly — not inferred from a counter ──
    const STATES = ['CONNECT', 'EHLO', 'STARTTLS', 'EHLO2', 'AUTH_LOGIN', 'AUTH_USER', 'AUTH_PASS', 'MAIL_FROM', 'RCPT_TO', 'DATA', 'BODY', 'QUIT', 'DONE'];
    let state = secure ? 'EHLO' : 'CONNECT';

    let socket;
    let buffer = '';
    let settled = false;

    const finish = (err, result) => {
      if (settled) return;
      settled = true;
      try { socket?.end(); } catch {}
      if (err) reject(err); else resolve(result);
    };

    const timeoutHandle = setTimeout(() => finish(new Error('SMTP connection timed out')), 20000);
    const clearAndFinish = (err, result) => { clearTimeout(timeoutHandle); finish(err, result); };

    function send(line) {
      socket.write(line + '\r\n');
    }

    /** Called once we have one or more complete, COMPLETE (final-line) SMTP replies in `buffer`. */
    function handleReply(replyLines) {
      const last = replyLines[replyLines.length - 1];
      const code = parseInt(last.slice(0, 3), 10);

      if (code >= 400) {
        return clearAndFinish(new Error(`SMTP error in state ${state}: ${last}`));
      }

      switch (state) {
        case 'CONNECT': // initial 220 banner
          state = 'EHLO';
          send(`EHLO kisukutitents.co.ke`);
          break;

        case 'EHLO': // reply to EHLO (plaintext, pre-STARTTLS) or EHLO over implicit TLS
          if (secure) {
            state = 'AUTH_LOGIN';
            send('AUTH LOGIN');
          } else {
            state = 'STARTTLS';
            send('STARTTLS');
          }
          break;

        case 'STARTTLS': // reply to STARTTLS command — now upgrade the socket
          upgradeToTLS();
          break;

        case 'EHLO2': // reply to the EHLO sent again after the TLS upgrade
          state = 'AUTH_LOGIN';
          send('AUTH LOGIN');
          break;

        case 'AUTH_LOGIN': // server asks for username (base64)
          state = 'AUTH_USER';
          send(Buffer.from(user).toString('base64'));
          break;

        case 'AUTH_USER': // server asks for password (base64)
          state = 'AUTH_PASS';
          send(Buffer.from(pass).toString('base64'));
          break;

        case 'AUTH_PASS': // authenticated
          state = 'MAIL_FROM';
          send(`MAIL FROM:<${user}>`);
          break;

        case 'MAIL_FROM':
          state = 'RCPT_TO';
          send(`RCPT TO:<${to}>`);
          break;

        case 'RCPT_TO':
          state = 'DATA';
          send('DATA');
          break;

        case 'DATA': // 354 "start mail input" — send headers+body, end with bare "."
          state = 'BODY';
          send(body + '\r\n.');
          break;

        case 'BODY': // message accepted
          state = 'QUIT';
          send('QUIT');
          break;

        case 'QUIT':
          state = 'DONE';
          clearAndFinish(null, { messageId });
          break;

        default:
          clearAndFinish(new Error(`Unexpected SMTP state: ${state}`));
      }
    }

    function upgradeToTLS() {
      const plainSocket = socket;
      plainSocket.removeAllListeners('data');
      const tlsSocket = tls.connect({ socket: plainSocket, servername: host, rejectUnauthorized: true }, () => {
        socket = tlsSocket;
        buffer = '';
        state = 'EHLO2';
        attachDataHandler(tlsSocket);
        send(`EHLO kisukutitents.co.ke`);
      });
      tlsSocket.on('error', (e) => clearAndFinish(new Error(`TLS upgrade failed: ${e.message}`)));
    }

    function attachDataHandler(sock) {
      sock.on('data', (chunk) => {
        buffer += chunk.toString('utf8');

        // SMTP multi-line replies: lines look like "250-foo\r\n...\r\n250 bar\r\n".
        // Only the LAST line of a complete reply has a space (not '-') after the code.
        // Wait until we have at least one fully-terminated line set ending in "code SPACE".
        if (!buffer.includes('\r\n')) return; // wait for more data

        const lines = buffer.split('\r\n').filter(Boolean);
        const last  = lines[lines.length - 1];
        // If the last line is "250-..." (continuation), the reply isn't finished yet — keep buffering.
        if (/^\d{3}-/.test(last)) return;
        // Must look like a real status line "NNN ..." to proceed.
        if (!/^\d{3}([ ].*)?$/.test(last)) return;

        buffer = '';
        handleReply(lines);
      });
    }

    // ── Kick off the connection ──────────────────────────────────────────
    if (secure) {
      socket = tls.connect({ host, port, rejectUnauthorized: true });
      socket.on('secureConnect', () => attachDataHandler(socket));
    } else {
      socket = net.connect({ host, port });
      attachDataHandler(socket);
    }
    socket.on('error', (e) => clearAndFinish(new Error(`SMTP connection error: ${e.message}`)));
  });
}

module.exports = { sendEmail };
