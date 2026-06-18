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

    const messageId = `<${Date.now()}.${Math.random().toString(36).slice(2)}@kisukutitents.co.ke>`;
    const body = [
      `From: ${from}`,
      `To: ${to}`,
      `Subject: ${subject}`,
      `Message-ID: ${messageId}`,
      'MIME-Version: 1.0',
      'Content-Type: text/html; charset=UTF-8',
      '',
      html || text || '',
    ].join('\r\n');

    const commands = [];
    let cmdIndex = 0;
    let socket;

    function nextCommand(line) {
      const code = parseInt(line.slice(0, 3));
      if (code >= 400) return reject(new Error(`SMTP error: ${line}`));
      if (cmdIndex < commands.length) {
        const cmd = commands[cmdIndex++];
        socket.write(cmd + '\r\n');
      }
    }

    function buildCommands() {
      commands.push(`EHLO kisukutitents.co.ke`);
      if (!secure) commands.push('STARTTLS');
      commands.push(`AUTH LOGIN`);
      commands.push(Buffer.from(user).toString('base64'));
      commands.push(Buffer.from(pass).toString('base64'));
      commands.push(`MAIL FROM:<${user}>`);
      commands.push(`RCPT TO:<${to}>`);
      commands.push('DATA');
      commands.push(body + '\r\n.');
      commands.push('QUIT');
    }
    buildCommands();

    const onConnect = (sock) => {
      socket = sock;
      socket.setTimeout(15000);
      socket.on('timeout', () => { socket.destroy(); reject(new Error('SMTP connection timed out')); });
      socket.on('error', reject);

      let buffer = '';
      socket.on('data', (chunk) => {
        buffer += chunk.toString();
        const lines = buffer.split('\r\n').filter(Boolean);
        const last  = lines[lines.length - 1];
        if (!last) return;

        // Handle STARTTLS upgrade
        if (last.startsWith('220') && cmdIndex === 1 && !secure) {
          buffer = '';
          socket.write('STARTTLS\r\n');
          cmdIndex++;
          return;
        }
        if (last.startsWith('220') && commands[cmdIndex - 1] === 'STARTTLS') {
          buffer = '';
          const tlsSocket = tls.connect({ socket, servername: host, rejectUnauthorized: true }, () => {
            socket = tlsSocket;
            tlsSocket.write(`EHLO kisukutitents.co.ke\r\n`);
            tlsSocket.on('data', handleTLSData);
          });
          return;
        }
        buffer = '';
        nextCommand(last);
        if (last.startsWith('250') && commands[cmdIndex - 1]?.startsWith('.')) {
          resolve({ messageId });
        }
      });

      function handleTLSData(chunk) {
        const line = chunk.toString().split('\r\n').filter(Boolean).pop();
        if (!line) return;
        const code = parseInt(line.slice(0, 3));
        if (code >= 400) return reject(new Error(`SMTP error: ${line}`));
        nextCommand(line);
        if (line.startsWith('250') && cmdIndex >= commands.length) {
          resolve({ messageId });
        }
      }
    };

    if (secure) {
      onConnect(tls.connect({ host, port, rejectUnauthorized: true }));
    } else {
      onConnect(net.connect({ host, port }));
    }
  });
}

module.exports = { sendEmail };
