import nodemailer from 'nodemailer';

/**
 * chatMailer.js — agent email notifications for the public website chat.
 * Suggested location:  controllers/chat/chatMailer.js
 *
 * ENV (all optional — with no SMTP config, notifications are silently skipped
 * and agents rely on the dashboard "Needs reply" badge instead):
 *   SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS
 *   AGENT_NOTIFY_EMAILS   comma-separated list of agent inboxes
 */

const mailer =
  process.env.SMTP_HOST && process.env.SMTP_USER
    ? nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port: Number(process.env.SMTP_PORT || 587),
        secure: Number(process.env.SMTP_PORT) === 465,
        auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
      })
    : null;

/**
 * Notify human agents that a visitor is waiting. Fire-and-forget: never
 * throws — a failed notification must not break the visitor's chat.
 *
 * @param {object} conversation  Full DB row (visitor_name, visitor_phone, ...)
 * @param {string} questionText  The visitor's message text
 */
export const notifyAgents = async (conversation, questionText) => {
  try {
    if (!mailer || !process.env.AGENT_NOTIFY_EMAILS) return;

    const recipients = process.env.AGENT_NOTIFY_EMAILS.split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    if (recipients.length === 0) return;

    await mailer.sendMail({
      from: `"Umrah Market Chat" <${process.env.SMTP_USER}>`,
      to: recipients.join(','),
      subject: `New chat message from ${conversation.visitor_name}`,
      html: `
        <div style="font-family:Arial,sans-serif;max-width:520px">
          <h2 style="color:#16a34a;margin-bottom:4px">New website chat message</h2>
          <p style="margin:2px 0"><strong>Visitor:</strong> ${conversation.visitor_name}</p>
          <p style="margin:2px 0"><strong>Phone:</strong> ${conversation.visitor_phone}</p>
          <p style="margin:2px 0"><strong>Email:</strong> ${conversation.visitor_email}</p>
          ${conversation.page_url ? `<p style="margin:2px 0"><strong>Page:</strong> ${conversation.page_url}</p>` : ''}
          <div style="background:#f3f4f6;border-radius:8px;padding:12px;margin:12px 0">
            ${String(questionText).replace(/</g, '&lt;')}
          </div>
          <p>Reply from the superadmin dashboard &rarr; <strong>Public Chat</strong> tab.</p>
        </div>`,
    });
  } catch (error) {
    
  }
};