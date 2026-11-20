import nodemailer from 'nodemailer';
import logger from '../config/logger.js';

// Same SMTP env vars as the rest of the app (SMTP_HOST/PORT/SECURE/USER/PASS).
// SMTP_SECURE falls back to "port 465 ⇒ TLS", matching email.service.js, so
// the two transports can't disagree about how to connect.
const port = Number(process.env.SMTP_PORT) || 465;
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port,
  secure: process.env.SMTP_SECURE ? process.env.SMTP_SECURE === 'true' : port === 465,
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
  // Fail fast instead of hanging the task request on a dead SMTP server.
  connectionTimeout: 10_000,
  greetingTimeout: 10_000,
  socketTimeout: 20_000,
});

const FROM_NAME = process.env.EMAIL_FROM_NAME || 'UmrahMarket';
const FROM_ADDRESS = process.env.SMTP_FROM || process.env.EMAIL_FROM_ADDRESS || process.env.SMTP_USER;
const APP_URL = (process.env.SUPERADMIN_APP_URL || 'https://umrahmarket.net/superadmin').replace(/\/$/, '');

/**
 * Send a task email. Never throws — returns a result so callers can report
 * delivery status instead of silently losing failures.
 * @returns {Promise<{sent: boolean, reason?: string}>}
 */
export async function sendTaskEmail(to, subject, html) {
  if (!to) return { sent: false, reason: 'no_email' };
  if (!process.env.SMTP_HOST || !process.env.SMTP_USER || !process.env.SMTP_PASS) {
    logger.warn('[taskEmail] SMTP not configured — task email skipped', { subject });
    return { sent: false, reason: 'smtp_not_configured' };
  }
  try {
    const info = await transporter.sendMail({ from: `"${FROM_NAME}" <${FROM_ADDRESS}>`, to, subject, html });
    logger.info('[taskEmail] sent', { to, subject, messageId: info.messageId });
    return { sent: true };
  } catch (err) {
    logger.error('[taskEmail] send failed', { to, subject, error: err.message, code: err.code, response: err.response });
    return { sent: false, reason: err.code === 'EAUTH' ? 'smtp_auth_failed' : 'smtp_error' };
  }
}

// Task titles/descriptions/names are user-entered — escape before putting
// them into HTML so one admin can't inject markup/links into another's inbox.
const esc = (v) => String(v ?? '')
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;').replace(/'/g, '&#39;');

// Subjects are plain text; strip CR/LF so a title can't inject mail headers.
const subj = (v) => String(v ?? '').replace(/[\r\n]+/g, ' ').slice(0, 180);

const taskUrl = (task) => `${APP_URL}?tab=tasks&task=${encodeURIComponent(task.id)}`;

const wrap = (title, bodyHtml, ctaUrl) => `
<!DOCTYPE html>
<html>
  <body style="margin:0;padding:0;background:#f4f6f8;font-family:Arial,Helvetica,sans-serif;">
    <table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f6f8;padding:32px 0;">
      <tr>
        <td align="center">
          <table width="560" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:16px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,0.08);">
            <tr>
              <td style="background:linear-gradient(135deg,#059669,#047857);padding:24px 32px;">
                <span style="color:#fff;font-size:18px;font-weight:700;">UmrahMarket · Task Management</span>
              </td>
            </tr>
            <tr>
              <td style="padding:32px;">
                <h2 style="margin:0 0 16px;color:#111827;font-size:20px;">${title}</h2>
                <div style="color:#374151;font-size:14px;line-height:1.6;">${bodyHtml}</div>
                ${ctaUrl ? `
                <div style="margin-top:28px;">
                  <a href="${ctaUrl}" style="background:#059669;color:#fff;text-decoration:none;padding:12px 22px;border-radius:10px;font-size:14px;font-weight:600;display:inline-block;">Open task</a>
                </div>` : ''}
              </td>
            </tr>
            <tr>
              <td style="padding:16px 32px;background:#f9fafb;border-top:1px solid #eee;">
                <span style="color:#9ca3af;font-size:11px;">This is an automated message from the UmrahMarket superadmin task system.</span>
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
  </body>
</html>`;

export const fmtDeadline = (d) =>
  new Date(d).toLocaleString('en-GB', { dateStyle: 'medium', timeStyle: 'short', timeZone: 'Africa/Nairobi' });

export const taskEmailTemplates = {
  assigned: (task, adminName, assignedByName) => ({
    subject: subj(`New task assigned: ${task.title}`),
    html: wrap(
      'You have a new task',
      `<p>Hi ${esc(adminName || 'there')},</p>
       <p><strong>${esc(task.title)}</strong> has been assigned to you${assignedByName ? ` by ${esc(assignedByName)}` : ''}.</p>
       ${task.description ? `<p style="color:#6b7280;white-space:pre-line;">${esc(task.description)}</p>` : ''}
       <p><strong>Deadline:</strong> ${esc(fmtDeadline(task.deadline))} (EAT)</p>`,
      taskUrl(task),
    ),
  }),
  reminder: (task, hoursLeft) => ({
    subject: subj(`Reminder: "${task.title}" is due in ${hoursLeft}h`),
    html: wrap(
      'Deadline approaching',
      `<p><strong>${esc(task.title)}</strong> is due <strong>${esc(fmtDeadline(task.deadline))}</strong> — about ${Number(hoursLeft)} hours from now.</p>
       <p>Current progress: <strong>${Number(task.progress_percent) || 0}%</strong></p>`,
      taskUrl(task),
    ),
  }),
  overdue: (task) => ({
    subject: subj(`Overdue: "${task.title}" has passed its deadline`),
    html: wrap(
      'Task is overdue',
      `<p><strong>${esc(task.title)}</strong> passed its deadline of <strong>${esc(fmtDeadline(task.deadline))}</strong> and is still at ${Number(task.progress_percent) || 0}%.</p>`,
      taskUrl(task),
    ),
  }),
  stageCompleted: (task, stage, completedByName) => ({
    subject: subj(`Progress: "${stage.title}" done on ${task.title}`),
    html: wrap(
      'Stage completed',
      `<p>${esc(completedByName || 'An assignee')} marked <strong>${esc(stage.title)}</strong> complete on <strong>${esc(task.title)}</strong>.</p>
       <p>Task is now at <strong>${Number(task.progress_percent) || 0}%</strong>.</p>`,
      taskUrl(task),
    ),
  }),
  taskCompleted: (task) => ({
    subject: subj(`Completed: ${task.title}`),
    html: wrap(
      'Task completed 🎉',
      `<p><strong>${esc(task.title)}</strong> reached 100% and is now marked complete.</p>`,
      taskUrl(task),
    ),
  }),
};
