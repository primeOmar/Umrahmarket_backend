import nodemailer from 'nodemailer';

// Mirrors the SMTP config already used for receipt emails in
// superadmin_routes.js (same env vars: SMTP_HOST/PORT/SECURE/USER/PASS/FROM),
// so no new environment variables are needed.
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT ?? 587),
  secure: process.env.SMTP_SECURE === 'true',
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
});

const FROM = process.env.SMTP_FROM || process.env.SMTP_USER;
const APP_URL = process.env.SUPERADMIN_APP_URL || 'https://umrahmarket.net/superadmin';

export async function sendTaskEmail(to, subject, html) {
  if (!to) return;
  if (!process.env.SMTP_HOST || !process.env.SMTP_USER || !process.env.SMTP_PASS) {
    // Mirrors the 501 guard in the batch-email route — mail just isn't
    // configured on this environment. Never break the task action for it.
    return;
  }
  try {
    await transporter.sendMail({ from: FROM, to, subject, html });
  } catch (err) {
    console.error(`[taskEmail] failed to send "${subject}" to ${to}:`, err.message);
  }
}

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
                  <a href="${ctaUrl}" style="background:#059669;color:#fff;text-decoration:none;padding:12px 22px;border-radius:10px;font-size:14px;font-weight:600;display:inline-block;">Open Dashboard</a>
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

const fmtDeadline = (d) =>
  new Date(d).toLocaleString('en-GB', { dateStyle: 'medium', timeStyle: 'short', timeZone: 'Africa/Nairobi' });

export const taskEmailTemplates = {
  assigned: (task, adminName) => ({
    subject: `New task assigned: ${task.title}`,
    html: wrap(
      'You have a new task',
      `<p>Hi ${adminName || 'there'},</p>
       <p><strong>${task.title}</strong> has been assigned to you.</p>
       ${task.description ? `<p style="color:#6b7280;">${task.description}</p>` : ''}
       <p><strong>Deadline:</strong> ${fmtDeadline(task.deadline)}</p>`,
      `${APP_URL}?tab=tasks&task=${task.id}`,
    ),
  }),
  reminder: (task, hoursLeft) => ({
    subject: `Reminder: "${task.title}" is due in ${hoursLeft}h`,
    html: wrap(
      'Deadline approaching',
      `<p><strong>${task.title}</strong> is due <strong>${fmtDeadline(task.deadline)}</strong> — about ${hoursLeft} hours from now.</p>
       <p>Current progress: <strong>${task.progress_percent || 0}%</strong></p>`,
      `${APP_URL}?tab=tasks&task=${task.id}`,
    ),
  }),
  overdue: (task) => ({
    subject: `Overdue: "${task.title}" has passed its deadline`,
    html: wrap(
      'Task is overdue',
      `<p><strong>${task.title}</strong> passed its deadline of <strong>${fmtDeadline(task.deadline)}</strong> and is still at ${task.progress_percent || 0}%.</p>`,
      `${APP_URL}?tab=tasks&task=${task.id}`,
    ),
  }),
  stageCompleted: (task, stage, completedByName) => ({
    subject: `Progress: "${stage.title}" done on ${task.title}`,
    html: wrap(
      'Stage completed',
      `<p>${completedByName || 'An assignee'} marked <strong>${stage.title}</strong> complete on <strong>${task.title}</strong>.</p>
       <p>Task is now at <strong>${task.progress_percent || 0}%</strong>.</p>`,
      `${APP_URL}?tab=tasks&task=${task.id}`,
    ),
  }),
  taskCompleted: (task) => ({
    subject: `Completed: ${task.title}`,
    html: wrap(
      'Task completed 🎉',
      `<p><strong>${task.title}</strong> reached 100% and is now marked complete.</p>`,
      `${APP_URL}?tab=tasks&task=${task.id}`,
    ),
  }),
};