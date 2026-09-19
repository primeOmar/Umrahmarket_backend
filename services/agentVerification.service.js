import twilio from 'twilio';
import nodemailer from 'nodemailer';
import logger from '../config/logger.js';

const twilioClient = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
const WHATSAPP_FROM = process.env.TWILIO_WHATSAPP_FROM; // e.g. 'whatsapp:+17372212163'

// Reuses the same Zoho SMTP credentials as the rest of the app's email
// (issueVerificationEmail / sendVerificationEmail). If email.service.js
// already exports a shared transporter, swap this for that import instead
// of creating a second connection pool.
const mailer = nodemailer.createTransport({
  host: process.env.ZOHO_SMTP_HOST,
  port: 465,
  secure: true,
  auth: { user: process.env.ZOHO_SMTP_USER, pass: process.env.ZOHO_SMTP_PASS },
});

const toWhatsAppNumber = (phone) => {
  if (!phone) return null;
  const digits = String(phone).replace(/[^\d+]/g, '');
  return `whatsapp:${digits.startsWith('+') ? digits : '+' + digits}`;
};

const sendWhatsApp = async (phone, contentSid, variables) => {
  const to = toWhatsAppNumber(phone);
  if (!to) {
    logger.warn('Skipping WhatsApp notification — agent has no phone on file', { variables });
    return { sent: false, reason: 'no_phone' };
  }
  try {
    await twilioClient.messages.create({
      from: WHATSAPP_FROM,
      to,
      contentSid,
      contentVariables: JSON.stringify(variables),
    });
    return { sent: true };
  } catch (err) {
    logger.error('WhatsApp verification notification failed', { error: err.message, to });
    return { sent: false, reason: err.message };
  }
};

const verificationEmailHtml = (firstName, isFollowUp) => {
  const heading = isFollowUp
    ? 'Reminder: Verification Documents Pending'
    : 'Welcome — Please Upload Your Verification Documents';
  const body = isFollowUp
    ? `Hi ${firstName}, we still haven't received your verification documents. Please upload them to activate your agent account fully.`
    : `Hi ${firstName}, welcome to UmrahMarket. To start listing packages, please upload your verification documents (Certificate of Incorporation, Tourism License, and KRAPIN).`;

  return `
    <div style="font-family:Arial,sans-serif;max-width:600px;margin:auto">
      <h2 style="color:#065f46">${heading}</h2>
      <p>${body}</p>
      <a href="${process.env.FRONTEND_URL || process.env.APP_URL}/agent/dashboard"
         style="display:inline-block;background:#065f46;color:#fff;padding:12px 24px;
                border-radius:6px;text-decoration:none;margin-top:12px">
        Upload Documents
      </a>
    </div>`;
};

const sendVerificationEmail = async (to, firstName, isFollowUp) => {
  try {
    await mailer.sendMail({
      from: `"UmrahMarket" <${process.env.ZOHO_SMTP_USER}>`,
      to,
      subject: isFollowUp
        ? 'Reminder: Complete Your Agent Verification'
        : 'Welcome to UmrahMarket — Upload Your Documents',
      html: verificationEmailHtml(firstName, isFollowUp),
    });
    return { sent: true };
  } catch (err) {
    logger.error('Verification email notification failed', { error: err.message, to });
    return { sent: false, reason: err.message };
  }
};

/**
 * Called from task_routes.js when a task is assigned to a superadmin/task
 * team member. Fire-and-forget — never blocks or fails the task-creation
 * response. Requires TWILIO_TEMPLATE_TASK_ASSIGNED_SID to be an approved
 * WhatsApp content template with two variables: {1: name, 2: taskTitle}.
 */
export const sendTaskAssignedWhatsApp = async (phone, fullNameOrUsername, taskTitle) => {
  return sendWhatsApp(phone, process.env.TWILIO_TEMPLATE_TASK_ASSIGNED_SID, {
    1: fullNameOrUsername,
    2: taskTitle,
  });
};

/**
 * Called once, right after a new agent's profile row is created.
 * Fire-and-forget — must never block or fail the registration response.
 */
export const notifyNewAgent = async ({ id, firstName, email, phone }, supabaseAdmin) => {
  try {
    await Promise.all([
      sendWhatsApp(phone, process.env.TWILIO_TEMPLATE_WELCOME_SID, { 1: firstName }),
      sendVerificationEmail(email, firstName, false),
    ]);

    const { error } = await supabaseAdmin
      .from('profiles')
      .update({ last_reminder_sent_at: new Date().toISOString(), reminder_count: 1 })
      .eq('id', id);

    if (error) {
      logger.error('Failed to record initial verification reminder timestamp', { error: error.message, userId: id });
    }
  } catch (err) {
    logger.error('notifyNewAgent failed', { error: err.message, userId: id });
  }
};

/**
 * Called by cron/verificationReminderJob.js for each agent whose 48hr
 * window has elapsed with no agent_documents row yet.
 */
export const sendVerificationReminder = async ({ id, firstName, email, phone, reminder_count }, supabaseAdmin) => {
  try {
    await Promise.all([
      sendWhatsApp(phone, process.env.TWILIO_TEMPLATE_REMINDER_SID, { 1: firstName }),
      sendVerificationEmail(email, firstName, true),
    ]);

    const { error } = await supabaseAdmin
      .from('profiles')
      .update({
        last_reminder_sent_at: new Date().toISOString(),
        reminder_count: (reminder_count || 0) + 1,
      })
      .eq('id', id);

    if (error) {
      logger.error('Failed to update reminder count', { error: error.message, userId: id });
    }
  } catch (err) {
    logger.error('sendVerificationReminder failed', { error: err.message, userId: id });
  }
};