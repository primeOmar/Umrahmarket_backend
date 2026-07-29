import nodemailer from 'nodemailer';
import logger from '../config/logger.js';


let transporter = null;

const getTransporter = () => {
  if (transporter) return transporter;

  const { SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS } = process.env;

  if (!SMTP_HOST || !SMTP_USER || !SMTP_PASS) {
    logger.warn('Email service: SMTP env vars not fully configured — emails will not send', {
      hasHost: !!SMTP_HOST,
      hasUser: !!SMTP_USER,
      hasPass: !!SMTP_PASS,
    });
  }

  transporter = nodemailer.createTransport({
    host: SMTP_HOST,
    port: Number(SMTP_PORT) || 465,
    secure: process.env.SMTP_SECURE ? process.env.SMTP_SECURE === 'true' : Number(SMTP_PORT) === 465,
    auth: { user: SMTP_USER, pass: SMTP_PASS },
    pool: true, // reuse connections — faster under repeated sends
    maxConnections: 3,
  });

  return transporter;
};

// Verify SMTP creds once at boot so misconfiguration shows up in logs
// immediately instead of silently failing on the first user's registration.
export const verifyEmailTransport = async () => {
  try {
    await getTransporter().verify();
    logger.info('Email service: SMTP connection verified');
    return true;
  } catch (error) {
    logger.error('Email service: SMTP verification failed', { error: error.message });
    return false;
  }
};

const FROM_NAME = process.env.EMAIL_FROM_NAME || 'UmrahMarket';
const FROM_ADDRESS = process.env.EMAIL_FROM_ADDRESS || process.env.SMTP_USER;

// ===========================================
// Brand shell — matches the emerald/teal UmrahMarket palette used across
// the app's dashboards. Kept as inline styles/tables for email-client safety.
// ===========================================
const brandShell = ({ preheader, bodyHtml }) => `
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>UmrahMarket</title>
</head>
<body style="margin:0;padding:0;background-color:#f4f6f5;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
  <span style="display:none;font-size:1px;color:#f4f6f5;line-height:1px;max-height:0;max-width:0;opacity:0;overflow:hidden;">${preheader}</span>
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#f4f6f5;padding:32px 16px;">
    <tr>
      <td align="center">
        <table role="presentation" width="100%" style="max-width:480px;background:#ffffff;border-radius:16px;overflow:hidden;box-shadow:0 1px 3px rgba(16,24,40,0.08);">
          <tr>
            <td style="background:linear-gradient(135deg,#10b981,#0d9488);padding:28px 32px;">
              <span style="color:#ffffff;font-size:20px;font-weight:700;letter-spacing:-0.02em;">UmrahMarket</span>
            </td>
          </tr>
          <tr>
            <td style="padding:32px;">
              ${bodyHtml}
            </td>
          </tr>
          <tr>
            <td style="padding:20px 32px;background:#f9fafb;border-top:1px solid #eef0ef;">
              <p style="margin:0;font-size:12px;line-height:18px;color:#98a2b3;">
                You're receiving this because an account was created with this email address on UmrahMarket.
                If this wasn't you, you can safely ignore this message.
              </p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>
`;

const escapeHtml = (str = '') =>
  String(str).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

// ===========================================
// Send: Account Confirmation Email
// ===========================================
export const sendVerificationEmail = async ({ to, firstName, verifyUrl }) => {
  const safeName = escapeHtml(firstName || 'there');

  const bodyHtml = `
    <h1 style="margin:0 0 12px;font-size:20px;font-weight:700;color:#101828;">Confirm your email</h1>
    <p style="margin:0 0 20px;font-size:14px;line-height:22px;color:#475467;">
      Hi ${safeName}, welcome to UmrahMarket. Please confirm this email address to finish setting up your account.
    </p>
    <table role="presentation" cellpadding="0" cellspacing="0">
      <tr>
        <td style="border-radius:10px;background:linear-gradient(135deg,#10b981,#0d9488);">
          <a href="${verifyUrl}" style="display:inline-block;padding:12px 28px;font-size:14px;font-weight:600;color:#ffffff;text-decoration:none;border-radius:10px;">
            Confirm my email
          </a>
        </td>
      </tr>
    </table>
    <p style="margin:24px 0 0;font-size:12px;line-height:20px;color:#98a2b3;">
      This link expires in 24 hours. If the button doesn't work, copy and paste this URL into your browser:<br />
      <span style="color:#0d9488;word-break:break-all;">${verifyUrl}</span>
    </p>
  `;

  const info = await getTransporter().sendMail({
    from: `"${FROM_NAME}" <${FROM_ADDRESS}>`,
    to,
    subject: 'Confirm your UmrahMarket account',
    html: brandShell({ preheader: 'Confirm your email to finish setting up your UmrahMarket account.', bodyHtml }),
  });

  logger.info('Verification email sent', { to, messageId: info.messageId });
  return info;
};

export default { sendVerificationEmail, verifyEmailTransport };