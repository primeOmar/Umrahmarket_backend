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

// ── Logo ─────────────────────────────────────────────────────────────────
// Email clients render this HTML with no "current page" to resolve a
// relative path against, so this needs one full, publicly-reachable URL.
//
// IMPORTANT: Header.jsx imports the logo via `import logoImage from
// '../assets/umramarket.png'` — a JS import, not a public/ file — so Vite
// content-hashes it at build time (e.g. /assets/umramarket-a1b2c3.png,
// which changes every deploy). That path can't be hardcoded here. Instead,
// place a copy of the same file at frontend/public/umramarket.png so it's
// served at a fixed, unhashed URL. Override via EMAIL_LOGO_URL if the
// deployed filename/path differs.
// NOTE: keep this a PNG/JPG, not SVG — Outlook and most webmail clients
// don't render inline SVG.
const FRONTEND_BASE_URL_FOR_ASSETS = (
  process.env.FRONTEND_URL ||
  process.env.APP_URL ||
  process.env.WEB_APP_URL ||
  'https://umrahmarket.net'
).replace(/\/$/, '');
const LOGO_URL = process.env.EMAIL_LOGO_URL || `${FRONTEND_BASE_URL_FOR_ASSETS}/umramarket.png`;

// ===========================================
// Brand shell — matches the emerald/teal UmrahMarket palette used across
// the app's dashboards. Kept as inline styles/tables for email-client safety.
// ===========================================
const brandShell = ({ preheader, bodyHtml, footerText }) => `
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<meta name="color-scheme" content="light" />
<meta name="supported-color-schemes" content="light" />
<title>UmrahMarket</title>
<style>
  :root { color-scheme: light only; supported-color-schemes: light only; }
  /* The logo PNG has a transparent background. Some clients (Apple Mail,
     Outlook.com, some Gmail contexts) auto-invert a white card to dark in
     dark mode, which leaves the transparent logo floating with no plate
     behind it. The meta tags above opt most clients out entirely; this
     media query is the belt-and-suspenders fallback for the rest. */
  @media (prefers-color-scheme: dark) {
    .um-bg { background-color: #f3f7f5 !important; }
    .um-card, .um-logo-plate, .um-logo-wrap, .um-footer { background-color: #ffffff !important; }
    .um-footer { background-color: #f9fafb !important; }
  }
  /* Gmail (web + the Android/iOS app) largely ignores prefers-color-scheme
     and the color-scheme meta tags above — it runs its own automatic dark
     mode and tags every element it recolors with a data-ogsc (and
     sometimes data-ogsb) attribute instead. That's what was stripping the
     white plate from behind the logo even though the rules above exist.
     Target those Gmail-specific hooks directly so the plate stays white
     no matter what Gmail decides to do around it. */
  [data-ogsc] .um-bg, [data-ogsb] .um-bg { background-color: #f3f7f5 !important; }
  [data-ogsc] .um-card, [data-ogsc] .um-logo-plate, [data-ogsc] .um-logo-wrap, [data-ogsc] .um-footer,
  [data-ogsb] .um-card, [data-ogsb] .um-logo-plate, [data-ogsb] .um-logo-wrap, [data-ogsb] .um-footer {
    background-color: #ffffff !important;
  }
  [data-ogsc] .um-footer, [data-ogsb] .um-footer { background-color: #f9fafb !important; }
</style>
</head>
<body style="margin:0;padding:0;background-color:#f3f7f5;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
  <span style="display:none;font-size:1px;color:#f3f7f5;line-height:1px;max-height:0;max-width:0;opacity:0;overflow:hidden;">${preheader}</span>
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" class="um-bg" bgcolor="#f3f7f5" style="background-color:#f3f7f5;padding:32px 16px;">
    <tr>
      <td align="center">
        <table role="presentation" width="100%" class="um-card" bgcolor="#ffffff" style="max-width:560px;background:#ffffff;border-radius:18px;overflow:hidden;box-shadow:0 10px 30px rgba(15,23,42,0.08);">
          <tr>
            <td class="um-logo-wrap" bgcolor="#ffffff" style="background-color:#ffffff;padding:24px 32px 20px;border-bottom:1px solid #edf2ee;">
              <table role="presentation" cellpadding="0" cellspacing="0" class="um-logo-plate" bgcolor="#ffffff" style="background-color:#ffffff;border-radius:14px;">
                <tr>
                  <td class="um-logo-plate" bgcolor="#ffffff" style="padding:14px 22px;background-color:#ffffff;border-radius:14px;">
                    <img
                      src="${LOGO_URL}"
                      alt="UmrahMarket"
                      width="260"
                      style="display:block;height:auto;max-width:260px;background-color:#ffffff;border:0;outline:none;text-decoration:none;border-radius:12px;"
                    />
                  </td>
                </tr>
              </table>
            </td>
          </tr>
          <tr>
            <td class="um-card" bgcolor="#ffffff" style="background-color:#ffffff;padding:32px;">
              ${bodyHtml}
            </td>
          </tr>
          <tr>
            <td class="um-footer" bgcolor="#f9fafb" style="padding:20px 32px 24px;background:#f9fafb;border-top:1px solid #eef3ee;">
              <p style="margin:0;font-size:12px;line-height:19px;color:#667085;">
                ${footerText || "You're receiving this message because it was sent directly to you by the UmrahMarket team. If it wasn’t meant for you, you can safely ignore it."}
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
// Markdown-lite renderer for broadcast messages
// ===========================================
// Superadmins compose broadcasts as plain text with light markdown
// (**bold**, [text](url)) or just a bare domain/URL. Two failure modes
// this guards against:
//  1) escapeHtml() alone leaves *, [, ], (, ) untouched, so "**bold**" and
//     "[text](url)" used to ship out with the literal punctuation visible.
//  2) A bare domain like "umrahmarket.net" with no markdown around it was
//     left as plain text — the *mail client* then auto-linked it with its
//     own default blue/underline styling, outside our control. This now
//     wraps bare URLs/domains in our own styled <a> tag server-side so the
//     client never gets a chance to.
//
// Order matters: escape first, then apply markdown/link rules on the
// escaped string. escapeHtml() only touches & < > " ' — never * [ ] ( ) —
// so this can't reintroduce unescaped input, and "&" inside a URL becomes
// "&amp;" in the href attribute, which is the *correct* HTML form (mail
// clients decode it back to "&").
//
// Markdown links are converted first and stashed behind a placeholder so
// the bare-URL pass below can't re-match text already inside an <a> tag
// (e.g. the raw URL inside "[text](https://...)").
const LINK_STYLE = 'color:#0d9488;font-weight:600;text-decoration:underline;';
const BARE_DOMAIN_RE =
  /\b((?:www\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|net|org|io|co|app|ke|africa|info|biz|me))\b(\/[^\s<]*)?/gi;

const applyInlineMarkdown = (escaped) => {
  const stash = [];
  const keep = (html) => {
    stash.push(html);
    return `\u0000${stash.length - 1}\u0000`;
  };

  let text = escaped
    // [text](url) — protect first so its inner URL isn't re-matched below
    .replace(/\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/g, (_, label, url) =>
      keep(`<a href="${url}" style="${LINK_STYLE}">${label}</a>`)
    )
    // **bold**
    .replace(/\*\*(.+?)\*\*/g, '<strong style="color:#101828;font-weight:700;">$1</strong>')
    // bare http(s) URL with no markdown around it
    .replace(/https?:\/\/[^\s<]+/g, (url) =>
      keep(`<a href="${url}" style="${LINK_STYLE}">${url.replace(/^https?:\/\//, '').replace(/\/$/, '')}</a>`)
    )
    // bare domain, e.g. "umrahmarket.net" — skip the part right after an
    // "@" so email addresses like support@umrahmarket.net aren't half-linked
    .replace(BARE_DOMAIN_RE, (m, domain, path, offset, full) => {
      if (full[offset - 1] === '@') return m;
      const target = domain + (path || '');
      return keep(`<a href="https://${target}" style="${LINK_STYLE}">${target}</a>`);
    });

  return text.replace(/\u0000(\d+)\u0000/g, (_, i) => stash[Number(i)]);
};

// A block counts as a call-to-action (rendered as a button, not inline
// text) when it's essentially a short label followed by one link and
// nothing else — e.g. "👉 Register now: umrahmarket.net" or
// "👉 **Register now:** [site](url)" alone on its own line. Bracket-link,
// bare-URL, and bare-domain forms are all recognized.
const CTA_BLOCK_RE = new RegExp(
  '^' +
  '(?:[^\\w]{0,6})?' +                                   // leading emoji/pointer chars
  '(?:\\*\\*([^*]{1,30})\\*\\*|([A-Za-z][A-Za-z0-9 ,\'-]{0,28}))?' + // optional label (bold or plain)
  ':?\\s*' +
  '(?:' +
    '\\[([^\\]]+)\\]\\((https?:\\/\\/[^\\s)]+)\\)' +      // [text](url)
    '|(https?:\\/\\/[^\\s)]+)' +                          // bare URL
    '|((?:www\\.)?[a-z0-9-]+(?:\\.[a-z0-9-]+)*\\.(?:com|net|org|io|co|app|ke|africa|info|biz|me)(?:\\/[^\\s)]*)?)' + // bare domain
  ')' +
  '\\s*$',
  'i'
);

const renderCtaButton = (label, url) => `
    <table role="presentation" cellpadding="0" cellspacing="0" style="margin:4px 0 24px;">
      <tr>
        <td style="border-radius:10px;background:linear-gradient(135deg,#10b981,#0d9488);box-shadow:0 6px 16px rgba(13,148,136,0.28);">
          <a href="${url}" style="display:inline-block;padding:13px 30px;font-size:14px;font-weight:700;color:#ffffff;text-decoration:none;border-radius:10px;letter-spacing:0.01em;">
            ${label} &rarr;
          </a>
        </td>
      </tr>
    </table>`;

const BULLET_PREFIX_RE = /^\s*(?:[-*•]|\p{Extended_Pictographic})\s+/u;
const isBulletLine = (line) => BULLET_PREFIX_RE.test(line);

const renderBulletList = (lines, firstName) => `
    <table role="presentation" cellpadding="0" cellspacing="0" style="width:100%;margin:0 0 20px;">
      ${lines
        .map((line) => {
          const text = applyInlineMarkdown(
            applyPersonalization(escapeHtml(line.replace(BULLET_PREFIX_RE, '').trim()), firstName)
          );
          return `
      <tr>
        <td style="padding:0 10px 12px 0;width:22px;vertical-align:top;">
          <span style="display:inline-block;width:18px;height:18px;border-radius:50%;background:#d1fae5;color:#0d9488;font-size:11px;line-height:18px;text-align:center;font-weight:700;">&#10003;</span>
        </td>
        <td style="padding:0 0 12px;font-size:14px;line-height:22px;color:#475467;">${text}</td>
      </tr>`;
        })
        .join('')}
    </table>`;


// Recognizes a mail-merge style token for the recipient's name so an
// admin can write "Dear {{agent_name}}," or "Dear [Agent Name]," once and
// have it fill in per recipient — the real first name when the recipient
// is a registered agent, and a plain fallback otherwise. The inserted name
// is bolded and tinted so it visibly reads as a personalized tag rather
// than blending into the paragraph.
//
// This runs on already-ESCAPED text (see renderMessageBody below), and
// inserts its own <strong> tag afterward — never on the raw message —
// so escapeHtml() can't turn that tag into visible "&lt;strong&gt;" text.
const AGENT_NAME_TOKEN_RE = /\{\{\s*agent[_ ]?name\s*\}\}|\[\s*agent(?:\s*\/\s*company)?\s*name\s*\]/gi;
const applyPersonalization = (escapedText, firstName) => {
  const safeFirst = escapeHtml(firstName || 'there');
  const tag = `<strong style="color:#0d9488;font-weight:700;">${safeFirst}</strong>`;
  return String(escapedText || '').replace(AGENT_NAME_TOKEN_RE, tag);
};

// Splits a raw message into blocks on blank lines, then renders each block
// as a CTA button, a bullet list, or a plain paragraph.
const renderMessageBody = (rawMessage, firstName) =>
  String(rawMessage || '')
    .split(/\n{2,}/)
    .map((block) => block.trim())
    .filter(Boolean)
    .map((block) => {
      const escapedBlock = applyPersonalization(escapeHtml(block), firstName);

      const ctaMatch = escapedBlock.match(CTA_BLOCK_RE);
      if (ctaMatch) {
        const [, boldLabel, plainLabel, linkText, mdUrl, bareUrl, bareDomain] = ctaMatch;
        const url = mdUrl || bareUrl || (bareDomain ? `https://${bareDomain}` : null);
        const rawLabel = boldLabel || plainLabel || linkText || bareDomain || 'Visit site';
        const label = rawLabel.replace(/:\s*$/, '').trim();
        if (url) return renderCtaButton(label, url);
      }

      const lines = block.split('\n').filter(Boolean);
      if (lines.length > 1 && lines.every(isBulletLine)) {
        return renderBulletList(lines, firstName);
      }

      const html = applyInlineMarkdown(escapedBlock).replace(/\n/g, '<br/>');
      return `<p style="margin:0 0 16px;font-size:14px;line-height:23px;color:#475467;">${html}</p>`;
    })
    .join('');

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

// ===========================================
// Send: Agent New Booking Notification Email
// ===========================================
// Fired whenever a client successfully books a package, so the agent knows
// to log in and move the booking forward (visa processing, docs, etc).
// Callers should treat failures here as non-fatal — the client's own
// receipt/confirmation email is the critical path, this is a courtesy
// notification on top of it.
export const sendAgentBookingNotificationEmail = async ({
  to,
  agentName,
  clientName,
  packageName,
  travelerCount,
  amountKes,
  dashboardUrl,
}) => {
  const recipient = String(to || '').trim();
  if (!recipient) {
    logger.warn('Agent booking notification: no agent email on file, skipping', { packageName });
    return { success: false, reason: 'missing_agent_email' };
  }

  const safeAgentName = escapeHtml(agentName || 'there');
  const safeClientName = escapeHtml(clientName || 'A client');
  const safePackageName = escapeHtml(packageName || 'your package');
  const travelerLine =
    typeof travelerCount === 'number' && travelerCount > 0
      ? ` for ${travelerCount} traveler${travelerCount === 1 ? '' : 's'}`
      : '';
  const formattedAmount =
    typeof amountKes === 'number'
      ? `KES ${amountKes.toLocaleString('en-KE', { minimumFractionDigits: 2 })}`
      : null;

  // NOTE: adjust the fallback path below if the agent dashboard is mounted
  // at a different route in the frontend router.
  const url = dashboardUrl || `${FRONTEND_BASE_URL_FOR_ASSETS}/agent/dashboard`;

  const bodyHtml = `
    <h1 style="margin:0 0 12px;font-size:20px;font-weight:700;color:#101828;">New booking received 🎉</h1>
    <p style="margin:0 0 16px;font-size:14px;line-height:22px;color:#475467;">
      Hi ${safeAgentName}, ${safeClientName} just booked <strong>${safePackageName}</strong>${travelerLine}.
    </p>
    ${
      formattedAmount
        ? `<p style="margin:0 0 20px;font-size:14px;line-height:22px;color:#475467;">Amount paid: <strong>${formattedAmount}</strong></p>`
        : ''
    }
    <p style="margin:0 0 20px;font-size:14px;line-height:22px;color:#475467;">
      Please log in to your dashboard to review the booking and start the next steps — visa processing, document collection, and travel prep.
    </p>
    <table role="presentation" cellpadding="0" cellspacing="0">
      <tr>
        <td style="border-radius:10px;background:linear-gradient(135deg,#10b981,#0d9488);">
          <a href="${url}" style="display:inline-block;padding:12px 28px;font-size:14px;font-weight:600;color:#ffffff;text-decoration:none;border-radius:10px;">
            Go to my dashboard
          </a>
        </td>
      </tr>
    </table>
  `;

  const info = await getTransporter().sendMail({
    from: `"${FROM_NAME}" <${FROM_ADDRESS}>`,
    to: recipient,
    subject: `New booking: ${packageName || 'a package'} was just booked`,
    html: brandShell({
      preheader: `${clientName || 'A client'} booked ${packageName || 'your package'} — log in to proceed.`,
      bodyHtml,
    }),
  });

  logger.info('Agent booking notification email sent', { to: recipient, messageId: info.messageId });
  return { success: true, messageId: info.messageId };
};

// ===========================================
// Send: Broadcast / Announcement Email (superadmin → one agent)
// ===========================================
// Single-recipient, same brand shell as every other email here. The
// superadmin batch-email route calls this once per selected agent with a
// delay between calls — this function itself does no looping or rate
// limiting, so it stays reusable if you ever need a one-off broadcast to a
// single agent too.
export const sendBroadcastEmail = async ({ to, agentName, subject, message, recipientType = 'agent' }) => {
  const recipient = String(to || '').trim();
  if (!recipient) {
    logger.warn('Broadcast email: missing recipient, skipping');
    return { success: false, reason: 'missing_email' };
  }

  const safeName = escapeHtml(agentName || 'there');
  const safeSubject = escapeHtml(subject || 'A message from UmrahMarket');
  const normalizedRecipientType = recipientType === 'external' ? 'external' : 'agent';
  const eyebrow = normalizedRecipientType === 'external' ? "You're invited" : 'For UmrahMarket agents';

  // Inline personalization token (e.g. "Dear {{agent_name}},") — first
  // name only, since it reads mid-sentence rather than in a "Hi ___,"
  // greeting. Falls back to "there" the same way the greeting above does,
  // so external/unrecognized recipients still get a coherent sentence.
  const firstName = (agentName || 'there').trim().split(/\s+/)[0];
  const messageHtml = renderMessageBody(message, firstName);

  const bodyHtml = `
    <p style="margin:0 0 8px;font-size:11px;font-weight:700;letter-spacing:0.08em;text-transform:uppercase;color:#0d9488;">${eyebrow}</p>
    <h1 style="margin:0 0 20px;font-size:23px;line-height:30px;font-weight:800;color:#101828;letter-spacing:-0.02em;">${safeSubject}</h1>
    <p style="margin:0 0 18px;font-size:14px;line-height:22px;color:#475467;">Hi ${safeName},</p>
    ${messageHtml}
  `;

  const footerText =
    normalizedRecipientType === 'external'
      ? "You're receiving this message because it was sent directly to you by the UmrahMarket team. If this email was sent to you by mistake, you can safely ignore it."
      : "You're receiving this because you're a registered agent on UmrahMarket. Questions? Reply to this email or contact support@umrahmarket.net.";

  const info = await getTransporter().sendMail({
    from: `"${FROM_NAME}" <${FROM_ADDRESS}>`,
    to: recipient,
    subject: subject || 'A message from UmrahMarket',
    html: brandShell({
      preheader: String(message || '')
        .replace(AGENT_NAME_TOKEN_RE, firstName || 'there')
        .replace(/\[([^\]]+)\]\([^)]+\)/g, '$1')
        .replace(/\*\*/g, '')
        .replace(/\s+/g, ' ')
        .trim()
        .slice(0, 120),
      bodyHtml,
      footerText,
    }),
  });

  logger.info('Broadcast email sent', { to: recipient, messageId: info.messageId, recipientType: normalizedRecipientType });
  return { success: true, messageId: info.messageId };
};

export default { sendVerificationEmail, sendAgentBookingNotificationEmail, sendBroadcastEmail, verifyEmailTransport };