
// Twilio WhatsApp integration for UmrahMarket.
//
// IMPORTANT — how WhatsApp Business messaging actually works:
// Any message YOUR business initiates (a client hasn't messaged you on
// WhatsApp in the last 24h) MUST use a pre-approved Content Template.
// Freeform text is only allowed as a *reply* inside an open 24h window
// after the user messages you first. Since booking confirmations and
// marketing offers are both business-initiated, BOTH must go through
// approved templates — there is no way around this, it's a WhatsApp/Meta
// policy enforced by Twilio, not a code limitation.
//
// Templates are created once in the Twilio Console (Content Template
// Builder) or via the Content API, submitted to WhatsApp for approval
// (usually a few hours), and then referenced here by their Content SID
// (starts with "HX..."). See SETUP.md for how to create them.
//
// Env vars required (add to .env, never commit):
//   TWILIO_ACCOUNT_SID=ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
//   TWILIO_AUTH_TOKEN=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
//   TWILIO_WHATSAPP_FROM=whatsapp:+14155238886        // "whatsapp:" prefix optional — normalised in twilioWhatsApp.config.js
//   (or) TWILIO_WHATSAPP_MESSAGING_SERVICE_SID=MGxxxx   // alternative: a Messaging Service with a WhatsApp sender
//   TWILIO_STATUS_CALLBACK_URL=https://yourdomain.com/api/whatsapp/status
//   WHATSAPP_TEMPLATE_BOOKING_CONFIRMED=HXxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

import twilio from 'twilio';
import { supabaseAdmin as supabase } from '../config/supabase.js';
import logger from '../config/logger.js';
import {
  resolveWhatsAppSender,
  toWhatsAppAddress,
  friendlyTwilioError,
  FATAL_CONFIG_CODES,
  RETRYABLE_CODES,
} from './twilioWhatsApp.config.js';

const {
  TWILIO_ACCOUNT_SID,
  TWILIO_AUTH_TOKEN,
  TWILIO_STATUS_CALLBACK_URL,
} = process.env;

const sender = resolveWhatsAppSender();
if (!TWILIO_ACCOUNT_SID || !TWILIO_AUTH_TOKEN) {
  logger.warn('[whatsappService] Twilio credentials missing — WhatsApp sending is disabled until configured.');
}
if (!sender.ok) logger.warn(`[whatsappService] ${sender.error}`);
else logger.info(`[whatsappService] WhatsApp sender: ${sender.label}`);

let client = null;
if (TWILIO_ACCOUNT_SID && TWILIO_AUTH_TOKEN) {
  try {
    client = twilio(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN);
  } catch (err) {
    logger.error('[whatsappService] Twilio disabled — invalid credentials', { error: err.message });
  }
}

/**
 * Is WhatsApp sending usable right now? Checked by the admin routes before a
 * broadcast so a misconfiguration is reported once, not once per recipient.
 */
export function getWhatsAppConfigStatus() {
  const problems = [];
  if (!TWILIO_ACCOUNT_SID || !TWILIO_AUTH_TOKEN) problems.push('TWILIO_ACCOUNT_SID / TWILIO_AUTH_TOKEN are not set.');
  else if (!client) problems.push('Twilio credentials are invalid (TWILIO_ACCOUNT_SID must start with "AC").');
  if (!sender.ok) problems.push(sender.error);
  return {
    ready: problems.length === 0,
    sender: sender.ok ? sender.label : null,
    statusCallback: !!TWILIO_STATUS_CALLBACK_URL,
    problems,
    // Which deployment answered — lets the dashboard prove it is talking to
    // the backend (and commit) you think it is. RENDER_GIT_COMMIT is set by Render.
    build: {
      commit: (process.env.RENDER_GIT_COMMIT || process.env.GIT_COMMIT || '').slice(0, 7) || 'local',
      env: process.env.NODE_ENV || 'development',
      service: process.env.RENDER_SERVICE_NAME || null,
    },
  };
}

/**
 * Live check against Twilio: are the credentials accepted and the account
 * active? Kept off the send path (one API call) and only run on demand.
 */
export async function verifyTwilioAccount() {
  if (!client) return { ok: false, error: 'Twilio client not initialised' };
  try {
    const acct = await client.api.v2010.accounts(TWILIO_ACCOUNT_SID).fetch();
    if (acct.status !== 'active') return { ok: false, error: `Twilio account status is "${acct.status}"` };
    return { ok: true, accountName: acct.friendlyName, accountType: acct.type };
  } catch (err) {
    return { ok: false, error: friendlyTwilioError(err.code, err.message), code: err.code || null };
  }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * Normalise a Kenyan number to E.164 (+254XXXXXXXXX).
 * Mirrors normalisePhone() in BookingFlow.jsx so numbers stored anywhere
 * in the system are consistent.
 */
export function toE164Kenya(raw) {
  if (!raw) return null;
  const d = String(raw).replace(/\D/g, '');
  if (d.startsWith('254') && d.length === 12) return `+${d}`;
  if (d.startsWith('0') && d.length === 10) return `+254${d.slice(1)}`;
  if ((d.startsWith('7') || d.startsWith('1')) && d.length === 9) return `+254${d}`;
  if (String(raw).trim().startsWith('+')) return `+${d}`; // already E.164 (e.g. non-Kenyan agent)
  return null;
}

/**
 * Send one WhatsApp template message and log it.
 *
 * @param {Object} opts
 * @param {string} opts.to               Raw or E.164 phone number
 * @param {string} opts.templateSid       Twilio Content SID (HXxxxx...)
 * @param {string} opts.templateName      Human label, for logging/UI only
 * @param {Object} [opts.variables]       Template variables, e.g. {"1": "Tonny", "2": "UM-2481"}
 * @param {string} opts.category          'booking_confirmation' | 'marketing_broadcast' | 'agent_notice' | 'other'
 * @param {Object} [opts.meta]            { recipientType, recipientId, bookingId, broadcastId }
 * @returns {Promise<{ok: boolean, sid?: string, error?: string, errorCode?: number|null, fatal?: boolean}>}
 */
export async function sendWhatsAppTemplate({
  to,
  templateSid,
  templateName,
  variables = {},
  category,
  meta = {},
}) {
  const e164 = toE164Kenya(to);
  if (!e164 || !/^\+[1-9]\d{7,14}$/.test(e164)) {
    return logAndReturn({ ok: false, to, templateSid, templateName, variables, category, meta, error: 'Invalid phone number' });
  }
  if (!client || !sender.ok) {
    return logAndReturn({
      ok: false, to: e164, templateSid, templateName, variables, category, meta,
      error: sender.ok ? 'Twilio not configured' : sender.error,
      fatal: true,
    });
  }

  const payload = {
    ...sender.params, // { from: 'whatsapp:+…' } or { messagingServiceSid: 'MG…' }
    to: toWhatsAppAddress(e164),
    contentSid: templateSid,
    contentVariables: JSON.stringify(variables),
    ...(TWILIO_STATUS_CALLBACK_URL ? { statusCallback: TWILIO_STATUS_CALLBACK_URL } : {}),
  };

  for (let attempt = 1; ; attempt++) {
    try {
      const msg = await client.messages.create(payload);
      return logAndReturn({
        ok: true, to: e164, templateSid, templateName, variables, category, meta,
        twilioSid: msg.sid,
        status: msg.status,
      });
    } catch (err) {
      const code = Number(err.code) || null;
      if (code && RETRYABLE_CODES.has(code) && attempt < 3) {
        await sleep(1000 * attempt);
        continue;
      }
      logger.error('[whatsappService] send failed', { to: e164, code, error: err.message, category });
      return logAndReturn({
        ok: false, to: e164, templateSid, templateName, variables, category, meta,
        error: friendlyTwilioError(code, err.message),
        errorCode: code,
        fatal: !!code && FATAL_CONFIG_CODES.has(code),
      });
    }
  }
}

async function logAndReturn({ ok, to, templateSid, templateName, variables, category, meta, twilioSid, status, error, errorCode, fatal }) {
  const { error: logErr } = await supabase.from('whatsapp_messages').insert({
    twilio_sid: twilioSid || null,
    category,
    to_number: to,
    template_sid: templateSid,
    template_name: templateName,
    variables,
    status: ok ? (status || 'sent') : 'failed',
    error_code: errorCode || null,
    error_message: error || null,
    recipient_profile_id: meta.recipientId || null, // profiles.id — null for external (non-profile) numbers
    booking_id: meta.bookingId || null,
    broadcast_id: meta.broadcastId || null,
  });
  // A logging failure must never turn a delivered message into a "failed" one.
  if (logErr) logger.error('[whatsappService] could not log message', { error: logErr.message, twilioSid });

  return ok
    ? { ok: true, sid: twilioSid }
    : { ok: false, error, errorCode: errorCode || null, fatal: !!fatal };
}

/**
 * Send the same template to many recipients (used by the batch broadcast
 * endpoint). Runs with a small concurrency cap to stay well under Twilio's
 * rate limits — WhatsApp Business API is capped per messaging-tier, and
 * sending thousands at once will get throttled or flagged.
 *
 * Stops early on configuration errors (bad sender/credentials) since every
 * remaining message would fail the same way.
 */
export async function sendWhatsAppBroadcast({ recipients, templateSid, templateName, category, broadcastId, buildVariables }) {
  const CONCURRENCY = 5;
  let sentCount = 0;
  const failed = [];
  let abortedReason = null;

  for (let i = 0; i < recipients.length; i += CONCURRENCY) {
    const batch = recipients.slice(i, i + CONCURRENCY);
    const results = await Promise.all(
      batch.map((r) =>
        sendWhatsAppTemplate({
          to: r.phone,
          templateSid,
          templateName,
          variables: buildVariables ? buildVariables(r) : {},
          category,
          meta: {
            recipientType: r.type,
            recipientId: r.id,
            broadcastId,
          },
        }).then((res) => ({ ...res, recipient: r }))
      )
    );

    for (const res of results) {
      if (res.ok) sentCount++;
      else failed.push({ id: res.recipient.id, phone: res.recipient.phone, error: res.error, code: res.errorCode || null });
    }

    const fatal = results.find((r) => !r.ok && r.fatal);
    if (fatal) {
      abortedReason = fatal.error;
      for (const r of recipients.slice(i + CONCURRENCY)) {
        failed.push({ id: r.id, phone: r.phone, error: 'Not sent — broadcast stopped after a configuration error', code: null });
      }
      logger.error('[whatsappService] broadcast aborted', { broadcastId, reason: abortedReason });
      break;
    }
  }

  return { sentCount, failedCount: failed.length, failed, abortedReason };
}

/**
 * Twilio status-callback webhook handler. Wire this to
 * POST /api/whatsapp/status (see whatsappRoutes.js) and set that URL in
 * TWILIO_STATUS_CALLBACK_URL so delivery/read receipts sync back.
 */
export async function handleStatusWebhook(body) {
  const { MessageSid, MessageStatus, ErrorCode, ErrorMessage } = body;
  if (!MessageSid || !MessageStatus) return;

  await supabase
    .from('whatsapp_messages')
    .update({
      status: MessageStatus,
      error_code: ErrorCode || null,
      ...(ErrorCode ? { error_message: friendlyTwilioError(ErrorCode, ErrorMessage) } : {}),
      updated_at: new Date().toISOString(),
    })
    .eq('twilio_sid', MessageSid);
}

/**
 * Shortcut used at booking-confirmation time. Call this right next to your
 * existing confirmation-email call in the booking route.
 */
export async function sendBookingConfirmationWhatsApp(booking) {
  const templateSid = process.env.WHATSAPP_TEMPLATE_BOOKING_CONFIRMED;
  if (!templateSid) {
    logger.warn('[whatsappService] WHATSAPP_TEMPLATE_BOOKING_CONFIRMED not set — skipping WhatsApp confirmation.');
    return { ok: false, error: 'Template not configured' };
  }

  return sendWhatsAppTemplate({
    to: booking.whatsapp_number || booking.phone,
    templateSid,
    templateName: 'booking_confirmed',
    // Variable numbering must match the template exactly as approved in
    // Twilio Content Template Builder. Example template body:
    // "Hi {{1}}, your {{2}} booking ({{3}}) is confirmed. Total: {{4}}.
    //  View your itinerary: {{5}}"
    variables: {
      1: booking.clientName || 'there',
      2: booking.packageName || 'Umrah package',
      3: booking.reference || booking.id,
      4: booking.totalDisplay || `${booking.currency} ${booking.amount}`,
      5: booking.receiptUrl || 'https://umrahmarket.net/dashboard/bookings',
    },
    category: 'booking_confirmation',
    meta: { recipientType: 'client', recipientId: booking.clientId, bookingId: booking.id },
  });
}
