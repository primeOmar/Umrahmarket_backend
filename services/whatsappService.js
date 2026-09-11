// services/whatsappService.js
//
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
//   TWILIO_WHATSAPP_FROM=whatsapp:+14155238886        // sandbox number until you have your own
//   TWILIO_STATUS_CALLBACK_URL=https://yourdomain.com/api/whatsapp/status
//   WHATSAPP_TEMPLATE_BOOKING_CONFIRMED=HXxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

import twilio from 'twilio';
import { supabase } from '../supabaseClient.js'; // adjust to your existing Supabase server client path

const {
  TWILIO_ACCOUNT_SID,
  TWILIO_AUTH_TOKEN,
  TWILIO_WHATSAPP_FROM,
  TWILIO_STATUS_CALLBACK_URL,
} = process.env;

if (!TWILIO_ACCOUNT_SID || !TWILIO_AUTH_TOKEN || !TWILIO_WHATSAPP_FROM) {
  console.warn('[whatsappService] Twilio env vars missing — WhatsApp sending is disabled until configured.');
}

const client = TWILIO_ACCOUNT_SID && TWILIO_AUTH_TOKEN
  ? twilio(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
  : null;

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
  if (raw.startsWith('+')) return raw; // already E.164 (e.g. non-Kenyan agent)
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
 * @returns {Promise<{ok: boolean, sid?: string, error?: string}>}
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
  if (!e164) {
    return logAndReturn({ ok: false, to, templateSid, templateName, variables, category, meta, error: 'Invalid phone number' });
  }
  if (!client) {
    return logAndReturn({ ok: false, to: e164, templateSid, templateName, variables, category, meta, error: 'Twilio not configured' });
  }

  try {
    const msg = await client.messages.create({
      from: TWILIO_WHATSAPP_FROM,
      to: `whatsapp:${e164}`,
      contentSid: templateSid,
      contentVariables: JSON.stringify(variables),
      ...(TWILIO_STATUS_CALLBACK_URL ? { statusCallback: TWILIO_STATUS_CALLBACK_URL } : {}),
    });

    return logAndReturn({
      ok: true,
      to: e164,
      templateSid,
      templateName,
      variables,
      category,
      meta,
      twilioSid: msg.sid,
      status: msg.status,
    });
  } catch (err) {
    return logAndReturn({
      ok: false,
      to: e164,
      templateSid,
      templateName,
      variables,
      category,
      meta,
      error: err.message,
      errorCode: err.code,
    });
  }
}

async function logAndReturn({ ok, to, templateSid, templateName, variables, category, meta, twilioSid, status, error, errorCode }) {
  await supabase.from('whatsapp_messages').insert({
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

  return ok ? { ok: true, sid: twilioSid } : { ok: false, error };
}

/**
 * Send the same template to many recipients (used by the batch broadcast
 * endpoint). Runs with a small concurrency cap to stay well under Twilio's
 * rate limits — WhatsApp Business API is capped per messaging-tier, and
 * sending thousands at once will get throttled or flagged.
 */
export async function sendWhatsAppBroadcast({ recipients, templateSid, templateName, category, broadcastId, buildVariables }) {
  const CONCURRENCY = 5;
  let sentCount = 0;
  const failed = [];

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
      else failed.push({ id: res.recipient.id, phone: res.recipient.phone, error: res.error });
    }
  }

  return { sentCount, failedCount: failed.length, failed };
}

/**
 * Twilio status-callback webhook handler. Wire this to
 * POST /api/whatsapp/status (see whatsappRoutes.js) and set that URL in
 * TWILIO_STATUS_CALLBACK_URL so delivery/read receipts sync back.
 */
export async function handleStatusWebhook(body) {
  const { MessageSid, MessageStatus, ErrorCode } = body;
  if (!MessageSid) return;

  await supabase
    .from('whatsapp_messages')
    .update({
      status: MessageStatus,
      error_code: ErrorCode || null,
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
    console.warn('[whatsappService] WHATSAPP_TEMPLATE_BOOKING_CONFIRMED not set — skipping WhatsApp confirmation.');
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