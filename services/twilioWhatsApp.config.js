// Single source of truth for the Twilio WhatsApp sender.
//
// Root cause this module fixes: Twilio requires `from` and `to` to be on the
// SAME channel. `to` was always sent as "whatsapp:+2547…", but the sender
// came straight from TWILIO_WHATSAPP_FROM, so a value like "+17372212163"
// (no "whatsapp:" prefix) made Twilio treat it as an SMS sender and reject
// every message with error 21910 "Invalid From and To pair".
//
// Accepted env formats (any of these work):
//   TWILIO_WHATSAPP_FROM=whatsapp:+17372212163
//   TWILIO_WHATSAPP_FROM=+17372212163
//   TWILIO_WHATSAPP_FROM=+1 (737) 221-2163
//   TWILIO_WHATSAPP_FROM=MGxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx      (Messaging Service)
//   TWILIO_WHATSAPP_MESSAGING_SERVICE_SID=MGxxxxxxxx…              (takes precedence)
//
// A Messaging Service must contain a WhatsApp-enabled sender in its pool.

const MG_SID = /^MG[0-9a-f]{32}$/i;

function clean(v) {
  return String(v ?? '').trim().replace(/^['"]|['"]$/g, '').trim();
}

/**
 * Resolve the sender into the exact params Twilio's messages.create needs.
 * @returns {{ ok: true, params: {from?: string, messagingServiceSid?: string}, label: string }
 *         | { ok: false, error: string }}
 */
export function resolveWhatsAppSender(env = process.env) {
  const service = clean(env.TWILIO_WHATSAPP_MESSAGING_SERVICE_SID);
  if (service) {
    if (!MG_SID.test(service)) {
      return { ok: false, error: 'TWILIO_WHATSAPP_MESSAGING_SERVICE_SID must be a Messaging Service SID starting with "MG".' };
    }
    return { ok: true, params: { messagingServiceSid: service }, label: `Messaging Service ${service.slice(0, 6)}…` };
  }

  const raw = clean(env.TWILIO_WHATSAPP_FROM);
  if (!raw) {
    return { ok: false, error: 'WhatsApp sender not configured — set TWILIO_WHATSAPP_FROM (e.g. whatsapp:+17372212163).' };
  }
  if (MG_SID.test(raw)) {
    return { ok: true, params: { messagingServiceSid: raw }, label: `Messaging Service ${raw.slice(0, 6)}…` };
  }

  let num = raw.replace(/^whatsapp:/i, '').replace(/[\s\-().]/g, '');
  if (num.startsWith('00')) num = `+${num.slice(2)}`;
  if (!num.startsWith('+')) num = `+${num}`;
  if (!/^\+[1-9]\d{7,14}$/.test(num)) {
    return { ok: false, error: `TWILIO_WHATSAPP_FROM is not a valid phone number ("${raw}"). Use E.164, e.g. whatsapp:+17372212163.` };
  }
  return { ok: true, params: { from: `whatsapp:${num}` }, label: `whatsapp:${num}` };
}

/** Format any recipient number as a WhatsApp address (same channel as the sender). */
export function toWhatsAppAddress(e164) {
  const n = String(e164 || '').replace(/^whatsapp:/i, '').trim();
  return n ? `whatsapp:${n.startsWith('+') ? n : `+${n}`}` : null;
}

// Twilio errors that mean the *configuration* is broken — every further send
// would fail identically, so bulk sends stop instead of burning through the list.
export const FATAL_CONFIG_CODES = new Set([20003, 20404, 21606, 21910, 63007, 63112]);

// Transient errors worth one retry with backoff.
export const RETRYABLE_CODES = new Set([20429, 63018]);

const FRIENDLY = {
  20003: 'Twilio authentication failed — check TWILIO_ACCOUNT_SID / TWILIO_AUTH_TOKEN.',
  20404: 'Template or sender not found in this Twilio account.',
  20429: 'Twilio rate limit hit — try again shortly.',
  21211: 'Invalid recipient phone number.',
  21408: 'Sending to this country is not enabled on the Twilio account.',
  21606: 'The configured sender number does not belong to this Twilio account or is not WhatsApp-enabled.',
  21610: 'Recipient has opted out (replied STOP).',
  21910: 'Sender/recipient channel mismatch — the sender is not configured as a WhatsApp sender.',
  63003: 'Recipient number is not on WhatsApp.',
  63007: 'The sender number is not registered as a WhatsApp sender in Twilio.',
  63016: 'Outside the 24-hour window — only an approved template can be sent.',
  63018: 'WhatsApp rate limit for this sender reached — try again later.',
  63024: 'Invalid message recipient.',
  63027: 'Template message rejected by WhatsApp (check variables match the approved template).',
  63049: 'Meta did not deliver this marketing message (recipient marketing limits).',
  63112: 'The WhatsApp Business account is disabled or restricted by Meta.',
};

export function friendlyTwilioError(code, fallback) {
  return FRIENDLY[Number(code)] || fallback || 'WhatsApp send failed';
}
