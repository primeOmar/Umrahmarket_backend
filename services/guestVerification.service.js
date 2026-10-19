// Guest WhatsApp verification for custom package requests, using Twilio's
// Verify API — a purpose-built OTP service. Unlike the Content-Template
// senders in whatsappService.js / agentVerification.service.js, Verify
// manages code generation, delivery, expiry and retry limits for you and
// does NOT need a pre-approved WhatsApp template; it only needs a Verify
// Service configured once in the Twilio Console.
//
// Env vars required:
//   TWILIO_ACCOUNT_SID=ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
//   TWILIO_AUTH_TOKEN=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
//   TWILIO_VERIFY_SERVICE_SID=VAxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
// Create the Verify Service once at twilio.com/console/verify/services —
// enable the WhatsApp channel on it (Verify > your service > Channels).

import twilio from 'twilio';
import logger from '../config/logger.js';

const { TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_VERIFY_SERVICE_SID } = process.env;

let client = null;
if (TWILIO_ACCOUNT_SID?.startsWith('AC') && TWILIO_AUTH_TOKEN) {
  try {
    client = twilio(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN);
  } catch (err) {
    logger.error('[guestVerification] Twilio disabled — invalid credentials', { error: err.message });
  }
}
if (!client || !TWILIO_VERIFY_SERVICE_SID) {
  logger.warn('[guestVerification] Twilio Verify not configured — guest OTP sending is disabled until TWILIO_VERIFY_SERVICE_SID is set.');
}

export const isGuestVerificationConfigured = () => !!(client && TWILIO_VERIFY_SERVICE_SID);

/**
 * Normalise a phone number to E.164. Accepts Kenyan local formats
 * (07xxxxxxxx, 7xxxxxxxx, 2547xxxxxxxx) or any already-international +number.
 */
export function toE164(raw) {
  if (!raw) return null;
  const s = String(raw).trim();
  if (s.startsWith('+')) {
    const digits = s.slice(1).replace(/\D/g, '');
    return digits.length >= 9 && digits.length <= 15 ? `+${digits}` : null;
  }
  const d = s.replace(/\D/g, '');
  if (d.startsWith('254') && d.length === 12) return `+${d}`;
  if (d.startsWith('0') && d.length === 10) return `+254${d.slice(1)}`;
  if ((d.startsWith('7') || d.startsWith('1')) && d.length === 9) return `+254${d}`;
  return null;
}

/**
 * Send a WhatsApp OTP via Twilio Verify.
 * @param {string} e164 Destination phone number, already normalised.
 * @returns {Promise<{ok: boolean, status?: string, error?: string}>}
 */
export async function sendGuestWhatsAppOtp(e164) {
  if (!isGuestVerificationConfigured()) return { ok: false, error: 'Verification is temporarily unavailable. Please try again later.' };
  try {
    const verification = await client.verify.v2.services(TWILIO_VERIFY_SERVICE_SID)
      .verifications.create({ to: e164, channel: 'whatsapp' });
    return { ok: true, status: verification.status };
  } catch (err) {
    logger.error('[guestVerification] OTP send failed', { error: err.message, to: e164 });
    return { ok: false, error: 'Could not send a WhatsApp verification code to that number. Double-check it and try again.' };
  }
}

/**
 * Check a submitted OTP code.
 * @returns {Promise<{ok: boolean, approved?: boolean, error?: string}>}
 */
export async function checkGuestWhatsAppOtp(e164, code) {
  if (!isGuestVerificationConfigured()) return { ok: false, error: 'Verification is temporarily unavailable. Please try again later.' };
  try {
    const check = await client.verify.v2.services(TWILIO_VERIFY_SERVICE_SID)
      .verificationChecks.create({ to: e164, code: String(code) });
    return { ok: true, approved: check.status === 'approved' };
  } catch (err) {
    // Twilio throws (rather than returning "denied") for expired/unknown
    // verification attempts — treat both as "not approved", not a crash.
    logger.warn('[guestVerification] OTP check failed', { error: err.message, to: e164 });
    return { ok: true, approved: false };
  }
}
