/**
 * Onboarding controller.
 *
 *   GET  /api/onboarding/missing      — bulk check across all active bookings
 *                                       (drives the nudge/auto-popup on the
 *                                       client dashboard, same pattern as
 *                                       getFacePhotoStatus for face photos)
 *   GET  /api/onboarding/status       — per-package completeness (drives the
 *                                       post-booking modal itself)
 *   POST /api/onboarding/contact      — save/confirm email + mobile number
 *   POST /api/onboarding/next-of-kin  — save next-of-kin details for a package
 *
 */
import { supabaseAdmin } from '../config/supabase.js';
import logger from '../config/logger.js';

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// Accepts local Kenyan formats (07XXXXXXXX / 01XXXXXXXX), 254XXXXXXXXX, or
// already-international +<country><number>. Normalises to +<digits>.
function normalizePhone(raw) {
  if (!raw) return null;
  let p = String(raw).trim().replace(/[\s\-()]/g, '');

  if (/^0\d{9}$/.test(p)) {
    p = `+254${p.slice(1)}`;
  } else if (/^254\d{9}$/.test(p)) {
    p = `+${p}`;
  } else if (/^\+\d{9,15}$/.test(p)) {
    // already looks international
  } else if (/^\d{9,15}$/.test(p)) {
    p = `+${p}`;
  } else {
    return null;
  }

  return /^\+\d{9,15}$/.test(p) ? p : null;
}

// ── shared state readers ─────────────────────────────────────────────────────
async function getContactState(userId) {
  const { data, error } = await supabaseAdmin
    .from('profiles')
    .select('email, phone')
    .eq('id', userId)
    .maybeSingle();
  if (error) throw new Error(error.message);

  const email = data?.email || null;
  const phone = data?.phone || null;
  return { email, phone, complete: Boolean(email && EMAIL_RE.test(email) && phone) };
}

async function getNextOfKinState(userId, packageId) {
  const { data, error } = await supabaseAdmin
    .from('next_of_kin')
    .select('id, full_name, relationship, phone, email')
    .eq('user_id', userId)
    .eq('package_id', packageId)
    .maybeSingle();
  if (error) throw new Error(error.message);

  return { data: data || null, complete: Boolean(data?.full_name && data?.phone) };
}

async function getPassportState(userId, packageId) {
  const { data, error } = await supabaseAdmin
    .from('passport_verifications')
    .select('verification_status, verified, passport_image_url')
    .eq('user_id', userId)
    .eq('package_id', packageId)
    .maybeSingle();
  if (error) throw new Error(error.message);

  const hasImage = Boolean(data?.passport_image_url) && !data.passport_image_url.startsWith('pending://');
  // Mirrors getPassportStatus()'s canProceed logic in passport.controller.js —
  // verified or manual_review both count as "done" for gating purposes.
  const complete = Boolean(data) && ['verified', 'manual_review'].includes(data.verification_status);

  return { status: data?.verification_status || null, hasImage, complete };
}

// =============================================================================
// GET /api/onboarding/status?packageId=...
// =============================================================================
export const getOnboardingStatus = async (req, res) => {
  try {
    const userId = req.user?.id ?? req.userId;
    const { packageId } = req.query;
    if (!packageId) return res.status(400).json({ success: false, message: 'packageId is required.' });

    const [contact, nextOfKin, passport] = await Promise.all([
      getContactState(userId),
      getNextOfKinState(userId, packageId),
      getPassportState(userId, packageId),
    ]);

    return res.json({
      success: true,
      contact,
      nextOfKin,
      passport,
      allComplete: contact.complete && nextOfKin.complete && passport.complete,
    });
  } catch (err) {
    logger.error('[getOnboardingStatus] failed', { error: err.message });
    return res.status(500).json({ success: false, message: 'Could not load onboarding status.' });
  }
};

// =============================================================================
// GET /api/onboarding/missing  — bulk check across all active bookings
// =============================================================================
export const getMissingOnboarding = async (req, res) => {
  try {
    const userId = req.user?.id ?? req.userId;

    const { data: bookings, error: bErr } = await supabaseAdmin
      .from('bookings')
      .select('id, package_id, status')
      .eq('user_id', userId)
      .in('status', ['confirmed', 'pending']);
    if (bErr) throw new Error(bErr.message);
    if (!bookings?.length) return res.json({ success: true, bookingsMissingDetails: [] });

    const packageIds = [...new Set(bookings.map((b) => b.package_id))];

    const [contact, kinRows, passRows] = await Promise.all([
      getContactState(userId),
      supabaseAdmin.from('next_of_kin').select('package_id, full_name, phone')
        .eq('user_id', userId).in('package_id', packageIds),
      supabaseAdmin.from('passport_verifications').select('package_id, verification_status')
        .eq('user_id', userId).in('package_id', packageIds),
    ]);

    const kinComplete = new Set(
      (kinRows.data || []).filter((k) => k.full_name && k.phone).map((k) => k.package_id)
    );
    const passportComplete = new Set(
      (passRows.data || [])
        .filter((p) => ['verified', 'manual_review'].includes(p.verification_status))
        .map((p) => p.package_id)
    );

    const bookingsMissingDetails = bookings
      .map((b) => ({
        bookingId: b.id,
        packageId: b.package_id,
        missingContact: !contact.complete,
        missingNextOfKin: !kinComplete.has(b.package_id),
        missingPassport: !passportComplete.has(b.package_id),
      }))
      .filter((b) => b.missingContact || b.missingNextOfKin || b.missingPassport);

    return res.json({ success: true, bookingsMissingDetails });
  } catch (err) {
    logger.error('[getMissingOnboarding] failed', { error: err.message });
    return res.status(500).json({ success: false, message: 'Could not check onboarding status.' });
  }
};

// =============================================================================
// POST /api/onboarding/contact  { email, phone }
// =============================================================================
export const saveContactInfo = async (req, res) => {
  try {
    const userId = req.user?.id ?? req.userId;
    const { email, phone } = req.body;

    const cleanEmail = String(email || '').trim().toLowerCase();
    const cleanPhone = normalizePhone(phone);

    if (!cleanEmail || !EMAIL_RE.test(cleanEmail)) {
      return res.status(400).json({ success: false, message: 'A valid email address is required.' });
    }
    if (!cleanPhone) {
      return res.status(400).json({
        success: false,
        message: 'A valid mobile number is required, e.g. 07XXXXXXXX or +2547XXXXXXXX.',
      });
    }

    const { error } = await supabaseAdmin
      .from('profiles')
      .update({ email: cleanEmail, phone: cleanPhone, updated_at: new Date().toISOString() })
      .eq('id', userId);

    if (error) {
      logger.error('[saveContactInfo] update failed', { error: error.message, userId });
      return res.status(500).json({ success: false, message: 'Could not save contact details. Please try again.' });
    }

    logger.info('[saveContactInfo] saved', { userId });
    return res.json({ success: true, contact: { email: cleanEmail, phone: cleanPhone } });
  } catch (err) {
    logger.error('[saveContactInfo] unexpected error', { error: err.message });
    return res.status(500).json({ success: false, message: 'Could not save contact details. Please try again.' });
  }
};

// =============================================================================
// POST /api/onboarding/next-of-kin  { packageId, fullName, relationship, phone, email }
// =============================================================================
export const saveNextOfKin = async (req, res) => {
  try {
    const userId = req.user?.id ?? req.userId;
    const { packageId, fullName, relationship, phone, email } = req.body;

    if (!packageId) return res.status(400).json({ success: false, message: 'packageId is required.' });

    const cleanName = String(fullName || '').trim().slice(0, 100);
    const cleanPhone = normalizePhone(phone);
    const cleanRelationship = relationship ? String(relationship).trim().slice(0, 60) : null;
    const cleanEmail = email ? String(email).trim().toLowerCase() : null;

    if (cleanName.length < 2) {
      return res.status(400).json({ success: false, message: "Next of kin's full name is required." });
    }
    if (!cleanPhone) {
      return res.status(400).json({
        success: false,
        message: 'A valid next-of-kin mobile number is required, e.g. 07XXXXXXXX or +2547XXXXXXXX.',
      });
    }
    if (cleanEmail && !EMAIL_RE.test(cleanEmail)) {
      return res.status(400).json({ success: false, message: 'Next-of-kin email address is invalid.' });
    }

    // Confirm this booking actually belongs to the caller so nobody can write
    // a next-of-kin record against a package they never booked.
    const { data: booking, error: bErr } = await supabaseAdmin
      .from('bookings')
      .select('id')
      .eq('user_id', userId)
      .eq('package_id', packageId)
      .maybeSingle();
    if (bErr) throw new Error(bErr.message);
    if (!booking) {
      return res.status(403).json({ success: false, message: 'No booking found for this package.' });
    }

    const { error } = await supabaseAdmin
      .from('next_of_kin')
      .upsert(
        {
          user_id: userId,
          package_id: packageId,
          booking_id: booking.id,
          full_name: cleanName,
          relationship: cleanRelationship,
          phone: cleanPhone,
          email: cleanEmail,
          updated_at: new Date().toISOString(),
        },
        { onConflict: 'user_id,package_id' }
      );

    if (error) {
      logger.error('[saveNextOfKin] upsert failed', { error: error.message, userId, packageId });
      return res.status(500).json({ success: false, message: 'Could not save next-of-kin details. Please try again.' });
    }

    logger.info('[saveNextOfKin] saved', { userId, packageId });
    return res.json({ success: true });
  } catch (err) {
    logger.error('[saveNextOfKin] unexpected error', { error: err.message });
    return res.status(500).json({ success: false, message: 'Could not save next-of-kin details. Please try again.' });
  }
};

export default { getOnboardingStatus, getMissingOnboarding, saveContactInfo, saveNextOfKin };