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
 * This does NOT touch passport document scanning/OCR (that's a separate,
 * pre-existing flow in passport.controller.js — checkPassportValidity /
 * verifyPassportImage). The "idPhoto" completeness here tracks a different,
 * simpler thing: the dedicated Umrah ID photo the client uploads/takes
 * directly (plain background, no OCR, no cropping) via
 * POST /api/passport/face-photo (saveFacePhoto), which writes to the same
 * passport_verifications.face_photo_url column.
 */
import { supabaseAdmin } from '../config/supabase.js';
import logger from '../config/logger.js';

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function errText(err) {
  return [err?.message, err?.details, err?.hint].filter(Boolean).join(' | ');
}

function parseMissingColumn(err) {
  const text = errText(err);
  let m = text.match(/Could not find the '([^']+)' column/i);
  if (m?.[1]) return m[1];
  m = text.match(/column\s+"?(?:[A-Za-z0-9_]+\.)?([A-Za-z0-9_]+)"?\s+does not exist/i);
  if (m?.[1]) return m[1];
  return null;
}

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

async function getActiveBookingState(userId, packageId) {
  const { data, error } = await supabaseAdmin
    .from('bookings')
    .select('id, traveler_count, status, created_at')
    .eq('user_id', userId)
    .eq('package_id', packageId)
    .in('status', ['confirmed', 'pending'])
    .order('created_at', { ascending: false })
    .limit(1);

  if (error) throw new Error(error.message);
  const booking = Array.isArray(data) ? data[0] : null;
  if (!booking) return null;
  return {
    id: booking.id,
    travelerCount: Math.max(1, Number(booking.traveler_count) || 1),
    status: booking.status,
  };
}

// This checks the DEDICATED Umrah ID photo (a plain-background, forward-facing
// photo the client uploads/takes directly — no OCR, no cropping). It is
// intentionally separate from passport *document* verification: that's a
// different, pre-existing flow (checkPassportValidity / verifyPassportImage)
// that this onboarding step does not gate on.
async function getIdPhotoState(userId, packageId, travelerCount = 1) {
  const { data, error } = await supabaseAdmin
    .from('passport_verifications')
    .select('traveler_index, face_photo_url')
    .eq('user_id', userId)
    .eq('package_id', packageId)
    .order('traveler_index', { ascending: true });

  if (error) {
    // Legacy fallback where traveler_index may not exist yet.
    if (parseMissingColumn(error) === 'traveler_index') {
      const legacy = await supabaseAdmin
        .from('passport_verifications')
        .select('face_photo_url')
        .eq('user_id', userId)
        .eq('package_id', packageId);
      if (legacy.error) throw new Error(legacy.error.message);

      const url = (legacy.data || []).find((r) => r.face_photo_url && !r.face_photo_url.startsWith('pending://'))?.face_photo_url || null;
      return {
        url,
        complete: Boolean(url),
        totalTravelers: travelerCount,
        completedTravelers: Boolean(url) ? 1 : 0,
        travelerPhotos: url ? [{ travelerIndex: 0, url, complete: true }] : [],
      };
    }
    throw new Error(error.message);
  }

  const rows = data || [];
  const travelerPhotos = Array.from({ length: travelerCount }, (_, i) => {
    const row = rows.find((r) => Number(r.traveler_index ?? 0) === i);
    const url = row?.face_photo_url || null;
    const complete = Boolean(url) && !String(url).startsWith('pending://');
    return { travelerIndex: i, url: complete ? url : null, complete };
  });

  const completedTravelers = travelerPhotos.filter((p) => p.complete).length;
  const firstUrl = travelerPhotos.find((p) => p.complete)?.url || null;

  return {
    url: firstUrl,
    complete: completedTravelers >= travelerCount,
    totalTravelers: travelerCount,
    completedTravelers,
    travelerPhotos,
  };
}

// This is the authoritative traveler identity list for a package: name and
// passport number as captured during the booking's passport scan (the
// existing checkPassportValidity/verifyPassportImage flow in
// passport.controller.js), keyed by traveler_index. It exists so the ID
// photo step can show the client WHO they are about to attach a photo to —
// sourced from the database, never from client-supplied labels — which is
// what prevents "traveler 2's photo saved under traveler 1's slot" mistakes
// on multi-traveler bookings.
//
// A traveler slot with no matching passport_verifications row means the
// booking flow never captured that traveler's identity yet. We deliberately
// do NOT let the client attach a photo to that slot (see
// resolveTravelerForPhotoUpload below) — there would be nothing to bind the
// photo to and no way to show the client whose photo they're taking.
function maskPassportNumber(raw) {
  const v = String(raw || '').trim();
  if (v.length <= 4) return v ? '••••' : null;
  return `${'•'.repeat(Math.max(0, v.length - 4))}${v.slice(-4)}`;
}

async function getTravelerIdentities(userId, packageId, travelerCount = 1) {
  const { data, error } = await supabaseAdmin
    .from('passport_verifications')
    .select('id, traveler_index, given_names, surname, full_name, passport_number, date_of_birth, face_photo_url')
    .eq('user_id', userId)
    .eq('package_id', packageId)
    .order('traveler_index', { ascending: true });

  if (error) {
    if (parseMissingColumn(error) === 'traveler_index') {
      // Legacy single-traveler fallback, mirrors getIdPhotoState's fallback.
      const legacy = await supabaseAdmin
        .from('passport_verifications')
        .select('given_names, surname, full_name, passport_number, date_of_birth, face_photo_url')
        .eq('user_id', userId)
        .eq('package_id', packageId)
        .maybeSingle();
      if (legacy.error) throw new Error(legacy.error.message);
      const row = legacy.data;
      const name = row?.full_name || [row?.given_names, row?.surname].filter(Boolean).join(' ') || null;
      return Array.from({ length: travelerCount }, (_, i) => ({
        travelerIndex: i,
        hasIdentity: i === 0 && Boolean(name),
        name: i === 0 && name ? name : null,
        passportNumberMasked: i === 0 ? maskPassportNumber(row?.passport_number) : null,
        dateOfBirth: i === 0 ? row?.date_of_birth || null : null,
        photoAttached: i === 0 ? Boolean(row?.face_photo_url) && !String(row.face_photo_url).startsWith('pending://') : false,
        // Legacy rows have no id selected in this fallback query — without a
        // traveler_index column there's only ever one traveler anyway, so
        // there's nothing to disambiguate and no verificationId is needed.
        verificationId: null,
      }));
    }
    throw new Error(error.message);
  }

  const rows = data || [];
  return Array.from({ length: travelerCount }, (_, i) => {
    const row = rows.find((r) => Number(r.traveler_index ?? 0) === i);
    const name = row?.full_name || [row?.given_names, row?.surname].filter(Boolean).join(' ').trim() || null;
    return {
      travelerIndex: i,
      hasIdentity: Boolean(row && name),
      name: name || null,
      passportNumberMasked: row ? maskPassportNumber(row.passport_number) : null,
      dateOfBirth: row?.date_of_birth || null,
      photoAttached: Boolean(row?.face_photo_url) && !String(row?.face_photo_url).startsWith('pending://'),
      // Echoed back by the client on POST /api/passport/face-photo as
      // travelerVerificationId — the server rejects the upload if it
      // doesn't match the row actually at this index at write time. See
      // resolveTravelerForPhotoUpload / saveFacePhoto's identity-binding
      // check.
      verificationId: row?.id || null,
    };
  });
}

// ── used by passport.controller.js (saveFacePhoto) ──────────────────────────
// Server-side authority for "is this travelerIndex a legitimate target for
// this user's photo upload, and who does it belong to". The upload handler
// must call this — and must NOT trust a client-supplied traveler name or
// passport number — before writing any file. Throws a typed error the
// controller can map to the right HTTP status.
export async function resolveTravelerForPhotoUpload(userId, packageId, travelerIndex) {
  if (!packageId) {
    const e = new Error('packageId is required.'); e.status = 400; throw e;
  }
  const idx = Number(travelerIndex);
  if (!Number.isInteger(idx) || idx < 0) {
    const e = new Error('A valid travelerIndex is required.'); e.status = 400; throw e;
  }

  const booking = await getActiveBookingState(userId, packageId);
  if (!booking) {
    const e = new Error('No active booking found for this package.'); e.status = 403; throw e;
  }
  if (idx >= booking.travelerCount) {
    const e = new Error('travelerIndex is out of range for this booking.'); e.status = 400; throw e;
  }

  const { data: row, error } = await supabaseAdmin
    .from('passport_verifications')
    .select('id, traveler_index, given_names, surname, full_name, passport_number')
    .eq('user_id', userId)
    .eq('package_id', packageId)
    .eq('traveler_index', idx)
    .maybeSingle();
  if (error && parseMissingColumn(error) !== 'traveler_index') throw new Error(error.message);

  const name = row?.full_name || [row?.given_names, row?.surname].filter(Boolean).join(' ').trim() || null;
  if (!row || !name) {
    const e = new Error(
      'This traveler\u2019s passport details have not been captured yet. Please complete their passport scan before adding a photo.'
    );
    e.status = 409;
    throw e;
  }

  return {
    verificationId: row.id,
    bookingId: booking.id,
    travelerIndex: idx,
    name,
    passportNumberMasked: maskPassportNumber(row.passport_number),
  };
}

// =============================================================================
// GET /api/onboarding/status?packageId=...
// =============================================================================
export const getOnboardingStatus = async (req, res) => {
  try {
    const userId = req.user?.id ?? req.userId;
    const { packageId } = req.query;
    if (!packageId) return res.status(400).json({ success: false, message: 'packageId is required.' });

    const booking = await getActiveBookingState(userId, packageId);
    if (!booking) {
      return res.status(403).json({ success: false, message: 'No active booking found for this package.' });
    }

    const [contact, nextOfKin, idPhoto, travelers] = await Promise.all([
      getContactState(userId),
      getNextOfKinState(userId, packageId),
      getIdPhotoState(userId, packageId, booking.travelerCount),
      getTravelerIdentities(userId, packageId, booking.travelerCount),
    ]);

    return res.json({
      success: true,
      booking: { id: booking.id, travelerCount: booking.travelerCount, status: booking.status },
      contact,
      nextOfKin,
      idPhoto,
      // DB-sourced identity per traveler slot (name + masked passport number),
      // used by the client to show/confirm WHO a photo is being attached to
      // before upload. Never derived from anything the client sent us.
      travelers,
      allComplete: contact.complete && nextOfKin.complete && idPhoto.complete,
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
      .select('id, package_id, traveler_count, status')
      .eq('user_id', userId)
      .in('status', ['confirmed', 'pending']);
    if (bErr) throw new Error(bErr.message);
    if (!bookings?.length) return res.json({ success: true, bookingsMissingDetails: [] });

    const packageIds = [...new Set(bookings.map((b) => b.package_id))];

    const [contact, kinRows, idPhotoRows] = await Promise.all([
      getContactState(userId),
      supabaseAdmin.from('next_of_kin').select('package_id, full_name, phone')
        .eq('user_id', userId).in('package_id', packageIds),
      supabaseAdmin.from('passport_verifications').select('package_id, traveler_index, face_photo_url')
        .eq('user_id', userId).in('package_id', packageIds),
    ]);

    const kinComplete = new Set(
      (kinRows.data || []).filter((k) => k.full_name && k.phone).map((k) => k.package_id)
    );
    const photoCoverage = new Map();
    const indexColumnMissing = parseMissingColumn(idPhotoRows.error) === 'traveler_index';

    if (!idPhotoRows.error) {
      (idPhotoRows.data || []).forEach((row) => {
        if (!row.face_photo_url || row.face_photo_url.startsWith('pending://')) return;
        const pkg = row.package_id;
        if (!photoCoverage.has(pkg)) photoCoverage.set(pkg, new Set());
        photoCoverage.get(pkg).add(Number(row.traveler_index ?? 0));
      });
    }

    const bookingsMissingDetails = bookings
      .map((b) => ({
        bookingId: b.id,
        packageId: b.package_id,
        missingContact: !contact.complete,
        missingNextOfKin: !kinComplete.has(b.package_id),
        missingIdPhoto: (() => {
          const expected = Math.max(1, Number(b.traveler_count) || 1);
          const covered = photoCoverage.get(b.package_id) || new Set();

          if (indexColumnMissing) {
            // Legacy mode: treat any uploaded photo as completion for single-traveler behavior.
            return covered.size === 0;
          }

          if (covered.size === 0) return true;
          return covered.size < expected;
        })(),
      }))
      .filter((b) => b.missingContact || b.missingNextOfKin || b.missingIdPhoto);

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
        message: 'A valid mobile number with country code is required, e.g. +2547XXXXXXXX or +447XXXXXXXXX.',
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
        message: 'A valid next-of-kin mobile number with country code is required, e.g. +2547XXXXXXXX or +447XXXXXXXXX.',
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