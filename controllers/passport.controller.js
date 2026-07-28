import { supabaseAdmin } from '../config/supabase.js';
import config from '../config/security.config.js';
import logger from '../config/logger.js';
import { extractPassport, compareWithInput } from '../lib/passportOcr.js';
import { uploadPassportBuffer, uploadFacePhotoBuffer } from '../middleware/uploads/PassportUpload.js';

const MAX_ATTEMPTS = 3;
const MIN_VALIDITY_MONTHS = 6;
const MIN_OCR_CONFIDENCE = 45; // below this the read is too noisy to trust a match
const MAX_TRAVELERS_PER_BOOKING = 30; // mirrors services/pricing.service.js

function errText(err) {
  return [err?.message, err?.details, err?.hint].filter(Boolean).join(' | ');
}

function parseMissingColumn(err) {
  const text = errText(err);
  let m = text.match(/Could not find the '([^']+)' column/i);
  if (m?.[1]) return m[1];
  m = text.match(/column\s+\"?(?:[A-Za-z0-9_]+\.)?([A-Za-z0-9_]+)\"?\s+does not exist/i);
  if (m?.[1]) return m[1];
  return null;
}

function isOnConflictSpecError(err) {
  const text = errText(err);
  return err?.code === '42P10'
    || /no unique or exclusion constraint/i.test(text)
    || /on conflict/i.test(text);
}

async function selectMaybeSingleWithFallback({ table, baseFilters, primarySelect, fallbackSelects }) {
  const tries = [primarySelect, ...(fallbackSelects || [])];
  let lastError = null;
  for (const fields of tries) {
    let q = supabaseAdmin.from(table).select(fields);
    baseFilters.forEach(({ op, col, val }) => {
      if (op === 'eq') q = q.eq(col, val);
      if (op === 'in') q = q.in(col, val);
    });
    const { data, error } = await q.maybeSingle();
    if (!error) return { data, usedFields: fields };

    const missing = parseMissingColumn(error);
    if (missing) {
      lastError = error;
      continue;
    }
    throw error;
  }
  if (lastError) throw lastError;
  return { data: null, usedFields: primarySelect };
}

async function upsertWithCompatibility({ row, onConflictCandidates }) {
  const workingRow = { ...row };
  let lastError = null;

  for (let i = 0; i < 12; i++) {
    for (const onConflict of onConflictCandidates) {
      const { error } = await supabaseAdmin
        .from('passport_verifications')
        .upsert(workingRow, { onConflict });

      if (!error) {
        return { ok: true, onConflict, rowKeys: Object.keys(workingRow) };
      }

      const missing = parseMissingColumn(error);
      if (missing && Object.prototype.hasOwnProperty.call(workingRow, missing)) {
        delete workingRow[missing];
        logger.warn('passport upsert fallback: dropping unknown column', { missing, onConflict });
        lastError = error;
        break;
      }

      if (isOnConflictSpecError(error)) {
        lastError = error;
        continue;
      }

      throw error;
    }
  }

  if (lastError) throw lastError;
  throw new Error('Could not save verification record.');
}

// Every traveler needs their own passport verified, regardless of age tier —
// defaults to 0 (the lead/account-holder traveler) so this stays backward
// compatible with any caller that doesn't send travelerIndex at all.
function sanitizeTravelerIndex(v) {
  const n = Number.parseInt(v, 10);
  return Number.isFinite(n) && n >= 0 && n < MAX_TRAVELERS_PER_BOOKING ? n : 0;
}

// ── date helpers (UTC, day-precision) ────────────────────────────────────────
function parseDateOnly(s) {
  if (!s) return null;
  const m = String(s).match(/^(\d{4})-(\d{2})-(\d{2})/);
  if (m) return new Date(Date.UTC(+m[1], +m[2] - 1, +m[3]));
  const d = new Date(s);
  return Number.isNaN(d.getTime()) ? null : new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));
}
function addMonths(date, months) {
  const d = new Date(date.getTime());
  d.setUTCMonth(d.getUTCMonth() + months);
  return d;
}
function todayUTC() {
  const n = new Date();
  return new Date(Date.UTC(n.getUTCFullYear(), n.getUTCMonth(), n.getUTCDate()));
}
function toISODate(d) {
  return d ? d.toISOString().slice(0, 10) : null;
}

// Resolve the travel date for a package (defaults to today if unset, so the
// 6-month rule still gives a safe floor) and compute the minimum valid expiry.
async function resolveTravelWindow(packageId) {
  let travelDate = todayUTC();
  let title = null;
  try {
    const { data } = await supabaseAdmin
      .from('packages')
      .select('available_from, title')
      .eq('id', packageId)
      .single();
    if (data?.available_from) {
      const t = parseDateOnly(data.available_from);
      if (t) travelDate = t;
    }
    title = data?.title || null;
  } catch (e) {
    logger.warn('Could not load package for passport check', { packageId, error: e.message });
  }
  return { travelDate, minExpiry: addMonths(travelDate, MIN_VALIDITY_MONTHS), packageTitle: title };
}

// Shared validity computation. Returns { valid, reason, travelDate, minExpiry, expiry }.
function evaluateExpiry(expiryInput, travelDate, minExpiry) {
  const expiry = parseDateOnly(expiryInput);
  if (!expiry) return { valid: false, reason: 'invalid_expiry', expiry: null };
  if (expiry < todayUTC()) return { valid: false, reason: 'already_expired', expiry };
  if (expiry < minExpiry) return { valid: false, reason: 'insufficient_validity', expiry };
  return { valid: true, reason: null, expiry };
}

// =============================================================================
// POST /api/passport/check  — pre-flight validity (no image, stateless)
// =============================================================================
export const checkPassportValidity = async (req, res) => {
  try {
    const { packageId, passportExpiry } = req.body;
    const travelerIndex = sanitizeTravelerIndex(req.body.travelerIndex);
    if (!packageId) return res.status(400).json({ success: false, error: 'packageId is required.' });

    const { travelDate, minExpiry, packageTitle } = await resolveTravelWindow(packageId);
    const result = evaluateExpiry(passportExpiry, travelDate, minExpiry);

    return res.json({
      success: true,
      travelerIndex,
      valid: result.valid,
      reason: result.reason,
      travelDate: toISODate(travelDate),
      minExpiry: toISODate(minExpiry),
      monthsRequired: MIN_VALIDITY_MONTHS,
      packageTitle,
      message: result.valid
        ? 'Passport meets the validity requirement.'
        : 'Your passport does not have enough validity for this trip. Please renew it (at least 6 months beyond the travel date) and book again.',
    });
  } catch (error) {
    logger.error('checkPassportValidity failed', { error: error.message });
    return res.status(500).json({ success: false, error: 'Validity check failed. Please try again.' });
  }
};

// =============================================================================
// POST /api/passport/verify-image  — OCR + match + persist
// (multipart; req.passportFile set by validatePassportFile middleware)
// =============================================================================
export const verifyPassportImage = async (req, res) => {
  const userId = req.userId;
  const debugRef = `PV-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
  try {
    const {
      packageId, passportNumber, passportCountry,
      passportExpiry, surname, givenNames, dateOfBirth, nationality,
    } = req.body;
    const travelerIndex = sanitizeTravelerIndex(req.body.travelerIndex);

    if (!packageId || !passportNumber || !passportExpiry || !surname) {
      return res.status(400).json({ success: false, error: 'Missing required passport details.' });
    }
    if (!req.passportFile?.buffer) {
      return res.status(400).json({ success: false, error: 'Passport image is required.' });
    }

    logger.info('Starting passport verification', {
      userId, packageId, travelerIndex, passportNumber: `${passportNumber.substring(0, 3)}***`,
      fileSize: req.passportFile.buffer.length,
    });

    // Don't re-verify an already-verified passport for this traveler slot.
    let existing = null;
    try {
      const withTraveler = await supabaseAdmin
        .from('passport_verifications')
        .select('id, attempts, verification_status, face_photo_url')
        .eq('user_id', userId)
        .eq('package_id', packageId)
        .eq('traveler_index', travelerIndex)
        .maybeSingle();

      if (!withTraveler.error) {
        existing = withTraveler.data;
      } else if (parseMissingColumn(withTraveler.error) === 'traveler_index') {
        logger.warn('passport verify fallback: traveler_index missing, using legacy row lookup');
        const legacy = await supabaseAdmin
          .from('passport_verifications')
          .select('id, attempts, verification_status, face_photo_url')
          .eq('user_id', userId)
          .eq('package_id', packageId)
          .maybeSingle();
        if (legacy.error) throw legacy.error;
        existing = legacy.data;
      } else {
        throw withTraveler.error;
      }
    } catch (lookupErr) {
      logger.error('passport existing-row lookup failed', {
        debugRef,
        error: lookupErr.message,
        code: lookupErr.code,
        userId,
        packageId,
        travelerIndex,
      });
      throw lookupErr;
    }

    if (existing?.verification_status === 'verified') {
      logger.info('Passport already verified for this traveler', { userId, packageId, travelerIndex });
      return res.json({
        success: true, status: 'verified', verified: true, canProceed: true,
        travelerIndex,
        facePhotoUrl: existing.face_photo_url || null,
        message: 'Passport already verified for this traveler.',
      });
    }

    // 1) Authoritative expiry / 6-month rule (server side, never trust client).
    const { travelDate, minExpiry } = await resolveTravelWindow(packageId);
    const validity = evaluateExpiry(passportExpiry, travelDate, minExpiry);
    if (!validity.valid) {
      logger.info('Passport expiry check failed', {
        userId, packageId, travelerIndex, reason: validity.reason, passportExpiry,
      });
      await upsertVerification({
        userId, packageId, travelerIndex, status: 'expired_passport', verified: false,
        input: { passportNumber, passportCountry, passportExpiry, surname, givenNames, dateOfBirth, nationality },
        travelDate, attempts: (existing?.attempts || 0),
      });
      return res.json({
        success: true, status: 'rejected', verified: false, canProceed: false,
        travelerIndex,
        reason: validity.reason,
        message: 'Passport does not meet the 6-month validity requirement. Please renew and book again.',
      });
    }

    // 2) OCR the photo and compare against the typed details.
    logger.info('Starting OCR extraction', { userId, packageId, travelerIndex, bufferSize: req.passportFile.buffer.length });
    const ocr = await extractPassport(req.passportFile.buffer);
    const attempts = (existing?.attempts || 0) + 1;

    logger.info('OCR extraction complete', {
      userId, packageId, travelerIndex, ocrOk: ocr.ok, confidence: ocr.confidence,
      mrz: ocr.mrz ? 'found' : 'not_found', reason: ocr.reason,
    });

    let comparison = { score: 0, matched: false, details: {} };
    if (ocr.ok && ocr.confidence >= MIN_OCR_CONFIDENCE) {
      comparison = compareWithInput(ocr.fields, {
        passportNumber, expiry: validity.expiry, surname, givenNames, nationality,
      });
      logger.info('OCR comparison result', {
        userId, packageId, travelerIndex, score: comparison.score, matched: comparison.matched,
        details: comparison.details,
      });
    } else {
      logger.warn('OCR confidence too low or extraction failed', {
        userId, packageId, travelerIndex, ocrOk: ocr.ok, confidence: ocr.confidence, minRequired: MIN_OCR_CONFIDENCE,
      });
    }

    // 3) Always store the image (private R2) so manual reviewers have evidence.
    let stored = null;
    try {
      stored = await uploadPassportBuffer({
        buffer: req.passportFile.buffer,
        mime: req.passportFile.mime,
        ext: req.passportFile.ext,
        userId, packageId, travelerIndex, ip: req.ip,
      });
      logger.info('Passport image uploaded to R2', { userId, packageId, travelerIndex, key: stored.key });
    } catch (uploadError) {
      logger.warn('Passport image upload failed, continuing without stored image', {
        error: uploadError.message,
        stack: uploadError.stack,
        userId,
        packageId,
        travelerIndex,
      });
    }

    // NOTE: passport-page face-photo cropping has been intentionally removed
    // from this step. Clients now provide their own dedicated headshot via
    // FacePhotoModal -> POST /api/passport/face-photo (saveFacePhoto), which
    // is a clearer photo than anything auto-cropped from the passport page
    // and avoids two flows racing to set face_photo_url for the same booking.
    // upsertVerification() below still preserves an existing face_photo_url
    // from that flow (or an earlier one) when this attempt doesn't provide one.
    const facePhoto = null;

    // 4) Decide outcome.
    const autoVerified = ocr.ok && ocr.confidence >= MIN_OCR_CONFIDENCE && comparison.matched;
    let status, canProceed, message;

    if (autoVerified) {
      status = 'verified'; canProceed = true;
      message = 'Passport verified successfully.';
    } else if (attempts >= MAX_ATTEMPTS) {
      status = 'manual_review'; canProceed = true;
      message = 'We could not automatically confirm your passport. Your booking will continue and our team will verify your document manually before travel.';
    } else {
      status = 'pending'; canProceed = false;
      message = !ocr.ok
        ? 'We could not read your passport clearly. Please retake the photo in good lighting with the whole page flat and visible.'
        : 'The photo did not match the details you entered. Please check your details and retake a clear photo.';
    }

    const persisted = await upsertVerification({
      userId, packageId, travelerIndex, status, verified: autoVerified,
      input: { passportNumber, passportCountry, passportExpiry, surname, givenNames, dateOfBirth, nationality },
      ocr, comparison, stored, facePhoto, travelDate, attempts,
    });

    logger.info('Passport verification attempt complete', {
      userId, packageId, travelerIndex, status, attempts,
      ocrOk: ocr.ok, ocrConfidence: ocr.confidence, matchScore: comparison.score,
    });

    return res.json({
      success: true,
      status,
      verified: autoVerified,
      canProceed,
      travelerIndex,
      attemptsUsed: attempts,
      attemptsRemaining: Math.max(0, MAX_ATTEMPTS - attempts),
      ocr: { read: ocr.ok, confidence: ocr.confidence },
      // Booleans only — never echo the raw OCR text / extracted PII back to the client.
      match: { score: comparison.score, fields: comparison.details },
      facePhotoUrl: persisted.facePhotoUrl,
      message,
    });
  } catch (error) {
    const errorMessage = config.env === 'development'
      ? error.message
      : 'Verification failed. Please try again.';

    logger.error('verifyPassportImage failed', {
      debugRef,
      error: error.message,
      stack: error.stack,
      userId,
      body: {
        packageId: req.body?.packageId,
        travelerIndex: req.body?.travelerIndex,
        passportNumber: req.body?.passportNumber,
        passportCountry: req.body?.passportCountry,
        passportExpiry: req.body?.passportExpiry,
        surname: req.body?.surname,
        givenNames: req.body?.givenNames,
        dateOfBirth: req.body?.dateOfBirth,
        nationality: req.body?.nationality,
      },
    });
    return res.status(500).json({ success: false, error: errorMessage, ref: debugRef });
  }
};

// =============================================================================
// GET /api/passport/status?packageId=...&travelerIndex=...
// =============================================================================
export const getPassportStatus = async (req, res) => {
  try {
    const userId = req.user?.id ?? req.userId;
    const { packageId } = req.query;
    const travelerIndex = sanitizeTravelerIndex(req.query.travelerIndex);
    if (!packageId) return res.status(400).json({ success: false, error: 'packageId is required.' });

    const { data, error } = await supabaseAdmin
      .from('passport_verifications')
      .select('verification_status, verified, attempts, match_score, face_photo_url, updated_at')
      .eq('user_id', userId)
      .eq('package_id', packageId)
      .eq('traveler_index', travelerIndex)
      .maybeSingle();

    if (error) throw error; // ← was silently swallowed before (destructured but never checked)

    return res.json({
      success: true,
      travelerIndex,
      exists: !!data,
      status: data?.verification_status || null,
      verified: data?.verified || false,
      canProceed: !!data && ['verified', 'manual_review'].includes(data.verification_status),
      attemptsUsed: data?.attempts || 0,
      attemptsRemaining: Math.max(0, MAX_ATTEMPTS - (data?.attempts || 0)),
      facePhotoUrl: data?.face_photo_url || null,
    });
  } catch (error) {
    logger.error('getPassportStatus failed', { error: error.message, code: error.code });
    return res.status(500).json({ success: false, error: 'Could not load verification status.' });
  }
};

// =============================================================================
// GET /api/passport/status-batch?packageId=...&totalTravelers=...
//
// Returns verification status for EVERY traveler slot (0..totalTravelers-1)
// on a booking in one call, so BookingFlow can tell up front whether *all*
// travelers already have a verified passport (e.g. a returning user who
// verified everyone earlier and got interrupted before payment), and if not,
// exactly which traveler to show the passport form for next — instead of
// gating the whole booking on only the account holder's own passport.
// =============================================================================
export const getPassportStatusBatch = async (req, res) => {
  try {
    const userId = req.user?.id ?? req.userId;
    const { packageId } = req.query;
    const totalTravelers = Math.max(1, Math.min(MAX_TRAVELERS_PER_BOOKING, Number.parseInt(req.query.totalTravelers, 10) || 1));
    if (!packageId) return res.status(400).json({ success: false, error: 'packageId is required.' });

    const indices = Array.from({ length: totalTravelers }, (_, i) => i);
    const { data, error } = await supabaseAdmin
      .from('passport_verifications')
      .select('traveler_index, verification_status, verified, attempts, face_photo_url')
      .eq('user_id', userId)
      .eq('package_id', packageId)
      .in('traveler_index', indices);

    if (error) throw error;

    const byIndex = new Map((data || []).map((row) => [row.traveler_index, row]));
    const travelers = indices.map((i) => {
      const row = byIndex.get(i);
      return {
        travelerIndex:     i,
        exists:            !!row,
        status:            row?.verification_status || null,
        verified:          row?.verified || false,
        canProceed:        !!row && ['verified', 'manual_review'].includes(row.verification_status),
        attemptsUsed:      row?.attempts || 0,
        attemptsRemaining: Math.max(0, MAX_ATTEMPTS - (row?.attempts || 0)),
        facePhotoUrl:      row?.face_photo_url || null,
      };
    });

    const allCanProceed = travelers.every((t) => t.canProceed);
    const nextIncompleteIndex = travelers.findIndex((t) => !t.canProceed);

    return res.json({
      success: true,
      totalTravelers,
      travelers,
      allCanProceed,
      nextIncompleteIndex: nextIncompleteIndex === -1 ? null : nextIncompleteIndex,
    });
  } catch (error) {
    logger.error('getPassportStatusBatch failed', { error: error.message, code: error.code });
    return res.status(500).json({ success: false, error: 'Could not load verification status.' });
  }
};

// ── persistence helper (upsert on user_id+package_id+traveler_index) ────────
async function upsertVerification({ userId, packageId, travelerIndex = 0, status, verified, input, ocr, comparison, stored, facePhoto, travelDate, attempts }) {
  const row = {
    user_id: userId,
    package_id: packageId,
    traveler_index: travelerIndex,
    passport_number: input.passportNumber,
    passport_country: input.passportCountry || (ocr?.fields?.issuingCountry ?? 'UNK'),
    passport_expiry: input.passportExpiry,
    travel_date: toISODate(travelDate),
    surname: input.surname || null,
    given_names: input.givenNames || null,
    full_name: [input.givenNames, input.surname].filter(Boolean).join(' ') || null,
    date_of_birth: input.dateOfBirth || null,
    nationality: ocr?.fields?.nationality || input.nationality || null,
    verification_status: status,
    verified: !!verified,
    attempts,
    last_attempt_at: new Date().toISOString(),
    verified_at: verified ? new Date().toISOString() : null,
  };
  if (stored) {
    row.passport_image_url = stored.url;
    row.image_key = stored.key;
  }
  if (facePhoto) {
    row.face_photo_url = facePhoto.url;
    row.face_photo_key = facePhoto.key;
  }
  if (ocr) {
    row.mrz_raw = ocr.mrz || null;
    row.ocr_confidence = ocr.confidence ?? null;
  }
  if (comparison) {
    row.match_score = comparison.score ?? null;
    row.match_details = comparison.details || null;
  }
  // passport_image_url is NOT NULL in the schema; on the expired-passport path
  // (no upload) we only reach here when a row may not yet exist, so guard it.
  // Also resolve face_photo_url here: if this attempt didn't produce a fresh
  // crop (e.g. OCR failed, or the crop step itself failed) but an earlier
  // attempt already has one stored, keep it rather than clearing it.
  let resolvedFacePhotoUrl = facePhoto?.url || null;
  if (!row.passport_image_url || !row.face_photo_url) {
    let prev = null;
    try {
      const primary = await selectMaybeSingleWithFallback({
        table: 'passport_verifications',
        baseFilters: [
          { op: 'eq', col: 'user_id', val: userId },
          { op: 'eq', col: 'package_id', val: packageId },
          { op: 'eq', col: 'traveler_index', val: travelerIndex },
        ],
        primarySelect: 'passport_image_url, image_key, face_photo_url, face_photo_key',
        fallbackSelects: ['passport_image_url, face_photo_url'],
      });
      prev = primary.data;
    } catch (err) {
      if (parseMissingColumn(err) === 'traveler_index') {
        const legacy = await selectMaybeSingleWithFallback({
          table: 'passport_verifications',
          baseFilters: [
            { op: 'eq', col: 'user_id', val: userId },
            { op: 'eq', col: 'package_id', val: packageId },
          ],
          primarySelect: 'passport_image_url, image_key, face_photo_url, face_photo_key',
          fallbackSelects: ['passport_image_url, face_photo_url'],
        });
        prev = legacy.data;
      } else {
        throw err;
      }
    }

    if (!row.passport_image_url) {
      if (prev?.passport_image_url) {
        row.passport_image_url = prev.passport_image_url;
        row.image_key = prev.image_key;
      } else {
        row.passport_image_url = 'pending://no-image';
      }
    }
    if (!row.face_photo_url && prev?.face_photo_url) {
      row.face_photo_url = prev.face_photo_url;
      row.face_photo_key = prev.face_photo_key;
      resolvedFacePhotoUrl = prev.face_photo_url;
    }
  }

  try {
    const result = await upsertWithCompatibility({
      row,
      onConflictCandidates: ['user_id,package_id,traveler_index', 'user_id,package_id'],
    });
    logger.info('passport_verifications upsert success', {
      userId,
      packageId,
      travelerIndex,
      onConflict: result.onConflict,
      rowKeys: result.rowKeys,
    });
  } catch (error) {
    logger.error('passport_verifications upsert failed', {
      error: error.message,
      code: error.code,
      details: error.details,
      hint: error.hint,
      userId,
      packageId,
      travelerIndex,
      rowKeys: Object.keys(row),
    });
    throw new Error('Could not save verification record.');
  }

  return { facePhotoUrl: resolvedFacePhotoUrl };
}

// =============================================================================
// GET /api/passport/face-photo-status
// =============================================================================
// Returns every confirmed/pending booking for this user that does NOT yet
// have a face_photo_url in passport_verifications.
// Response: { bookingsMissingPhoto: [{ bookingId, packageId }] }
export async function getFacePhotoStatus(req, res) {
  const userId = req.user?.id ?? req.userId;
  try {
    // 1. Fetch the user's active bookings
    const { data: bookings, error: bErr } = await supabaseAdmin
      .from('bookings')
      .select('id, package_id, status')
      .eq('user_id', userId)
      .in('status', ['confirmed', 'pending']);

    if (bErr) throw new Error(bErr.message);
    if (!bookings?.length) {
      return res.json({ bookingsMissingPhoto: [] });
    }

    const packageIds = bookings.map((b) => b.package_id);

    // 2. Fetch existing verifications that already have a face photo
    const { data: verifications, error: vErr } = await supabaseAdmin
      .from('passport_verifications')
      .select('package_id, face_photo_url')
      .eq('user_id', userId)
      .in('package_id', packageIds);

    if (vErr) throw new Error(vErr.message);

    // Build a set of package IDs that already have a photo
    const hasPhoto = new Set(
      (verifications ?? [])
        .filter((v) => v.face_photo_url && !v.face_photo_url.startsWith('pending://'))
        .map((v) => v.package_id),
    );

    // 3. Return bookings where the face photo is still missing
    const bookingsMissingPhoto = bookings
      .filter((b) => !hasPhoto.has(b.package_id))
      .map((b) => ({ bookingId: b.id, packageId: b.package_id }));

    return res.json({ bookingsMissingPhoto });
  } catch (err) {
    logger.error('getFacePhotoStatus error', { userId, error: err.message });
    return res.status(500).json({ error: 'Could not check face photo status.' });
  }
}

// =============================================================================
// POST /api/passport/face-photo
// =============================================================================
// Saves the pilgrim's dedicated selfie (taken or uploaded in FacePhotoModal
// after a successful payment). This photo is stored as public-read in R2 and
// written to passport_verifications.face_photo_url so that:
//   - the agent dashboard can embed it on the Umrah ID card PDF
//   - getFacePhotoStatus no longer returns this booking as missing a photo
//
// multipart/form-data: field "face" (single image) + field "packageId"
export async function saveFacePhoto(req, res) {
  const userId = req.user?.id ?? req.userId;
  try {
    const { packageId } = req.body;
    if (!packageId) {
      return res.status(400).json({ success: false, error: 'packageId is required.' });
    }
    if (!req.file?.buffer) {
      return res.status(400).json({ success: false, error: 'Face photo is required.' });
    }

    // Deep MIME check on the buffer (same logic as validatePassportFile).
    const { fileTypeFromBuffer } = await import('file-type');
    const ALLOWED_MIMES = ['image/jpeg', 'image/png', 'image/webp'];
    const detected = await fileTypeFromBuffer(req.file.buffer);
    if (!detected || !ALLOWED_MIMES.includes(detected.mime)) {
      return res.status(400).json({
        success: false,
        error: 'File type verification failed. Only JPEG, PNG, and WebP images are allowed.',
      });
    }

    // Confirm the user has a confirmed/pending booking for this package
    // so random users can't write photos to arbitrary package slots.
    const { data: booking, error: bErr } = await supabaseAdmin
      .from('bookings')
      .select('id, status, traveler_count')
      .eq('user_id', userId)
      .eq('package_id', packageId)
      .in('status', ['confirmed', 'pending'])
      .maybeSingle();

    if (bErr) {
      logger.error('saveFacePhoto booking check failed', { error: bErr.message, userId, packageId });
      return res.status(500).json({ success: false, error: 'Could not verify booking. Please try again.' });
    }
    if (!booking) {
      return res.status(403).json({
        success: false,
        error: 'No confirmed booking found for this package.',
      });
    }

    // A verified (or manual-review) passport is mandatory for EVERY traveler
    // on this booking — not just the account holder's — since BookingFlow now
    // walks each adult/child/minor_child/infant through its own passport
    // check before payment. Enforce it here too so this endpoint can't be
    // hit directly to bypass verification for any traveler on the booking.
    const totalTravelers = Math.max(1, booking.traveler_count || 1);
    const travelerIndices = Array.from({ length: totalTravelers }, (_, i) => i);
    const { data: existingRows, error: existErr } = await supabaseAdmin
      .from('passport_verifications')
      .select('traveler_index, verification_status')
      .eq('user_id', userId)
      .eq('package_id', packageId)
      .in('traveler_index', travelerIndices);

    if (existErr) {
      logger.error('saveFacePhoto passport check failed', { error: existErr.message, userId, packageId });
      return res.status(500).json({ success: false, error: 'Could not verify booking. Please try again.' });
    }

    const verifiedByIndex = new Map((existingRows || []).map((r) => [r.traveler_index, r.verification_status]));
    const allVerified = travelerIndices.every((i) => ['verified', 'manual_review'].includes(verifiedByIndex.get(i)));

    if (!allVerified) {
      logger.warn('saveFacePhoto rejected — not every traveler on this booking has a verified passport', {
        userId, packageId, totalTravelers,
        statuses: travelerIndices.map((i) => verifiedByIndex.get(i) || 'none'),
      });
      return res.status(403).json({
        success: false,
        error: 'Please complete passport verification for every traveler on this booking before submitting your ID photo.',
      });
    }

    // Upload to R2 (public-read, just the headshot — no PII baked in).
    const facePhoto = await uploadFacePhotoBuffer({
      buffer: req.file.buffer,
      mime: detected.mime,
      ext: detected.ext,
      userId,
      packageId,
    });

    logger.info('Dedicated face photo uploaded', { userId, packageId, key: facePhoto.key });

    // Patch only the face photo fields — never touch the verification fields.
    const { error: upErr } = await supabaseAdmin
      .from('passport_verifications')
      .update({
        face_photo_url: facePhoto.url,
        face_photo_key: facePhoto.key,
      })
      .eq('user_id', userId)
      .eq('package_id', packageId);

    if (upErr) {
      logger.error('saveFacePhoto update failed', { error: upErr.message, userId, packageId });
      return res.status(500).json({ success: false, error: 'Could not save photo. Please try again.' });
    }

    return res.json({
      success: true,
      facePhotoUrl: facePhoto.url,
      message: 'Face photo saved successfully.',
    });
  } catch (err) {
    logger.error('saveFacePhoto unexpected error', { error: err.message, userId });
    return res.status(500).json({ success: false, error: 'Could not save photo. Please try again.' });
  }
}

export default { checkPassportValidity, verifyPassportImage, getPassportStatus, getPassportStatusBatch, getFacePhotoStatus, saveFacePhoto };