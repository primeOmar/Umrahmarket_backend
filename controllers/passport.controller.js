import { supabaseAdmin } from '../config/supabase.js';
import config from '../config/security.config.js';
import logger from '../config/logger.js';
import { extractPassport, compareWithInput } from '../lib/passportOcr.js';
import { uploadPassportBuffer, uploadFacePhotoBuffer } from '../middleware/uploads/PassportUpload.js';
import { evaluatePassportStatusForBooking } from '../services/passportStatus.service.js';

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

async function selectFirstWithFallback({ table, baseFilters, primarySelect, fallbackSelects, orderBy = 'last_attempt_at' }) {
  const tries = [primarySelect, ...(fallbackSelects || [])];
  let lastError = null;
  for (const fields of tries) {
    for (const useOrder of [true, false]) {
      let q = supabaseAdmin.from(table).select(fields);
      baseFilters.forEach(({ op, col, val }) => {
        if (op === 'eq') q = q.eq(col, val);
        if (op === 'in') q = q.in(col, val);
      });

      if (useOrder && orderBy) {
        q = q.order(orderBy, { ascending: false });
      }
      const { data, error } = await q.limit(1);
      if (!error) return { data: Array.isArray(data) ? (data[0] || null) : null, usedFields: fields };

      const missing = parseMissingColumn(error);
      if (!missing) throw error;

      // If the ORDER BY column is missing, retry once without ordering.
      if (useOrder && orderBy && missing === orderBy) {
        lastError = error;
        continue;
      }

      // Missing selected/filter column — try the next field projection.
      lastError = error;
      break;
    }
  }
  if (lastError) throw lastError;
  return { data: null, usedFields: primarySelect };
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

  // If conflict/index assumptions are wrong in production, fall back to a
  // manual update/insert flow that does not depend on ON CONFLICT.
  let idRow = null;
  try {
    const byTraveler = await selectFirstWithFallback({
      table: 'passport_verifications',
      baseFilters: [
        { op: 'eq', col: 'user_id', val: workingRow.user_id },
        { op: 'eq', col: 'package_id', val: workingRow.package_id },
        { op: 'eq', col: 'traveler_index', val: workingRow.traveler_index ?? 0 },
      ],
      primarySelect: 'id',
      fallbackSelects: [],
    });
    idRow = byTraveler.data;
  } catch (findErr) {
    if (parseMissingColumn(findErr) === 'traveler_index') {
      const legacy = await selectFirstWithFallback({
        table: 'passport_verifications',
        baseFilters: [
          { op: 'eq', col: 'user_id', val: workingRow.user_id },
          { op: 'eq', col: 'package_id', val: workingRow.package_id },
        ],
        primarySelect: 'id',
        fallbackSelects: [],
      });
      idRow = legacy.data;
      delete workingRow.traveler_index;
    } else {
      throw findErr;
    }
  }

  for (let i = 0; i < 12; i++) {
    if (idRow?.id) {
      const { error: updateErr } = await supabaseAdmin
        .from('passport_verifications')
        .update(workingRow)
        .eq('id', idRow.id);
      if (!updateErr) {
        return { ok: true, onConflict: 'manual-update', rowKeys: Object.keys(workingRow) };
      }
      const missing = parseMissingColumn(updateErr);
      if (missing && Object.prototype.hasOwnProperty.call(workingRow, missing)) {
        delete workingRow[missing];
        logger.warn('passport update fallback: dropping unknown column', { missing, mode: 'manual-update' });
        continue;
      }
      throw updateErr;
    }

    const { error: insertErr } = await supabaseAdmin
      .from('passport_verifications')
      .insert(workingRow);
    if (!insertErr) {
      return { ok: true, onConflict: 'manual-insert', rowKeys: Object.keys(workingRow) };
    }
    const missing = parseMissingColumn(insertErr);
    if (missing && Object.prototype.hasOwnProperty.call(workingRow, missing)) {
      delete workingRow[missing];
      logger.warn('passport insert fallback: dropping unknown column', { missing, mode: 'manual-insert' });
      continue;
    }
    throw insertErr;
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

// Stricter variant for saveFacePhoto only: unlike the other passport
// endpoints (where an omitted travelerIndex legitimately means "the lead
// traveler"), silently defaulting an invalid index to 0 here would mean a
// client-side bug could quietly attach every photo to traveler 0 without
// anyone noticing. This returns null on anything invalid so the caller can
// reject the request instead of guessing.
function strictTravelerIndex(v) {
  if (v === undefined || v === null || v === '') return null;
  const n = Number.parseInt(v, 10);
  return Number.isFinite(n) && n >= 0 && n < MAX_TRAVELERS_PER_BOOKING ? n : null;
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
      const withTraveler = await selectFirstWithFallback({
        table: 'passport_verifications',
        baseFilters: [
          { op: 'eq', col: 'user_id', val: userId },
          { op: 'eq', col: 'package_id', val: packageId },
          { op: 'eq', col: 'traveler_index', val: travelerIndex },
        ],
        primarySelect: 'id, attempts, verification_status, face_photo_url',
        fallbackSelects: ['id, attempts, verification_status, face_photo_url'],
      });
      existing = withTraveler.data;
    } catch (lookupErr) {
      if (parseMissingColumn(lookupErr) === 'traveler_index') {
        logger.warn('passport verify fallback: traveler_index missing, using legacy row lookup');
        const legacy = await selectFirstWithFallback({
          table: 'passport_verifications',
          baseFilters: [
            { op: 'eq', col: 'user_id', val: userId },
            { op: 'eq', col: 'package_id', val: packageId },
          ],
          primarySelect: 'id, attempts, verification_status, face_photo_url',
          fallbackSelects: ['id, attempts, verification_status, face_photo_url'],
        });
        existing = legacy.data;
      } else {
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
    }

    if (!existing) {
      logger.info('No existing passport row found; creating fresh verification record', {
        debugRef,
        userId,
        packageId,
        travelerIndex,
      });
    }

    try {
      // no-op; keeps scope for catch logging consistency
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
    let ocr;
    try {
      ocr = await extractPassport(req.passportFile.buffer);
    } catch (ocrErr) {
      // A crash/timeout in the OCR library shouldn't 500 the whole request —
      // treat it the same as "could not read the passport" so the user gets
      // a retry prompt (or manual review after MAX_ATTEMPTS) instead of a
      // generic server error.
      logger.error('extractPassport threw', {
        debugRef, userId, packageId, travelerIndex,
        error: ocrErr.message, stack: ocrErr.stack,
      });
      ocr = { ok: false, confidence: 0, reason: 'ocr_error', fields: {}, mrz: null };
    }
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

    const { data, error } = await supabaseAdmin
      .from('passport_verifications')
      .select('traveler_index, verification_status, verified, attempts, face_photo_url')
      .eq('user_id', userId)
      .eq('package_id', packageId)
      .order('traveler_index', { ascending: true });

    if (error) throw error;

    const evaluation = evaluatePassportStatusForBooking({
      passportRows: data || [],
      totalTravelers,
    });

    return res.json({
      success: true,
      totalTravelers: evaluation.totalTravelers,
      travelers: evaluation.travelers,
      allCanProceed: evaluation.allCanProceed,
      nextIncompleteIndex: evaluation.nextIncompleteIndex === -1 ? null : evaluation.nextIncompleteIndex,
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
      const primary = await selectFirstWithFallback({
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
        const legacy = await selectFirstWithFallback({
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
      .select('id, package_id, status, traveler_count')
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
      .select('package_id, traveler_index, face_photo_url')
      .eq('user_id', userId)
      .in('package_id', packageIds);

    if (vErr) throw new Error(vErr.message);

    // Build package -> covered traveler indices
    const coveredByPackage = new Map();
    (verifications || []).forEach((row) => {
      if (!row.face_photo_url || row.face_photo_url.startsWith('pending://')) return;
      if (!coveredByPackage.has(row.package_id)) coveredByPackage.set(row.package_id, new Set());
      coveredByPackage.get(row.package_id).add(Number(row.traveler_index ?? 0));
    });

    // 3. Return bookings where the face photo is still missing
    const bookingsMissingPhoto = bookings
      .filter((b) => {
        const expected = Math.max(1, Number(b.traveler_count) || 1);
        const covered = coveredByPackage.get(b.package_id)?.size || 0;
        return covered < expected;
      })
      .map((b) => ({
        bookingId: b.id,
        packageId: b.package_id,
        travelerCount: Math.max(1, Number(b.traveler_count) || 1),
      }));

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
// multipart/form-data fields:
//   face                    — the image (required)
//   packageId               — (required)
//   bookingId               — optional, disambiguates when a user has more
//                             than one booking for the same package
//   travelerIndex           — required if the booking has more than one
//                             traveler; defaults to 0 for single-traveler
//                             bookings (backward compatible with the older
//                             FacePhotoModal flow, which never sends it)
//   travelerVerificationId  — required if the booking has more than one
//                             traveler; must equal the id of the
//                             passport_verifications row actually at
//                             travelerIndex right now. This is the
//                             client's proof that it showed the user this
//                             exact traveler's name/passport (fetched from
//                             GET /api/onboarding/status) and had them
//                             confirm it, so a photo can never be attached
//                             to the wrong traveler on a multi-traveler
//                             booking just because of a stale index.
export async function saveFacePhoto(req, res) {
  const userId = req.user?.id ?? req.userId;
  try {
    const { packageId, bookingId } = req.body;
    // travelerIndex is optional in the request — omitted entirely (as the
    // single-traveler FacePhotoModal flow still does) is fine and resolved
    // to 0 below once we know the booking only has one traveler. What's
    // NOT fine is a garbage value (negative, non-numeric, out of range),
    // which we reject outright rather than silently coercing to 0 — see
    // strictTravelerIndex's comment.
    const rawTravelerIndex = req.body?.travelerIndex;
    let travelerIndex = rawTravelerIndex === undefined || rawTravelerIndex === null || rawTravelerIndex === ''
      ? null
      : strictTravelerIndex(rawTravelerIndex);
    if (rawTravelerIndex !== undefined && rawTravelerIndex !== null && rawTravelerIndex !== '' && travelerIndex === null) {
      return res.status(400).json({ success: false, error: 'A valid travelerIndex is required.' });
    }
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
    let bookingQuery = supabaseAdmin
      .from('bookings')
      .select('id, status, traveler_count, package_id, created_at')
      .eq('user_id', userId)
      .in('status', ['confirmed', 'pending']);

    if (bookingId) {
      bookingQuery = bookingQuery.eq('id', bookingId);
    } else {
      bookingQuery = bookingQuery.eq('package_id', packageId).order('created_at', { ascending: false }).limit(1);
    }

    const { data: bookingRows, error: bErr } = await bookingQuery;

    if (bErr) {
      logger.error('saveFacePhoto booking check failed', { error: bErr.message, userId, packageId });
      return res.status(500).json({ success: false, error: 'Could not verify booking. Please try again.' });
    }
    const booking = Array.isArray(bookingRows) ? bookingRows[0] : bookingRows;
    if (!booking) {
      return res.status(403).json({
        success: false,
        error: 'No confirmed booking found for this package.',
      });
    }

    if (String(booking.package_id) !== String(packageId)) {
      return res.status(400).json({ success: false, error: 'bookingId does not match packageId.' });
    }

    // A verified (or manual-review) passport is mandatory for EVERY traveler
    // on this booking — not just the account holder's — since BookingFlow now
    // walks each adult/child/minor_child/infant through its own passport
    // check before payment. Enforce it here too so this endpoint can't be
    // hit directly to bypass verification for any traveler on the booking.
    const totalTravelers = Math.max(1, booking.traveler_count || 1);

    if (travelerIndex === null) {
      if (totalTravelers > 1) {
        // No ambiguity is acceptable here — guessing which of several
        // travelers this photo belongs to is exactly the bug we're
        // preventing. Callers on multi-traveler bookings must send an
        // explicit travelerIndex (the PostBookingModal flow does).
        return res.status(400).json({
          success: false,
          error: 'This booking has more than one traveler — travelerIndex is required.',
        });
      }
      travelerIndex = 0; // single-traveler booking, no ambiguity possible
    }

    if (travelerIndex >= totalTravelers) {
      return res.status(400).json({
        success: false,
        error: `travelerIndex must be between 0 and ${totalTravelers - 1}.`,
      });
    }
    const travelerIndices = Array.from({ length: totalTravelers }, (_, i) => i);
    const { data: existingRows, error: existErr } = await supabaseAdmin
      .from('passport_verifications')
      .select('id, traveler_index, verification_status, full_name, given_names, surname, passport_number')
      .eq('user_id', userId)
      .eq('package_id', packageId)
      .in('traveler_index', travelerIndices);

    if (existErr) {
      if (parseMissingColumn(existErr) === 'traveler_index') {
        return res.status(500).json({
          success: false,
          error: 'Database schema is missing traveler_index. Apply the multi-traveler onboarding migration first.',
        });
      }
      logger.error('saveFacePhoto passport check failed', { error: existErr.message, userId, packageId });
      return res.status(500).json({ success: false, error: 'Could not verify booking. Please try again.' });
    }

    const rowsByIndex = new Map((existingRows || []).map((r) => [r.traveler_index, r]));
    const allVerified = travelerIndices.every((i) => ['verified', 'manual_review'].includes(rowsByIndex.get(i)?.verification_status));

    if (!allVerified) {
      logger.warn('saveFacePhoto rejected — not every traveler on this booking has a verified passport', {
        userId, packageId, totalTravelers,
        statuses: travelerIndices.map((i) => rowsByIndex.get(i)?.verification_status || 'none'),
      });
      return res.status(403).json({
        success: false,
        error: 'Please complete passport verification for every traveler on this booking before submitting your ID photo.',
      });
    }

    // ── identity binding ──────────────────────────────────────────────────
    // The client is expected to have shown the user this exact traveler's
    // name/passport (from GET /api/onboarding/status → travelers[]) and had
    // them explicitly confirm it before capturing/uploading a photo. It must
    // echo back that record's id here as travelerVerificationId. If it's
    // missing or doesn't match what's actually in the DB for this index —
    // e.g. the booking's traveler list changed between page-load and
    // upload, or the client is bypassing the confirmation UI — we refuse
    // the write rather than silently attaching the photo to whichever
    // record happens to sit at that index right now. This is what actually
    // prevents "photo attached to the wrong traveler" on multi-traveler
    // bookings; the travelerIndex bounds check above only prevents writing
    // outside the booking entirely, not writing to the wrong slot within it.
    const targetRow = rowsByIndex.get(travelerIndex);
    if (!targetRow?.id) {
      return res.status(409).json({
        success: false,
        error: 'This traveler\u2019s passport details were not found. Please refresh and try again.',
      });
    }
    const claimedVerificationId = req.body?.travelerVerificationId;
    if (totalTravelers > 1) {
      // Multi-traveler booking: there IS a wrong-slot to attach to, so the
      // client must prove it showed the user this exact record and had
      // them confirm it (see PostBookingModal's identity confirmation
      // card). No echo, or an echo that doesn't match what's actually in
      // the DB right now, means we can't trust that the person looking at
      // the camera is who this upload claims to be for.
      if (!claimedVerificationId) {
        return res.status(400).json({
          success: false,
          error: 'Missing traveler confirmation. Please confirm the traveler\u2019s identity before uploading a photo.',
        });
      }
      if (String(claimedVerificationId) !== String(targetRow.id)) {
        logger.warn('saveFacePhoto rejected — traveler confirmation mismatch', {
          userId, packageId, travelerIndex, claimedVerificationId, actualId: targetRow.id,
        });
        return res.status(409).json({
          success: false,
          error: 'Traveler details for this slot have changed. Please refresh and confirm the correct traveler before uploading again.',
        });
      }
    } else if (claimedVerificationId && String(claimedVerificationId) !== String(targetRow.id)) {
      // Single-traveler booking with an echo that was sent anyway (e.g. a
      // future FacePhotoModal update) but doesn't match — still reject,
      // since a mismatch here means the client's view of the record is
      // stale for some other reason.
      return res.status(409).json({
        success: false,
        error: 'Traveler details have changed. Please refresh and try again.',
      });
    }

    const targetName = targetRow.full_name || [targetRow.given_names, targetRow.surname].filter(Boolean).join(' ').trim() || null;

    // Upload to R2 (public-read, just the headshot — no PII baked in).
    const facePhoto = await uploadFacePhotoBuffer({
      buffer: req.file.buffer,
      mime: detected.mime,
      ext: detected.ext,
      userId,
      packageId,
    });

    logger.info('Dedicated face photo uploaded', {
      userId, packageId, key: facePhoto.key, travelerIndex,
      boundToVerificationId: targetRow.id,
      boundToName: targetName, // audit trail: exactly who this photo was attached to
    });

    // Patch only the targeted traveler's face photo fields.
    const patch = {
      face_photo_url: facePhoto.url,
      face_photo_key: facePhoto.key,
      booking_id: booking.id,
      updated_at: new Date().toISOString(),
    };

    // Update by primary key (targetRow.id), not just user/package/index —
    // the id was already verified above to belong to userId+packageId+
    // travelerIndex, and matching on it directly (rather than re-matching
    // the same three columns again) removes any window in which a
    // concurrent request could have changed which row sits at this index
    // between the check above and this write.
    const { data: updatedRows, error: upErr } = await supabaseAdmin
      .from('passport_verifications')
      .update(patch)
      .eq('id', targetRow.id)
      .eq('user_id', userId)
      .select('id');

    if (upErr) {
      logger.error('saveFacePhoto update failed', { error: upErr.message, userId, packageId, travelerIndex });
      return res.status(500).json({ success: false, error: 'Could not save photo. Please try again.' });
    }

    if (!updatedRows?.length) {
      // Row disappeared between the check and the write (e.g. deleted
      // concurrently) — do not fall back to inserting a fresh row here,
      // since that would silently create an unconfirmed identity slot and
      // defeat the whole point of the check above.
      logger.error('saveFacePhoto: confirmed row vanished before update', { userId, packageId, travelerIndex, verificationId: targetRow.id });
      return res.status(409).json({
        success: false,
        error: 'Traveler details changed while saving. Please refresh and try again.',
      });
    }

    return res.json({
      success: true,
      bookingId: booking.id,
      travelerIndex,
      travelerVerificationId: targetRow.id,
      travelerName: targetName,
      facePhotoUrl: facePhoto.url,
      message: `Photo saved for ${targetName || 'this traveler'}.`,
    });
  } catch (err) {
    logger.error('saveFacePhoto unexpected error', { error: err.message, userId });
    return res.status(500).json({ success: false, error: 'Could not save photo. Please try again.' });
  }
}

export default { checkPassportValidity, verifyPassportImage, getPassportStatus, getPassportStatusBatch, getFacePhotoStatus, saveFacePhoto };