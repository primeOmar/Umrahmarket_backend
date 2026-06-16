/**
 * Passport verification controller.
 *
 *   POST /api/passport/check         — validate typed details + 6-month rule (no image)
 *   POST /api/passport/verify-image  — OCR the photo, confirm it matches the typed
 *                                      details, enforce the expiry rule, persist.
 *   GET  /api/passport/status        — latest verification for (user, package)
 *
 * Policy (set with the product owner):
 *   - Passport expiry must be ≥ 6 months after the travel date (package
 *     available_from). Otherwise the user is told to renew.
 *   - The OCR'd photo must match the typed passport number AND expiry to
 *     auto-verify. Up to MAX_ATTEMPTS tries are allowed; after that the row is
 *     flagged for manual review and the user may proceed to payment.
 */
import { supabaseAdmin } from '../config/supabase.js';
import config from '../config/security.config.js';
import logger from '../config/logger.js';
import { extractPassport, compareWithInput } from '../lib/passportOcr.js';
import { uploadPassportBuffer } from '../middleware/uploads/PassportUpload.js';

const MAX_ATTEMPTS = 3;
const MIN_VALIDITY_MONTHS = 6;
const MIN_OCR_CONFIDENCE = 45; // below this the read is too noisy to trust a match

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
    if (!packageId) return res.status(400).json({ success: false, error: 'packageId is required.' });

    const { travelDate, minExpiry, packageTitle } = await resolveTravelWindow(packageId);
    const result = evaluateExpiry(passportExpiry, travelDate, minExpiry);

    return res.json({
      success: true,
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
  try {
    const {
      packageId, passportNumber, passportCountry,
      passportExpiry, surname, givenNames, dateOfBirth, nationality,
    } = req.body;

    if (!packageId || !passportNumber || !passportExpiry || !surname) {
      return res.status(400).json({ success: false, error: 'Missing required passport details.' });
    }
    if (!req.passportFile?.buffer) {
      return res.status(400).json({ success: false, error: 'Passport image is required.' });
    }

    logger.info('Starting passport verification', {
      userId, packageId, passportNumber: `${passportNumber.substring(0, 3)}***`,
      fileSize: req.passportFile.buffer.length,
    });

    // Don't re-verify an already-verified passport for this package.
    const { data: existing } = await supabaseAdmin
      .from('passport_verifications')
      .select('id, attempts, verification_status')
      .eq('user_id', userId)
      .eq('package_id', packageId)
      .maybeSingle();

    if (existing?.verification_status === 'verified') {
      logger.info('Passport already verified for this package', { userId, packageId });
      return res.json({
        success: true, status: 'verified', verified: true, canProceed: true,
        message: 'Passport already verified for this package.',
      });
    }

    // 1) Authoritative expiry / 6-month rule (server side, never trust client).
    const { travelDate, minExpiry } = await resolveTravelWindow(packageId);
    const validity = evaluateExpiry(passportExpiry, travelDate, minExpiry);
    if (!validity.valid) {
      logger.info('Passport expiry check failed', {
        userId, packageId, reason: validity.reason, passportExpiry,
      });
      await upsertVerification({
        userId, packageId, status: 'expired_passport', verified: false,
        input: { passportNumber, passportCountry, passportExpiry, surname, givenNames, dateOfBirth, nationality },
        travelDate, attempts: (existing?.attempts || 0),
      });
      return res.json({
        success: true, status: 'rejected', verified: false, canProceed: false,
        reason: validity.reason,
        message: 'Passport does not meet the 6-month validity requirement. Please renew and book again.',
      });
    }

    // 2) OCR the photo and compare against the typed details.
    logger.info('Starting OCR extraction', { userId, packageId, bufferSize: req.passportFile.buffer.length });
    const ocr = await extractPassport(req.passportFile.buffer);
    const attempts = (existing?.attempts || 0) + 1;

    logger.info('OCR extraction complete', {
      userId, packageId, ocrOk: ocr.ok, confidence: ocr.confidence,
      mrz: ocr.mrz ? 'found' : 'not_found', reason: ocr.reason,
    });

    let comparison = { score: 0, matched: false, details: {} };
    if (ocr.ok && ocr.confidence >= MIN_OCR_CONFIDENCE) {
      comparison = compareWithInput(ocr.fields, {
        passportNumber, expiry: validity.expiry, surname, givenNames, nationality,
      });
      logger.info('OCR comparison result', {
        userId, packageId, score: comparison.score, matched: comparison.matched,
        details: comparison.details,
      });
    } else {
      logger.warn('OCR confidence too low or extraction failed', {
        userId, packageId, ocrOk: ocr.ok, confidence: ocr.confidence, minRequired: MIN_OCR_CONFIDENCE,
      });
    }

    // 3) Always store the image (private R2) so manual reviewers have evidence.
    let stored = null;
    try {
      stored = await uploadPassportBuffer({
        buffer: req.passportFile.buffer,
        mime: req.passportFile.mime,
        ext: req.passportFile.ext,
        userId, packageId, ip: req.ip,
      });
      logger.info('Passport image uploaded to R2', { userId, packageId, key: stored.key });
    } catch (uploadError) {
      logger.warn('Passport image upload failed, continuing without stored image', {
        error: uploadError.message,
        stack: uploadError.stack,
        userId,
        packageId,
      });
    }

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

    await upsertVerification({
      userId, packageId, status, verified: autoVerified,
      input: { passportNumber, passportCountry, passportExpiry, surname, givenNames, dateOfBirth, nationality },
      ocr, comparison, stored, travelDate, attempts,
    });

    logger.info('Passport verification attempt complete', {
      userId, packageId, status, attempts,
      ocrOk: ocr.ok, ocrConfidence: ocr.confidence, matchScore: comparison.score,
    });

    return res.json({
      success: true,
      status,
      verified: autoVerified,
      canProceed,
      attemptsUsed: attempts,
      attemptsRemaining: Math.max(0, MAX_ATTEMPTS - attempts),
      ocr: { read: ocr.ok, confidence: ocr.confidence },
      // Booleans only — never echo the raw OCR text / extracted PII back to the client.
      match: { score: comparison.score, fields: comparison.details },
      message,
    });
  } catch (error) {
    const errorMessage = config.env === 'development'
      ? error.message
      : 'Verification failed. Please try again.';

    logger.error('verifyPassportImage failed', {
      error: error.message,
      stack: error.stack,
      userId,
      body: {
        packageId: req.body?.packageId,
        passportNumber: req.body?.passportNumber,
        passportCountry: req.body?.passportCountry,
        passportExpiry: req.body?.passportExpiry,
        surname: req.body?.surname,
        givenNames: req.body?.givenNames,
        dateOfBirth: req.body?.dateOfBirth,
        nationality: req.body?.nationality,
      },
    });
    return res.status(500).json({ success: false, error: errorMessage });
  }
};

// =============================================================================
// GET /api/passport/status?packageId=...
// =============================================================================
export const getPassportStatus = async (req, res) => {
  try {
    const { packageId } = req.query;
    if (!packageId) return res.status(400).json({ success: false, error: 'packageId is required.' });

    const { data } = await supabaseAdmin
      .from('passport_verifications')
      .select('verification_status, verified, attempts, match_score, updated_at')
      .eq('user_id', req.userId)
      .eq('package_id', packageId)
      .maybeSingle();

    return res.json({
      success: true,
      exists: !!data,
      status: data?.verification_status || null,
      verified: data?.verified || false,
      canProceed: !!data && ['verified', 'manual_review'].includes(data.verification_status),
      attemptsUsed: data?.attempts || 0,
      attemptsRemaining: Math.max(0, MAX_ATTEMPTS - (data?.attempts || 0)),
    });
  } catch (error) {
    logger.error('getPassportStatus failed', { error: error.message });
    return res.status(500).json({ success: false, error: 'Could not load verification status.' });
  }
};

// ── persistence helper (upsert on user_id+package_id) ────────────────────────
async function upsertVerification({ userId, packageId, status, verified, input, ocr, comparison, stored, travelDate, attempts }) {
  const row = {
    user_id: userId,
    package_id: packageId,
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
  if (!row.passport_image_url) {
    const { data: prev } = await supabaseAdmin
      .from('passport_verifications')
      .select('passport_image_url, image_key')
      .eq('user_id', userId).eq('package_id', packageId).maybeSingle();
    if (prev?.passport_image_url) {
      row.passport_image_url = prev.passport_image_url;
      row.image_key = prev.image_key;
    } else {
      row.passport_image_url = 'pending://no-image';
    }
  }

  const { error } = await supabaseAdmin
    .from('passport_verifications')
    .upsert(row, { onConflict: 'user_id,package_id' });
  if (error) {
    logger.error('passport_verifications upsert failed', { error: error.message, userId, packageId });
    throw new Error('Could not save verification record.');
  }
}

export default { checkPassportValidity, verifyPassportImage, getPassportStatus };
