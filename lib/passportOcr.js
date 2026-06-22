/**
 * Passport OCR + MRZ parsing — Tesseract.js (no external API).
 *
 * Reads a passport image and extracts identity fields from the
 * Machine-Readable Zone (MRZ, TD3 format: 2 lines × 44 chars). The MRZ is
 * preferred over free-text because every critical field carries an ICAO 9303
 * check digit, so we can self-validate what the OCR produced.
 *
 * Exports:
 *   - extractPassport(buffer)      → { ok, rawText, mrz, fields, checks, confidence }
 *   - compareWithInput(fields, in) → { score, matched, details }
 *   - parseMrzDate(yyMMdd)         → Date|null   (also used by callers)
 *   - extractFacePhoto(buffer)     → { ok, buffer, mime, ext, width, height, method }
 *   - terminateOcrWorker()         → void        (graceful shutdown)
 *
 * Concurrency: Tesseract workers are NOT safe for parallel recognize() calls,
 * so a single shared worker is serialised behind a promise mutex. Passport
 * verification is low-frequency, so serialisation is an acceptable trade-off.
 */
import { createWorker } from 'tesseract.js';
import sharp from 'sharp';
import logger from '../config/logger.js';

const MRZ_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789<';
const TD3_LEN = 44;

// ── Shared worker (lazy) + serialisation mutex ───────────────────────────────
let _workerPromise = null;
let _queue = Promise.resolve();

async function getWorker() {
  if (!_workerPromise) {
    _workerPromise = (async () => {
      try {
        const workerOpts = {
          // Quiet logger; honour an explicit lang-data cache dir if provided.
          cachePath: process.env.OCR_CACHE_PATH || undefined,
        };

        // Log worker initialization
        if (process.env.NODE_ENV === 'development') {
          console.log('[Tesseract] Initializing worker with options:', workerOpts);
        }

        const worker = await createWorker('eng', 1, workerOpts);
        logger.info('Tesseract worker initialized successfully', { cachePath: workerOpts.cachePath });
        return worker;
      } catch (err) {
        logger.error('Failed to initialize Tesseract worker', {
          error: err.message,
          stack: err.stack,
          cachePath: process.env.OCR_CACHE_PATH,
        });
        _workerPromise = null; // allow retry on next call
        throw new Error(`OCR worker initialization failed: ${err.message}`);
      }
    })().catch((err) => {
      _workerPromise = null; // allow retry on next call
      throw err;
    });
  }
  return _workerPromise;
}

// Run an OCR pass restricted to MRZ characters, serialised.
function recognizeMrz(buffer) {
  const run = async () => {
    const worker = await getWorker();
    await worker.setParameters({
      tessedit_char_whitelist: MRZ_CHARS,
      tessedit_pageseg_mode: '6', // assume a uniform block of text
      preserve_interword_spaces: '0',
    });
    const { data } = await worker.recognize(buffer);
    return { text: data.text || '', confidence: data.confidence ?? 0 };
  };
  const result = _queue.then(run, run);
  _queue = result.then(() => {}, () => {}); // keep the chain alive on error
  return result;
}

// ── Image preprocessing (sharp) ──────────────────────────────────────────────
async function preprocess(buffer, { mrzBand = false } = {}) {
  try {
    const base = () => sharp(buffer, { failOn: 'none' }).rotate(); // auto-orient via EXIF
    let pipeline = base();

    if (mrzBand) {
      const meta = await base().metadata();
      if (meta.height && meta.width) {
        const top = Math.floor(meta.height * 0.68); // MRZ lives in the bottom band
        pipeline = base().extract({
          left: 0,
          top,
          width: meta.width,
          height: meta.height - top,
        });
      }
    }

    const processed = await pipeline
      .grayscale()
      .normalize()
      .resize({ width: 1600, withoutEnlargement: true })
      .sharpen()
      .toBuffer();

    return processed;
  } catch (err) {
    logger.error('Image preprocessing failed', {
      error: err.message,
      stack: err.stack,
      mrzBand,
      bufferSize: buffer?.length || 0,
    });
    throw new Error(`Image preprocessing failed: ${err.message}`);
  }
}

// ── ICAO 9303 check digit ────────────────────────────────────────────────────
function charValue(c) {
  if (c >= '0' && c <= '9') return c.charCodeAt(0) - 48;
  if (c >= 'A' && c <= 'Z') return c.charCodeAt(0) - 55; // A=10 … Z=35
  return 0; // '<' and anything else
}

function checkDigit(input) {
  const weights = [7, 3, 1];
  let sum = 0;
  for (let i = 0; i < input.length; i++) {
    sum += charValue(input[i]) * weights[i % 3];
  }
  return sum % 10;
}

function digitsMatch(field, expected) {
  const e = parseInt(expected, 10);
  if (Number.isNaN(e)) return false;
  return checkDigit(field) === e;
}

// ── MRZ line detection + parsing ─────────────────────────────────────────────
function cleanLine(line) {
  return line.toUpperCase().replace(/[^A-Z0-9<]/g, '');
}

// Pull the two TD3 lines out of noisy OCR text.
function findMrzLines(text) {
  const candidates = text
    .split(/\r?\n/)
    .map(cleanLine)
    .filter((l) => l.length >= 28); // tolerate dropped trailing fillers

  // Line 1 starts with the document type 'P'. Line 2 is the data line.
  const l1 = candidates.find((l) => /^P[A-Z0-9<]/.test(l) && l.includes('<'));
  // Line 2: first 9 chars are the passport number, char 10 a check digit.
  const l2 = candidates.find((l) => l !== l1 && /^[A-Z0-9<]{9}[0-9<]/.test(l) && /\d/.test(l));

  if (!l1 || !l2) return null;
  return [pad(l1), pad(l2)];
}

function pad(line) {
  return (line + '<'.repeat(TD3_LEN)).slice(0, TD3_LEN);
}

export function parseMrzDate(yyMMdd) {
  if (!/^\d{6}$/.test(yyMMdd)) return null;
  const yy = parseInt(yyMMdd.slice(0, 2), 10);
  const mm = parseInt(yyMMdd.slice(2, 4), 10);
  const dd = parseInt(yyMMdd.slice(4, 6), 10);
  if (mm < 1 || mm > 12 || dd < 1 || dd > 31) return null;
  // Expiry/DOB heuristic: <= 60 → 20xx, else 19xx. Good enough for the
  // 2000-2060 expiry window passports use.
  const year = yy <= 60 ? 2000 + yy : 1900 + yy;
  const d = new Date(Date.UTC(year, mm - 1, dd));
  return Number.isNaN(d.getTime()) ? null : d;
}

function parseTd3(l1, l2) {
  // Line 1: P<ISS SURNAME<<GIVEN<NAMES
  const issuingCountry = l1.slice(2, 5).replace(/</g, '');
  const namePart = l1.slice(5);
  const [surnameRaw, givenRaw = ''] = namePart.split('<<');
  const surname = surnameRaw.replace(/</g, ' ').trim();
  const givenNames = givenRaw.replace(/</g, ' ').trim();

  // Line 2 fixed positions
  const passportNumber = l2.slice(0, 9).replace(/</g, '');
  const pnCheck = l2[9];
  const nationality = l2.slice(10, 13).replace(/</g, '');
  const dob = l2.slice(13, 19);
  const dobCheck = l2[19];
  const sex = l2[20] === '<' ? '' : l2[20];
  const expiry = l2.slice(21, 27);
  const expiryCheck = l2[27];
  const personalNumber = l2.slice(28, 42).replace(/</g, '');
  const compositeCheck = l2[43];

  const checks = {
    passportNumber: digitsMatch(l2.slice(0, 9), pnCheck),
    dob: digitsMatch(dob, dobCheck),
    expiry: digitsMatch(expiry, expiryCheck),
  };
  // Composite check covers number+checks+dob+expiry+personal fields.
  const composite = l2.slice(0, 10) + l2.slice(13, 20) + l2.slice(21, 43);
  checks.composite = digitsMatch(composite, compositeCheck);

  const passed = Object.values(checks).filter(Boolean).length;
  const confidence = Math.round((passed / 4) * 100);

  return {
    fields: {
      documentType: 'P',
      issuingCountry,
      surname,
      givenNames,
      fullName: `${givenNames} ${surname}`.trim(),
      passportNumber,
      nationality,
      dateOfBirth: parseMrzDate(dob),
      sex,
      expiry: parseMrzDate(expiry),
      personalNumber,
    },
    checks,
    confidence,
  };
}

// ── Public: full extraction ──────────────────────────────────────────────────
export async function extractPassport(buffer) {
  let mrzText = '';
  let ocrConfidence = 0;
  try {
    // Validate buffer
    if (!buffer || !Buffer.isBuffer(buffer) || buffer.length === 0) {
      logger.warn('Invalid buffer provided to extractPassport', {
        bufferType: typeof buffer,
        isBuffer: Buffer.isBuffer(buffer),
        size: buffer?.length || 0,
      });
      return {
        ok: false,
        reason: 'invalid_buffer',
        rawText: '',
        mrz: null,
        fields: null,
        checks: null,
        confidence: 0,
      };
    }

    // Pass 1: bottom band (where the MRZ lives) — best signal.
    try {
      const bandImg = await preprocess(buffer, { mrzBand: true });
      const band = await recognizeMrz(bandImg);
      mrzText = band.text;
      ocrConfidence = band.confidence;
    } catch (preprocessErr) {
      logger.warn('MRZ band preprocessing/recognition failed, trying full image', {
        error: preprocessErr.message,
      });
    }

    let mrz = findMrzLines(mrzText);

    // Pass 2: whole image, in case the crop missed the MRZ.
    if (!mrz) {
      try {
        const fullImg = await preprocess(buffer, { mrzBand: false });
        const full = await recognizeMrz(fullImg);
        mrzText = `${mrzText}\n${full.text}`;
        ocrConfidence = Math.max(ocrConfidence, full.confidence);
        mrz = findMrzLines(mrzText);
      } catch (fullErr) {
        logger.warn('Full image OCR failed', { error: fullErr.message });
      }
    }

    if (!mrz) {
      logger.info('MRZ not found in passport image', { extractedText: mrzText.substring(0, 100) });
      return {
        ok: false,
        reason: 'mrz_not_found',
        rawText: mrzText,
        mrz: null,
        fields: null,
        checks: null,
        confidence: 0,
      };
    }

    const parsed = parseTd3(mrz[0], mrz[1]);
    return {
      ok: true,
      rawText: mrzText,
      mrz: mrz.join('\n'),
      fields: parsed.fields,
      checks: parsed.checks,
      // Blend OCR engine confidence with check-digit pass rate.
      confidence: Math.round((parsed.confidence * 0.7) + (ocrConfidence * 0.3)),
    };
  } catch (err) {
    logger.error('Passport OCR extraction failed', {
      error: err.message,
      stack: err.stack,
      bufferSize: buffer?.length || 0,
    });
    return {
      ok: false,
      reason: 'ocr_error',
      rawText: mrzText,
      mrz: null,
      fields: null,
      checks: null,
      confidence: 0,
    };
  }
}

// ── Public: compare OCR result with the user's typed input ───────────────────
const normAlnum = (s) => (s || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
const normName = (s) =>
  (s || '')
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '') // strip diacritics (combining marks)
    .toUpperCase()
    .replace(/[^A-Z ]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();

function sameDay(a, b) {
  if (!(a instanceof Date) || !(b instanceof Date)) return false;
  if (Number.isNaN(a.getTime()) || Number.isNaN(b.getTime())) return false;
  return a.getUTCFullYear() === b.getUTCFullYear()
    && a.getUTCMonth() === b.getUTCMonth()
    && a.getUTCDate() === b.getUTCDate();
}

/**
 * input: { passportNumber, expiry (Date), surname, givenNames, nationality }
 * Critical fields (must match): passportNumber, expiry.
 * Secondary (weighted): surname, given-name overlap, nationality.
 */
export function compareWithInput(fields, input) {
  const details = {};

  details.passportNumber = !!fields.passportNumber
    && normAlnum(fields.passportNumber) === normAlnum(input.passportNumber);

  details.expiry = sameDay(fields.expiry, input.expiry instanceof Date ? input.expiry : new Date(input.expiry));

  const ocrSurname = normName(fields.surname);
  const inSurname = normName(input.surname);
  details.surname = !!ocrSurname && !!inSurname
    && (ocrSurname.includes(inSurname) || inSurname.includes(ocrSurname));

  const ocrGiven = new Set(normName(fields.givenNames).split(' ').filter(Boolean));
  const inGiven = normName(input.givenNames).split(' ').filter(Boolean);
  details.givenNames = inGiven.length > 0 && inGiven.some((n) => ocrGiven.has(n));

  if (input.nationality) {
    details.nationality = normAlnum(fields.nationality) === normAlnum(input.nationality);
  }

  // Weighted score (critical fields dominate)
  const weights = { passportNumber: 40, expiry: 30, surname: 15, givenNames: 10, nationality: 5 };
  let total = 0, got = 0;
  for (const [k, w] of Object.entries(weights)) {
    if (k in details) {
      total += w;
      if (details[k]) got += w;
    }
  }
  const score = total ? Math.round((got / total) * 100) : 0;

  // A verification is auto-accepted only when BOTH critical fields match.
  const matched = details.passportNumber === true && details.expiry === true;

  return { score, matched, details };
}

// ── Public: face photo crop (geometry-based, no ML dependency) ──────────────
//
// TD3 passport photo pages place the holder's photo in a consistent region:
// upper-left area of the page, above the MRZ band (the MRZ band itself starts
// at ~68% of page height — see preprocess()'s `mrzBand` split above). This
// crops that region directly from page geometry rather than running face
// detection, which keeps this module dependency-free (sharp is already a
// dependency for OCR preprocessing).
//
// This is intentionally approximate: photo placement varies a little by
// issuing country/booklet design, so the crop sometimes includes a sliver of
// page border or isn't perfectly centred on the face. It is good enough for
// a small ID-card thumbnail. If crop quality becomes a real problem, replace
// the body of this function with a real face-detection call (e.g.
// @vladmandic/face-api) — the call site and return shape don't need to change.
const FACE_CROP_REGION = {
  // Fractions of the full page (post EXIF auto-orient), tuned for TD3 photo
  // pages where the photo sits upper-left, comfortably clear of the MRZ.
  left: 0.04,
  top: 0.06,
  width: 0.36,
  height: 0.56,
};
const FACE_OUTPUT = { width: 240, height: 300 }; // portrait, ID-card friendly

/**
 * Crop the holder's photo out of a passport page image.
 * Returns { ok, buffer, mime, ext, width, height, method } on success,
 * or { ok: false, reason } if the buffer/region was unusable.
 */
export async function extractFacePhoto(buffer, region = FACE_CROP_REGION) {
  try {
    if (!buffer || !Buffer.isBuffer(buffer) || buffer.length === 0) {
      return { ok: false, reason: 'invalid_buffer' };
    }

    const meta = await sharp(buffer, { failOn: 'none' }).rotate().metadata();
    if (!meta.width || !meta.height) {
      return { ok: false, reason: 'no_dimensions' };
    }

    const left = Math.max(0, Math.round(meta.width * region.left));
    const top = Math.max(0, Math.round(meta.height * region.top));
    const width = Math.min(meta.width - left, Math.round(meta.width * region.width));
    const height = Math.min(meta.height - top, Math.round(meta.height * region.height));

    if (width <= 0 || height <= 0) {
      return { ok: false, reason: 'invalid_crop_region' };
    }

    const cropped = await sharp(buffer, { failOn: 'none' })
      .rotate()
      .extract({ left, top, width, height })
      .resize(FACE_OUTPUT.width, FACE_OUTPUT.height, { fit: 'cover', position: 'attention' })
      .jpeg({ quality: 88 })
      .toBuffer();

    return {
      ok: true,
      buffer: cropped,
      mime: 'image/jpeg',
      ext: 'jpg',
      width: FACE_OUTPUT.width,
      height: FACE_OUTPUT.height,
      method: 'geometry', // distinguishes this from any future ML-based method in logs
    };
  } catch (err) {
    logger.error('Face photo crop failed', {
      error: err.message,
      stack: err.stack,
      bufferSize: buffer?.length || 0,
    });
    return { ok: false, reason: 'crop_error' };
  }
}

// ── Public: graceful shutdown ─────────────────────────────────────────────────
export async function terminateOcrWorker() {
  if (_workerPromise) {
    try {
      const w = await _workerPromise;
      await w.terminate();
    } catch {
      /* ignore — best-effort cleanup */
    }
    _workerPromise = null;
  }
}

export default {
  extractPassport,
  compareWithInput,
  parseMrzDate,
  extractFacePhoto,
  terminateOcrWorker,
};