/**
 * Passport image upload middleware (Cloudflare R2).
 *
 * Differs from the documents flow: the image buffer must be OCR-scanned by the
 * controller BEFORE we decide to persist it, so this module only PARSES the
 * multipart body into memory + runs deep validation. The controller calls
 * `uploadPassportBuffer()` to push the bytes to R2 once a row is being written.
 *
 * Exports:
 *   - parsePassportImage   — multer middleware (field: "passport", single file)
 *   - validatePassportFile — deep MIME + injection check on req.file (middleware)
 *   - uploadPassportBuffer — async helper: store a validated buffer in R2 (private)
 */
import multer from 'multer';
import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3';
import { fileTypeFromBuffer } from 'file-type';
import crypto from 'crypto';
import logger, { logFileUpload, logSuspiciousActivity } from '../../config/logger.js';

const R2 = new S3Client({
  region: 'auto',
  endpoint: `https://${process.env.CLOUDFLARE_ACCOUNT_ID}.r2.cloudflarestorage.com`,
  credentials: {
    accessKeyId: process.env.CLOUDFLARE_R2_ACCESS_KEY_ID,
    secretAccessKey: process.env.CLOUDFLARE_R2_SECRET_ACCESS_KEY,
  },
});

const BUCKET = process.env.CLOUDFLARE_R2_BUCKET_NAME;
const PUBLIC_URL = process.env.CLOUDFLARE_R2_PUBLIC_URL;

// Passports must be photographs — no PDFs (we OCR raster pixels).
const PASSPORT_MIMES = ['image/jpeg', 'image/png', 'image/webp'];
const MAX_SIZE = 8 * 1024 * 1024; // 8 MB

const upload = multer({
  storage: multer.memoryStorage(),
  fileFilter: (_req, file, cb) => {
    if (!PASSPORT_MIMES.includes(file.mimetype)) {
      return cb(new Error(`Invalid file type: ${file.mimetype}. Allowed: JPEG, PNG, WebP.`), false);
    }
    cb(null, true);
  },
  limits: { fileSize: MAX_SIZE, files: 1, fields: 20, parts: 25 },
});

// Step 1 — parse single "passport" file into req.file
export const parsePassportImage = (req, res, next) => {
  upload.single('passport')(req, res, (err) => {
    if (err instanceof multer.MulterError) {
      const msgs = {
        LIMIT_FILE_SIZE: `Image too large. Max ${MAX_SIZE / 1024 / 1024} MB.`,
        LIMIT_FILE_COUNT: 'Upload one passport image at a time.',
        LIMIT_UNEXPECTED_FILE: 'Unexpected file field. Use the field name "passport".',
      };
      return res.status(400).json({ success: false, error: msgs[err.code] || err.message });
    }
    if (err) return res.status(400).json({ success: false, error: err.message });
    next();
  });
};

// Step 2 — deep validation (magic-byte MIME + injection scan)
export const validatePassportFile = async (req, res, next) => {
  try {
    if (!req.file) {
      return res.status(400).json({ success: false, error: 'Passport image is required.' });
    }
    const buffer = req.file.buffer;

    const detected = await fileTypeFromBuffer(buffer);
    if (!detected || !PASSPORT_MIMES.includes(detected.mime)) {
      logSuspiciousActivity('Passport upload rejected — MIME mismatch', {
        claimed: req.file.mimetype, detected: detected?.mime ?? 'unknown',
        userId: req.userId, ip: req.ip,
      });
      return res.status(400).json({
        success: false,
        error: 'File type verification failed. Only JPEG, PNG, and WebP images are allowed.',
      });
    }

    const header = buffer.slice(0, 2048).toString('latin1');
    if (header.includes('<?php') || header.includes('<?=') || header.includes('<script')) {
      logSuspiciousActivity('Passport upload rejected — executable code detected', {
        userId: req.userId, ip: req.ip,
      });
      return res.status(400).json({ success: false, error: 'File contains executable content and was rejected.' });
    }

    req.passportFile = { buffer, mime: detected.mime, ext: detected.ext };
    next();
  } catch (error) {
    logger.error('Passport file validation failed', { error: error.message, userId: req.userId });
    return res.status(500).json({ success: false, error: 'Could not process the image. Please try again.' });
  }
};

/**
 * Store a validated passport buffer in R2 (private). Returns { key, url }.
 * Key pattern: passports/{userId}/{packageId}/{ts}-{rand}.{ext}
 */
export async function uploadPassportBuffer({ buffer, mime, ext, userId, packageId, ip }) {
  const uid = crypto.randomBytes(16).toString('hex');
  const safeExt = (ext || 'jpg').replace(/[^a-z0-9]/gi, '');
  const key = `passports/${userId ?? 'anon'}/${packageId ?? 'na'}/${Date.now()}-${uid}.${safeExt}`;

  await R2.send(new PutObjectCommand({
    Bucket: BUCKET,
    Key: key,
    Body: buffer,
    ContentType: mime,
    // Private object — sensitive PII. Never served with a public-read ACL.
    Metadata: { userId: String(userId ?? 'anon'), kind: 'passport' },
  }));

  logFileUpload(userId, key, mime, buffer.length, true, ip);
  return { key, url: `${PUBLIC_URL}/${key}` };
}

/**
 * Store a cropped face-photo buffer in R2. Unlike the raw passport scan,
 * this is just a headshot crop — no MRZ, no passport number, no page
 * border — so it's stored as public-read so it can be embedded directly in
 * the agent dashboard / ID card PDF without a signed URL.
 * Key pattern: passport-faces/{userId}/{packageId}/{ts}-{rand}.{ext}
 * Returns { key, url }.
 */
export async function uploadFacePhotoBuffer({ buffer, mime, ext, userId, packageId }) {
  const uid = crypto.randomBytes(16).toString('hex');
  const safeExt = (ext || 'jpg').replace(/[^a-z0-9]/gi, '');
  const key = `passport-faces/${userId ?? 'anon'}/${packageId ?? 'na'}/${Date.now()}-${uid}.${safeExt}`;

  await R2.send(new PutObjectCommand({
    Bucket: BUCKET,
    Key: key,
    Body: buffer,
    ContentType: mime,
    ACL: 'public-read',
    Metadata: { userId: String(userId ?? 'anon'), kind: 'passport-face-crop' },
  }));

  logFileUpload(userId, key, mime, buffer.length, true, undefined);
  return { key, url: `${PUBLIC_URL}/${key}` };
}

export default { parsePassportImage, validatePassportFile, uploadPassportBuffer, uploadFacePhotoBuffer };