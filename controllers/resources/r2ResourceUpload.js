import multer from 'multer';
import { S3Client, PutObjectCommand, DeleteObjectCommand } from '@aws-sdk/client-s3';
import { fileTypeFromBuffer } from 'file-type';
import crypto from 'crypto';
import path from 'path';
import logger, { logFileUpload, logSuspiciousActivity } from '../../config/logger.js';

/**
 * Cloudflare R2 Upload Middleware — Resources flow
 * Mirrors parseDocumentData / uploadDocumentsToR2 but for a single
 * PDF-or-image resource file (superadmin "Add Resource" modal).
 *
 * Exports:
 *  - parseResourceData    — multer parse (single field: "file")
 *  - uploadResourceToR2   — validate + upload to R2, sets req.resourceFile
 *  - deleteResourceFromR2 — helper to remove an object by its public URL
 */

// ─── R2 Client ────────────────────────────────────────────────────────────────
const R2 = new S3Client({
  region: 'auto',
  endpoint: `https://${process.env.CLOUDFLARE_ACCOUNT_ID}.r2.cloudflarestorage.com`,
  credentials: {
    accessKeyId:     process.env.CLOUDFLARE_R2_ACCESS_KEY_ID,
    secretAccessKey: process.env.CLOUDFLARE_R2_SECRET_ACCESS_KEY,
  },
});

const BUCKET     = process.env.CLOUDFLARE_R2_BUCKET_NAME;
const PUBLIC_URL = process.env.CLOUDFLARE_R2_PUBLIC_URL;

// ─── Allowed types / limits ───────────────────────────────────────────────────
const RESOURCE_MIMES  = ['image/jpeg', 'image/png', 'image/webp', 'application/pdf'];
const RESOURCE_MAX_SIZE = 15 * 1024 * 1024; // 15 MB — matches AddResourceModal MAX_FILE_MB

const resourceUpload = multer({
  storage: multer.memoryStorage(),
  fileFilter: (_req, file, cb) => {
    if (!RESOURCE_MIMES.includes(file.mimetype)) {
      return cb(new Error(`Invalid file type: ${file.mimetype}. Allowed: jpeg, png, webp, pdf`), false);
    }
    cb(null, true);
  },
  limits: {
    fileSize: RESOURCE_MAX_SIZE,
    files:    1,
    fields:   10,
    parts:    11,
  },
});

// Step 1 — parse multipart (single field: "file")
export const parseResourceData = (req, res, next) => {
  resourceUpload.single('file')(req, res, (err) => {
    if (err instanceof multer.MulterError) {
      const msgs = {
        LIMIT_FILE_SIZE:       `File too large. Max ${RESOURCE_MAX_SIZE / 1024 / 1024} MB.`,
        LIMIT_FILE_COUNT:      'Only one file can be uploaded at a time.',
        LIMIT_UNEXPECTED_FILE: 'Unexpected field name. Expected field: file.',
      };
      return res.status(400).json({ success: false, error: msgs[err.code] || err.message });
    }
    if (err) return res.status(400).json({ success: false, error: err.message });
    next();
  });
};

// Step 2 — validate & upload the resource file to R2 under resources/
export const uploadResourceToR2 = async (req, res, next) => {
  try {
    const file = req.file;
    if (!file) {
      return res.status(400).json({ success: false, error: 'No file was provided.' });
    }

    const buffer = file.buffer;

    // ── Deep MIME check ────────────────────────────────────────────────────
    const detected = await fileTypeFromBuffer(buffer);
    const isPdfClaim = file.mimetype === 'application/pdf';

    // Plain-text/empty-buffer PDFs sometimes fail magic-byte sniffing; fall back
    // to trusting the multer-reported mimetype only for the pdf case if detection
    // yields nothing, since fileTypeFromBuffer requires binary signatures.
    const effectiveMime = detected?.mime || (isPdfClaim ? 'application/pdf' : null);

    if (!effectiveMime || !RESOURCE_MIMES.includes(effectiveMime)) {
      logSuspiciousActivity('R2 resource upload rejected — MIME mismatch', {
        claimed: file.mimetype, detected: detected?.mime ?? 'unknown',
        userId: req.userId, ip: req.ip,
      });
      return res.status(400).json({
        success: false,
        error: 'File type verification failed. Only JPEG, PNG, WebP, and PDF are allowed.',
      });
    }

    // ── Code injection check (header scan) ─────────────────────────────────
    const headerStr = buffer.slice(0, 2048).toString('latin1');
    if (headerStr.includes('<?php') || headerStr.includes('<?=') || headerStr.includes('<script')) {
      logSuspiciousActivity('R2 resource upload rejected — executable code detected', {
        userId: req.userId, ip: req.ip,
      });
      return res.status(400).json({ success: false, error: 'File contains executable code and was rejected.' });
    }

    // ── Generate safe R2 key ────────────────────────────────────────────────
    // Pattern: resources/{userId}/{timestamp}-{random}.{ext}
    const uid = crypto.randomBytes(16).toString('hex');
    const ext = detected?.ext ? `.${detected.ext}` : path.extname(file.originalname).toLowerCase() || '.pdf';
    const key = `resources/${req.userId ?? 'anon'}/${Date.now()}-${uid}${ext}`;

    // ── Upload to R2 ─────────────────────────────────────────────────────────
    await R2.send(new PutObjectCommand({
      Bucket:      BUCKET,
      Key:         key,
      Body:        buffer,
      ContentType: effectiveMime,
    }));

    const publicUrl = `${PUBLIC_URL}/${key}`;
    logFileUpload(req.userId, key, effectiveMime, buffer.length, true, req.ip);

    req.resourceFile = {
      url:      publicUrl,
      key,
      mimeType: effectiveMime,
      size:     buffer.length,
      isImage:  effectiveMime.startsWith('image/'),
      isPdf:    effectiveMime === 'application/pdf',
    };

    next();

  } catch (error) {
    logger.error('R2 resource upload failed', { error: error.message, userId: req.userId });
    return res.status(500).json({ success: false, error: 'Resource upload failed. Please try again.' });
  }
};

// ─── Helper: delete a resource object from R2 given its public URL ───────────
export const deleteResourceFromR2 = async (publicUrl) => {
  if (!publicUrl || !PUBLIC_URL || !publicUrl.startsWith(PUBLIC_URL)) return;
  const key = publicUrl.slice(PUBLIC_URL.length + 1); // strip "PUBLIC_URL/"
  try {
    await R2.send(new DeleteObjectCommand({ Bucket: BUCKET, Key: key }));
  } catch (error) {
    logger.error('R2 resource delete failed', { error: error.message, key });
  }
};