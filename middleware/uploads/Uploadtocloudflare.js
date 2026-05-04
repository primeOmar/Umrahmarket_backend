import multer from 'multer';
import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3';
import { fileTypeFromBuffer } from 'file-type';
import crypto from 'crypto';
import path from 'path';
import logger, { logFileUpload, logSuspiciousActivity } from '../../config/logger.js';

/**
 * Cloudflare R2 Upload Middleware
 * Parses multipart form data, validates files, uploads to R2
 *
 * Exports:
 *  - parseFormData        — image uploads  (packages flow)
 *  - uploadImagesToR2     — image uploads  (packages flow)
 *  - parseDocumentData    — document uploads (agent documents flow)
 *  - uploadDocumentsToR2  — document uploads (agent documents flow)
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

// ─── Allowed types ────────────────────────────────────────────────────────────
const IMAGE_MIMES    = ['image/jpeg', 'image/png', 'image/webp'];
const DOCUMENT_MIMES = ['image/jpeg', 'image/png', 'image/webp', 'application/pdf'];

// Valid document field names (must match document_routes.js)
const DOCUMENT_KEYS  = ['incorporation', 'tourism', 'krapin', 'director_id', 'office_photo'];

// ─── Size limits ──────────────────────────────────────────────────────────────
const IMAGE_MAX_SIZE    = 10 * 1024 * 1024; // 10 MB
const DOCUMENT_MAX_SIZE =  5 * 1024 * 1024; //  5 MB
const MAX_FILES         = 10;

// =============================================================================
// IMAGE UPLOAD (existing — packages flow, unchanged)
// =============================================================================

const imageUpload = multer({
  storage: multer.memoryStorage(),
  fileFilter: (_req, file, cb) => {
    if (!IMAGE_MIMES.includes(file.mimetype)) {
      return cb(new Error(`Invalid file type: ${file.mimetype}. Allowed: jpeg, png, webp`), false);
    }
    cb(null, true);
  },
  limits: {
    fileSize: IMAGE_MAX_SIZE,
    files:    MAX_FILES,
    fields:   30,
    parts:    MAX_FILES + 30,
  },
});

// Step 1 — parse
export const parseFormData = (req, res, next) => {
  imageUpload.array('images', MAX_FILES)(req, res, (err) => {
    if (err instanceof multer.MulterError) {
      const msgs = {
        LIMIT_FILE_SIZE:       `File too large. Max ${IMAGE_MAX_SIZE / 1024 / 1024} MB per image.`,
        LIMIT_FILE_COUNT:      `Too many files. Max ${MAX_FILES} images.`,
        LIMIT_UNEXPECTED_FILE: 'Unexpected field name for file upload.',
      };
      return res.status(400).json({ success: false, error: msgs[err.code] || err.message });
    }
    if (err) return res.status(400).json({ success: false, error: err.message });
    next();
  });
};

// Step 2 — upload images to R2 under packages/
export const uploadImagesToR2 = async (req, res, next) => {
  try {
    const files = req.files ?? [];
    if (files.length === 0) { req.imageUrls = []; return next(); }

    const urls = [];

    for (const file of files) {
      const buffer = file.buffer;

      const detected = await fileTypeFromBuffer(buffer);
      if (!detected || !IMAGE_MIMES.includes(detected.mime)) {
        logSuspiciousActivity('R2 upload rejected — MIME mismatch', {
          claimed: file.mimetype, detected: detected?.mime ?? 'unknown',
          userId: req.userId, ip: req.ip,
        });
        return res.status(400).json({
          success: false,
          error: 'File type verification failed. Only JPEG, PNG, and WebP images are allowed.',
        });
      }

      const headerStr = buffer.slice(0, 1024).toString('latin1');
      if (headerStr.includes('<?php') || headerStr.includes('<?=') || headerStr.includes('<script')) {
        logSuspiciousActivity('R2 upload rejected — executable code detected', { userId: req.userId, ip: req.ip });
        return res.status(400).json({ success: false, error: 'File contains executable code and was rejected.' });
      }

      const uid = crypto.randomBytes(16).toString('hex');
      const ext = path.extname(file.originalname).toLowerCase() || `.${detected.ext}`;
      const key = `packages/${req.userId ?? 'anon'}/${Date.now()}-${uid}${ext}`;

      await R2.send(new PutObjectCommand({
        Bucket: BUCKET, Key: key, Body: buffer, ContentType: detected.mime,
      }));

      const publicUrl = `${PUBLIC_URL}/${key}`;
      urls.push(publicUrl);
      logFileUpload(req.userId, key, detected.mime, buffer.length, true, req.ip);
    }

    req.imageUrls = urls;
    next();

  } catch (error) {
    logger.error('R2 image upload failed', { error: error.message, userId: req.userId });
    return res.status(500).json({ success: false, error: 'Image upload failed. Please try again.' });
  }
};

// =============================================================================
// DOCUMENT UPLOAD (new — agent documents flow)
// =============================================================================

const documentUpload = multer({
  storage: multer.memoryStorage(),
  fileFilter: (_req, file, cb) => {
    if (!DOCUMENT_MIMES.includes(file.mimetype)) {
      return cb(
        new Error(`Invalid file type: ${file.mimetype}. Allowed: jpeg, png, webp, pdf`),
        false
      );
    }
    cb(null, true);
  },
  limits: {
    fileSize: DOCUMENT_MAX_SIZE,
    files:    DOCUMENT_KEYS.length + 4, // +4 for up to 5 office_photo slots
    fields:   10,
    parts:    DOCUMENT_KEYS.length + 4 + 10,
  },
});

// Step 1 — parse multipart (accepts fields: incorporation | tourism | krapin | director_id | office_photo)
// office_photo accepts up to 5 images
export const parseDocumentData = (req, res, next) => {
  const fieldConfig = DOCUMENT_KEYS.map(k => ({
    name: k,
    maxCount: k === 'office_photo' ? 5 : 1,
  }));
  documentUpload.fields(fieldConfig)(req, res, (err) => {
    if (err instanceof multer.MulterError) {
      const msgs = {
        LIMIT_FILE_SIZE:       `File too large. Max ${DOCUMENT_MAX_SIZE / 1024 / 1024} MB per document.`,
        LIMIT_FILE_COUNT:      `Too many files. Max ${DOCUMENT_KEYS.length} documents at once.`,
        LIMIT_UNEXPECTED_FILE: 'Unexpected field name. Allowed: incorporation, tourism, krapin, director_id, office_photo.',
      };
      return res.status(400).json({ success: false, error: msgs[err.code] || err.message });
    }
    if (err) return res.status(400).json({ success: false, error: err.message });
    next();
  });
};

// Step 2 — validate & upload documents to R2 under documents/
export const uploadDocumentsToR2 = async (req, res, next) => {
  try {
    const files = req.files ?? {};

    // Reject unknown field names
    const unknownKeys = Object.keys(files).filter(k => !DOCUMENT_KEYS.includes(k));
    if (unknownKeys.length > 0) {
      return res.status(400).json({
        success: false,
        error: `Unexpected file field(s): ${unknownKeys.join(', ')}.`,
      });
    }

    if (Object.keys(files).length === 0) {
      req.documentUrls = {};
      return next();
    }

    const documentUrls = {}; // { incorporation: 'https://…', … }

    for (const docKey of DOCUMENT_KEYS) {
      if (!files[docKey]) continue;

      // office_photo supports multiple files; all others use only the first file
      const fileList = files[docKey];
      const uploadedUrls = [];

      for (const file of fileList) {
      const buffer = file.buffer;

      // ── Deep MIME check ────────────────────────────────────────────────
      const detected = await fileTypeFromBuffer(buffer);

      // PDFs: file-type detects as 'application/pdf'
      // Images: jpeg / png / webp
      if (!detected || !DOCUMENT_MIMES.includes(detected.mime)) {
        logSuspiciousActivity('R2 document upload rejected — MIME mismatch', {
          field: docKey, claimed: file.mimetype, detected: detected?.mime ?? 'unknown',
          userId: req.userId, ip: req.ip,
        });
        return res.status(400).json({
          success: false,
          error: `${docKey}: file type verification failed. Only JPEG, PNG, WebP, and PDF allowed.`,
        });
      }

      // ── Code injection check (header scan) ────────────────────────────
      // PDFs can embed JS — scan first 2KB for obvious injections
      const headerStr = buffer.slice(0, 2048).toString('latin1');
      if (
        headerStr.includes('<?php') ||
        headerStr.includes('<?=')   ||
        headerStr.includes('<script')
      ) {
        logSuspiciousActivity('R2 document upload rejected — executable code detected', {
          field: docKey, userId: req.userId, ip: req.ip,
        });
        return res.status(400).json({
          success: false,
          error: `${docKey}: file contains executable code and was rejected.`,
        });
      }

      // ── Generate safe R2 key ───────────────────────────────────────────
      // Pattern: documents/{agentId}/{docType}/{timestamp}-{random}.{ext}
      const uid = crypto.randomBytes(16).toString('hex');
      const ext = detected.ext ? `.${detected.ext}` : path.extname(file.originalname).toLowerCase();
      const key = `documents/${req.userId ?? 'anon'}/${docKey}/${Date.now()}-${uid}${ext}`;

      // ── Upload to R2 ──────────────────────────────────────────────────
      await R2.send(new PutObjectCommand({
        Bucket:      BUCKET,
        Key:         key,
        Body:        buffer,
        ContentType: detected.mime,
        // Documents are private — no public-read ACL
        // Access them via signed URLs on the backend
        Metadata: {
          agentId: String(req.userId ?? 'anon'),
          docType: docKey,
        },
      }));

        uploadedUrls.push(`${PUBLIC_URL}/${key}`);
        logFileUpload(req.userId, key, detected.mime, buffer.length, true, req.ip);
      } // end inner file loop

      // office_photo stores an array of URLs; all other doc types store a single URL string
      documentUrls[docKey] = docKey === 'office_photo' ? uploadedUrls : uploadedUrls[0];
    }

    req.documentUrls = documentUrls;
    next();

  } catch (error) {
    logger.error('R2 document upload failed', { error: error.message, userId: req.userId });
    return res.status(500).json({ success: false, error: 'Document upload failed. Please try again.' });
  }
};