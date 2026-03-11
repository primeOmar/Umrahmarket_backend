import multer from 'multer';
import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3';
import { fileTypeFromBuffer } from 'file-type';
import crypto from 'crypto';
import path from 'path';
import logger, { logFileUpload, logSuspiciousActivity } from '../../config/logger.js';

/**
 * Cloudflare R2 Upload Middleware
 * Parses multipart form data, validates files, uploads to R2
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

// ─── Multer (memory storage — no disk writes on Render) ──────────────────────
const ALLOWED_MIMES = ['image/jpeg', 'image/png', 'image/webp'];
const MAX_SIZE      = 10 * 1024 * 1024; // 10 MB
const MAX_FILES     = 10;

const storage = multer.memoryStorage();

const fileFilter = (req, file, cb) => {
  if (!ALLOWED_MIMES.includes(file.mimetype)) {
    return cb(new Error(`Invalid file type: ${file.mimetype}. Allowed: jpeg, png, webp`), false);
  }
  cb(null, true);
};

const upload = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: MAX_SIZE,
    files:    MAX_FILES,
    fields:   30,
    parts:    MAX_FILES + 30,
  },
});

// ─── Step 1: parseFormData ────────────────────────────────────────────────────
// Runs multer — populates req.body and req.files (in memory)
// Nothing is uploaded to R2 yet.
export const parseFormData = (req, res, next) => {
  upload.array('images', MAX_FILES)(req, res, (err) => {
    if (err instanceof multer.MulterError) {
      const msgs = {
        LIMIT_FILE_SIZE:  `File too large. Max ${MAX_SIZE / 1024 / 1024} MB per image.`,
        LIMIT_FILE_COUNT: `Too many files. Max ${MAX_FILES} images.`,
        LIMIT_UNEXPECTED_FILE: 'Unexpected field name for file upload.',
      };
      return res.status(400).json({
        success: false,
        error: msgs[err.code] || err.message,
      });
    }
    if (err) {
      return res.status(400).json({ success: false, error: err.message });
    }
    next();
  });
};

// ─── Step 2: uploadImagesToR2 ─────────────────────────────────────────────────
// Security-scans each buffer, uploads to R2, attaches req.imageUrls
export const uploadImagesToR2 = async (req, res, next) => {
  try {
    const files = req.files ?? [];

    if (files.length === 0) {
      req.imageUrls = [];
      return next();
    }

    const urls = [];

    for (const file of files) {
      const buffer = file.buffer;

      // ── Deep MIME check ──────────────────────────────────────────────────
      const detected = await fileTypeFromBuffer(buffer);
      if (!detected || !ALLOWED_MIMES.includes(detected.mime)) {
        logSuspiciousActivity('R2 upload rejected — MIME mismatch', {
          claimed:  file.mimetype,
          detected: detected?.mime ?? 'unknown',
          userId:   req.userId,
          ip:       req.ip,
        });
        return res.status(400).json({
          success: false,
          error:   'File type verification failed. Possible file manipulation.',
        });
      }

      // ── PHP / shell code check ────────────────────────────────────────────
      const str = buffer.toString('utf8');
      if (str.includes('<?php') || str.includes('<?=')) {
        return res.status(400).json({
          success: false,
          error:   'File contains executable code and was rejected.',
        });
      }

      // ── Null-byte check ───────────────────────────────────────────────────
      if (buffer.includes(0x00)) {
        return res.status(400).json({
          success: false,
          error:   'File contains null bytes and was rejected.',
        });
      }

      // ── Generate safe key ─────────────────────────────────────────────────
      const uid  = crypto.randomBytes(16).toString('hex');
      const ext  = path.extname(file.originalname).toLowerCase() || `.${detected.ext}`;
      const key  = `packages/${req.userId ?? 'anon'}/${Date.now()}-${uid}${ext}`;

      // ── Upload to R2 ──────────────────────────────────────────────────────
      await R2.send(new PutObjectCommand({
        Bucket:      BUCKET,
        Key:         key,
        Body:        buffer,
        ContentType: detected.mime,
        // R2 objects are private by default; expose via public bucket or Workers
      }));

      const publicUrl = `${PUBLIC_URL}/${key}`;
      urls.push(publicUrl);

      logFileUpload(req.userId, key, detected.mime, buffer.length, true, req.ip);
    }

    req.imageUrls = urls;
    next();

  } catch (error) {
    logger.error('R2 upload failed', { error: error.message, userId: req.userId });
    return res.status(500).json({
      success: false,
      error:   'Image upload failed. Please try again.',
    });
  }
};