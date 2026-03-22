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
export const parseFormData = (req, res, next) => {
  upload.array('images', MAX_FILES)(req, res, (err) => {
    if (err instanceof multer.MulterError) {
      const msgs = {
        LIMIT_FILE_SIZE:       `File too large. Max ${MAX_SIZE / 1024 / 1024} MB per image.`,
        LIMIT_FILE_COUNT:      `Too many files. Max ${MAX_FILES} images.`,
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
      // Verify actual file signature matches claimed MIME type
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
          error:   'File type verification failed. Only JPEG, PNG, and WebP images are allowed.',
        });
      }

      // ── PHP / shell code check ────────────────────────────────────────────
      // Scan only the first 1KB as text — binary image data beyond header
      // is irrelevant for code injection and contains valid null bytes
      const headerStr = buffer.slice(0, 1024).toString('latin1');
      if (headerStr.includes('<?php') || headerStr.includes('<?=') || headerStr.includes('<script')) {
        logSuspiciousActivity('R2 upload rejected — executable code detected', {
          userId: req.userId,
          ip:     req.ip,
        });
        return res.status(400).json({
          success: false,
          error:   'File contains executable code and was rejected.',
        });
      }

      // NOTE: Null-byte check removed — JPEG/PNG/WebP files legitimately
      // contain null bytes (0x00) as part of their binary format.
      // The MIME signature check above is sufficient security.

      // ── Generate safe key ─────────────────────────────────────────────────
      const uid = crypto.randomBytes(16).toString('hex');
      const ext = path.extname(file.originalname).toLowerCase() || `.${detected.ext}`;
      const key = `packages/${req.userId ?? 'anon'}/${Date.now()}-${uid}${ext}`;

      // ── Upload to R2 ──────────────────────────────────────────────────────
      await R2.send(new PutObjectCommand({
        Bucket:      BUCKET,
        Key:         key,
        Body:        buffer,
        ContentType: detected.mime,
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
