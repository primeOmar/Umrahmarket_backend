/**
 * Passport verification routes.
 * Base: /api/passport   (mounted in server.js)
 *
 * All endpoints require an authenticated user. Verification attempts are
 * rate-limited to blunt brute-force / image-spamming.
 */
import express from 'express';
import { body, query } from 'express-validator';
import { requireAuth } from '../middleware/auth.middleware.js';
import { handleValidationErrors } from '../middleware/validation.middleware.js';
import { uploadRateLimiter } from '../middleware/security.middleware.js';
import { parsePassportImage, validatePassportFile } from '../middleware/uploads/PassportUpload.js';
import multer from 'multer';

// Lightweight multer instance for the face-photo endpoint.
// The controller handles its own deep MIME validation, so this just
// enforces size + field name so we never buffer more than 8 MB.
const faceUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 8 * 1024 * 1024, files: 1 },
}).single('face');
import {
  checkPassportValidity,
  verifyPassportImage,
  getPassportStatus,
  getPassportStatusBatch,
  getFacePhotoStatus,
  saveFacePhoto,
} from '../controllers/passport.controller.js';

const router = express.Router();

// ISO yyyy-mm-dd validator
const isoDate = (field, { optional = false } = {}) => {
  const chain = body(field).trim();
  return (optional ? chain.optional({ values: 'falsy' }) : chain.notEmpty().withMessage(`${field} is required`))
    .matches(/^\d{4}-\d{2}-\d{2}$/).withMessage(`${field} must be YYYY-MM-DD`);
};

// ── POST /api/passport/check ─────────────────────────────────────────────────
router.post(
  '/check',
  requireAuth,
  body('packageId').trim().notEmpty().withMessage('packageId is required'),
  isoDate('passportExpiry'),
  handleValidationErrors,
  checkPassportValidity,
);

// ── POST /api/passport/verify-image ──────────────────────────────────────────
// multipart/form-data: file field "passport" + text fields.
router.post(
  '/verify-image',
  requireAuth,
  uploadRateLimiter,
  parsePassportImage,        // multer → req.file
  // Validate text fields (present alongside the file in the multipart body)
  body('packageId').trim().notEmpty().withMessage('packageId is required'),
  body('passportNumber').trim().notEmpty().isLength({ min: 4, max: 20 })
    .matches(/^[A-Za-z0-9]+$/).withMessage('Passport number must be alphanumeric'),
  body('surname').trim().notEmpty().isLength({ max: 60 }).escape(),
  body('givenNames').optional({ values: 'falsy' }).trim().isLength({ max: 80 }).escape(),
  body('passportCountry').optional({ values: 'falsy' }).trim().isLength({ max: 60 }).escape(),
  body('nationality').optional({ values: 'falsy' }).trim().isLength({ max: 3 }),
  isoDate('passportExpiry'),
  isoDate('dateOfBirth', { optional: true }),
  handleValidationErrors,
  validatePassportFile,      // deep MIME + injection scan → req.passportFile
  verifyPassportImage,
);

// ── GET /api/passport/status ─────────────────────────────────────────────────
router.get(
  '/status',
  requireAuth,
  query('packageId').trim().notEmpty().withMessage('packageId is required'),
  handleValidationErrors,
  getPassportStatus,
);

// ── GET /api/passport/status-batch ───────────────────────────────────────────
// Returns verification status for every traveler slot (0..totalTravelers-1)
// on a booking in one call — lets BookingFlow check everyone up front instead
// of gating on just the account holder's own passport.
router.get(
  '/status-batch',
  requireAuth,
  query('packageId').trim().notEmpty().withMessage('packageId is required'),
  query('totalTravelers').optional().isInt({ min: 1, max: 30 }).withMessage('totalTravelers must be between 1 and 30'),
  handleValidationErrors,
  getPassportStatusBatch,
);

// ── GET /api/passport/face-photo-status ──────────────────────────────────────
// Returns which of the user's confirmed/pending bookings are missing a
// face photo for their Umrah ID card.
// Response: { bookingsMissingPhoto: [{ bookingId, packageId }] }
router.get(
  '/face-photo-status',
  requireAuth,
  getFacePhotoStatus,
);

// ── POST /api/passport/face-photo ─────────────────────────────────────────────
// Saves the pilgrim's dedicated selfie submitted via FacePhotoModal after a
// successful payment. The photo is stored in R2 (public-read, headshot only)
// and written to passport_verifications.face_photo_url so the agent can embed
// it on the Umrah ID card PDF.
//
// multipart/form-data:
//   face      — image/jpeg | image/png | image/webp, max 8 MB
//   packageId — the package this booking belongs to
router.post(
  '/face-photo',
  requireAuth,
  uploadRateLimiter,
  (req, res, next) => {
    faceUpload(req, res, (err) => {
      if (err instanceof multer.MulterError) {
        const msgs = {
          LIMIT_FILE_SIZE: 'Image too large. Max 8 MB.',
          LIMIT_FILE_COUNT: 'Upload one photo at a time.',
          LIMIT_UNEXPECTED_FILE: 'Unexpected file field. Use the field name "face".',
        };
        return res.status(400).json({ success: false, error: msgs[err.code] || err.message });
      }
      if (err) return res.status(400).json({ success: false, error: err.message });
      next();
    });
  },
  body('packageId').trim().notEmpty().withMessage('packageId is required'),
  body('bookingId').optional({ values: 'falsy' }).isUUID().withMessage('bookingId must be a valid UUID'),
  body('travelerIndex').optional({ values: 'falsy' }).isInt({ min: 0, max: 29 }).withMessage('travelerIndex must be between 0 and 29'),
  handleValidationErrors,
  saveFacePhoto,
);

export default router;