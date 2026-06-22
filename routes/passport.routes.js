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
import {
  checkPassportValidity,
  verifyPassportImage,
  getPassportStatus,
  getFacePhotoStatus,
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

// ── GET /api/passport/face-photo-status ──────────────────────────────────────
// Returns which of the user's confirmed/pending bookings are missing a
// face photo for their Umrah ID card.
// Response: { bookingsMissingPhoto: [{ bookingId, packageId }] }
router.get(
  '/face-photo-status',
  requireAuth,
  getFacePhotoStatus,
);

export default router;