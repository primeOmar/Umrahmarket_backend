// routes/onboarding.routes.js
// Base: /api/onboarding   (add `import onboardingRoutes from './routes/onboarding.routes.js'`
// and `app.use('/api/onboarding', onboardingRoutes);` next to the other route mounts in server.js)
import express from 'express';
import { body, query } from 'express-validator';
import { requireAuth } from '../middleware/auth.middleware.js';
import { handleValidationErrors } from '../middleware/validation.middleware.js';
import {
  getOnboardingStatus,
  getMissingOnboarding,
  saveContactInfo,
  saveNextOfKin,
} from '../controllers/onboarding.controller.js';

const router = express.Router();

// GET /api/onboarding/missing — bulk nudge check across all active bookings
router.get('/missing', requireAuth, getMissingOnboarding);

// GET /api/onboarding/status?packageId=... — per-package completeness
router.get(
  '/status',
  requireAuth,
  query('packageId').trim().notEmpty().withMessage('packageId is required'),
  handleValidationErrors,
  getOnboardingStatus,
);

// POST /api/onboarding/contact — { email, phone }
router.post(
  '/contact',
  requireAuth,
  body('email').trim().notEmpty().isEmail().withMessage('A valid email is required'),
  body('phone').trim().notEmpty().withMessage('Mobile number is required'),
  handleValidationErrors,
  saveContactInfo,
);

// POST /api/onboarding/next-of-kin — { packageId, fullName, relationship, phone, email }
router.post(
  '/next-of-kin',
  requireAuth,
  body('packageId').trim().notEmpty().withMessage('packageId is required'),
  body('fullName').trim().notEmpty().isLength({ min: 2, max: 100 }).withMessage("Next of kin's full name is required"),
  body('phone').trim().notEmpty().withMessage('Next-of-kin mobile number is required'),
  body('relationship').optional({ values: 'falsy' }).trim().isLength({ max: 60 }),
  body('email').optional({ values: 'falsy' }).trim().isEmail().withMessage('Next-of-kin email is invalid'),
  handleValidationErrors,
  saveNextOfKin,
);

export default router;