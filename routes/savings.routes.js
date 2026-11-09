// routes/savings.routes.js — Lipa Mdogo Mdogo (pilgrim-facing)
// Base: /api/savings
import express from 'express';
import rateLimit from 'express-rate-limit';
import { body } from 'express-validator';
import { requireAuth, requireUserType } from '../middleware/auth.middleware.js';
import { handleValidationErrors } from '../middleware/validation.middleware.js';
import { uploadRateLimiter } from '../middleware/security.middleware.js';
import { parsePassportImage, validatePassportFile } from '../middleware/uploads/PassportUpload.js';
import {
  getSummary,
  listTransactions,
  updateGoal,
  depositMpesa,
  depositCard,
  getDepositStatus,
  verifyCardDeposit,
  mpesaCallback,
  downloadReceipt,
  listPackages,
  redeem,
  getPassport,
  uploadPassport,
  requestSurplus,
  listNotifications,
  markNotificationsRead,
} from '../controllers/savings.controller.js';

const router = express.Router();

const limiter = (max, message) => rateLimit({
  windowMs: 60_000,
  max,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message },
});

const depositLimiter = limiter(5, 'Too many deposit attempts. Please wait a minute and try again.');
const statusLimiter = limiter(60, 'Too many requests.');
const actionLimiter = limiter(10, 'Too many requests. Please slow down.');

// Public — Safaricom posts STK results here (no JWT; IP-checked in production).
router.post('/mpesa/callback', mpesaCallback);

// Everything else: signed-in pilgrims only.
const pilgrim = [requireAuth, requireUserType(['client'])];

router.get('/summary', ...pilgrim, getSummary);
router.get('/transactions', ...pilgrim, listTransactions);
router.get('/transactions/:id/receipt', ...pilgrim, statusLimiter, downloadReceipt);
router.put('/goal', ...pilgrim, actionLimiter, updateGoal);

router.post('/deposits/mpesa', ...pilgrim, depositLimiter, depositMpesa);
router.post('/deposits/card', ...pilgrim, depositLimiter, depositCard);
router.post('/deposits/card/verify', ...pilgrim, statusLimiter, verifyCardDeposit);
router.get('/deposits/:id/status', ...pilgrim, statusLimiter, getDepositStatus);

router.get('/packages', ...pilgrim, listPackages);
router.post('/redeem', ...pilgrim, actionLimiter, redeem);

router.get('/passport', ...pilgrim, getPassport);
router.post(
  '/passport',
  ...pilgrim,
  uploadRateLimiter,
  parsePassportImage,
  body('passportNumber').trim().notEmpty().isLength({ min: 4, max: 20 })
    .matches(/^[A-Za-z0-9]+$/).withMessage('Passport number must be letters and numbers only'),
  body('surname').trim().notEmpty().withMessage('Surname is required').isLength({ max: 60 }).escape(),
  body('givenNames').optional({ values: 'falsy' }).trim().isLength({ max: 80 }).escape(),
  body('passportCountry').optional({ values: 'falsy' }).trim().isLength({ max: 60 }).escape(),
  body('nationality').optional({ values: 'falsy' }).trim().isLength({ max: 3 }),
  body('passportExpiry').trim().matches(/^\d{4}-\d{2}-\d{2}$/).withMessage('Expiry date must be YYYY-MM-DD'),
  body('dateOfBirth').optional({ values: 'falsy' }).trim().matches(/^\d{4}-\d{2}-\d{2}$/).withMessage('Date of birth must be YYYY-MM-DD'),
  handleValidationErrors,
  validatePassportFile,
  uploadPassport,
);

router.post('/surplus', ...pilgrim, actionLimiter, requestSurplus);

router.get('/notifications', ...pilgrim, listNotifications);
router.post('/notifications/read', ...pilgrim, markNotificationsRead);

export default router;
