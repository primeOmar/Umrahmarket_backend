// routes/card.routes.js
import express   from 'express';
import rateLimit from 'express-rate-limit';
import { initiate, verify, ipn } from '../controllers/cardController.js';
import { requireAuth } from '../middleware/auth.middleware.js';

const router = express.Router();

const initiateLimiter = rateLimit({
  windowMs: 60_000, max: 5,
  message: { success: false, message: 'Too many payment requests. Please wait.' },
  standardHeaders: true, legacyHeaders: false,
});

const verifyLimiter = rateLimit({
  windowMs: 60_000, max: 20,
  message: { success: false, message: 'Too many verification attempts.' },
  standardHeaders: true, legacyHeaders: false,
});

// POST /api/payments/card/initiate  — get Pesapal redirect URL
// Body: { packageId }
router.post('/initiate', requireAuth, initiateLimiter, initiate);

// POST /api/payments/card/verify    — verify after Pesapal redirect back
// Body: { orderTrackingId, packageId }
router.post('/verify', requireAuth, verifyLimiter, verify);

// POST /api/payments/card/ipn       — Pesapal async IPN (PUBLIC — no JWT)
router.post('/ipn', ipn);

export default router;