// routes/mpesa.routes.js
import express   from 'express';
import rateLimit from 'express-rate-limit';
import { initiate, callback, getStatus } from '../controllers/mpesaController.js';
import { requireAuth } from '../middleware/auth.middleware.js'; 

const router = express.Router();
// ── Rate limiters ──────────────────────────────────────────────────────────
const initiateLimiter = rateLimit({
  windowMs: 60_000,
  max:      5,
  message:  { success: false, message: 'Too many payment attempts. Please wait and try again.' },
  standardHeaders: true,
  legacyHeaders:   false,
});

const statusLimiter = rateLimit({
  windowMs: 60_000,
  max:      60,
  message:  { success: false, message: 'Too many requests.' },
  standardHeaders: true,
  legacyHeaders:   false,
});

// POST /api/payments/mpesa/initiate
router.post('/initiate', requireAuth, initiateLimiter, initiate);

// POST /api/payments/mpesa/callback  (public — no JWT, Safaricom calls this)
router.post('/callback', callback);

// GET /api/payments/mpesa/status/:checkoutRequestId
router.get('/status/:checkoutRequestId', requireAuth, statusLimiter, getStatus);

export default router;