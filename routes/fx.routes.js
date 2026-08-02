// routes/fx.routes.js
import express   from 'express';
import rateLimit from 'express-rate-limit';
import { getRate } from '../controllers/fx.controller.js';

const router = express.Router();

// Public and read-only (no requireAuth — package prices need to render for
// logged-out visitors too). Light rate limit purely to blunt scraping/abuse,
// not because this is expensive to serve (currency.service.js already
// caches for 10 minutes internally).
const rateLimiter = rateLimit({
  windowMs: 60_000,
  max:      60,
  standardHeaders: true,
  legacyHeaders:   false,
});

// GET /api/fx/rate
router.get('/rate', rateLimiter, getRate);

export default router;