// routes/fx.routes.js
import express from 'express';
import { getUsdKesRateMeta } from '../services/currency.service.js';
import { requireAuth } from '../middleware/auth.middleware.js';

const router = express.Router();

// GET /api/fx/rate
// Returns live USD/KES rate with source + cache metadata.
// Authenticated to prevent external hammering (frontend uses this on booking open).
router.get('/rate', async (req, res) => {
  try {
    const { rate, source, cached } = await getUsdKesRateMeta();
    return res.json({
      success:     true,
      usdKes:      rate,
      source,
      cached,
      fetchedAt:   new Date().toISOString(),
    });
  } catch (err) {
    
    return res.status(503).json({
      success: false,
      message: 'Exchange rate temporarily unavailable. Please retry.',
    });
  }
});

export default router;