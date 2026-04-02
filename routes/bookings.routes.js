// routes/bookings.routes.js
import express from 'express';
import { getMyBookings } from '../controllers/bookings.controller.js';
import { requireAuth }   from '../middleware/auth.middleware.js';

const router = express.Router();

// GET /api/bookings/my  — authenticated user's own bookings
router.get('/my', requireAuth, getMyBookings);

export default router;