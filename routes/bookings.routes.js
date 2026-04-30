// routes/bookings.routes.js
import express from 'express';
import { getMyBookings, getAgentClients } from '../controllers/bookings.controller.js';
import { requireAuth }   from '../middleware/auth.middleware.js';

const router = express.Router();

// GET /api/bookings/my  — authenticated user's own bookings
router.get('/my', requireAuth, getMyBookings);

// GET /api/bookings/agent-clients  — all clients who booked the agent's packages
router.get('/agent-clients', requireAuth, getAgentClients);

export default router;