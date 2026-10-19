import express from 'express';
import { verifyToken, requireUserType } from '../middleware/auth.middleware.js';
import {
  listAgents, createRequest, listMyRequests, closeRequest,
  decideOffer, listIncoming, unreadCount, markViewed, respond,
} from '../controllers/inquiries.controller.js';

// Custom requests now require a signed-in client account, so the old guest
// (OTP, no-account) endpoints are retired. The router stays mounted so
// existing imports keep working, and answers with a clear message.
export const publicRouter = express.Router();
publicRouter.use('/guest', (_req, res) =>
  res.status(401).json({ success: false, message: 'Please sign in or create an account to request a custom package.' }));

const router = express.Router();
router.use(verifyToken);

// Agent side (declared first so "agent" is never read as an :id)
router.get('/agent/incoming', requireUserType(['agent']), listIncoming);
router.get('/agent/unread-count', requireUserType(['agent']), unreadCount);
router.post('/agent/:recipientId/view', requireUserType(['agent']), markViewed);
router.post('/agent/:recipientId/respond', requireUserType(['agent']), respond);

// Client side
router.get('/agents', requireUserType(['client']), listAgents);
router.get('/mine', requireUserType(['client']), listMyRequests);
router.post('/', requireUserType(['client']), createRequest);
router.post('/:id/close', requireUserType(['client']), closeRequest);
router.post('/:id/offers/:recipientId/decision', requireUserType(['client']), decideOffer);

export default router;
