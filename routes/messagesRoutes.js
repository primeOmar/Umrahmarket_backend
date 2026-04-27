// routes/messagesRoutes.js
import express from 'express';
import {
  sendMessage,
  getMessages,
  getUnreadCount,
  markMessagesAsRead,
  getAgentConversations,
} from '../controllers/messagesController.js';
import { verifyToken } from '../middleware/auth.middleware.js';

const router = express.Router();

// All message routes require auth
router.use(verifyToken);

// POST   /api/messages               — send a message
router.post('/', sendMessage);

// POST   /api/messages/mark-read     — mark messages as read
router.post('/mark-read', markMessagesAsRead);

// GET    /api/messages/count/unread  — get unread message count (must be before /:bookingId)
router.get('/count/unread', getUnreadCount);

// GET    /api/messages/agent/conversations — get all conversations for an agent
router.get('/agent/conversations', getAgentConversations);

// GET    /api/messages/:bookingId    — get all messages for a booking
router.get('/:bookingId', getMessages);

export default router;