import express from 'express';
import { sendMessage, getMessages, getUnreadCount } from '../controllers/messagesController.js';
import { verifyToken } from '../middleware/auth.middleware.js';

const router = express.Router();

// All message routes require auth
router.use(verifyToken);

// POST   /api/messages           — send a message
router.post('/', sendMessage);

// GET    /api/messages/:bookingId — get all messages for a booking
router.get('/:bookingId', getMessages);

// GET    /api/messages/unread    — get unread message count
router.get('/count/unread', getUnreadCount);

export default router;
