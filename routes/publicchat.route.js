import express from 'express';
import {
  startConversation, getVisitorMessages, sendVisitorMessage,
  listConversations, getConversationMessages, sendAgentReply,
  closeConversation, markConversationRead,
} from '../controllers/publicchat/Publicchat.js';
import { authenticateSuperadmin } from './superadmin_routes.js';

const router = express.Router();

router.post('/chat/conversations', startConversation);
router.get('/chat/conversations/:id/messages', getVisitorMessages);
router.post('/chat/conversations/:id/messages', sendVisitorMessage);
router.get('/superadmin/public-chats', authenticateSuperadmin, listConversations);
router.get('/superadmin/public-chats/:id/messages', authenticateSuperadmin, getConversationMessages);
router.post('/superadmin/public-chats/:id/messages', authenticateSuperadmin, sendAgentReply);
router.post('/superadmin/public-chats/:id/close', authenticateSuperadmin, closeConversation);
router.post('/superadmin/public-chats/:id/read', authenticateSuperadmin, markConversationRead);

export default router;