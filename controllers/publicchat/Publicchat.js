import crypto from 'crypto';
import { supabaseAdmin as supabase } from '../../config/supabase.js';
import { notifyAgents } from './chatMailer.js';

/**
 * publicChat.js — controllers for the public website live chat.
 * Suggested location:  controllers/chat/publicChat.js
 *
 * Data lives in the `public_chat_conversations` table (see
 * public_chat_schema.sql). All messages — visitor sends, agent replies and
 * system notes — are stored in the row's `messages` JSONB array, each entry
 * shaped as { id, sender, text, created_at }. Appends go through the
 * `append_public_chat_message()` Postgres function so counters and the
 * needs_agent flag update atomically.
 */

export const handleDatabaseError = (res, error) => {
  console.error('Database error:', error);
  return res.status(500).json({ success: false, message: 'An internal server error occurred.' });
};

function sanitizeText(value = '', maxLen = 120) {
  return String(value)
    .replace(/\0/g, '')
    .replace(/<[^>]*>/g, '')
    .replace(/&(?:#x?[\da-f]+|[a-z]+);/gi, '')
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '')
    .replace(/[ \t]+/g, ' ')
    .trimStart()
    .slice(0, maxLen);
}

const TABLE = 'public_chat_conversations';

const PHONE_REGEX = /^\+?[0-9][0-9\s\-()]{6,18}[0-9]$/;
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const buildMessage = (sender, text) => ({
  id: crypto.randomUUID(),
  sender, // 'visitor' | 'agent' | 'system'
  text,
  created_at: new Date().toISOString(),
});

/** Atomic append via the Postgres function (see public_chat_schema.sql). */
const appendMessage = async (conversationId, message) => {
  const { data, error } = await supabase.rpc('append_public_chat_message', {
    p_conversation_id: conversationId,
    p_message: message,
  });
  if (error) throw new Error(error.message);
  return data; // full updated conversation row
};

/** Map a DB row to the shape the superadmin PublicChatTab expects. */
const toListShape = (row) => ({
  id: row.id,
  visitorName: row.visitor_name,
  visitorPhone: row.visitor_phone,
  visitorEmail: row.visitor_email,
  status: row.status,
  escalated: row.needs_agent, // "Needs reply" badge
  messageCount: row.message_count,
  lastMessage: row.last_message,
  lastSender: row.last_sender,
  lastActivity: row.last_activity,
  pageUrl: row.page_url,
  createdAt: row.created_at,
  closeReason: row.close_reason,
});

const isClosedError = (error) => /not found or already closed/i.test(error?.message || '');

// ─────────────────────────────────────────────────────────────────────────────
// startConversation   POST /api/chat/conversations   (public — no auth)
// Expects: { name, phone, email, page_url }
// ─────────────────────────────────────────────────────────────────────────────
export const startConversation = async (req, res) => {
  const name = sanitizeText(req.body?.name, 100).trim();
  const phone = String(req.body?.phone || '').trim();
  const email = String(req.body?.email || '').trim();
  const pageUrl = req.body?.page_url ? String(req.body.page_url).slice(0, 500) : null;

  if (!name) {
    return res.status(400).json({ success: false, message: 'Name is required.' });
  }
  if (!PHONE_REGEX.test(phone)) {
    return res.status(400).json({ success: false, message: 'Invalid phone number.' });
  }
  if (!EMAIL_REGEX.test(email)) {
    return res.status(400).json({ success: false, message: 'Invalid email address.' });
  }

  const greeting = [
    buildMessage('system', `Welcome, ${name.split(' ')[0]}. You are connected to Umrah Market support.`),
    buildMessage(
      'agent',
      'Assalamu alaikum! Ask anything about our services, customer care agents are here to serve you.'
    ),
  ];

  try {
    const { data, error } = await supabase
      .from(TABLE)
      .insert([{
        visitor_name: name,
        visitor_phone: phone,
        visitor_email: email,
        page_url: pageUrl,
        messages: greeting,
        message_count: greeting.length,
        last_message: greeting[greeting.length - 1].text,
        last_sender: 'agent',
      }])
      .select('id, status, messages')
      .single();

    if (error) throw error;

    return res.status(201).json({
      success: true,
      conversation_id: data.id,
      status: data.status,
      messages: data.messages,
    });

  } catch (error) {
    return handleDatabaseError(res, error);
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// getVisitorMessages   GET /api/chat/conversations/:id/messages   (public)
// The visitor's widget polls this for agent replies.
// ─────────────────────────────────────────────────────────────────────────────
export const getVisitorMessages = async (req, res) => {
  const { id } = req.params;

  if (!id) {
    return res.status(400).json({ success: false, message: 'Conversation id is required.' });
  }

  try {
    const { data, error } = await supabase
      .from(TABLE)
      .select('id, status, messages')
      .eq('id', id)
      .single();

    if (error || !data) {
      return res.status(404).json({ success: false, message: 'Conversation not found.' });
    }

    return res.status(200).json({ success: true, status: data.status, messages: data.messages });

  } catch (error) {
    return handleDatabaseError(res, error);
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// sendVisitorMessage   POST /api/chat/conversations/:id/messages   (public)
// Appends the visitor's message and notifies human agents (fire-and-forget).
// ─────────────────────────────────────────────────────────────────────────────
export const sendVisitorMessage = async (req, res) => {
  const { id } = req.params;
  const text = String(req.body?.text || '').trim().slice(0, 2000);

  if (!id) {
    return res.status(400).json({ success: false, message: 'Conversation id is required.' });
  }
  if (!text) {
    return res.status(400).json({ success: false, message: 'Message text is required.' });
  }

  try {
    const message = buildMessage('visitor', text);
    const conversation = await appendMessage(id, message);

    // Alert human agents — never blocks or fails the visitor's request
    notifyAgents(conversation, text);

    return res.status(201).json({
      success: true,
      message,
      status: conversation.status,
      messages: conversation.messages,
    });

  } catch (error) {
    if (isClosedError(error)) {
      return res.status(410).json({ success: false, message: 'This conversation has been closed.' });
    }
    return handleDatabaseError(res, error);
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// listConversations   GET /api/superadmin/public-chats
// ─────────────────────────────────────────────────────────────────────────────
export const listConversations = async (req, res) => {
  try {
    const { data, error } = await supabase
      .from(TABLE)
      .select(
        'id, visitor_name, visitor_phone, visitor_email, status, needs_agent, message_count, last_message, last_sender, last_activity, page_url, created_at, close_reason'
      )
      .order('last_activity', { ascending: false })
      .limit(200);

    if (error) throw error;

    return res.status(200).json({ success: true, data: (data ?? []).map(toListShape) });

  } catch (error) {
    return handleDatabaseError(res, error);
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// getConversationMessages   GET /api/superadmin/public-chats/:id/messages
// ─────────────────────────────────────────────────────────────────────────────
export const getConversationMessages = async (req, res) => {
  const { id } = req.params;

  if (!id) {
    return res.status(400).json({ success: false, message: 'Conversation id is required.' });
  }

  try {
    const { data, error } = await supabase
      .from(TABLE)
      .select('id, status, messages')
      .eq('id', id)
      .single();

    if (error || !data) {
      return res.status(404).json({ success: false, message: 'Conversation not found.' });
    }

    return res.status(200).json({ success: true, status: data.status, data: data.messages });

  } catch (error) {
    return handleDatabaseError(res, error);
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// sendAgentReply   POST /api/superadmin/public-chats/:id/messages
// Stored with sender 'agent'; resets the needs_agent flag via the append fn.
// ─────────────────────────────────────────────────────────────────────────────
export const sendAgentReply = async (req, res) => {
  const { id } = req.params;
  const text = String(req.body?.text || '').trim().slice(0, 2000);

  if (!id) {
    return res.status(400).json({ success: false, message: 'Conversation id is required.' });
  }
  if (!text) {
    return res.status(400).json({ success: false, message: 'Reply text is required.' });
  }

  try {
    const message = buildMessage('agent', text);
    const conversation = await appendMessage(id, message);

    return res.status(201).json({ success: true, message, messages: conversation.messages });

  } catch (error) {
    if (isClosedError(error)) {
      return res.status(410).json({ success: false, message: 'This conversation is closed.' });
    }
    return handleDatabaseError(res, error);
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// closeConversation   POST /api/superadmin/public-chats/:id/close
// Expects: { reason }
// ─────────────────────────────────────────────────────────────────────────────
export const closeConversation = async (req, res) => {
  const { id } = req.params;
  const reason = sanitizeText(req.body?.reason, 500).trim();

  if (!id) {
    return res.status(400).json({ success: false, message: 'Conversation id is required.' });
  }
  if (!reason) {
    return res.status(400).json({ success: false, message: 'A close reason is required.' });
  }

  try {
    // Append a system note so the visitor sees the chat was ended
    try {
      await appendMessage(
        id,
        buildMessage('system', 'This conversation has been closed by our support team.')
      );
    } catch {
      /* already closed — the update below still 404s if the row is missing */
    }

    const { data, error } = await supabase
      .from(TABLE)
      .update({
        status: 'closed',
        needs_agent: false,
        close_reason: reason,
        closed_at: new Date().toISOString(),
      })
      .eq('id', id)
      .select()
      .single();

    if (error || !data) {
      return res.status(404).json({ success: false, message: 'Conversation not found.' });
    }

    return res.status(200).json({
      success: true,
      message: 'Conversation closed successfully.',
      data: toListShape(data),
    });

  } catch (error) {
    return handleDatabaseError(res, error);
  }
};