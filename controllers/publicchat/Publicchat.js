import crypto from 'crypto';
import { supabaseAdmin as supabase } from '../../config/supabase.js';
import { notifyAgents } from './chatMailer.js';

/**
 * publicChat.js — controllers for the public website live chat.
 * Suggested location:  controllers/chat/publicChat.js
 *
 * Data lives in the `public_chat_conversations` table. All messages are stored
 * in the row's `messages` JSONB array as { id, sender, text, created_at }.
 * Appends go through the `append_public_chat_message()` Postgres function so
 * counters and the needs_agent flag update atomically.
 *
 * THIS REVISION ADDS TYPING PRESENCE (polling-based):
 *   The row gains two timestamp columns —
 *     ALTER TABLE public_chat_conversations
 *       ADD COLUMN IF NOT EXISTS visitor_typing_at timestamptz,
 *       ADD COLUMN IF NOT EXISTS agent_typing_at   timestamptz;
 *   Each side POSTs a throttled "typing" ping that stamps its column with
 *   now(). The other side's poll returns a boolean derived from freshness
 *   (stamp within TYPING_FRESH_MS). Sending a real message clears your own
 *   stamp so the indicator disappears the moment the message lands.
 *
 * New routes to register:
 *   publicChatRouter.post('/chat/conversations/:id/typing', setVisitorTyping);
 *   superadminChatRouter.post('/superadmin/public-chats/:id/typing', setAgentTyping);
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

// A typing stamp older than this is considered stale (the person stopped).
// Slightly longer than the widget's 4s poll so the indicator doesn't flicker
// between polls while someone is actively composing.
const TYPING_FRESH_MS = 8000;

const isTypingFresh = (ts) => {
  if (!ts) return false;
  const t = new Date(ts).getTime();
  return Number.isFinite(t) && Date.now() - t < TYPING_FRESH_MS;
};

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

/**
 * Best-effort update of a typing timestamp. Never throws — presence is
 * cosmetic and must not break message flows.
 */
const stampTyping = async (conversationId, column, value) => {
  try {
    await supabase
      .from(TABLE)
      .update({ [column]: value })
      .eq('id', conversationId)
      .neq('status', 'closed');
  } catch {
    /* ignore — next ping will try again */
  }
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
// The visitor's widget polls this for agent replies AND typing presence.
// ─────────────────────────────────────────────────────────────────────────────
export const getVisitorMessages = async (req, res) => {
  const { id } = req.params;

  if (!id) {
    return res.status(400).json({ success: false, message: 'Conversation id is required.' });
  }

  try {
    const { data, error } = await supabase
      .from(TABLE)
      .select('id, status, messages, agent_typing_at')
      .eq('id', id)
      .single();

    if (error || !data) {
      return res.status(404).json({ success: false, message: 'Conversation not found.' });
    }

    return res.status(200).json({
      success: true,
      status: data.status,
      messages: data.messages,
      agent_typing: data.status !== 'closed' && isTypingFresh(data.agent_typing_at),
    });

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

    // The message landed — the "visitor is typing" stamp is now stale.
    stampTyping(id, 'visitor_typing_at', null); // fire-and-forget

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
// setVisitorTyping   POST /api/chat/conversations/:id/typing   (public)
// Throttled ping from the widget while the visitor is composing.
// ─────────────────────────────────────────────────────────────────────────────
export const setVisitorTyping = async (req, res) => {
  const { id } = req.params;
  if (!id) {
    return res.status(400).json({ success: false, message: 'Conversation id is required.' });
  }
  await stampTyping(id, 'visitor_typing_at', new Date().toISOString());
  return res.status(204).end();
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
// Now also returns visitor typing presence for the open-thread indicator.
// ─────────────────────────────────────────────────────────────────────────────
export const getConversationMessages = async (req, res) => {
  const { id } = req.params;

  if (!id) {
    return res.status(400).json({ success: false, message: 'Conversation id is required.' });
  }

  try {
    const { data, error } = await supabase
      .from(TABLE)
      .select('id, status, messages, visitor_typing_at')
      .eq('id', id)
      .single();

    if (error || !data) {
      return res.status(404).json({ success: false, message: 'Conversation not found.' });
    }

    return res.status(200).json({
      success: true,
      status: data.status,
      data: data.messages,
      visitor_typing: data.status !== 'closed' && isTypingFresh(data.visitor_typing_at),
    });

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

    // The reply landed — the "agent is typing" stamp is now stale.
    stampTyping(id, 'agent_typing_at', null); // fire-and-forget

    return res.status(201).json({ success: true, message, messages: conversation.messages });

  } catch (error) {
    if (isClosedError(error)) {
      return res.status(410).json({ success: false, message: 'This conversation is closed.' });
    }
    return handleDatabaseError(res, error);
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// setAgentTyping   POST /api/superadmin/public-chats/:id/typing
// Throttled ping from the dashboard while an agent is composing a reply.
// ─────────────────────────────────────────────────────────────────────────────
export const setAgentTyping = async (req, res) => {
  const { id } = req.params;
  if (!id) {
    return res.status(400).json({ success: false, message: 'Conversation id is required.' });
  }
  await stampTyping(id, 'agent_typing_at', new Date().toISOString());
  return res.status(204).end();
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
        visitor_typing_at: null,
        agent_typing_at: null,
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