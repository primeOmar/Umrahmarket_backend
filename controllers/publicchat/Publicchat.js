import crypto from 'crypto';
import { supabaseAdmin as supabase } from '../../config/supabase.js';
import { notifyAgents } from './chatMailer.js';

/**
 * publicChat.js — controllers for the public website live chat.
 * Suggested location:  controllers/chat/publicChat.js
 *
 * Data lives in the `public_chat_conversations` table. All messages are
 * stored in the row's `messages` JSONB array as { id, sender, text,
 * created_at }. Appends go through the `append_public_chat_message()`
 * Postgres function so counters and the needs_agent flag update atomically.
 *
 * REALTIME REVISION — no more client polling.
 *
 * Every write that changes what a client needs to see now BROADCASTS over
 * Supabase Realtime, using the same service-role client already imported
 * as `supabase` (no extra credentials needed):
 *
 *   - `chat:conversation:{id}`  'messages_updated'  { messages, status }
 *       -> consumed by the visitor's ChatWidget and, when open, the
 *          superadmin thread modal. Sent after every append and on close.
 *
 *   - `chat:admin:list`  'conversation_created' | 'conversation_updated'
 *       -> consumed by the superadmin grid so cards update live without a
 *          15s poll. Sent on conversation start, every message (visitor or
 *          agent), and on close.
 *
 * TYPING is no longer a backend concern at all — it moved to direct
 * client-to-client broadcasts (ChatWidget <-> PublicChatTab) over the same
 * `chat:conversation:{id}` channel, on the 'typing' event. That's why the
 * `agent_typing_at` / `visitor_typing_at` columns and the /typing endpoints
 * from the previous revision are gone — typing is ephemeral and doesn't
 * need persistence or server validation, so keeping it server-side only
 * added latency and load for no benefit.
 *
 * SECURITY NOTE: broadcasting is independent of table RLS — it only
 * requires the Realtime service (on by default). Channel names are scoped
 * by the conversation's UUID, matching the same trust boundary the REST
 * endpoints already use. For stronger guarantees, enable Supabase Realtime
 * Authorization (private channels gated by a Supabase JWT).
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
const ADMIN_LIST_CHANNEL = 'chat:admin:list';

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
// Realtime broadcast helpers
//
// supabase-js channels are lightweight; we cache one per conversation (plus
// the single shared admin-list channel) for the life of the Node process
// instead of creating/subscribing a new one on every request.
// ─────────────────────────────────────────────────────────────────────────────
const channelCache = new Map();

const getChannel = (name) => {
  if (channelCache.has(name)) return channelCache.get(name);
  const channel = supabase.channel(name);
  channel.subscribe(); // joins so .send() can publish
  channelCache.set(name, channel);
  return channel;
};

/** Best-effort broadcast — must never fail or block the HTTP response. */
const broadcast = async (channelName, event, payload) => {
  try {
    const channel = getChannel(channelName);
    await channel.send({ type: 'broadcast', event, payload });
  } catch (err) {
    console.error(`Realtime broadcast failed (${channelName}/${event}):`, err.message);
  }
};

const broadcastConversationUpdate = (conversationRow) => {
  broadcast(ADMIN_LIST_CHANNEL, 'conversation_updated', toListShape(conversationRow));
};

const broadcastMessagesUpdated = (conversationId, messages, status) => {
  broadcast(`chat:conversation:${conversationId}`, 'messages_updated', { messages, status });
};

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
      // Select every column toListShape() needs so the dashboard grid gets
      // a complete card the instant this conversation is broadcast to it.
      .select(
        'id, visitor_name, visitor_phone, visitor_email, status, needs_agent, message_count, last_message, last_sender, last_activity, page_url, created_at, close_reason, messages'
      )
      .single();

    if (error) throw error;

    broadcast(ADMIN_LIST_CHANNEL, 'conversation_created', toListShape(data));

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
// Used for the widget's initial load and its Realtime reconciliation fetch
// (on reconnect / tab focus) — no longer polled in a loop.
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
// Appends the visitor's message, notifies human agents, and broadcasts the
// update to both the agent's open thread (if any) and the admin grid.
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

    broadcastMessagesUpdated(id, conversation.messages, conversation.status);
    broadcastConversationUpdate(conversation);

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
// Still used for first load and the long-interval safety-net refresh; the
// grid's live updates now come from the 'chat:admin:list' broadcast channel.
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
// Used for the thread modal's initial load and reconciliation fetch.
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
// Stored with sender 'agent'; resets the needs_agent flag via the append fn,
// then broadcasts to the visitor's widget and the admin grid.
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

    broadcastMessagesUpdated(id, conversation.messages, conversation.status);
    broadcastConversationUpdate(conversation);

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
      .select('id, visitor_name, visitor_phone, visitor_email, status, needs_agent, message_count, last_message, last_sender, last_activity, page_url, created_at, close_reason, messages')
      .single();

    if (error || !data) {
      return res.status(404).json({ success: false, message: 'Conversation not found.' });
    }

    broadcastMessagesUpdated(id, data.messages, 'closed');
    broadcastConversationUpdate(data);

    return res.status(200).json({
      success: true,
      message: 'Conversation closed successfully.',
      data: toListShape(data),
    });

  } catch (error) {
    return handleDatabaseError(res, error);
  }
};