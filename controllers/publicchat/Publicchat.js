import crypto from 'crypto';
import { supabaseAdmin as supabase } from '../../config/supabase.js';
import { notifyAgents } from './chatMailer.js';

/**
 * publicChat.js — controllers for the public website live chat.
 *
 * REALTIME REVISION 4 — DB-backed unread_count.
 *
 * Unread badges were previously pure client-side state, rebuilt from
 * whatever broadcasts a given browser tab happened to see. That breaks the
 * moment a second agent window opens, or an existing one is refreshed —
 * there's no history to replay, so it starts blank and stays wrong until
 * fresh traffic arrives.
 *
 * Fixed by making unread_count a real column (see
 * public_chat_unread_migration.sql), maintained here:
 *   - incremented via the increment_public_chat_unread() RPC on every
 *     visitor message
 *   - reset to 0 via reset_public_chat_unread() on every agent reply,
 *     on close, and via the new markConversationRead() endpoint (called
 *     when an agent opens a thread)
 *   - included in every 'conversation_updated' broadcast (via toListShape),
 *     so any window — new tab, refreshed tab, a different agent entirely —
 *     converges on the same number the instant it (re)connects, and stays
 *     in sync as other agents read/reply.
 *
 * The direct 'visitor_message' / 'message_sent' broadcasts from REALTIME
 * REVISION 3 are unaffected and still give the instant, backend-independent
 * feel — this is just what makes the *number* correct everywhere, not just
 * in the tab that happened to be open when it changed.
 *
 * REALTIME REVISION 3 (still in effect) — client-supplied message ids, so
 * a direct broadcast and its persisted copy share an id and never render
 * twice.
 *
 * REALTIME REVISION 2 (still in effect) — broadcasts are awaited before the
 * response is sent, and built fresh per call (subscribe, send, remove)
 * instead of cached across requests, so a process that was frozen/
 * suspended between requests (Render free spin-down) can't hand a
 * broadcast to an already-dead socket.
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
const CHANNEL_SUBSCRIBE_TIMEOUT_MS = 15000; // generous — covers a Render cold start

const PHONE_REGEX = /^\+?[0-9][0-9\s\-()]{6,18}[0-9]$/;
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// Every column the dashboard needs, including the new unread_count.
const ROW_SELECT =
  'id, visitor_name, visitor_phone, visitor_email, status, needs_agent, unread_count, message_count, last_message, last_sender, last_activity, page_url, created_at, close_reason, messages';
const ROW_SELECT_NO_MESSAGES =
  'id, visitor_name, visitor_phone, visitor_email, status, needs_agent, unread_count, message_count, last_message, last_sender, last_activity, page_url, created_at, close_reason';

/** Use a client-supplied id if present and well-formed, else mint one. */
const resolveMessageId = (requestedId) =>
  typeof requestedId === 'string' && UUID_REGEX.test(requestedId) ? requestedId : crypto.randomUUID();

const buildMessage = (sender, text, requestedId) => ({
  id: resolveMessageId(requestedId),
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

/** Fetch the current unread_count for a conversation (authoritative). */
const fetchUnreadCount = async (conversationId) => {
  const { data } = await supabase.from(TABLE).select('unread_count').eq('id', conversationId).single();
  return data?.unread_count ?? 0;
};

const incrementUnread = async (conversationId) => {
  await supabase.rpc('increment_public_chat_unread', { p_conversation_id: conversationId });
  return fetchUnreadCount(conversationId);
};

const resetUnread = async (conversationId) => {
  await supabase.rpc('reset_public_chat_unread', { p_conversation_id: conversationId });
  return 0;
};

/** Map a DB row to the shape the superadmin PublicChatTab expects. */
const toListShape = (row) => ({
  id: row.id,
  visitorName: row.visitor_name,
  visitorPhone: row.visitor_phone,
  visitorEmail: row.visitor_email,
  status: row.status,
  escalated: row.needs_agent, // "Needs reply" badge
  unreadCount: row.unread_count ?? 0,
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
// Realtime broadcast helper
//
// One-shot per call: open a channel, wait for SUBSCRIBED, send, then remove
// it. No cross-request caching, so a process that was frozen/suspended
// between requests (Render free spin-down) can never hand a broadcast to a
// socket that's already dead.
// ─────────────────────────────────────────────────────────────────────────────
const broadcastOnce = (channelName, event, payload) =>
  new Promise((resolve) => {
    const channel = supabase.channel(channelName);
    let settled = false;

    const cleanup = (ok, err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      supabase.removeChannel(channel);
      if (!ok) console.error(`Realtime broadcast failed (${channelName}/${event}):`, err?.message || err);
      resolve(ok);
    };

    const timeout = setTimeout(() => {
      cleanup(false, new Error(`subscribe timed out for channel "${channelName}"`));
    }, CHANNEL_SUBSCRIBE_TIMEOUT_MS);

    channel.subscribe(async (status, err) => {
      if (status === 'SUBSCRIBED') {
        try {
          await channel.send({ type: 'broadcast', event, payload });
          cleanup(true);
        } catch (sendErr) {
          cleanup(false, sendErr);
        }
        return;
      }
      if (status === 'CHANNEL_ERROR' || status === 'TIMED_OUT' || status === 'CLOSED') {
        cleanup(false, err || new Error(`channel "${channelName}" reported ${status}`));
      }
    });
  });

/** Best-effort broadcast — logs on failure but never throws to the caller. */
const broadcast = async (channelName, event, payload) => {
  await broadcastOnce(channelName, event, payload);
};

/**
 * Admin-grid update, tagged with the id of the message that produced it
 * (dedupes an agent tab's own optimistic bump against this event) and
 * carrying the authoritative unread_count from the DB — this is what lets
 * a second agent window, or a refreshed one, show the correct number
 * immediately instead of starting from zero.
 */
const broadcastConversationUpdate = (conversationRow) => {
  const lastMessageId = Array.isArray(conversationRow.messages) && conversationRow.messages.length
    ? conversationRow.messages[conversationRow.messages.length - 1].id
    : undefined;
  return broadcast(ADMIN_LIST_CHANNEL, 'conversation_updated', { ...toListShape(conversationRow), lastMessageId });
};

const broadcastMessagesUpdated = (conversationId, messages, status) =>
  broadcast(`chat:conversation:${conversationId}`, 'messages_updated', { messages, status });

// ─────────────────────────────────────────────────────────────────────────────
// startConversation   POST /api/chat/conversations   (public — no auth)
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
        unread_count: 0, // greeting is from us, nothing unread yet
      }])
      .select(ROW_SELECT)
      .single();

    if (error) throw error;

    await broadcast(ADMIN_LIST_CHANNEL, 'conversation_created', toListShape(data));

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
// Expects: { text, id? }
// ─────────────────────────────────────────────────────────────────────────────
export const sendVisitorMessage = async (req, res) => {
  const { id: conversationId } = req.params;
  const text = String(req.body?.text || '').trim().slice(0, 2000);
  const requestedId = req.body?.id;

  if (!conversationId) {
    return res.status(400).json({ success: false, message: 'Conversation id is required.' });
  }
  if (!text) {
    return res.status(400).json({ success: false, message: 'Message text is required.' });
  }

  try {
    const message = buildMessage('visitor', text, requestedId);
    const conversation = await appendMessage(conversationId, message);

    // A visitor message always adds one unread, for every agent watching
    // the grid — regardless of which window/tab they're in.
    conversation.unread_count = await incrementUnread(conversationId);

    await broadcastMessagesUpdated(conversationId, conversation.messages, conversation.status);
    await broadcastConversationUpdate(conversation);

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
      .select(ROW_SELECT_NO_MESSAGES)
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
// Expects: { text, id? }
// A reply implies the agent has read the thread, so this resets
// unread_count to 0 for everyone watching the grid.
// ─────────────────────────────────────────────────────────────────────────────
export const sendAgentReply = async (req, res) => {
  const { id: conversationId } = req.params;
  const text = String(req.body?.text || '').trim().slice(0, 2000);
  const requestedId = req.body?.id;

  if (!conversationId) {
    return res.status(400).json({ success: false, message: 'Conversation id is required.' });
  }
  if (!text) {
    return res.status(400).json({ success: false, message: 'Reply text is required.' });
  }

  try {
    const message = buildMessage('agent', text, requestedId);
    const conversation = await appendMessage(conversationId, message);
    conversation.unread_count = await resetUnread(conversationId);

    await broadcastMessagesUpdated(conversationId, conversation.messages, conversation.status);
    await broadcastConversationUpdate(conversation);

    return res.status(201).json({ success: true, message, messages: conversation.messages });

  } catch (error) {
    if (isClosedError(error)) {
      return res.status(410).json({ success: false, message: 'This conversation is closed.' });
    }
    return handleDatabaseError(res, error);
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// markConversationRead   POST /api/superadmin/public-chats/:id/read
// Called when an agent opens a thread, even if they don't reply right
// away. Resets unread_count to 0 and broadcasts it, so every other agent
// window sees the badge clear too — not just the one that opened it.
// ─────────────────────────────────────────────────────────────────────────────
export const markConversationRead = async (req, res) => {
  const { id } = req.params;

  if (!id) {
    return res.status(400).json({ success: false, message: 'Conversation id is required.' });
  }

  try {
    await resetUnread(id);

    const { data, error } = await supabase.from(TABLE).select(ROW_SELECT).eq('id', id).single();
    if (error || !data) {
      return res.status(404).json({ success: false, message: 'Conversation not found.' });
    }

    await broadcastConversationUpdate(data);

    return res.status(200).json({ success: true, data: toListShape(data) });

  } catch (error) {
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
        unread_count: 0,
        close_reason: reason,
        closed_at: new Date().toISOString(),
      })
      .eq('id', id)
      .select(ROW_SELECT)
      .single();

    if (error || !data) {
      return res.status(404).json({ success: false, message: 'Conversation not found.' });
    }

    await broadcastMessagesUpdated(id, data.messages, 'closed');
    await broadcastConversationUpdate(data);

    return res.status(200).json({
      success: true,
      message: 'Conversation closed successfully.',
      data: toListShape(data),
    });

  } catch (error) {
    return handleDatabaseError(res, error);
  }
};