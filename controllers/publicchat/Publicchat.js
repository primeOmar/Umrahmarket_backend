import crypto from 'crypto';
import { supabaseAdmin as supabase } from '../../config/supabase.js';
import { notifyAgents } from './chatMailer.js';

/**
 * publicChat.js — controllers for the public website live chat.
 *
 * REALTIME REVISION 6 — resume an existing conversation by identity.
 *
 * startConversation() now checks for an existing, non-closed conversation
 * with the same email AND phone before creating a new row. If one exists,
 * it's returned as-is (same response shape as a fresh start) instead of
 * inserting a duplicate — so a visitor who reopens the site, or refills
 * the pre-chat form after clearing session storage, picks up where they
 * left off rather than spawning a new thread every time. Once a
 * conversation is closed, this lookup deliberately excludes it — closed
 * means closed, and the next message starts a brand new conversation.
 *
 * Phone numbers are compared digit-only (normalizePhone), since the same
 * number can be stored as "+254799690364" or "254799690364" depending on
 * how it was typed — a plain string match would treat those as different
 * visitors.
 *
 * REALTIME REVISION 5 (still in effect) — read state lives on each
 * message (`read: boolean` in the messages jsonb), not a bare counter.
 * `unread_count` is a cached number for the grid list, always recomputed
 * from the messages array (countUnread/syncUnreadCount), never
 * incremented as an independent operation. mark_public_chat_read() flips
 * every visitor message to read and zeroes the count atomically —used
 * when a thread is opened and right after an agent reply.
 *
 * REALTIME REVISION 3 (still in effect) — a message broadcasts directly to
 * the other side the instant it's sent, over the same channel typing uses;
 * the REST call + backend broadcast is the durable/reconciling path
 * underneath, using a client-supplied id so both never render twice.
 *
 * REALTIME REVISION 2 (still in effect) — every broadcast is awaited and
 * built fresh per call (subscribe, send, remove) instead of cached across
 * requests, so a process frozen/suspended between requests (Render free
 * spin-down) can't hand a broadcast to an already-dead socket.
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

const ROW_SELECT =
  'id, visitor_name, visitor_phone, visitor_email, status, needs_agent, unread_count, message_count, last_message, last_sender, last_activity, page_url, created_at, close_reason, messages';
const ROW_SELECT_NO_MESSAGES =
  'id, visitor_name, visitor_phone, visitor_email, status, needs_agent, unread_count, message_count, last_message, last_sender, last_activity, page_url, created_at, close_reason';

/** Digits only, so "+254799690364" and "254799690364" compare equal. */
const normalizePhone = (value) => String(value || '').replace(/[^0-9]/g, '');

/** Use a client-supplied id if present and well-formed, else mint one. */
const resolveMessageId = (requestedId) =>
  typeof requestedId === 'string' && UUID_REGEX.test(requestedId) ? requestedId : crypto.randomUUID();

const buildMessage = (sender, text, requestedId) => ({
  id: resolveMessageId(requestedId),
  sender, // 'visitor' | 'agent' | 'system'
  text,
  created_at: new Date().toISOString(),
  // Only visitor messages are ever counted as unread; agent/system
  // messages are marked read for consistency, though nothing reads this
  // field for them.
  read: sender !== 'visitor',
});

/** Atomic append via the Postgres function (see public_chat_schema.sql).
 *  Unchanged — it just appends whatever message object it's given, so the
 *  `read` field passes through with no changes needed on its side. */
const appendMessage = async (conversationId, message) => {
  const { data, error } = await supabase.rpc('append_public_chat_message', {
    p_conversation_id: conversationId,
    p_message: message,
  });
  if (error) throw new Error(error.message);
  return data; // full updated conversation row
};

/** The single source of truth for "how many are unread" — always derived
 *  from the messages array itself, never tracked independently. */
const countUnread = (messages) =>
  Array.isArray(messages) ? messages.filter((m) => m.sender === 'visitor' && m.read === false).length : 0;

/** Recompute unread_count from the row's own messages array and persist
 *  it as the cached value the grid list reads. */
const syncUnreadCount = async (conversationId, messages) => {
  const unreadCount = countUnread(messages);
  await supabase.from(TABLE).update({ unread_count: unreadCount }).eq('id', conversationId);
  return unreadCount;
};

/** Marks every visitor message in the conversation read and zeroes
 *  unread_count, atomically, via mark_public_chat_read(). Used both when
 *  an agent opens/re-views a thread and right after an agent reply. */
const markRead = async (conversationId) => {
  const { data, error } = await supabase.rpc('mark_public_chat_read', { p_conversation_id: conversationId });
  if (error) throw new Error(error.message);
  return data; // full updated row, messages included
};

/** Finds a non-closed conversation with the same email and phone, most
 *  recently active first. Returns the full row, or null if none matches. */
const findResumableConversation = async (email, phone) => {
  const { data, error } = await supabase
    .from(TABLE)
    .select(ROW_SELECT)
    .ilike('visitor_email', email)
    .neq('status', 'closed')
    .order('last_activity', { ascending: false });

  if (error || !Array.isArray(data)) return null;

  const targetPhone = normalizePhone(phone);
  return data.find((row) => normalizePhone(row.visitor_phone) === targetPhone) || null;
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
// Realtime broadcast helper — one-shot per call, no cross-request caching.
// See REALTIME REVISION 2 in the module comment for why.
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

const broadcast = async (channelName, event, payload) => {
  await broadcastOnce(channelName, event, payload);
};

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
// Expects: { name, phone, email, page_url }
//
// If a non-closed conversation already exists for this email+phone, it's
// resumed (returned as-is, response includes resumed: true) instead of
// creating a new row. Otherwise behaves exactly as before.
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

  try {
    const resumable = await findResumableConversation(email, phone);
    if (resumable) {
      return res.status(200).json({
        success: true,
        resumed: true,
        conversation_id: resumable.id,
        status: resumable.status,
        messages: resumable.messages,
      });
    }

    const greeting = [
      buildMessage('system', `Welcome, ${name.split(' ')[0]}. You are connected to Umrah Market support.`),
      buildMessage(
        'agent',
        'Assalamu alaikum! Ask anything about our services, customer care agents are here to serve you.'
      ),
    ];

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
        unread_count: 0, // greeting is from us — nothing unread yet
      }])
      .select(ROW_SELECT)
      .single();

    if (error) throw error;

    await broadcast(ADMIN_LIST_CHANNEL, 'conversation_created', toListShape(data));

    return res.status(201).json({
      success: true,
      resumed: false,
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
// New message starts unread (read: false, set in buildMessage). No
// increment RPC — unread_count is recomputed straight from the array.
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
    conversation.unread_count = await syncUnreadCount(conversationId, conversation.messages);

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
// Replying implies the agent has seen everything up to now, so this marks
// all visitor messages read (and unread_count -> 0) right after appending.
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
    await appendMessage(conversationId, message);
    const conversation = await markRead(conversationId); // full row, messages read-flagged, unread_count 0

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
// Called when an agent opens a thread, AND again each time a new visitor
// message arrives while that thread is still open — so messages that come
// in while the agent is actively watching get marked read as they land,
// not just once at open time. If nobody calls this (thread not open),
// messages simply stay unread — that's just the default state.
// ─────────────────────────────────────────────────────────────────────────────
export const markConversationRead = async (req, res) => {
  const { id } = req.params;

  if (!id) {
    return res.status(400).json({ success: false, message: 'Conversation id is required.' });
  }

  try {
    const data = await markRead(id);
    if (!data) {
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