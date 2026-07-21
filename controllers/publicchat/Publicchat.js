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
 * REALTIME REVISION 2 — fix for Render free-tier spin-down.
 *
 * The previous revision cached one long-lived Realtime channel per name in
 * a module-level Map, and fired broadcasts without awaiting them before
 * the HTTP response was sent. That's fine on an always-on process, but on
 * a host that can idle-suspend the process (Render free web services spin
 * down after ~15 min with no HTTP traffic):
 *
 *   1. A cold start after spin-down can take longer than the channel
 *      subscribe timeout, so the very first broadcast after waking up
 *      silently fails (caught, logged, never surfaced).
 *   2. If the process is frozen rather than cleanly restarted, a cached
 *      channel's underlying socket can die without ever firing the
 *      CLOSED/CHANNEL_ERROR callback that would evict it from the cache —
 *      so later requests keep reusing a channel whose socket is dead.
 *   3. Because the broadcast calls were not awaited, the request handler
 *      could return its HTTP response (and the platform could recycle the
 *      process) before the broadcast's websocket send had actually
 *      flushed.
 *
 * Fix: broadcasts are now (a) awaited before the response is sent, and
 * (b) built fresh per call — subscribe, send, then remove — instead of
 * cached across requests. This trades a small per-message handshake cost
 * for immunity to stale/dead sockets left over from a suspend/resume
 * cycle. For this traffic volume (human-typed chat messages) that cost is
 * negligible.
 *
 * If you later move off a spin-down-capable host, the long-lived cache
 * from the previous revision is a reasonable optimization to bring back —
 * but only alongside a keep-alive ping so the process never actually
 * spins down while conversations are active. On Render specifically,
 * either upgrade off the free instance type or hit a lightweight health
 * endpoint from an external cron every 5–10 minutes to prevent spin-down;
 * cold starts are the biggest lever here, bigger than anything in this
 * file.
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
const CHANNEL_SUBSCRIBE_TIMEOUT_MS = 15000; // generous — covers a Render cold start

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
// Realtime broadcast helper
//
// One-shot per call: open a channel, wait for SUBSCRIBED, send, then remove
// it. No cross-request caching, so a process that was frozen/suspended
// between requests (Render free spin-down) can never hand a broadcast to a
// socket that's already dead. Slightly more handshake overhead per message
// than a long-lived cache, but immune to the stale-channel failure mode.
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

const broadcastConversationUpdate = (conversationRow) =>
  broadcast(ADMIN_LIST_CHANNEL, 'conversation_updated', toListShape(conversationRow));

const broadcastMessagesUpdated = (conversationId, messages, status) =>
  broadcast(`chat:conversation:${conversationId}`, 'messages_updated', { messages, status });

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

    // Awaited: don't let the platform recycle the process before this send flushes.
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

    // Both awaited: guarantees the send is flushed before we respond, and
    // before any spin-down-capable host could recycle the process.
    await broadcastMessagesUpdated(id, conversation.messages, conversation.status);
    await broadcastConversationUpdate(conversation);

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

    await broadcastMessagesUpdated(id, conversation.messages, conversation.status);
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