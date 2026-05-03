// controllers/messagesController.js
import { supabaseAdmin } from '../config/supabase.js';

// ─────────────────────────────────────────────────────────────────────────────
// Create Automated Booking Message (Internal)
// Called after successful booking from payment controllers
// ─────────────────────────────────────────────────────────────────────────────
export const createBookingMessage = async (bookingId, clientId, agentId, packageName) => {
  try {
    // Fetch package details for hotel info
    const { data: packageData } = await supabaseAdmin
      .from('packages')
      .select('makkah_hotel_name, madinah_hotel_name, agent_name')
      .eq('created_by', agentId)
      .single();

    const agentDisplayName = packageData?.agent_name || 'Your Umrah Agent';

    // ── Automated welcome message FROM agent TO client ──────────────────────
    const welcomeMessage =
      `✨ Booking Confirmed! ✨\n\n` +
      `Assalamu Alaikum! Thank you for booking *${packageName}*. May Allah bless your journey. 🙏\n\n` +
      `📋 Booking Reference: ${bookingId}\n\n` +
      `🕌 What happens next?\n` +
      `• Our team will reach out within 24 hours\n` +
      `• You'll receive visa & travel documents guidance\n` +
      `• Feel free to ask any questions about your Umrah journey right here\n\n` +
      `🏨 Hotel Details:\n` +
      `• Makkah: ${packageData?.makkah_hotel_name || '5-Star Hotel Near Haram'}\n` +
      `• Madinah: ${packageData?.madinah_hotel_name || '5-Star Hotel Near Masjid Nabawi'}\n\n` +
      `Need urgent help? Reply to this message anytime.\n\n` +
      `Barakallahu feekum! 🤲`;

    const { error: clientMsgError } = await supabaseAdmin
      .from('messages')
      .insert({
        booking_id: bookingId,
        sender_id: agentId,           // must be a valid uuid — 'system' violates FK
        sender_type: 'agent',
        client_id: clientId,
        agent_id: agentId,
        message: welcomeMessage,
        is_read: false,
        created_at: new Date().toISOString(),
      });

    if (clientMsgError) throw clientMsgError;

    // ── Notification message for agent about new booking ───────────────────
    const agentNotification =
      `🎉 New Booking Alert!\n\n` +
      `A client has successfully booked *${packageName}*.\n\n` +
      `📋 Booking ID: ${bookingId}\n` +
      `👤 Client ID: ${clientId}\n\n` +
      `Please reach out to the client within 24 hours to confirm details and next steps.\n\n` +
      `You can chat with them directly in this conversation.`;

    const { error: agentMsgError } = await supabaseAdmin
      .from('messages')
      .insert({
        booking_id: bookingId,
        sender_id: agentId,           // use agentId not 'system' — constraint forbids it
        sender_type: 'agent',
        client_id: clientId,
        agent_id: agentId,
        message: agentNotification,
        is_read: false,
        created_at: new Date(Date.now() + 1).toISOString(),
      });

    if (agentMsgError) throw agentMsgError;

    console.log(`[BookingMessage] Created automated messages for booking ${bookingId}`);
    return true;
  } catch (err) {
    console.error('[createBookingMessage]', err.message);
    return false;
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// Send Message  POST /api/messages
// ─────────────────────────────────────────────────────────────────────────────
export const sendMessage = async (req, res) => {
  const userId = req.user.id;
  const { bookingId, message, imageUrls } = req.body;

  if (!bookingId || !message) {
    return res.status(400).json({ success: false, message: 'bookingId and message are required' });
  }

  try {
    // Step 1: get booking
    const { data: booking, error: bookingErr } = await supabaseAdmin
      .from('bookings')
      .select('id, user_id, package_id')
      .eq('id', bookingId)
      .single();

    if (bookingErr || !booking) {
      return res.status(404).json({ success: false, message: 'Booking not found' });
    }

    // Step 2: get package separately to reliably get created_by (agent)
    const { data: pkg, error: pkgErr } = await supabaseAdmin
      .from('packages')
      .select('id, name, created_by')
      .eq('id', booking.package_id)
      .single();

    if (pkgErr || !pkg) {
      console.error('[sendMessage] package lookup failed:', pkgErr?.message);
      return res.status(404).json({ success: false, message: 'Package not found' });
    }

    const agentId  = pkg.created_by;
    const isClient = booking.user_id === userId;
    const isAgent  = agentId === userId;

    console.log('[sendMessage] userId:', userId, '| agentId:', agentId, '| clientId:', booking.user_id, '| isClient:', isClient, '| isAgent:', isAgent);

    if (!isClient && !isAgent) {
      return res.status(403).json({ success: false, message: 'Unauthorized' });
    }

    const { data: newMessage, error } = await supabaseAdmin
      .from('messages')
      .insert({
        booking_id:  bookingId,
        sender_id:   userId,
        sender_type: isClient ? 'client' : 'agent',
        client_id:   booking.user_id,
        agent_id:    agentId,           // now reliably set
        message:     message.trim(),
        image_urls:  imageUrls || [],
        created_at:  new Date().toISOString(),
      })
      .select()
      .single();

    if (error) throw error;

    return res.json({ success: true, message: newMessage });
  } catch (err) {
    console.error('[sendMessage]', err.message);
    return res.status(500).json({ success: false, message: 'Failed to send message' });
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// Mark Messages as Read  POST /api/messages/mark-read
// ─────────────────────────────────────────────────────────────────────────────
export const markMessagesAsRead = async (req, res) => {
  const userId = req.user.id;
  const { messageIds } = req.body;

  if (!messageIds?.length) {
    return res.json({ success: true });
  }

  try {
    const { error } = await supabaseAdmin
      .from('messages')
      .update({ is_read: true })
      .in('id', messageIds)
      .neq('sender_id', userId);

    if (error) throw error;

    return res.json({ success: true });
  } catch (err) {
    console.error('[markMessagesAsRead]', err.message);
    return res.status(500).json({ success: false, message: 'Failed to mark as read' });
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// Get Messages  GET /api/messages/:bookingId
// ─────────────────────────────────────────────────────────────────────────────
export const getMessages = async (req, res) => {
  const userId = req.user.id;
  const { bookingId } = req.params;

  try {
    const { data: booking, error: bookingErr } = await supabaseAdmin
      .from('bookings')
      .select('id, user_id, package_id')
      .eq('id', bookingId)
      .single();

    if (bookingErr || !booking) {
      return res.status(404).json({ success: false, message: 'Booking not found' });
    }

    const { data: pkg } = await supabaseAdmin
      .from('packages')
      .select('id, name, created_by, agent_name')
      .eq('id', booking.package_id)
      .single();

    const agentId = pkg?.created_by;
    const isClient = booking.user_id === userId;
    const isAgent  = agentId === userId;

    if (!isClient && !isAgent) {
      return res.status(403).json({ success: false, message: 'Unauthorized' });
    }

    const { data: messages, error } = await supabaseAdmin
      .from('messages')
      .select('*')
      .eq('booking_id', bookingId)
      .order('created_at', { ascending: true });

    if (error) throw error;

    return res.json({
      success: true,
      messages: messages || [],
      currentUserId: userId,
      agentName: pkg?.agent_name || 'Agent',
      packageName: pkg?.name || 'Package',
    });
  } catch (err) {
    console.error('[getMessages]', err.message);
    return res.status(500).json({ success: false, message: 'Failed to fetch messages' });
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// Get Unread Count  GET /api/messages/count/unread
// ─────────────────────────────────────────────────────────────────────────────
export const getUnreadCount = async (req, res) => {
  const userId = req.user.id;

  try {
    // Count messages not sent by this user, not yet read
    const { count, error } = await supabaseAdmin
      .from('messages')
      .select('*', { count: 'exact', head: true })
      .neq('sender_id', userId)
      .eq('is_read', false)
      .or(`client_id.eq.${userId},agent_id.eq.${userId}`);

    if (error) throw error;

    return res.json({ success: true, count: count || 0 });
  } catch (err) {
    console.error('[getUnreadCount]', err.message);
    return res.status(500).json({ success: false, count: 0 });
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// Get Agent Conversations  GET /api/messages/agent/conversations
// Returns a list of all bookings the agent has messages for (for sidebar)
// ─────────────────────────────────────────────────────────────────────────────
export const getAgentConversations = async (req, res) => {
  const agentId = req.user.id;

  try {
    // Step 1: get latest message per booking for this agent
    // Use agent_id OR fall back to checking packages created by this agent
    const { data: messages, error: msgErr } = await supabaseAdmin
      .from('messages')
      .select('booking_id, message, created_at, is_read, sender_id, client_id')
      .eq('agent_id', agentId)
      .order('created_at', { ascending: false });

    if (msgErr) throw msgErr;

    // Deduplicate — latest message per booking
    const seen = new Set();
    const deduplicated = [];
    for (const msg of (messages || [])) {
      if (!seen.has(msg.booking_id)) {
        seen.add(msg.booking_id);
        deduplicated.push(msg);
      }
    }

    if (deduplicated.length === 0) {
      return res.json({ success: true, conversations: [] });
    }

    const bookingIds = deduplicated.map(m => m.booking_id);

    // Step 2: fetch booking + package info (no users join)
    const { data: bookings } = await supabaseAdmin
      .from('bookings')
      .select('id, status, user_id, package:packages!package_id(name)')
      .in('id', bookingIds);

    const bookingMap = {};
    for (const b of (bookings || [])) bookingMap[b.id] = b;

    // Step 3: fetch user profiles separately from your profiles/users table
    const clientIds = [...new Set(deduplicated.map(m => m.client_id).filter(Boolean))];
    let profileMap = {};
    if (clientIds.length) {
      // Try 'profiles' table first, fall back to auth metadata
      const { data: profiles } = await supabaseAdmin
        .from('profiles')
        .select('id, first_name, last_name, email')
        .in('id', clientIds);

      if (profiles?.length) {
        for (const p of profiles) profileMap[p.id] = p;
      } else {
        // Fallback: fetch from auth.users via admin API
        for (const cid of clientIds) {
          const { data: authUser } = await supabaseAdmin.auth.admin.getUserById(cid);
          if (authUser?.user) {
            const meta = authUser.user.user_metadata || {};
            profileMap[cid] = {
              id: cid,
              first_name: meta.first_name || meta.firstName || '',
              last_name: meta.last_name || meta.lastName || '',
              email: authUser.user.email,
            };
          }
        }
      }
    }

    // Step 4: unread counts per booking
    const { data: unreadData } = await supabaseAdmin
      .from('messages')
      .select('booking_id')
      .eq('agent_id', agentId)
      .neq('sender_id', agentId)
      .eq('is_read', false);

    const unreadCounts = {};
    for (const row of (unreadData || [])) {
      unreadCounts[row.booking_id] = (unreadCounts[row.booking_id] || 0) + 1;
    }

    const result = deduplicated.map(msg => {
      const booking = bookingMap[msg.booking_id];
      const profile = profileMap[msg.client_id];
      const clientName = profile
        ? `${profile.first_name || ''} ${profile.last_name || ''}`.trim() || profile.email
        : 'Client';
      return {
        bookingId:     msg.booking_id,
        lastMessage:   msg.message,
        lastTime:      msg.created_at,
        unreadCount:   unreadCounts[msg.booking_id] || 0,
        clientId:      msg.client_id,
        clientName,
        clientEmail:   profile?.email || '',
        packageName:   booking?.package?.name || 'Package',
        bookingStatus: booking?.status || 'pending',
      };
    });

    return res.json({ success: true, conversations: result });
  } catch (err) {
    console.error('[getAgentConversations]', err.message);
    return res.status(500).json({ success: false, conversations: [] });
  }
};