// controllers/messagesController.js
import { supabaseAdmin } from '../config/supabase.js';

// ─────────────────────────────────────────────────────────────────────────────
// HELPER: resolve agentId + clientId for a booking
// Chain: bookings.package_id → packages.created_by (agent profiles.id)
//        bookings.user_id = client (auth.users.id = profiles.id)
// ─────────────────────────────────────────────────────────────────────────────
const resolveParties = async (bookingId) => {
  // Single query joining booking + package
  const { data: booking, error } = await supabaseAdmin
    .from('bookings')
    .select('id, user_id, package_id')
    .eq('id', bookingId)
    .single();

  if (error || !booking) {
    console.error('[resolveParties] booking not found:', bookingId, error?.message);
    return null;
  }

  const { data: pkg, error: pkgErr } = await supabaseAdmin
    .from('packages')
    .select('id, name, created_by, agent_name, agent_number, makkah_hotel_name, madinah_hotel_name')
    .eq('id', booking.package_id)
    .single();

  if (pkgErr || !pkg) {
    console.error('[resolveParties] package not found for id:', booking.package_id, pkgErr?.message);
    return null;
  }

  // If created_by is null, attempt live fix via agent_number → profiles
  let agentId = pkg.created_by;
  if (!agentId && pkg.agent_number) {
    console.warn('[resolveParties] created_by null — attempting fix via agent_number:', pkg.agent_number);
    const { data: agentProfile } = await supabaseAdmin
      .from('profiles')
      .select('id')
      .eq('agent_number', pkg.agent_number)
      .single();

    if (agentProfile?.id) {
      agentId = agentProfile.id;
      // Persist the fix
      await supabaseAdmin
        .from('packages')
        .update({ created_by: agentId })
        .eq('id', pkg.id);
      console.log('[resolveParties] ✅ Fixed created_by for package', pkg.id);
    }
  }

  if (!agentId) {
    console.error('[resolveParties] cannot resolve agentId for package:', pkg.id);
    return null;
  }

  return {
    bookingId:   booking.id,
    clientId:    booking.user_id,
    agentId,
    packageId:   pkg.id,
    packageName: pkg.name,
    agentName:   pkg.agent_name,
    makkahHotel: pkg.makkah_hotel_name,
    madinahHotel: pkg.madinah_hotel_name,
  };
};

// ─────────────────────────────────────────────────────────────────────────────
// Automated booking confirmation message
// ─────────────────────────────────────────────────────────────────────────────
export const createBookingMessage = async (bookingId, clientId, agentId, packageName) => {
  try {
    const parties = await resolveParties(bookingId);
    const resolvedAgentId = parties?.agentId || agentId;

    if (!resolvedAgentId) {
      console.error('[createBookingMessage] no agentId — aborting');
      return false;
    }

    const welcomeMsg =
      `✨ Booking Confirmed! ✨\n\n` +
      `Assalamu Alaikum! Thank you for booking *${packageName}*. May Allah bless your journey. 🙏\n\n` +
      `📋 Booking Reference: ${bookingId}\n\n` +
      `🕌 What happens next?\n` +
      `• Our team will reach out within 24 hours\n` +
      `• You'll receive visa & travel document guidance\n` +
      `• Ask any questions about your journey right here\n\n` +
      `🏨 Hotels:\n` +
      `• Makkah: ${parties?.makkahHotel || '5-Star Near Haram'}\n` +
      `• Madinah: ${parties?.madinahHotel || '5-Star Near Masjid Nabawi'}\n\n` +
      `Barakallahu feekum! 🤲`;

    const { error } = await supabaseAdmin
      .from('messages')
      .insert({
        booking_id:  bookingId,
        sender_id:   resolvedAgentId,
        sender_type: 'agent',
        client_id:   clientId,
        agent_id:    resolvedAgentId,
        message:     welcomeMsg,
        is_read:     false,
      });

    if (error) throw error;
    console.log(`[createBookingMessage] ✅ booking=${bookingId} agentId=${resolvedAgentId}`);
    return true;
  } catch (err) {
    console.error('[createBookingMessage]', err.message);
    return false;
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/messages — send a message
// ─────────────────────────────────────────────────────────────────────────────
export const sendMessage = async (req, res) => {
  const userId = req.user.id;
  const { bookingId, message, imageUrls } = req.body;

  if (!bookingId || !message?.trim()) {
    return res.status(400).json({ success: false, message: 'bookingId and message are required' });
  }

  try {
    const parties = await resolveParties(bookingId);
    if (!parties) {
      return res.status(404).json({ success: false, message: 'Booking/package not found or agent unresolvable' });
    }

    const { clientId, agentId } = parties;
    const isClient = clientId === userId;
    const isAgent  = agentId  === userId;

    console.log(`[sendMessage] userId=${userId} agentId=${agentId} clientId=${clientId} isClient=${isClient} isAgent=${isAgent}`);

    if (!isClient && !isAgent) {
      return res.status(403).json({ success: false, message: 'Unauthorized — not a party to this booking' });
    }

    const { data: newMsg, error } = await supabaseAdmin
      .from('messages')
      .insert({
        booking_id:  bookingId,
        sender_id:   userId,
        sender_type: isClient ? 'client' : 'agent',
        client_id:   clientId,
        agent_id:    agentId,
        message:     message.trim(),
        image_urls:  imageUrls || [],
      })
      .select()
      .single();

    if (error) throw error;
    return res.json({ success: true, message: newMsg });
  } catch (err) {
    console.error('[sendMessage]', err.message);
    return res.status(500).json({ success: false, message: 'Failed to send message' });
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/messages/:bookingId
// ─────────────────────────────────────────────────────────────────────────────
export const getMessages = async (req, res) => {
  const userId = req.user.id;
  const { bookingId } = req.params;

  try {
    const parties = await resolveParties(bookingId);
    if (!parties) {
      return res.status(404).json({ success: false, message: 'Booking/package not found' });
    }

    const { clientId, agentId, agentName, packageName } = parties;
    const isClient = clientId === userId;
    const isAgent  = agentId  === userId;

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
      agentName,
      packageName,
    });
  } catch (err) {
    console.error('[getMessages]', err.message);
    return res.status(500).json({ success: false, message: 'Failed to fetch messages' });
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/messages/mark-read
// ─────────────────────────────────────────────────────────────────────────────
export const markMessagesAsRead = async (req, res) => {
  const userId = req.user.id;
  const { messageIds } = req.body;
  if (!messageIds?.length) return res.json({ success: true });

  try {
    const { error } = await supabaseAdmin
      .from('messages')
      .update({ is_read: true, read_at: new Date().toISOString() })
      .in('id', messageIds)
      .neq('sender_id', userId);

    if (error) throw error;
    return res.json({ success: true });
  } catch (err) {
    console.error('[markMessagesAsRead]', err.message);
    return res.status(500).json({ success: false });
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/messages/count/unread
// ─────────────────────────────────────────────────────────────────────────────
export const getUnreadCount = async (req, res) => {
  const userId = req.user.id;
  try {
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
// GET /api/messages/agent/conversations
// ─────────────────────────────────────────────────────────────────────────────
export const getAgentConversations = async (req, res) => {
  const agentId = req.user.id;

  try {
    // Get latest message per booking for this agent
    const { data: messages, error: msgErr } = await supabaseAdmin
      .from('messages')
      .select('id, booking_id, message, created_at, is_read, sender_id, client_id')
      .eq('agent_id', agentId)
      .order('created_at', { ascending: false });

    if (msgErr) throw msgErr;
    if (!messages?.length) return res.json({ success: true, conversations: [] });

    // Deduplicate — latest per booking
    const seen = new Set();
    const latest = [];
    for (const m of messages) {
      if (!seen.has(m.booking_id)) { seen.add(m.booking_id); latest.push(m); }
    }

    const bookingIds = latest.map(m => m.booking_id);
    const clientIds  = [...new Set(latest.map(m => m.client_id).filter(Boolean))];

    // Fetch bookings, packages, profiles in parallel
    const [bookingsRes, profilesRes] = await Promise.all([
      supabaseAdmin
        .from('bookings')
        .select('id, status, package_id')
        .in('id', bookingIds),
      clientIds.length
        ? supabaseAdmin
            .from('profiles')
            .select('id, first_name, last_name, email')
            .in('id', clientIds)
        : { data: [] },
    ]);

    const bookingMap = Object.fromEntries((bookingsRes.data || []).map(b => [b.id, b]));
    const profileMap = Object.fromEntries((profilesRes.data || []).map(p => [p.id, p]));

    const packageIds = [...new Set(Object.values(bookingMap).map(b => b.package_id).filter(Boolean))];
    const { data: packages } = await supabaseAdmin
      .from('packages')
      .select('id, name')
      .in('id', packageIds);

    const packageMap = Object.fromEntries((packages || []).map(p => [p.id, p]));

    // Unread counts
    const { data: unreadRows } = await supabaseAdmin
      .from('messages')
      .select('booking_id')
      .eq('agent_id', agentId)
      .neq('sender_id', agentId)
      .eq('is_read', false);

    const unreadCounts = {};
    for (const r of (unreadRows || [])) {
      unreadCounts[r.booking_id] = (unreadCounts[r.booking_id] || 0) + 1;
    }

    const conversations = latest.map(msg => {
      const booking = bookingMap[msg.booking_id];
      const pkg     = packageMap[booking?.package_id];
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
        packageName:   pkg?.name || 'Package',
        bookingStatus: booking?.status || 'pending',
      };
    });

    return res.json({ success: true, conversations });
  } catch (err) {
    console.error('[getAgentConversations]', err.message);
    return res.status(500).json({ success: false, conversations: [] });
  }
};