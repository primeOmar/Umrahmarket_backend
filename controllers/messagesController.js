import supabaseAdmin from '../config/supabase.js';

// ─────────────────────────────────────────────────────────────────────────────
// Send Message  POST /api/messages
// Body: { bookingId, message, imageUrls? }
// ─────────────────────────────────────────────────────────────────────────────
export const sendMessage = async (req, res) => {
  const userId = req.user.id;
  const { bookingId, message, imageUrls } = req.body;

  if (!bookingId || !message) {
    return res.status(400).json({ 
      success: false, 
      message: 'bookingId and message are required' 
    });
  }

  try {
    // Verify booking exists and user is associated with it
    const { data: booking, error: bookingErr } = await supabaseAdmin
      .from('bookings')
      .select('id, user_id, package_id')
      .eq('id', bookingId)
      .single();

    if (bookingErr || !booking) {
      return res.status(404).json({ 
        success: false, 
        message: 'Booking not found' 
      });
    }

    // Verify user is client or agent for this booking
    const isClient = booking.user_id === userId;
    if (!isClient) {
      // TODO: Add agent verification when agent profile is added
      return res.status(403).json({ 
        success: false, 
        message: 'Unauthorized' 
      });
    }

    // Get package to find agent
    const { data: pkg } = await supabaseAdmin
      .from('packages')
      .select('created_by')
      .eq('id', booking.package_id)
      .single();

    // Insert message
    const { data: newMessage, error } = await supabaseAdmin
      .from('messages')
      .insert({
        booking_id: bookingId,
        sender_id: userId,
        sender_type: isClient ? 'client' : 'agent',
        client_id: booking.user_id,
        agent_id: pkg?.created_by,
        message,
        image_urls: imageUrls || [],
      })
      .select()
      .single();

    if (error) throw error;

    return res.json({ success: true, message: newMessage });
  } catch (err) {
    console.error('[sendMessage]', err.message);
    return res.status(500).json({ 
      success: false, 
      message: 'Failed to send message' 
    });
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// Get Messages  GET /api/messages/:bookingId
// Returns: { success, messages: Message[] }
// ─────────────────────────────────────────────────────────────────────────────
export const getMessages = async (req, res) => {
  const userId = req.user.id;
  const { bookingId } = req.params;

  try {
    // Verify user is associated with booking
    const { data: booking, error: bookingErr } = await supabaseAdmin
      .from('bookings')
      .select('id, user_id')
      .eq('id', bookingId)
      .single();

    if (bookingErr || !booking) {
      return res.status(404).json({ 
        success: false, 
        message: 'Booking not found' 
      });
    }

    if (booking.user_id !== userId) {
      return res.status(403).json({ 
        success: false, 
        message: 'Unauthorized' 
      });
    }

    // Fetch all messages
    const { data: messages, error } = await supabaseAdmin
      .from('messages')
      .select('*')
      .eq('booking_id', bookingId)
      .order('created_at', { ascending: true });

    if (error) throw error;

    // Mark messages as read if receiver
    await supabaseAdmin
      .from('messages')
      .update({ is_read: true })
      .eq('booking_id', bookingId)
      .neq('sender_id', userId);

    return res.json({ success: true, messages: messages || [] });
  } catch (err) {
    console.error('[getMessages]', err.message);
    return res.status(500).json({ 
      success: false, 
      message: 'Failed to fetch messages' 
    });
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// Create Automated Booking Message (Internal)
// Called after successful booking
// ─────────────────────────────────────────────────────────────────────────────
export const createBookingMessage = async (bookingId, clientId, agentId, packageName) => {
  try {
    const message = `You have booked the package: ${packageName}. Your booking is confirmed. An agent will contact you shortly.`;

    await supabaseAdmin
      .from('messages')
      .insert({
        booking_id: bookingId,
        sender_id: agentId || 'system',
        sender_type: 'agent',
        client_id: clientId,
        agent_id: agentId,
        message,
        is_read: false,
      });

    console.log(`[createBookingMessage] Created for booking ${bookingId}`);
  } catch (err) {
    console.error('[createBookingMessage]', err.message);
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// Get Unread Count  GET /api/messages/unread
// Returns: { success, unreadCount }
// ─────────────────────────────────────────────────────────────────────────────
export const getUnreadCount = async (req, res) => {
  const userId = req.user.id;

  try {
    const { data, error } = await supabaseAdmin
      .from('messages')
      .select('id')
      .eq('client_id', userId)
      .eq('is_read', false);

    if (error) throw error;

    return res.json({ 
      success: true, 
      unreadCount: data?.length || 0 
    });
  } catch (err) {
    console.error('[getUnreadCount]', err.message);
    return res.status(500).json({ 
      success: false, 
      message: 'Failed to fetch unread count' 
    });
  }
};
