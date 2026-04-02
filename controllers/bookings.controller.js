// controllers/bookings.controller.js
// ─────────────────────────────────────────────────────────────────────────────
// GET /api/bookings/my  — returns all bookings for the authenticated user,
//                         newest first, with full package + payment details.
// ─────────────────────────────────────────────────────────────────────────────

import { supabaseAdmin } from '../config/supabase.js';

export const getMyBookings = async (req, res) => {
  try {
    const userId = req.user?.id;
    if (!userId)
      return res.status(401).json({ success: false, message: 'Unauthorised' });

    const { data: bookings, error } = await supabaseAdmin
      .from('bookings')
      .select(`
        id,
        status,
        payment_method,
        amount_paid,
        currency,
        confirmed_at,
        created_at,
        package:package_id (
          id,
          name,
          price,
          duration_days,
          location,
          hotel_stars,
          makkah_hotel_distance,
          image_urls,
          package_type,
          agency:agency_id (
            id,
            name
          )
        ),
        payment:payment_id (
          id,
          status,
          method,
          result_code,
          paid_at
        )
      `)
      .eq('user_id', userId)
      .order('created_at', { ascending: false });

    if (error) {
      console.error('[getMyBookings] DB error:', error.message);
      return res.status(500).json({ success: false, message: 'Failed to fetch bookings' });
    }

    return res.json({ success: true, bookings: bookings ?? [] });
  } catch (err) {
    console.error('[getMyBookings] Unexpected error:', err.message);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
};