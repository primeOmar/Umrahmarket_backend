// controllers/bookings.controller.js
// ─────────────────────────────────────────────────────────────────────────────
// GET /api/bookings/my  — returns all bookings for the authenticated user,
//                         newest first, with full package + payment details.
// ─────────────────────────────────────────────────────────────────────────────

import { supabaseAdmin } from '../config/supabase.js';

const recoverMissingBookings = async (userId) => {
  if (!supabaseAdmin) {
    console.warn('[recoverMissingBookings] Supabase admin client not configured');
    return;
  }

  const { data: existingBookings, error: existingErr } = await supabaseAdmin
    .from('bookings')
    .select('payment_id')
    .eq('user_id', userId);

  if (existingErr) {
    console.error('[recoverMissingBookings] Existing bookings load failed:', existingErr.message, existingErr.details);
    return;
  }

  const existingPaymentIds = (existingBookings || [])
    .map((booking) => booking.payment_id)
    .filter(Boolean);

  let paymentsQuery = supabaseAdmin
    .from('payments')
    .select('id, user_id, package_id, amount_kes, method')
    .eq('user_id', userId)
    .eq('status', 'SUCCESS');

  if (existingPaymentIds.length > 0) {
    paymentsQuery = paymentsQuery.not('id', 'in', `(${existingPaymentIds.map((id) => `"${id}"`).join(',')})`);
  }

  const { data: successfulPayments, error: paymentsErr } = await paymentsQuery;

  if (paymentsErr) {
    console.error('[recoverMissingBookings] Successful payments load failed:', paymentsErr.message, paymentsErr.details);
    return;
  }

  if (!successfulPayments?.length) {
    return;
  }

  const bookingRecords = successfulPayments.map((payment) => ({
    user_id:        payment.user_id,
    package_id:     payment.package_id,
    payment_id:     payment.id,
    payment_method: payment.method || 'UNKNOWN',
    amount_paid:    payment.amount_kes,
    currency:       'KES',
    status:         'confirmed',
    confirmed_at:   new Date().toISOString(),
  }));

  const { error: insertErr } = await supabaseAdmin
    .from('bookings')
    .insert(bookingRecords);

  if (insertErr) {
    console.error('[recoverMissingBookings] Booking recovery insert failed:', insertErr.message, insertErr.details);
  } else {
    console.info(`[recoverMissingBookings] Recovered ${bookingRecords.length} booking(s) for user ${userId}`);
  }
};

export const getMyBookings = async (req, res) => {
  try {
    const userId = req.user?.id;
    if (!userId)
      return res.status(401).json({ success: false, message: 'Unauthorised' });

    await recoverMissingBookings(userId);

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
        package:packages!package_id (
          id,
          name,
          price,
          original_price,
          duration,
          location,
          makkah_hotel_name,
          makkah_hotel_rating,
          makkah_hotel_distance,
          madinah_hotel_name,
          madinah_hotel_rating,
          madinah_hotel_distance,
          image_urls,
          type,
          agent_name,
          agent_number,
          status
        ),
        payment:payments!payment_id (
          id,
          status,
          method,
          result_code,
          result_desc,
          mpesa_ref,
          paid_at
        )
      `)
      .eq('user_id', userId)
      .order('created_at', { ascending: false });

    if (error) {
      // Log full error so Render logs show the exact Supabase reason
      console.error('[getMyBookings] DB error:', {
        message: error.message,
        code:    error.code,
        details: error.details,
        hint:    error.hint,
      });
      return res.status(500).json({
        success: false,
        message: error.message,
        hint:    error.hint ?? null,
      });
    }

    return res.json({ success: true, bookings: bookings ?? [] });
  } catch (err) {
    console.error('[getMyBookings] Unexpected error:', err.message);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
};