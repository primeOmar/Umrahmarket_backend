// routes/bookings.routes.js
import express from 'express';
import { supabaseAdmin } from '../config/supabase.js';
import { requireAuth } from '../middleware/auth.middleware.js';
import { sendBookingReceiptEmail } from '../services/bookingReceipt.service.js';

const router = express.Router();

const recoverMissingBookings = async (userId) => {
  if (!supabaseAdmin) return;

  const { data: existingBookings, error: existingErr } = await supabaseAdmin
    .from('bookings')
    .select('payment_id, package_id')
    .eq('user_id', userId)
    .not('payment_id', 'is', null);

  if (existingErr) {
    console.error('[recoverMissingBookings] Existing bookings load failed:', existingErr.message);
    return;
  }

  const existingPaymentIds = new Set(
    (existingBookings || []).map(b => b.payment_id).filter(Boolean)
  );
  const existingCombinations = new Set(
    (existingBookings || []).map(b => `${b.package_id}|${b.payment_id}`)
  );

  let paymentsQuery = supabaseAdmin
    .from('payments')
    .select('id, user_id, package_id, amount_kes, amount_usd, fx_rate_used, method, created_at, status')
    .eq('user_id', userId)
    .eq('status', 'SUCCESS');

  if (existingPaymentIds.size > 0) {
    const excludeIds = Array.from(existingPaymentIds);
    paymentsQuery = paymentsQuery.not('id', 'in', `(${excludeIds.map(id => `'${id}'`).join(',')})`);
  }

  const { data: successfulPayments, error: paymentsErr } = await paymentsQuery;
  if (paymentsErr || !successfulPayments?.length) return;

  const uniquePayments = successfulPayments.filter(p => !existingCombinations.has(`${p.package_id}|${p.id}`));
  if (!uniquePayments.length) return;

  const bookingRecords = uniquePayments.map((payment) => ({
    user_id:        payment.user_id,
    package_id:     payment.package_id,
    payment_id:     payment.id,
    payment_method: payment.method || 'UNKNOWN',
    amount_paid:    payment.amount_kes,
    currency:       'KES',
    status:         'confirmed',
    confirmed_at:   payment.created_at || new Date().toISOString(),
    created_at:     new Date().toISOString(),
  }));

  const { error: insertErr } = await supabaseAdmin
    .from('bookings')
    .upsert(bookingRecords, { onConflict: 'payment_id', ignoreDuplicates: true });

  if (insertErr) console.error('[recoverMissingBookings] Insert failed:', insertErr.message);
};

// GET /api/bookings/my
router.get('/my', requireAuth, async (req, res) => {
  try {
    const userId = req.user?.id;
    if (!userId) return res.status(401).json({ success: false, message: 'Unauthorised' });

    recoverMissingBookings(userId).catch(err =>
      console.error('[getMyBookings] Background recovery failed:', err)
    );

    const { data: rawBookings, error: bookingsError } = await supabaseAdmin
      .from('bookings')
      .select('*')
      .eq('user_id', userId)
      .order('created_at', { ascending: false });

    if (bookingsError) return res.status(500).json({ success: false, message: bookingsError.message });

    const uniqueBookings = [];
    const seenIds = new Set();
    for (const booking of (rawBookings || [])) {
      if (!seenIds.has(booking.id)) { seenIds.add(booking.id); uniqueBookings.push(booking); }
    }

    const bookingsWithDetails = await Promise.all(
      uniqueBookings.map(async (booking) => {
        const { data: packageData } = await supabaseAdmin
          .from('packages').select('*').eq('id', booking.package_id).single();

        let paymentData = null;
        if (booking.payment_id) {
          const { data: payment } = await supabaseAdmin
            .from('payments')
            .select('id, method, status, amount_kes, amount_usd, fx_rate_used, currency, paid_at, mpesa_ref, pesapal_merchant_ref')
            .eq('id', booking.payment_id).single();
          paymentData = payment;
        }

        return { ...booking, package: packageData, payment: paymentData };
      })
    );

    return res.json({ success: true, bookings: bookingsWithDetails, count: bookingsWithDetails.length });
  } catch (err) {
    console.error('[getMyBookings] Unexpected error:', err.message);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// GET /api/bookings/agent-clients
router.get('/agent-clients', requireAuth, async (req, res) => {
  try {
    const agentId = req.user?.id;
    if (!agentId) return res.status(401).json({ success: false, message: 'Unauthorised' });
    if (req.user.role !== 'agent') return res.status(403).json({ success: false, message: 'Forbidden' });

    const { data: agentPackages, error: pkgErr } = await supabaseAdmin
      .from('packages').select('id').eq('created_by', agentId);

    if (pkgErr) return res.status(500).json({ success: false, message: pkgErr.message });
    if (!agentPackages?.length) return res.json({ success: true, clients: [] });

    const packageIds = agentPackages.map(p => p.id);

    const { data: bookings, error: bookErr } = await supabaseAdmin
      .from('bookings')
      .select('id, status, amount_paid, currency, notes, created_at, user_id, package_id, payment_id, packages(id, name, type, duration, available_from, available_to)')
      .in('package_id', packageIds)
      .order('created_at', { ascending: false });

    if (bookErr) return res.status(500).json({ success: false, message: bookErr.message });
    if (!bookings?.length) return res.json({ success: true, clients: [] });

    const paymentIds = bookings.map(b => b.payment_id).filter(Boolean);
    let paymentFxMap = {};
    if (paymentIds.length > 0) {
      const { data: payments } = await supabaseAdmin
        .from('payments').select('id, amount_usd, fx_rate_used').in('id', paymentIds);
      paymentFxMap = Object.fromEntries((payments || []).map(p => [p.id, p]));
    }

    const userIds = [...new Set(bookings.map(b => b.user_id).filter(Boolean))];
    const { data: profiles, error: profErr } = await supabaseAdmin
      .from('profiles').select('id, first_name, last_name, email, phone').in('id', userIds);

    if (profErr) return res.status(500).json({ success: false, message: profErr.message });

    const profileMap = Object.fromEntries((profiles || []).map(p => [p.id, p]));

    // Passport verification status + face-crop photo for each (user, package)
    // pair — this was previously missing entirely, which is why the agent
    // dashboard always showed clients as "not verified" / no ID photo
    // regardless of actual state.
    const { data: passportRows, error: passErr } = await supabaseAdmin
      .from('passport_verifications')
      .select('user_id, package_id, verification_status, verified, passport_number, nationality, date_of_birth, passport_expiry, face_photo_url')
      .in('user_id', userIds)
      .in('package_id', packageIds);

    if (passErr) {
      // Don't fail the whole dashboard if this lookup has a problem —
      // clients just show as unverified, same as before this fix existed.
      console.error('[getAgentClients] passport_verifications lookup failed:', passErr.message);
    }

    const passportMap = Object.fromEntries(
      (passportRows || []).map(p => [`${p.user_id}|${p.package_id}`, p])
    );

    const clients = bookings.map(b => {
      const profile = profileMap[b.user_id] || {};
      const fx      = paymentFxMap[b.payment_id] || {};
      const passport = passportMap[`${b.user_id}|${b.package_id}`] || null;
      return {
        bookingId:     b.id,
        userId:        b.user_id,
        name:          [profile.first_name, profile.last_name].filter(Boolean).join(' ') || 'Unknown',
        email:         profile.email || '—',
        phone:         profile.phone || '—',
        package:       b.packages,
        packageName:   b.packages?.name || '—',
        packageType:   b.packages?.type || 'umrah',
        duration:      b.packages?.duration,
        availableFrom: b.packages?.available_from,
        availableTo:   b.packages?.available_to,
        status:        b.status,
        amountPaid:    b.amount_paid,
        amountUsd:     fx.amount_usd ?? null,
        fxRateUsed:    fx.fx_rate_used ?? null,
        currency:      b.currency || 'KES',
        notes:         b.notes,
        bookedAt:      b.created_at,
        // Passport / ID-card fields — null/false when no verification row
        // exists yet (client hasn't reached that step), not an error state.
        passportVerified: passport?.verification_status === 'verified',
        passportStatus:   passport?.verification_status || null,
        passportNumber:   passport?.passport_number || null,
        nationality:      passport?.nationality || null,
        dateOfBirth:      passport?.date_of_birth || null,
        passportExpiry:   passport?.passport_expiry || null,
        facePhotoUrl:     passport?.face_photo_url || null,
      };
    });

    return res.json({ success: true, clients });
  } catch (err) {
    console.error('[getAgentClients] Unexpected error:', err.message);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// POST /api/bookings/:id/resend-receipt
// Sends booking receipt email again for the authenticated booking owner.
router.post('/:id/resend-receipt', requireAuth, async (req, res) => {
  try {
    const userId = req.user?.id;
    const bookingId = req.params.id;
    if (!userId) return res.status(401).json({ success: false, message: 'Unauthorised' });
    if (!bookingId) return res.status(400).json({ success: false, message: 'booking id is required' });

    const { data: booking, error: bookErr } = await supabaseAdmin
      .from('bookings')
      .select('id, user_id, payment_id')
      .eq('id', bookingId)
      .eq('user_id', userId)
      .maybeSingle();

    if (bookErr || !booking) {
      return res.status(404).json({ success: false, message: 'Booking not found' });
    }

    if (!booking.payment_id) {
      return res.status(422).json({ success: false, message: 'Booking has no payment record yet' });
    }

    const result = await sendBookingReceiptEmail({
      paymentId: booking.payment_id,
      bookingId: booking.id,
      force: true,
    });

    if (!result?.success) {
      return res.status(422).json({
        success: false,
        message: 'Receipt email not sent',
        reason: result?.reason || 'unknown',
      });
    }

    return res.json({
      success: true,
      message: `Receipt email sent to ${result.recipient}`,
      recipient: result.recipient,
      messageId: result.messageId || null,
      reason: result.reason || null,
    });
  } catch (err) {
    console.error('[resend-receipt] Unexpected error:', err.message);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

export default router;