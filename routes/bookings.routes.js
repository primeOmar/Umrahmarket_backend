// routes/bookings.routes.js
import express from 'express';
import { supabaseAdmin } from '../config/supabase.js';
import { requireAuth } from '../middleware/auth.middleware.js';

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
      .select('id, status, amount_paid, currency, notes, created_at, user_id, payment_id, packages(id, name, type, duration, available_from, available_to)')
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

    const clients = bookings.map(b => {
      const profile = profileMap[b.user_id] || {};
      const fx      = paymentFxMap[b.payment_id] || {};
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
      };
    });

    return res.json({ success: true, clients });
  } catch (err) {
    console.error('[getAgentClients] Unexpected error:', err.message);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

export default router;