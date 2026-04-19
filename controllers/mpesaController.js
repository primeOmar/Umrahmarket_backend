// controllers/mpesaController.js
// Pure Supabase — no Mongoose models used anywhere in this file.
import { supabaseAdmin } from '../config/supabase.js';
import { stkPush, stkQuery } from '../services/Mpesaservice.js';
import { createBookingMessage } from './messagesController.js';

const KES_RATE       = Number(process.env.KES_PER_USD) || 130;
const MPESA_PHONE_RE = /^254[17]\d{8}$/;
function maskPhone(p) { return p ? `${p.slice(0, 6)}****${p.slice(-2)}` : '?'; }

// ── POST /api/payments/mpesa/initiate ────────────────────────────────────────
export const initiate = async (req, res) => {
  try {
    const userId    = req.user?.id;
    const { packageId, phone } = req.body;

    if (!userId)
      return res.status(401).json({ success: false, message: 'Unauthorised' });

    if (!packageId || !phone)
      return res.status(400).json({ success: false, message: 'packageId and phone are required' });

    // Accept Supabase UUIDs or numeric package IDs
    const isUUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(packageId);
    const isNumericId = /^[0-9]+$/.test(packageId);
    if (!isUUID && !isNumericId)
      return res.status(400).json({ success: false, message: 'Invalid packageId' });

    if (!MPESA_PHONE_RE.test(phone))
      return res.status(400).json({ success: false, message: 'Invalid Safaricom number (must start 2547... or 2541...)' });

    // ── Fetch package from Supabase — NEVER trust FE price ──────────────
    const { data: pkg, error: pkgErr } = await supabaseAdmin
      .from('packages')
      .select('id, name, price, status')
      .eq('id', packageId)
      .maybeSingle();

    if (pkgErr) {
      console.error('[M-Pesa initiate] Package fetch error:', pkgErr.message);
      return res.status(500).json({ success: false, message: 'Failed to fetch package details' });
    }
    if (!pkg) {
      return res.status(404).json({ success: false, message: 'Package not found' });
    }

    // Accept any reasonable active-like status — adjust to match your DB values
    const pkgStatus = (pkg.status || '').toLowerCase();
    if (!['active', 'published', 'approved', 'available'].includes(pkgStatus)) {
      return res.status(400).json({ success: false, message: `Package is not available for booking (status: ${pkg.status})` });
    }

    // Resolve price — handle both column name variants
    const priceUSD  = pkg.price ?? 0;
    const amountKes = Math.ceil(Number(priceUSD) * KES_RATE);
    if (amountKes <= 0)
      return res.status(400).json({ success: false, message: 'Package has no valid price' });

    // ── Check if user already has a confirmed booking for this package ──
    const { data: existingBooking, error: bookingErr } = await supabaseAdmin
      .from('bookings')
      .select('id, status')
      .eq('user_id', userId)
      .eq('package_id', packageId)
      .eq('status', 'confirmed')
      .maybeSingle();

    if (bookingErr) {
      console.error('[M-Pesa initiate] Booking check error:', bookingErr.message);
      return res.status(500).json({ success: false, message: 'Failed to verify booking status' });
    }

    if (existingBooking) {
      return res.status(400).json({ success: false, message: 'You have already booked this package. You cannot book the same package twice.' });
    }

    // ── Idempotency — resume PENDING payment within last 5 min ──────────
    const fiveMinAgo = new Date(Date.now() - 5 * 60_000).toISOString();
    const { data: existing } = await supabaseAdmin
      .from('payments')
      .select('checkout_request_id')
      .eq('user_id', userId)
      .eq('package_id', packageId)
      .eq('status', 'PENDING')
      .gte('created_at', fiveMinAgo)
      .maybeSingle();

    if (existing?.checkout_request_id) {
      return res.json({ success: true, checkoutRequestId: existing.checkout_request_id, resumed: true });
    }

    // ── Fire STK push ────────────────────────────────────────────────────
    let darajaRes;
    try {
      darajaRes = await stkPush({
        phone,
        amount:      amountKes,
        accountRef:  `PKG-${packageId.slice(-6).toUpperCase()}`,
        description: 'Umrah Package',
      });
    } catch (darajaErr) {
      console.error('[M-Pesa initiate] Daraja STK push failed:', darajaErr.message);
      return res.status(502).json({ success: false, message: `M-Pesa error: ${darajaErr.message}` });
    }

    // Daraja returns PascalCase — normalise both casings
    const checkoutRequestId = darajaRes.CheckoutRequestID ?? darajaRes.checkoutRequestId;
    const merchantRequestId = darajaRes.MerchantRequestID ?? darajaRes.merchantRequestId;

    if (!checkoutRequestId) {
      console.error('[M-Pesa initiate] No checkoutRequestId in Daraja response:', JSON.stringify(darajaRes));
      return res.status(502).json({ success: false, message: 'Invalid M-Pesa response — please try again.' });
    }

    // ── Persist pending payment in Supabase ─────────────────────────────
    const { error: insertErr } = await supabaseAdmin
      .from('payments')
      .insert({
        user_id:             userId,
        package_id:          packageId,
        method:              'MPESA',
        status:              'PENDING',
        amount_kes:          amountKes,
        phone,
        merchant_request_id: merchantRequestId ?? null,
        checkout_request_id: checkoutRequestId,
      });

    if (insertErr) {
      console.error('[M-Pesa initiate] DB insert failed:', insertErr.message, insertErr.details);
      // STK was already sent — don't return 502, let FE poll so user can complete payment
      return res.status(500).json({
        success: false,
        message: 'Payment prompt sent but could not be recorded. Contact support if you are charged.',
      });
    }

    console.info(`[M-Pesa] STK sent → ${maskPhone(phone)} | pkg: ${packageId} | checkout: ${checkoutRequestId}`);
    return res.json({ success: true, checkoutRequestId });

  } catch (err) {
    console.error('[M-Pesa initiate] Unexpected error:', err.message, err.stack);
    return res.status(500).json({ success: false, message: 'Payment initiation failed. Please try again.' });
  }
};

// ── POST /api/payments/mpesa/callback ────────────────────────────────────────
const SAFARICOM_IPS = new Set([
  '196.201.214.200', '196.201.214.206', '196.201.213.114', '196.201.214.207',
  '196.201.214.208', '196.201.213.44',  '196.201.212.127', '196.201.212.138',
  '196.201.212.129', '196.201.212.136', '196.201.212.74',  '196.201.212.69',
]);

export const callback = async (req, res) => {
  const ip = (req.headers['x-forwarded-for'] || req.socket?.remoteAddress || '')
    .split(',')[0].trim();

  const isSandbox = (process.env.MPESA_ENV || 'sandbox') !== 'production';
  if (!isSandbox && !SAFARICOM_IPS.has(ip)) {
    console.warn(`[M-Pesa callback] Blocked unknown IP: ${ip}`);
    return res.json({ ResultCode: 0, ResultDesc: 'Accepted' });
  }

  try {
    const body = req.body?.Body?.stkCallback;
    if (!body) {
      console.warn('[M-Pesa callback] Malformed body:', JSON.stringify(req.body));
      return res.json({ ResultCode: 0, ResultDesc: 'Accepted' });
    }

    const { MerchantRequestID, CheckoutRequestID, ResultCode, ResultDesc, CallbackMetadata } = body;

    // Look up the payment record in Supabase
    const { data: payment, error: payErr } = await supabaseAdmin
      .from('payments')
      .select('id, user_id, package_id, amount_kes, status')
      .or(`checkout_request_id.eq.${CheckoutRequestID},merchant_request_id.eq.${MerchantRequestID}`)
      .maybeSingle();

    if (payErr) {
      console.error('[M-Pesa callback] Payment lookup error:', payErr.message);
      return res.json({ ResultCode: 0, ResultDesc: 'Accepted' });
    }
    if (!payment) {
      console.warn(`[M-Pesa callback] Unknown payment — checkout: ${CheckoutRequestID}`);
      return res.json({ ResultCode: 0, ResultDesc: 'Accepted' });
    }
    if (payment.status !== 'PENDING') {
      // Already processed (duplicate callback)
      return res.json({ ResultCode: 0, ResultDesc: 'Accepted' });
    }

    // ── Payment failed / cancelled by user ───────────────────────────────
    if (ResultCode !== 0) {
      await supabaseAdmin
        .from('payments')
        .update({ status: 'FAILED', result_code: String(ResultCode), result_desc: ResultDesc })
        .eq('id', payment.id);

      console.info(`[M-Pesa callback] FAILED — code: ${ResultCode} | ${ResultDesc}`);
      return res.json({ ResultCode: 0, ResultDesc: 'Accepted' });
    }

    // ── Payment succeeded ────────────────────────────────────────────────
    const meta = {};
    (CallbackMetadata?.Item || []).forEach(i => { meta[i.Name] = i.Value; });
    const mpesaRef   = meta.MpesaReceiptNumber || '';
    const paidAmount = Number(meta.Amount) || payment.amount_kes;

    // Amount sanity check (allow ±1 KES rounding)
    if (Math.abs(paidAmount - payment.amount_kes) > 1) {
      console.error(`[M-Pesa callback] Amount mismatch — expected ${payment.amount_kes}, got ${paidAmount}`);
      await supabaseAdmin
        .from('payments')
        .update({ status: 'FAILED', result_desc: 'Amount mismatch' })
        .eq('id', payment.id);
      return res.json({ ResultCode: 0, ResultDesc: 'Accepted' });
    }

    // Mark payment SUCCESS
    await supabaseAdmin
      .from('payments')
      .update({
        status:      'SUCCESS',
        mpesa_ref:   mpesaRef,
        result_code: '0',
        result_desc: ResultDesc,
        paid_at:     new Date().toISOString(),
      })
      .eq('id', payment.id);

    // Create booking in Supabase
    const { data: booking, error: bookErr } = await supabaseAdmin
      .from('bookings')
      .insert({
        user_id:        payment.user_id,
        package_id:     payment.package_id,
        payment_id:     payment.id,
        payment_method: 'MPESA',
        amount_paid:    paidAmount,
        currency:       'KES',
        status:         'confirmed',
        confirmed_at:   new Date().toISOString(),
      })
      .select('id')
      .single();

    if (bookErr) {
      console.error('[M-Pesa callback] Booking creation failed:', bookErr.message, bookErr.details);
    } else {
      console.info(`[M-Pesa callback] Booking ${booking.id} created — mpesa ref: ${mpesaRef}`);
    }

    return res.json({ ResultCode: 0, ResultDesc: 'Accepted' });

  } catch (err) {
    console.error('[M-Pesa callback] Unexpected:', err.message, err.stack);
    return res.json({ ResultCode: 0, ResultDesc: 'Accepted' }); // always 200 to Safaricom
  }
};

// ── GET /api/payments/mpesa/status/:checkoutRequestId ────────────────────────
export const getStatus = async (req, res) => {
  try {
    const userId            = req.user?.id;
    const { checkoutRequestId } = req.params;

    if (!userId)
      return res.status(401).json({ success: false, message: 'Unauthorised' });

    if (!checkoutRequestId || !/^[a-zA-Z0-9_\-]{5,80}$/.test(checkoutRequestId))
      return res.status(400).json({ success: false, message: 'Invalid checkoutRequestId' });

    // Fetch payment — IDOR prevention: user can only query their own
    const { data: payment, error: payErr } = await supabaseAdmin
      .from('payments')
      .select('id, status, result_desc, user_id, package_id, amount_kes')
      .eq('checkout_request_id', checkoutRequestId)
      .eq('user_id', userId)
      .maybeSingle();

    if (payErr) {
      console.error('[M-Pesa status] DB error:', payErr.message);
      return res.status(500).json({ success: false, message: 'Server error' });
    }
    if (!payment)
      return res.status(404).json({ success: false, message: 'Payment not found' });

    // ── SUCCESS: return booking details, and create missing booking if needed ─
    if (payment.status === 'SUCCESS') {
      let { data: booking, error: bookingErr } = await supabaseAdmin
        .from('bookings')
        .select('id, status, amount_paid, confirmed_at, package:package_id(id, name, price, image_urls, duration)')
        .eq('payment_id', payment.id)
        .maybeSingle();

      if (!booking) {
        const { data: newBooking, error: createErr } = await supabaseAdmin
          .from('bookings')
          .insert({
            user_id:        payment.user_id,
            package_id:     payment.package_id,
            payment_id:     payment.id,
            payment_method: 'MPESA',
            amount_paid:    payment.amount_kes,
            currency:       'KES',
            status:         'confirmed',
            confirmed_at:   new Date().toISOString(),
          })
          .select('id, status, amount_paid, confirmed_at, package:package_id(id, name, price, image_urls, duration)')
          .maybeSingle();

        if (createErr) {
          console.error('[M-Pesa status] Missing booking creation failed:', createErr.message, createErr.details);
        } else {
          booking = newBooking;
          console.info(`[M-Pesa status] Recovered missing booking ${booking?.id}`);
          
          // Create automated booking message
          if (booking?.id) {
            const pkgName = booking.package?.name || 'Your booked package';
            await createBookingMessage(booking.id, payment.user_id, null, pkgName);
          }
        }
      }

      return res.json({ success: true, status: 'SUCCESS', booking });
    }

    // ── FAILED / CANCELLED ───────────────────────────────────────────────
    if (payment.status === 'FAILED' || payment.status === 'CANCELLED') {
      return res.json({ success: true, status: payment.status, resultDesc: payment.result_desc });
    }

    // ── PENDING: query Daraja as fallback ────────────────────────────────
    try {
      const darajaRes = await stkQuery(checkoutRequestId);
      const rc = darajaRes.ResultCode ?? darajaRes.resultCode;

      if (rc === '0' || rc === 0)
        return res.json({ success: true, status: 'PENDING' }); // callback not yet received — keep polling

      if (rc !== undefined && rc !== '1032' && rc !== 1032) {
        // Non-pending result code from Daraja — update DB and return FAILED
        await supabaseAdmin
          .from('payments')
          .update({ status: 'FAILED', result_code: String(rc), result_desc: darajaRes.ResultDesc ?? darajaRes.resultDesc })
          .eq('id', payment.id);

        return res.json({ success: true, status: 'FAILED', resultDesc: darajaRes.ResultDesc ?? darajaRes.resultDesc });
      }
    } catch (qErr) {
      console.warn('[M-Pesa status] Daraja query failed (non-fatal):', qErr.message);
    }

    return res.json({ success: true, status: 'PENDING' });

  } catch (err) {
    console.error('[M-Pesa status] Unexpected:', err.message, err.stack);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
};