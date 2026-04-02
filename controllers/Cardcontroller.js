// controllers/cardController.js
// ─────────────────────────────────────────────────────────────────────────────
// Card payment via Pesapal (PCI-DSS compliant — hosted payment page).
//
// HOW IT WORKS (card data never touches your server):
//   1. POST /api/payments/card/initiate  → backend gets Pesapal token,
//      registers IPN, submits order → returns redirect_url to frontend
//   2. Frontend redirects user to Pesapal hosted checkout page
//      (user enters card / M-Pesa on Pesapal's PCI-certified servers)
//   3. Pesapal redirects back to PESAPAL_CALLBACK_URL/:packageId with ?OrderTrackingId=xxx
//   4. Frontend calls POST /api/payments/card/verify { orderTrackingId, packageId }
//   5. Backend queries Pesapal transaction status server-to-server
//   6. All security checks pass → booking created in Supabase
//   7. POST /api/payments/card/ipn  ← Pesapal async notification (backup)
//
// Required env vars (Render dashboard):
//   PESAPAL_CONSUMER_KEY      ← from Pesapal merchant dashboard
//   PESAPAL_CONSUMER_SECRET   ← from Pesapal merchant dashboard
//   PESAPAL_ENV               ← 'sandbox' or 'production'
//   PESAPAL_CALLBACK_URL      ← https://umrahmarket.vercel.app/payment/callback
//   PESAPAL_IPN_URL           ← https://umrahmarket-backend.onrender.com/api/payments/card/ipn
//   KES_PER_USD               ← e.g. 130
// ─────────────────────────────────────────────────────────────────────────────

import axios             from 'axios';
import crypto            from 'crypto';
import { supabaseAdmin } from '../config/supabase.js';

const KES_RATE   = Number(process.env.KES_PER_USD) || 130;
const IS_SANDBOX = (process.env.PESAPAL_ENV || 'sandbox') !== 'production';
const BASE_URL   = IS_SANDBOX
  ? 'https://cybqa.pesapal.com/pesapalv3'
  : 'https://pay.pesapal.com/v3';

// ── In-memory token cache ─────────────────────────────────────────────────────
let _tokenCache = { token: null, expiresAt: 0 };

async function getPesapalToken() {
  if (_tokenCache.token && Date.now() < _tokenCache.expiresAt) {
    return _tokenCache.token;
  }

  const key    = process.env.PESAPAL_CONSUMER_KEY;
  const secret = process.env.PESAPAL_CONSUMER_SECRET;
  if (!key || !secret) throw new Error('PESAPAL_CONSUMER_KEY or PESAPAL_CONSUMER_SECRET not set');

  const { data } = await axios.post(
    `${BASE_URL}/api/Auth/RequestToken`,
    { consumer_key: key, consumer_secret: secret },
    { headers: { Accept: 'application/json', 'Content-Type': 'application/json' }, timeout: 10_000 }
  );

  if (!data?.token) throw new Error(`Pesapal auth failed: ${JSON.stringify(data)}`);

  // Pesapal tokens expire in 5 minutes — cache for 4 min to be safe
  _tokenCache = { token: data.token, expiresAt: Date.now() + 4 * 60_000 };
  return data.token;
}

// ── Register IPN URL once (idempotent) ───────────────────────────────────────
// Pesapal requires you to register your IPN URL before submitting orders.
// We cache the ipnId in memory after first registration.
let _ipnId = null;

async function getIpnId(token) {
  if (_ipnId) return _ipnId;

  const ipnUrl = process.env.PESAPAL_IPN_URL;
  if (!ipnUrl) throw new Error('PESAPAL_IPN_URL not set');

  // First check if already registered
  try {
    const { data: listRes } = await axios.get(
      `${BASE_URL}/api/URLSetup/GetIpnList`,
      { headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' }, timeout: 10_000 }
    );
    const existing = listRes?.find?.(i => i.url === ipnUrl);
    if (existing?.ipn_id) { _ipnId = existing.ipn_id; return _ipnId; }
  } catch { /* fall through to register */ }

  const { data } = await axios.post(
    `${BASE_URL}/api/URLSetup/RegisterIPN`,
    { url: ipnUrl, ipn_notification_type: 'POST' },
    { headers: { Authorization: `Bearer ${token}`, Accept: 'application/json', 'Content-Type': 'application/json' }, timeout: 10_000 }
  );

  if (!data?.ipn_id) throw new Error(`IPN registration failed: ${JSON.stringify(data)}`);
  _ipnId = data.ipn_id;
  return _ipnId;
}

// ── Query a transaction status ────────────────────────────────────────────────
async function queryTransaction(orderTrackingId, token) {
  const { data } = await axios.get(
    `${BASE_URL}/api/Transactions/GetTransactionStatus?orderTrackingId=${orderTrackingId}`,
    { headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' }, timeout: 15_000 }
  );
  return data;
  // shape: { payment_status_description, amount, currency, confirmation_code, ... }
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/payments/card/initiate
// Body: { packageId }
// Auth: requireAuth
// Returns: { redirectUrl, orderTrackingId }
// ─────────────────────────────────────────────────────────────────────────────
export const initiate = async (req, res) => {
  try {
    const userId     = req.user?.id;
    const { packageId } = req.body;

    if (!userId)
      return res.status(401).json({ success: false, message: 'Unauthorised' });
    if (!packageId)
      return res.status(400).json({ success: false, message: 'packageId is required' });

    // Validate packageId (UUID or MongoDB ObjectId)
    const isUUID     = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(packageId);
    const isObjectId = /^[0-9a-f]{24}$/i.test(packageId);
    if (!isUUID && !isObjectId)
      return res.status(400).json({ success: false, message: 'Invalid packageId' });

    // ── 1. Fetch package price from DB — NEVER trust frontend ────────────────
    const { data: pkg, error: pkgErr } = await supabaseAdmin
      .from('packages')
      .select('id, name, price, status')
      .eq('id', packageId)
      .maybeSingle();

    if (pkgErr) {
      console.error('[Card initiate] DB error:', pkgErr.message);
      return res.status(500).json({ success: false, message: 'Failed to fetch package' });
    }
    if (!pkg)
      return res.status(404).json({ success: false, message: 'Package not found' });

    const pkgStatus = (pkg.status || '').toLowerCase();
    if (!['active', 'published', 'approved'].includes(pkgStatus))
      return res.status(404).json({ success: false, message: 'Package not available for booking' });

    const priceUSD = pkg.price ?? 0;
    const priceKES = Math.ceil(priceUSD * KES_RATE);
    if (priceKES <= 0)
      return res.status(400).json({ success: false, message: 'Package has no valid price' });

    // ── 2. Idempotency — resume pending within 10 min ────────────────────────
    const tenMinAgo = new Date(Date.now() - 10 * 60_000).toISOString();
    const { data: existing } = await supabaseAdmin
      .from('payments')
      .select('id, pesapal_order_tracking_id, pesapal_redirect_url')
      .eq('user_id', userId)
      .eq('package_id', packageId)
      .eq('method', 'CARD')
      .eq('status', 'PENDING')
      .gte('created_at', tenMinAgo)
      .not('pesapal_redirect_url', 'is', null)
      .maybeSingle();

    if (existing?.pesapal_redirect_url) {
      return res.json({
        success:         true,
        redirectUrl:     existing.pesapal_redirect_url,
        orderTrackingId: existing.pesapal_order_tracking_id,
        resumed:         true,
      });
    }

    // ── 3. Get Pesapal auth token ─────────────────────────────────────────────
    let token;
    try {
      token = await getPesapalToken();
    } catch (authErr) {
      console.error('[Card initiate] Pesapal auth error:', authErr.message);
      return res.status(502).json({ success: false, message: `Pesapal auth failed: ${authErr.message}` });
    }

    // ── 4. Register IPN ───────────────────────────────────────────────────────
    let ipnId;
    try {
      ipnId = await getIpnId(token);
    } catch (ipnErr) {
      console.error('[Card initiate] IPN registration error:', ipnErr.message);
      return res.status(502).json({ success: false, message: 'Payment setup failed. Please try again.' });
    }

    // ── 5. Generate unique merchant order reference ───────────────────────────
    // Must be unique per transaction — tied to userId + packageId + timestamp
    const merchantRef = `UMR-${userId.slice(-6).toUpperCase()}-${Date.now()}`;
    const _callbackBase = process.env.PESAPAL_CALLBACK_URL;
    if (!_callbackBase) throw new Error('PESAPAL_CALLBACK_URL not set');

    // FIX: Embed packageId in the URL PATH, not as a query param.
    // Pesapal replaces the entire query string on redirect (dropping any params
    // you add), but it preserves the path — so this is the only reliable way
    // to carry packageId back to the frontend callback page.
    const callbackUrl = `${_callbackBase}/${packageId}`;

    // ── 6. Submit order to Pesapal ────────────────────────────────────────────
    const orderPayload = {
      id:                    merchantRef,
      currency:              'KES',
      amount:                priceKES,
      description:           `Umrah Package: ${(pkg.name || '').slice(0, 100)}`,
      callback_url:          callbackUrl,
      notification_id:       ipnId,
      billing_address: {
        email_address: req.user?.email || '',
        first_name:    req.user?.firstName || 'Customer',
        last_name:     req.user?.lastName  || '',
      },
    };

    let orderRes;
    try {
      const { data } = await axios.post(
        `${BASE_URL}/api/Transactions/SubmitOrderRequest`,
        orderPayload,
        {
          headers: {
            Authorization:  `Bearer ${token}`,
            Accept:         'application/json',
            'Content-Type': 'application/json',
          },
          timeout: 15_000,
        }
      );
      orderRes = data;
    } catch (orderErr) {
      const detail = orderErr.response?.data ? JSON.stringify(orderErr.response.data) : orderErr.message;
      console.error('[Card initiate] Pesapal order submit error:', detail);
      return res.status(502).json({ success: false, message: `Payment initiation failed: ${detail}` });
    }

    if (!orderRes?.redirect_url || !orderRes?.order_tracking_id) {
      console.error('[Card initiate] Invalid Pesapal response:', JSON.stringify(orderRes));
      return res.status(502).json({ success: false, message: 'Invalid response from payment provider' });
    }

    // ── 7. Save pending payment record ────────────────────────────────────────
    const { error: insertErr } = await supabaseAdmin
      .from('payments')
      .insert({
        user_id:                    userId,
        package_id:                 packageId,
        method:                     'CARD',
        status:                     'PENDING',
        amount_kes:                 priceKES,
        phone:                      req.user?.phone || 'N/A',
        pesapal_merchant_ref:       merchantRef,
        pesapal_order_tracking_id:  orderRes.order_tracking_id,
        pesapal_redirect_url:       orderRes.redirect_url,
      });

    if (insertErr) {
      console.error('[Card initiate] DB insert error:', insertErr.message);
      return res.status(500).json({ success: false, message: 'Payment initiated but could not be recorded. Contact support.' });
    }

    console.info(`[Card] Order submitted | ref: ${merchantRef} | tracking: ${orderRes.order_tracking_id}`);
    return res.json({
      success:         true,
      redirectUrl:     orderRes.redirect_url,
      orderTrackingId: orderRes.order_tracking_id,
    });

  } catch (err) {
    console.error('[Card initiate] Unexpected error:', err.message, err.stack);
    return res.status(500).json({ success: false, message: 'Server error. Please try again.' });
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/payments/card/verify
// Called by frontend after Pesapal redirects back to callback URL.
// Body: { orderTrackingId, packageId }
// Auth: requireAuth
// ─────────────────────────────────────────────────────────────────────────────
export const verify = async (req, res) => {
  try {
    const userId = req.user?.id;
    const { orderTrackingId, packageId } = req.body;

    if (!userId)
      return res.status(401).json({ success: false, message: 'Unauthorised' });
    if (!orderTrackingId || !packageId)
      return res.status(400).json({ success: false, message: 'orderTrackingId and packageId are required' });

    // Basic format guard — Pesapal tracking IDs are UUIDs
    if (!/^[a-zA-Z0-9-]{10,60}$/.test(orderTrackingId))
      return res.status(400).json({ success: false, message: 'Invalid orderTrackingId' });

    // ── 1. Find payment record — scoped to this user (IDOR prevention) ───────
    const { data: payment, error: payErr } = await supabaseAdmin
      .from('payments')
      .select('id, user_id, package_id, amount_kes, status, pesapal_merchant_ref')
      .eq('pesapal_order_tracking_id', orderTrackingId)
      .eq('user_id', userId)
      .eq('package_id', packageId)
      .maybeSingle();

    if (payErr || !payment)
      return res.status(404).json({ success: false, message: 'Payment record not found. Contact support.' });

    // Double-submit protection
    if (payment.status === 'SUCCESS') {
      const { data: booking } = await supabaseAdmin
        .from('bookings')
        .select('id, status, amount_paid, confirmed_at')
        .eq('payment_id', payment.id)
        .maybeSingle();
      return res.json({ success: true, alreadyProcessed: true, booking });
    }

    if (payment.status === 'FAILED')
      return res.status(400).json({ success: false, message: 'This payment was already marked as failed.' });

    // ── 2. Query Pesapal server-to-server ─────────────────────────────────────
    let token, txStatus;
    try {
      token    = await getPesapalToken();
      txStatus = await queryTransaction(orderTrackingId, token);
    } catch (queryErr) {
      console.error('[Card verify] Pesapal query error:', queryErr.message);
      return res.status(502).json({ success: false, message: 'Could not verify payment. Contact support if charged.' });
    }

    const statusDesc = (txStatus?.payment_status_description || '').toUpperCase();

    // ── 3. Security checks ────────────────────────────────────────────────────

    // 3a. Must be COMPLETED
    if (statusDesc !== 'COMPLETED') {
      if (['FAILED', 'INVALID', 'REVERSED'].includes(statusDesc)) {
        await supabaseAdmin.from('payments')
          .update({ status: 'FAILED', result_desc: `Pesapal: ${statusDesc}` })
          .eq('id', payment.id);
        return res.status(400).json({ success: false, message: `Payment ${statusDesc.toLowerCase()}. Please try again.` });
      }
      // PENDING — tell FE to poll
      return res.json({ success: true, status: 'PENDING' });
    }

    // 3b. Currency must be KES
    if (txStatus.currency && txStatus.currency !== 'KES') {
      console.error(`[Card verify] Currency mismatch — got ${txStatus.currency}`);
      await supabaseAdmin.from('payments').update({ status: 'FAILED', result_desc: 'Currency mismatch' }).eq('id', payment.id);
      return res.status(400).json({ success: false, message: 'Currency mismatch. Contact support.' });
    }

    // 3c. Amount must match (allow 1 KES tolerance)
    const paidAmount = Number(txStatus.amount);
    if (!isNaN(paidAmount) && Math.abs(paidAmount - payment.amount_kes) > 1) {
      console.error(`[Card verify] Amount mismatch — expected ${payment.amount_kes}, got ${paidAmount}`);
      await supabaseAdmin.from('payments').update({ status: 'FAILED', result_desc: 'Amount mismatch' }).eq('id', payment.id);
      return res.status(400).json({ success: false, message: 'Amount mismatch. Contact support.' });
    }

    const confirmationCode = txStatus.confirmation_code || txStatus.payment_account || '';

    // ── 4. Mark payment SUCCESS ───────────────────────────────────────────────
    await supabaseAdmin.from('payments')
      .update({
        status:      'SUCCESS',
        result_desc: `Pesapal: ${statusDesc}`,
        result_code: confirmationCode,
        paid_at:     new Date().toISOString(),
      })
      .eq('id', payment.id);

    // ── 5. Create booking ─────────────────────────────────────────────────────
    const { data: booking, error: bookErr } = await supabaseAdmin
      .from('bookings')
      .insert({
        user_id:        payment.user_id,
        package_id:     payment.package_id,
        payment_id:     payment.id,
        payment_method: 'CARD',
        amount_paid:    isNaN(paidAmount) ? payment.amount_kes : paidAmount,
        currency:       'KES',
        status:         'confirmed',
        confirmed_at:   new Date().toISOString(),
      })
      .select('id, status, amount_paid, confirmed_at, package:package_id(id, name, price, image_urls, duration_days)')
      .single();

    if (bookErr) {
      console.error('[Card verify] Booking creation failed:', bookErr.message);
      return res.json({ success: true, booking: null, warning: 'Payment confirmed but booking creation failed. Contact support.' });
    }

    console.info(`[Card] Booking ${booking.id} created | tracking: ${orderTrackingId} | ref: ${confirmationCode}`);
    return res.json({ success: true, status: 'SUCCESS', booking });

  } catch (err) {
    console.error('[Card verify] Unexpected error:', err.message, err.stack);
    return res.status(500).json({ success: false, message: 'Server error during payment verification.' });
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/payments/card/ipn
// Pesapal Instant Payment Notification — PUBLIC, no JWT.
// Verified by querying Pesapal server-to-server (Pesapal sends no secret hash).
// This is the BACKUP path — verify() is the primary path.
// ─────────────────────────────────────────────────────────────────────────────
export const ipn = async (req, res) => {
  try {
    // Pesapal sends: { orderTrackingId, orderMerchantReference, orderNotificationType }
    const { orderTrackingId, orderMerchantReference } = req.body;

    if (!orderTrackingId) {
      console.warn('[Card IPN] Missing orderTrackingId');
      return res.status(200).json({ orderNotificationType: 'IPNCHANGE', orderTrackingId: '', orderMerchantReference: '', status: '200' });
    }

    console.info(`[Card IPN] Received | tracking: ${orderTrackingId} | ref: ${orderMerchantReference}`);

    // Find payment
    const { data: payment } = await supabaseAdmin
      .from('payments')
      .select('id, user_id, package_id, amount_kes, status')
      .eq('pesapal_order_tracking_id', orderTrackingId)
      .maybeSingle();

    if (!payment || payment.status !== 'PENDING') {
      return res.status(200).json({ orderNotificationType: 'IPNCHANGE', orderTrackingId, orderMerchantReference, status: '200' });
    }

    // Query Pesapal to confirm — never trust IPN body alone
    let token, txStatus;
    try {
      token    = await getPesapalToken();
      txStatus = await queryTransaction(orderTrackingId, token);
    } catch (qErr) {
      console.error('[Card IPN] Query failed:', qErr.message);
      return res.status(200).json({ orderNotificationType: 'IPNCHANGE', orderTrackingId, orderMerchantReference, status: '200' });
    }

    const statusDesc = (txStatus?.payment_status_description || '').toUpperCase();

    if (statusDesc !== 'COMPLETED') {
      if (['FAILED', 'INVALID', 'REVERSED'].includes(statusDesc)) {
        await supabaseAdmin.from('payments')
          .update({ status: 'FAILED', result_desc: `IPN: ${statusDesc}` })
          .eq('id', payment.id);
      }
      return res.status(200).json({ orderNotificationType: 'IPNCHANGE', orderTrackingId, orderMerchantReference, status: '200' });
    }

    // Amount check
    const paidAmount = Number(txStatus.amount);
    if (!isNaN(paidAmount) && Math.abs(paidAmount - payment.amount_kes) > 1) {
      console.error(`[Card IPN] Amount mismatch — expected ${payment.amount_kes}, got ${paidAmount}`);
      await supabaseAdmin.from('payments').update({ status: 'FAILED', result_desc: 'IPN amount mismatch' }).eq('id', payment.id);
      return res.status(200).json({ orderNotificationType: 'IPNCHANGE', orderTrackingId, orderMerchantReference, status: '200' });
    }

    // Mark SUCCESS
    await supabaseAdmin.from('payments')
      .update({ status: 'SUCCESS', result_desc: 'IPN: COMPLETED', paid_at: new Date().toISOString() })
      .eq('id', payment.id);

    // Create booking
    const { error: bookErr } = await supabaseAdmin
      .from('bookings')
      .insert({
        user_id:        payment.user_id,
        package_id:     payment.package_id,
        payment_id:     payment.id,
        payment_method: 'CARD',
        amount_paid:    isNaN(paidAmount) ? payment.amount_kes : paidAmount,
        currency:       'KES',
        status:         'confirmed',
        confirmed_at:   new Date().toISOString(),
      });

    if (bookErr) console.error('[Card IPN] Booking creation failed:', bookErr.message);
    else console.info(`[Card IPN] Booking created | tracking: ${orderTrackingId}`);

    // Pesapal requires this exact response format
    return res.status(200).json({ orderNotificationType: 'IPNCHANGE', orderTrackingId, orderMerchantReference, status: '200' });

  } catch (err) {
    console.error('[Card IPN] Unexpected error:', err.message);
    return res.status(200).json({ orderNotificationType: 'IPNCHANGE', orderTrackingId: '', orderMerchantReference: '', status: '200' });
  }
};