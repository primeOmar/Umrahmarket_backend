// controllers/mpesaController.js
import { supabaseAdmin } from '../config/supabase.js';
import { stkPush, stkQuery } from '../services/Mpesaservice.js';

const KES_RATE       = Number(process.env.KES_PER_USD) || 130;
const MPESA_PHONE_RE = /^254[17]\d{8}$/;
function maskPhone(p) { return p ? `${p.slice(0, 6)}****${p.slice(-2)}` : '?'; }

// ── POST /api/payments/mpesa/initiate ─────────────────────────────────────────
export const initiate = async (req, res) => {
  try {
    const userId = req.user?.id;
    const { packageId, phone } = req.body;

    if (!userId)
      return res.status(401).json({ success: false, message: 'Unauthorised' });
    if (!packageId || !phone)
      return res.status(400).json({ success: false, message: 'packageId and phone are required' });

    // FIX 1: Accept both UUID (Supabase) and MongoDB ObjectId (24-hex) formats
    const isUUID     = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(packageId);
    const isObjectId = /^[0-9a-f]{24}$/i.test(packageId);
    if (!isUUID && !isObjectId)
      return res.status(400).json({ success: false, message: 'Invalid packageId' });

    if (!MPESA_PHONE_RE.test(phone))
      return res.status(400).json({ success: false, message: 'Invalid Safaricom number' });

    // Fetch package — NEVER trust FE price
    const { data: pkg, error: pkgErr } = await supabaseAdmin
      .from('packages')
      .select('id, name, price_per_person, price, status')
      .eq('id', packageId)
      .maybeSingle();

    if (pkgErr) {
      console.error('[M-Pesa initiate] Package fetch error:', pkgErr.message);
      return res.status(500).json({ success: false, message: 'Failed to fetch package' });
    }
    if (!pkg) {
      return res.status(404).json({ success: false, message: 'Package not found' });
    }

    // FIX 2: Handle different status values your DB might use
    const pkgStatus = (pkg.status || '').toLowerCase();
    if (!['active', 'published', 'approved'].includes(pkgStatus)) {
      return res.status(404).json({ success: false, message: 'Package is not available for booking' });
    }

    // FIX 3: Handle both price_per_person and price column names
    const priceUSD  = pkg.price_per_person ?? pkg.price ?? 0;
    const amountKes = Math.ceil(priceUSD * KES_RATE);
    if (amountKes <= 0)
      return res.status(400).json({ success: false, message: 'Package has no valid price' });

    // Idempotency — resume existing PENDING payment within last 5 min
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

    // Fire STK push — catch Daraja errors separately for clearer error messages
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

    // FIX 4: Daraja returns PascalCase. Normalise regardless of what stkPush returns.
    const checkoutRequestId = darajaRes.CheckoutRequestID ?? darajaRes.checkoutRequestId;
    const merchantRequestId = darajaRes.MerchantRequestID ?? darajaRes.merchantRequestId;

    if (!checkoutRequestId) {
      console.error('[M-Pesa initiate] No checkoutRequestId in Daraja response:', JSON.stringify(darajaRes));
      return res.status(502).json({ success: false, message: 'Invalid M-Pesa response. Please try again.' });
    }

    // Persist pending payment record
    const { error: insertErr } = await supabaseAdmin
      .from('payments')
      .insert({
        user_id:             userId,
        package_id:          packageId,
        method:              'MPESA',
        status:              'PENDING',
        amount_kes:          amountKes,
        phone,
        merchant_request_id: merchantRequestId,
        checkout_request_id: checkoutRequestId,
      });

    if (insertErr) {
      console.error('[M-Pesa initiate] DB insert failed:', insertErr.message);
      // STK was already sent — don't return 502, let FE poll
      return res.status(500).json({ success: false, message: 'Payment sent but could not be recorded. Contact support if charged.' });
    }

    console.info(`[M-Pesa] STK sent → ${maskPhone(phone)} | pkg: ${packageId} | id: ${checkoutRequestId}`);
    return res.json({ success: true, checkoutRequestId });

  } catch (err) {
    console.error('[M-Pesa initiate] Unexpected error:', err.message, err.stack);
    return res.status(502).json({ success: false, message: 'Payment initiation failed. Please try again.' });
  }
};

// ── POST /api/payments/mpesa/callback ─────────────────────────────────────────
const SAFARICOM_IPS = new Set([
  '196.201.214.200', '196.201.214.206', '196.201.213.114', '196.201.214.207',
  '196.201.214.208', '196.201.213.44',  '196.201.212.127', '196.201.212.138',
  '196.201.212.129', '196.201.212.136', '196.201.212.74',  '196.201.212.69',
]);

export const callback = async (req, res) => {
  const ip = (req.headers['x-forwarded-for'] || req.socket?.remoteAddress || '')
    .split(',')[0].trim();

  // FIX 5: Skip IP check in sandbox — Safaricom sandbox uses different IPs
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

    const { data: payment } = await supabaseAdmin
      .from('payments')
      .select('id, user_id, package_id, amount_kes, status')
      .or(`checkout_request_id.eq.${CheckoutRequestID},merchant_request_id.eq.${MerchantRequestID}`)
      .maybeSingle();

    if (!payment) {
      console.warn(`[M-Pesa callback] Unknown payment — checkout: ${CheckoutRequestID}`);
      return res.json({ ResultCode: 0, ResultDesc: 'Accepted' });
    }
    if (payment.status !== 'PENDING') {
      return res.json({ ResultCode: 0, ResultDesc: 'Accepted' });
    }

    if (ResultCode !== 0) {
      await supabaseAdmin.from('payments')
        .update({ status: 'FAILED', result_code: String(ResultCode), result_desc: ResultDesc })
        .eq('id', payment.id);
      console.info(`[M-Pesa callback] FAILED — code: ${ResultCode} | ${ResultDesc}`);
      return res.json({ ResultCode: 0, ResultDesc: 'Accepted' });
    }

    const meta = {};
    (CallbackMetadata?.Item || []).forEach(i => { meta[i.Name] = i.Value; });
    const mpesaRef   = meta.MpesaReceiptNumber || '';
    const paidAmount = Number(meta.Amount) || payment.amount_kes;

    if (Math.abs(paidAmount - payment.amount_kes) > 1) {
      console.error(`[M-Pesa callback] Amount mismatch — expected ${payment.amount_kes}, got ${paidAmount}`);
      await supabaseAdmin.from('payments')
        .update({ status: 'FAILED', result_desc: 'Amount mismatch' })
        .eq('id', payment.id);
      return res.json({ ResultCode: 0, ResultDesc: 'Accepted' });
    }

    await supabaseAdmin.from('payments')
      .update({ status: 'SUCCESS', mpesa_ref: mpesaRef, result_code: '0', result_desc: ResultDesc, paid_at: new Date().toISOString() })
      .eq('id', payment.id);

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

    if (bookErr) console.error('[M-Pesa callback] Booking creation failed:', bookErr.message);
    else console.info(`[M-Pesa callback] Booking ${booking.id} created — ref: ${mpesaRef}`);

    return res.json({ ResultCode: 0, ResultDesc: 'Accepted' });

  } catch (err) {
    console.error('[M-Pesa callback] Unexpected:', err.message);
    return res.json({ ResultCode: 0, ResultDesc: 'Accepted' }); // always 200 to Safaricom
  }
};

// ── GET /api/payments/mpesa/status/:checkoutRequestId ─────────────────────────
export const getStatus = async (req, res) => {
  try {
    const userId = req.user?.id;
    const { checkoutRequestId } = req.params;

    if (!userId)
      return res.status(401).json({ success: false, message: 'Unauthorised' });

    // FIX 7: Loosened regex — Safaricom IDs vary in length/format between sandbox & production
    if (!checkoutRequestId || !/^[a-zA-Z0-9_]{5,60}$/.test(checkoutRequestId))
      return res.status(400).json({ success: false, message: 'Invalid checkoutRequestId' });

    const { data: payment } = await supabaseAdmin
      .from('payments')
      .select('id, status, result_desc')
      .eq('checkout_request_id', checkoutRequestId)
      .eq('user_id', userId) // IDOR prevention — user can only query their own
      .maybeSingle();

    if (!payment)
      return res.status(404).json({ success: false, message: 'Payment not found' });

    if (payment.status === 'SUCCESS') {
      const { data: booking } = await supabaseAdmin
        .from('bookings')
        .select('id, status, amount_paid, confirmed_at, package:package_id(id, name, price, image_urls, duration_days)')
        .eq('payment_id', payment.id)
        .maybeSingle();
      return res.json({ success: true, status: 'SUCCESS', booking });
    }

    if (payment.status === 'FAILED') {
      return res.json({ success: true, status: 'FAILED', resultDesc: payment.result_desc });
    }

    // Still PENDING — query Daraja directly as a fallback
    try {
      const darajaRes = await stkQuery(checkoutRequestId);
      // FIX 8: Handle both PascalCase and camelCase from stkQuery
      const rc = darajaRes.ResultCode ?? darajaRes.resultCode;
      if (rc === '0' || rc === 0)
        return res.json({ success: true, status: 'SUCCESS', booking: null });
      if (rc !== undefined && rc !== '1032' && rc !== 1032)
        return res.json({ success: true, status: 'FAILED', resultDesc: darajaRes.ResultDesc ?? darajaRes.resultDesc });
    } catch (qErr) {
      console.warn('[M-Pesa status] Daraja query failed (non-fatal):', qErr.message);
    }

    return res.json({ success: true, status: 'PENDING' });

  } catch (err) {
    console.error('[M-Pesa status]', err.message);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
};