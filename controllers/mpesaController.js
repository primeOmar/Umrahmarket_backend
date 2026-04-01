// controllers/mpesaController.js
import { supabaseAdmin } from '../config/supabase.js';
import { stkPush, stkQuery } from '../services/Mpesaservice.js';

// All DB writes use supabaseAdmin (service role) — bypasses RLS safely.
const KES_RATE       = Number(process.env.KES_PER_USD) || 130;
const MPESA_PHONE_RE = /^254[17]\d{8}$/;
function maskPhone(p) { return p ? `${p.slice(0, 6)}****${p.slice(-2)}` : '?'; }

// ── POST /api/payments/mpesa/initiate ─────────────────────────────────────────
export const initiate = async (req, res) => {
  try {
    const userId = req.user?.id;
    const { packageId, phone } = req.body;

    if (!userId) return res.status(401).json({ success: false, message: 'Unauthorised' });
    if (!packageId || !phone)
      return res.status(400).json({ success: false, message: 'packageId and phone are required' });
    if (!/^[0-9a-f-]{36}$/i.test(packageId))
      return res.status(400).json({ success: false, message: 'Invalid packageId' });
    if (!MPESA_PHONE_RE.test(phone))
      return res.status(400).json({ success: false, message: 'Invalid Safaricom number' });

    // Fetch package — never trust FE price
    const { data: pkg, error: pkgErr } = await supabaseAdmin
      .from('packages')
      .select('id, name, price')
      .eq('id', packageId)
      .eq('status', 'Active')
      .maybeSingle();

    if (pkgErr || !pkg)
      return res.status(404).json({ success: false, message: 'Package not found or inactive' });

    const amountKes = Math.ceil((pkg.price ?? 0) * KES_RATE);
    if (amountKes <= 0)
      return res.status(400).json({ success: false, message: 'Package has no valid price' });

    // Idempotency — resume pending payment within last 5 min
    const fiveMinAgo = new Date(Date.now() - 5 * 60_000).toISOString();
    const { data: existing } = await supabaseAdmin
      .from('payments')
      .select('checkout_request_id')
      .eq('user_id', userId)
      .eq('package_id', packageId)
      .eq('status', 'PENDING')
      .gte('created_at', fiveMinAgo)
      .maybeSingle();

    if (existing)
      return res.json({ success: true, checkoutRequestId: existing.checkout_request_id, resumed: true });

    // Fire STK push
    const darajaRes = await stkPush({
      phone, amount: amountKes,
      accountRef:  `PKG-${packageId.slice(-6).toUpperCase()}`,
      description: 'Umrah Package',
    });

    // Persist pending payment
    const { error: insertErr } = await supabaseAdmin
      .from('payments')
      .insert({
        user_id: userId, package_id: packageId,
        method: 'MPESA', status: 'PENDING', amount_kes: amountKes, phone,
        merchant_request_id: darajaRes.merchantRequestId,
        checkout_request_id: darajaRes.checkoutRequestId,
      });

    if (insertErr) {
      console.error('[M-Pesa initiate] DB insert failed:', insertErr.message);
      return res.status(500).json({ success: false, message: 'Payment initiation failed. Please try again.' });
    }

    console.info(`[M-Pesa] STK sent to ${maskPhone(phone)} for pkg ${packageId}`);
    return res.json({ success: true, checkoutRequestId: darajaRes.checkoutRequestId });

  } catch (err) {
    console.error('[M-Pesa initiate]', err.message);
    return res.status(502).json({ success: false, message: 'Payment initiation failed. Please try again.' });
  }
};

// ── POST /api/payments/mpesa/callback ─────────────────────────────────────────
const SAFARICOM_IPS = new Set([
  '196.201.214.200','196.201.214.206','196.201.213.114','196.201.214.207',
  '196.201.214.208','196.201.213.44', '196.201.212.127','196.201.212.138',
  '196.201.212.129','196.201.212.136','196.201.212.74', '196.201.212.69',
]);

export const callback = async (req, res) => {
  const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
  if (!SAFARICOM_IPS.has(ip)) {
    console.warn(`[M-Pesa callback] Blocked IP: ${ip}`);
    return res.json({ ResultCode: 0, ResultDesc: 'Accepted' });
  }

  try {
    const body = req.body?.Body?.stkCallback;
    if (!body) return res.json({ ResultCode: 0, ResultDesc: 'Accepted' });

    const { MerchantRequestID, CheckoutRequestID, ResultCode, ResultDesc, CallbackMetadata } = body;

    const { data: payment } = await supabaseAdmin
      .from('payments')
      .select('id, user_id, package_id, amount_kes, status')
      .or(`checkout_request_id.eq.${CheckoutRequestID},merchant_request_id.eq.${MerchantRequestID}`)
      .maybeSingle();

    if (!payment) { console.warn(`[M-Pesa callback] Unknown payment ${CheckoutRequestID}`); return res.json({ ResultCode: 0, ResultDesc: 'Accepted' }); }
    if (payment.status !== 'PENDING') return res.json({ ResultCode: 0, ResultDesc: 'Accepted' });

    if (ResultCode !== 0) {
      await supabaseAdmin.from('payments')
        .update({ status: 'FAILED', result_code: String(ResultCode), result_desc: ResultDesc })
        .eq('id', payment.id);
      return res.json({ ResultCode: 0, ResultDesc: 'Accepted' });
    }

    const meta = {};
    (CallbackMetadata?.Item || []).forEach(i => { meta[i.Name] = i.Value; });
    const mpesaRef   = meta.MpesaReceiptNumber || '';
    const paidAmount = Number(meta.Amount) || payment.amount_kes;

    // Amount validation — prevent partial-payment attacks
    if (Math.abs(paidAmount - payment.amount_kes) > 1) {
      console.error(`[M-Pesa callback] Amount mismatch! Expected ${payment.amount_kes}, got ${paidAmount}`);
      await supabaseAdmin.from('payments').update({ status: 'FAILED', result_desc: 'Amount mismatch' }).eq('id', payment.id);
      return res.json({ ResultCode: 0, ResultDesc: 'Accepted' });
    }

    // Mark payment SUCCESS
    await supabaseAdmin.from('payments')
      .update({ status: 'SUCCESS', mpesa_ref: mpesaRef, result_code: '0', result_desc: ResultDesc, paid_at: new Date().toISOString() })
      .eq('id', payment.id);

    // Create booking
    const { data: booking, error: bookErr } = await supabaseAdmin
      .from('bookings')
      .insert({
        user_id: payment.user_id, package_id: payment.package_id,
        payment_id: payment.id, payment_method: 'MPESA',
        amount_paid: paidAmount, currency: 'KES',
        status: 'confirmed', confirmed_at: new Date().toISOString(),
      })
      .select('id').single();

    if (bookErr) console.error('[M-Pesa callback] Booking creation failed:', bookErr.message);
    else console.info(`[M-Pesa callback] Booking ${booking.id} created — ref ${mpesaRef}`);

    return res.json({ ResultCode: 0, ResultDesc: 'Accepted' });

  } catch (err) {
    console.error('[M-Pesa callback] Unexpected:', err.message);
    return res.json({ ResultCode: 0, ResultDesc: 'Accepted' });
  }
};

// ── GET /api/payments/mpesa/status/:checkoutRequestId ─────────────────────────
export const getStatus = async (req, res) => {
  try {
    const userId = req.user?.id;
    const { checkoutRequestId } = req.params;

    if (!userId) return res.status(401).json({ success: false, message: 'Unauthorised' });
    if (!checkoutRequestId || !/^ws_CO_[\w]{1,30}$/.test(checkoutRequestId))
      return res.status(400).json({ success: false, message: 'Invalid checkoutRequestId' });

    const { data: payment } = await supabaseAdmin
      .from('payments').select('id, status')
      .eq('checkout_request_id', checkoutRequestId)
      .eq('user_id', userId)       // scoped — prevents IDOR
      .maybeSingle();

    if (!payment) return res.status(404).json({ success: false, message: 'Payment not found' });

    if (payment.status === 'SUCCESS') {
      const { data: booking } = await supabaseAdmin
        .from('bookings')
        .select('id, status, amount_paid, confirmed_at, package:package_id(id, name, price, image_urls, duration)')
        .eq('payment_id', payment.id).maybeSingle();
      return res.json({ success: true, status: 'SUCCESS', booking });
    }

    if (payment.status === 'FAILED') return res.json({ success: true, status: 'FAILED' });

    // Still PENDING — query Daraja as fallback
    try {
      const darajaRes = await stkQuery(checkoutRequestId);
      if (darajaRes.resultCode === '0' || darajaRes.resultCode === 0)
        return res.json({ success: true, status: 'SUCCESS', booking: null });
      if (darajaRes.resultCode && darajaRes.resultCode !== '1032')
        return res.json({ success: true, status: 'FAILED' });
    } catch { /* keep returning PENDING */ }

    return res.json({ success: true, status: 'PENDING' });

  } catch (err) {
    console.error('[M-Pesa status]', err.message);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
};