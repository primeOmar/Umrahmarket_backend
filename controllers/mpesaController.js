// controllers/mpesaController.js
// ─────────────────────────────────────────────────────────────────────────────
// Three endpoints:
//   POST /api/payments/mpesa/initiate  — trigger STK push
//   POST /api/payments/mpesa/callback  — Safaricom webhook (public, no auth)
//   GET  /api/payments/mpesa/status/:checkoutRequestId  — poll from FE
//
// Security hardening applied:
//   • Amount is read from DB, never trusted from the request body
//   • Phone is validated/normalised server-side
//   • Callback IP is verified against Safaricom's published CIDR list
//   • idempotency key prevents duplicate charges on retry
//   • All sensitive fields are masked in logs
//   • MongoDB query uses strict ObjectId casting to prevent injection

const mongoose   = require('mongoose');
const { stkPush, stkQuery } = require('../services/mpesaService');

// ── Import your existing models (adjust paths as needed) ──────────────────────
const Package  = require('../models/Package');   // your existing package model
const Booking  = require('../models/Booking');   // your existing booking model (create if needed)
const Payment  = require('../models/Payment');   // create this model — schema below

// ── Safaricom callback IP whitelist (update if Safaricom changes them) ────────
// https://developer.safaricom.co.ke/docs#ip-whitelist
const SAFARICOM_IPS = new Set([
  '196.201.214.200', '196.201.214.206', '196.201.213.114',
  '196.201.214.207', '196.201.214.208', '196.201.213.44',
  '196.201.212.127', '196.201.212.138', '196.201.212.129',
  '196.201.212.136', '196.201.212.74',  '196.201.212.69',
]);

// KES/USD rate — move to env or a DB config document for production
const KES_RATE = Number(process.env.KES_PER_USD) || 130;

// Safaricom M-Pesa phone regex (after normalisation to 254...)
const MPESA_PHONE_RE = /^254[17]\d{8}$/;

function maskPhone(p) {
  return p ? `${p.slice(0, 6)}****${p.slice(-2)}` : '?';
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/payments/mpesa/initiate
// Body: { packageId, phone }
// Auth: requireAuth middleware must be applied on the route
// ─────────────────────────────────────────────────────────────────────────────
exports.initiate = async (req, res) => {
  try {
    const userId    = req.user?.id;       // set by your auth middleware
    const { packageId, phone } = req.body;

    // ── 1. Input validation ────────────────────────────────────────────────
    if (!userId) return res.status(401).json({ success: false, message: 'Unauthorised' });

    if (!packageId || !phone) {
      return res.status(400).json({ success: false, message: 'packageId and phone are required' });
    }

    if (!mongoose.Types.ObjectId.isValid(packageId)) {
      return res.status(400).json({ success: false, message: 'Invalid packageId' });
    }

    if (!MPESA_PHONE_RE.test(phone)) {
      return res.status(400).json({ success: false, message: 'Invalid phone number' });
    }

    // ── 2. Fetch package from DB (never trust FE price) ───────────────────
    const pkg = await Package.findOne({ _id: packageId, is_active: true }).lean();
    if (!pkg) {
      return res.status(404).json({ success: false, message: 'Package not found or inactive' });
    }

    const priceKes = Math.ceil((pkg.price_per_person ?? pkg.price ?? 0) * KES_RATE);
    if (priceKes <= 0) {
      return res.status(400).json({ success: false, message: 'Package has no valid price' });
    }

    // ── 3. Idempotency — prevent double-charge on rapid retry ─────────────
    const existing = await Payment.findOne({
      userId,
      packageId,
      status:    'PENDING',
      createdAt: { $gte: new Date(Date.now() - 5 * 60_000) }, // within last 5 min
    });
    if (existing) {
      // Return the existing checkout so FE can resume polling
      return res.json({
        success:           true,
        checkoutRequestId: existing.checkoutRequestId,
        resumed:           true,
      });
    }

    // ── 4. Trigger STK push ───────────────────────────────────────────────
    const darajaRes = await stkPush({
      phone,
      amount:      priceKes,
      accountRef:  `PKG-${packageId.slice(-6).toUpperCase()}`,
      description: 'Umrah Package',
    });

    // ── 5. Persist pending payment record ─────────────────────────────────
    await Payment.create({
      userId,
      packageId,
      phone,                               // stored masked at rest if your model does that
      amountKes:         priceKes,
      merchantRequestId: darajaRes.MerchantRequestID,
      checkoutRequestId: darajaRes.CheckoutRequestID,
      status:            'PENDING',
    });

    console.info(`[M-Pesa] STK sent to ${maskPhone(phone)} for pkg ${packageId}`);

    return res.json({
      success:           true,
      checkoutRequestId: darajaRes.CheckoutRequestID,
      message:           darajaRes.CustomerMessage,
    });

  } catch (err) {
    console.error('[M-Pesa initiate]', err.message);
    return res.status(502).json({
      success: false,
      message: 'Payment initiation failed. Please try again.',
    });
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/payments/mpesa/callback
// Called by Safaricom — NO user auth, but we verify the source IP.
// This route MUST be public (no JWT middleware).
// ─────────────────────────────────────────────────────────────────────────────
exports.callback = async (req, res) => {
  // ── 1. IP whitelist check ─────────────────────────────────────────────────
  const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '')
    .split(',')[0]
    .trim();

  if (!SAFARICOM_IPS.has(ip)) {
    console.warn(`[M-Pesa callback] Blocked request from unknown IP: ${ip}`);
    // Respond 200 so Safaricom stops retrying, but do nothing
    return res.json({ ResultCode: 0, ResultDesc: 'Accepted' });
  }

  // ── 2. Parse Daraja callback body ─────────────────────────────────────────
  try {
    const body = req.body?.Body?.stkCallback;
    if (!body) {
      console.error('[M-Pesa callback] Malformed body', JSON.stringify(req.body));
      return res.json({ ResultCode: 0, ResultDesc: 'Accepted' });
    }

    const {
      MerchantRequestID,
      CheckoutRequestID,
      ResultCode,
      ResultDesc,
      CallbackMetadata,
    } = body;

    // ── 3. Find the payment record ─────────────────────────────────────────
    const payment = await Payment.findOne({
      $or: [
        { merchantRequestId: MerchantRequestID },
        { checkoutRequestId: CheckoutRequestID },
      ],
    });

    if (!payment) {
      console.warn(`[M-Pesa callback] Unknown payment ${CheckoutRequestID}`);
      return res.json({ ResultCode: 0, ResultDesc: 'Accepted' });
    }

    // Prevent reprocessing already-settled payments
    if (payment.status !== 'PENDING') {
      return res.json({ ResultCode: 0, ResultDesc: 'Accepted' });
    }

    // ── 4. Handle failure ─────────────────────────────────────────────────
    if (ResultCode !== 0) {
      await Payment.findByIdAndUpdate(payment._id, {
        status:     'FAILED',
        resultCode: ResultCode,
        resultDesc: ResultDesc,
      });
      console.info(`[M-Pesa callback] Payment FAILED for ${payment.checkoutRequestId}: ${ResultDesc}`);
      return res.json({ ResultCode: 0, ResultDesc: 'Accepted' });
    }

    // ── 5. Extract metadata from successful callback ───────────────────────
    const meta   = {};
    (CallbackMetadata?.Item || []).forEach(item => {
      meta[item.Name] = item.Value;
    });

    const mpesaRef   = meta.MpesaReceiptNumber || '';
    const paidAmount = Number(meta.Amount)     || payment.amountKes;
    const paidPhone  = String(meta.PhoneNumber || payment.phone);

    // ── 6. Validate paid amount matches expected ───────────────────────────
    if (Math.abs(paidAmount - payment.amountKes) > 1) {  // allow 1 KES rounding
      console.error(
        `[M-Pesa callback] Amount mismatch! Expected ${payment.amountKes}, got ${paidAmount} (ref ${mpesaRef})`
      );
      await Payment.findByIdAndUpdate(payment._id, {
        status:     'FAILED',
        resultDesc: 'Amount mismatch',
      });
      return res.json({ ResultCode: 0, ResultDesc: 'Accepted' });
    }

    // ── 7. Use a MongoDB session for atomic booking + payment update ───────
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      // Mark payment as successful
      await Payment.findByIdAndUpdate(
        payment._id,
        {
          status:    'SUCCESS',
          mpesaRef,
          paidAt:    new Date(),
        },
        { session }
      );

      // Create booking
      const [booking] = await Booking.create(
        [{
          userId:       payment.userId,
          packageId:    payment.packageId,
          paymentId:    payment._id,
          mpesaRef,
          amountPaid:   paidAmount,
          currency:     'KES',
          phone:        paidPhone,
          status:       'confirmed',
          bookedAt:     new Date(),
        }],
        { session }
      );

      await session.commitTransaction();
      console.info(`[M-Pesa callback] Booking created ${booking._id} for payment ${mpesaRef}`);

    } catch (dbErr) {
      await session.abortTransaction();
      console.error('[M-Pesa callback] DB transaction failed:', dbErr.message);
      // Don't update payment status — let it stay PENDING so admin can reconcile
    } finally {
      session.endSession();
    }

    return res.json({ ResultCode: 0, ResultDesc: 'Accepted' });

  } catch (err) {
    console.error('[M-Pesa callback] Unexpected error:', err.message);
    return res.json({ ResultCode: 0, ResultDesc: 'Accepted' });  // always 200 to Safaricom
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/payments/mpesa/status/:checkoutRequestId
// Auth: requireAuth middleware must be applied on the route
// ─────────────────────────────────────────────────────────────────────────────
exports.getStatus = async (req, res) => {
  try {
    const userId            = req.user?.id;
    const { checkoutRequestId } = req.params;

    if (!userId) return res.status(401).json({ success: false, message: 'Unauthorised' });

    // Basic format check to prevent probing other users' transactions
    if (!checkoutRequestId || !/^ws_CO_[\w]{1,30}$/.test(checkoutRequestId)) {
      return res.status(400).json({ success: false, message: 'Invalid checkoutRequestId' });
    }

    // ── 1. Find payment — user can only query their OWN payment ───────────
    const payment = await Payment.findOne({
      checkoutRequestId,
      userId,  // scoped to the requesting user
    }).lean();

    if (!payment) {
      return res.status(404).json({ success: false, message: 'Payment not found' });
    }

    // ── 2. Already settled? Return immediately ────────────────────────────
    if (payment.status === 'SUCCESS') {
      const booking = await Booking.findOne({ paymentId: payment._id })
        .select('_id packageId status bookedAt mpesaRef amountPaid')
        .populate('packageId', 'name price_per_person image_urls')
        .lean();

      return res.json({ success: true, status: 'SUCCESS', booking });
    }

    if (payment.status === 'FAILED') {
      return res.json({
        success:    true,
        status:     'FAILED',
        resultDesc: payment.resultDesc || 'Payment was not completed',
      });
    }

    // ── 3. Still PENDING — query Daraja for latest status ─────────────────
    try {
      const darajaRes = await stkQuery(checkoutRequestId);

      if (darajaRes.ResultCode === '0' || darajaRes.ResultCode === 0) {
        // Paid but callback hasn't arrived yet (rare) — treat as success
        return res.json({ success: true, status: 'SUCCESS', booking: null });
      }

      if (darajaRes.ResultCode && darajaRes.ResultCode !== '1032') {
        // 1032 = request still being processed (pending)
        return res.json({
          success:    true,
          status:     'FAILED',
          resultDesc: darajaRes.ResultDesc || 'Payment failed',
        });
      }
    } catch {
      // Daraja query failed — just return PENDING, FE will retry
    }

    return res.json({ success: true, status: 'PENDING' });

  } catch (err) {
    console.error('[M-Pesa status]', err.message);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
};
