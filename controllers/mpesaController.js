// controllers/mpesaController.js
import mongoose from 'mongoose';
import { stkPush, stkQuery } from '../services/Mpesaservice.js';
import Package from '../models/Package.js';
import Booking from '../models/Booking.js';
import Payment from '../models/Payment.js';

const SAFARICOM_IPS = new Set([
  '196.201.214.200', '196.201.214.206', '196.201.213.114',
  '196.201.214.207', '196.201.214.208', '196.201.213.44',
  '196.201.212.127', '196.201.212.138', '196.201.212.129',
  '196.201.212.136', '196.201.212.74',  '196.201.212.69',
]);

const KES_RATE      = Number(process.env.KES_PER_USD) || 130;
const MPESA_PHONE_RE = /^254[17]\d{8}$/;

function maskPhone(p) {
  return p ? `${p.slice(0, 6)}****${p.slice(-2)}` : '?';
}

// ── POST /api/payments/mpesa/initiate ─────────────────────────────────────────
export const initiate = async (req, res) => {
  try {
    const userId = req.user?.id;
    const { packageId, phone } = req.body;

    if (!userId) return res.status(401).json({ success: false, message: 'Unauthorised' });

    if (!packageId || !phone)
      return res.status(400).json({ success: false, message: 'packageId and phone are required' });

    if (!mongoose.Types.ObjectId.isValid(packageId))
      return res.status(400).json({ success: false, message: 'Invalid packageId' });

    if (!MPESA_PHONE_RE.test(phone))
      return res.status(400).json({ success: false, message: 'Invalid Safaricom number' });

    const pkg = await Package.findOne({ _id: packageId, is_active: true }).lean();
    if (!pkg) return res.status(404).json({ success: false, message: 'Package not found or inactive' });

    const priceKes = Math.ceil((pkg.price_per_person ?? pkg.price ?? 0) * KES_RATE);
    if (priceKes <= 0)
      return res.status(400).json({ success: false, message: 'Package has no valid price' });

    // Idempotency — resume existing pending payment within last 5 min
    const existing = await Payment.findOne({
      userId, packageId, status: 'PENDING',
      createdAt: { $gte: new Date(Date.now() - 5 * 60_000) },
    });
    if (existing) {
      return res.json({ success: true, checkoutRequestId: existing.checkoutRequestId, resumed: true });
    }

    const darajaRes = await stkPush({
      phone,
      amount:      priceKes,
      accountRef:  `PKG-${packageId.slice(-6).toUpperCase()}`,
      description: 'Umrah Package',
    });

    await Payment.create({
      userId,
      packageId,
      phone,
      amountKes:         priceKes,
      method:            'MPESA',
      merchantRequestId: darajaRes.merchantRequestId,
      checkoutRequestId: darajaRes.checkoutRequestId,
      status:            'PENDING',
    });

    console.info(`[M-Pesa] STK sent to ${maskPhone(phone)} for pkg ${packageId}`);

    return res.json({
      success:           true,
      checkoutRequestId: darajaRes.checkoutRequestId,
    });

  } catch (err) {
    console.error('[M-Pesa initiate]', err.message);
    return res.status(502).json({ success: false, message: 'Payment initiation failed. Please try again.' });
  }
};

// ── POST /api/payments/mpesa/callback ─────────────────────────────────────────
export const callback = async (req, res) => {
  const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '')
    .split(',')[0].trim();

  if (!SAFARICOM_IPS.has(ip)) {
    console.warn(`[M-Pesa callback] Blocked IP: ${ip}`);
    return res.json({ ResultCode: 0, ResultDesc: 'Accepted' });
  }

  try {
    const body = req.body?.Body?.stkCallback;
    if (!body) return res.json({ ResultCode: 0, ResultDesc: 'Accepted' });

    const { MerchantRequestID, CheckoutRequestID, ResultCode, ResultDesc, CallbackMetadata } = body;

    const payment = await Payment.findOne({
      $or: [{ merchantRequestId: MerchantRequestID }, { checkoutRequestId: CheckoutRequestID }],
    });

    if (!payment || payment.status !== 'PENDING')
      return res.json({ ResultCode: 0, ResultDesc: 'Accepted' });

    if (ResultCode !== 0) {
      await Payment.findByIdAndUpdate(payment._id, {
        status: 'FAILED', resultCode: String(ResultCode), resultDesc: ResultDesc,
      });
      return res.json({ ResultCode: 0, ResultDesc: 'Accepted' });
    }

    const meta   = {};
    (CallbackMetadata?.Item || []).forEach(i => { meta[i.Name] = i.Value; });

    const mpesaRef   = meta.MpesaReceiptNumber || '';
    const paidAmount = Number(meta.Amount) || payment.amountKes;

    // Amount validation — prevent partial-payment attacks
    if (Math.abs(paidAmount - payment.amountKes) > 1) {
      console.error(`[M-Pesa callback] Amount mismatch! Expected ${payment.amountKes}, got ${paidAmount}`);
      await Payment.findByIdAndUpdate(payment._id, { status: 'FAILED', resultDesc: 'Amount mismatch' });
      return res.json({ ResultCode: 0, ResultDesc: 'Accepted' });
    }

    // Atomic: update payment + create booking
    const session = await mongoose.startSession();
    session.startTransaction();
    try {
      await Payment.findByIdAndUpdate(
        payment._id,
        { status: 'SUCCESS', mpesaRef, paidAt: new Date(), resultCode: '0', resultDesc: ResultDesc },
        { session }
      );

      const [booking] = await Booking.create(
        [{
          userId:        payment.userId,
          packageId:     payment.packageId,
          paymentId:     payment._id,
          paymentMethod: 'MPESA',
          mpesaRef,
          amountPaid:    paidAmount,
          currency:      'KES',
          status:        'confirmed',
          confirmedAt:   new Date(),
        }],
        { session }
      );

      await session.commitTransaction();
      console.info(`[M-Pesa callback] Booking ${booking._id} created — ref ${mpesaRef}`);
    } catch (dbErr) {
      await session.abortTransaction();
      console.error('[M-Pesa callback] Transaction failed:', dbErr.message);
    } finally {
      session.endSession();
    }

    return res.json({ ResultCode: 0, ResultDesc: 'Accepted' });

  } catch (err) {
    console.error('[M-Pesa callback]', err.message);
    return res.json({ ResultCode: 0, ResultDesc: 'Accepted' });
  }
};

// ── GET /api/payments/mpesa/status/:checkoutRequestId ────────────────────────
export const getStatus = async (req, res) => {
  try {
    const userId             = req.user?.id;
    const { checkoutRequestId } = req.params;

    if (!userId) return res.status(401).json({ success: false, message: 'Unauthorised' });

    if (!checkoutRequestId || !/^ws_CO_[\w]{1,30}$/.test(checkoutRequestId))
      return res.status(400).json({ success: false, message: 'Invalid checkoutRequestId' });

    const payment = await Payment.findOne({ checkoutRequestId, userId }).lean();
    if (!payment) return res.status(404).json({ success: false, message: 'Payment not found' });

    if (payment.status === 'SUCCESS') {
      const booking = await Booking.findOne({ paymentId: payment._id })
        .select('_id packageId status confirmedAt amountPaid')
        .populate('packageId', 'name price_per_person image_urls')
        .lean();
      return res.json({ success: true, status: 'SUCCESS', booking });
    }

    if (payment.status === 'FAILED') {
      return res.json({ success: true, status: 'FAILED', resultDesc: 'Payment was not completed' });
    }

    // Still PENDING — query Daraja as fallback
    try {
      const darajaRes = await stkQuery(checkoutRequestId);
      if (darajaRes.resultCode === '0' || darajaRes.resultCode === 0) {
        return res.json({ success: true, status: 'SUCCESS', booking: null });
      }
      if (darajaRes.resultCode && darajaRes.resultCode !== '1032') {
        return res.json({ success: true, status: 'FAILED' });
      }
    } catch { /* keep returning PENDING on Daraja query failure */ }

    return res.json({ success: true, status: 'PENDING' });

  } catch (err) {
    console.error('[M-Pesa status]', err.message);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
};