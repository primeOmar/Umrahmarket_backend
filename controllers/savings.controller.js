// controllers/savings.controller.js
// Lipa Mdogo Mdogo — pay-little-by-little Umrah savings.
//
// Money flow
//   deposit:   create PENDING ledger row → STK push / Pesapal order →
//              callback | IPN | status poll | reconcile job → savings_credit_deposit()
//              (credits exactly once) → receipt email + WhatsApp + in-app.
//   redeem:    price computed server-side from the package row →
//              savings_redeem() debits + creates payments/bookings atomically →
//              passport copied to passport_verifications → booking message +
//              booking receipt + savings notifications.
//   surplus:   savings_request_surplus() sets money aside → superadmin resolves.

import axios from 'axios';
import { supabaseAdmin } from '../config/supabase.js';
import logger from '../config/logger.js';
import { stkPush, stkQuery } from '../services/Mpesaservice.js';
import { getPesapalToken, getIpnId, queryTransaction } from './Cardcontroller.js';
import { createBookingMessage } from './messagesController.js';
import { sendBookingReceiptEmail } from '../services/bookingReceipt.service.js';
import { computeBookingAmount, deriveClientCountry } from '../services/pricing.service.js';
import { usdToKes } from '../services/currency.service.js';
import { isPackageExpired } from '../utils/packageExpiry.js';
import { extractPassport, compareWithInput } from '../lib/passportOcr.js';
import { uploadPassportBuffer } from '../middleware/uploads/PassportUpload.js';
import {
  SAVINGS,
  FRONTEND_URL,
  EXTRA_SERVICES,
  getSavingsQuote,
  computeProgress,
  ensureSavingsAccount,
  getPassportOnFile,
  passportStatusView,
  notifyDepositCredited,
  notifyRedemption,
  notifySurplusRequested,
  renderDepositReceiptPdf,
  loadProfile,
  parseDateOnly,
  addMonthsUTC,
} from '../services/savings.service.js';

const MPESA_PHONE_RE = /^254[17]\d{8}$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const BOOKABLE_STATUSES = new Set(['active', 'published', 'approved', 'available']);
const MAX_PASSPORT_ATTEMPTS = 3;
const MIN_OCR_CONFIDENCE = 45;

const PESAPAL_IS_SANDBOX = (process.env.PESAPAL_ENV || 'sandbox') !== 'production';
const PESAPAL_BASE_URL = PESAPAL_IS_SANDBOX
  ? 'https://cybqa.pesapal.com/pesapalv3'
  : 'https://pay.pesapal.com/v3';

const TX_PUBLIC_FIELDS = 'id, type, direction, method, status, amount_kes, balance_after_kes, receipt_no, mpesa_ref, package_id, booking_id, result_desc, created_at, paid_at';

// ── Helpers ──────────────────────────────────────────────────────────────────
export function normaliseKenyanPhone(raw) {
  if (!raw) return null;
  const d = String(raw).replace(/\D/g, '');
  if (d.startsWith('254') && d.length === 12) return d;
  if (d.startsWith('0') && d.length === 10) return `254${d.slice(1)}`;
  if ((d.startsWith('7') || d.startsWith('1')) && d.length === 9) return `254${d}`;
  return null;
}

function parseAmount(raw) {
  const n = Number(raw);
  if (!Number.isFinite(n)) return null;
  return Math.round(n); // whole shillings only — M-Pesa doesn't take cents
}

function savingsMpesaCallbackUrl() {
  if (process.env.SAVINGS_MPESA_CALLBACK_URL) return process.env.SAVINGS_MPESA_CALLBACK_URL;
  const base = process.env.MPESA_CALLBACK_URL || '';
  if (base.includes('/api/payments/mpesa/callback')) {
    return base.replace('/api/payments/mpesa/callback', '/api/savings/mpesa/callback');
  }
  if (process.env.BACKEND_PUBLIC_URL) {
    return `${process.env.BACKEND_PUBLIC_URL.replace(/\/$/, '')}/api/savings/mpesa/callback`;
  }
  return null;
}

function savingsPesapalCallbackUrl() {
  return process.env.SAVINGS_PESAPAL_CALLBACK_URL || `${FRONTEND_URL}/lipa-mdogo-mdogo/callback`;
}

function rpcErrorCode(err) {
  const m = String(err?.message || '').match(/SAVINGS_[A-Z_]+/);
  return m ? m[0] : null;
}

const fail = (res, status, message, extra = {}) => res.status(status).json({ success: false, message, ...extra });

// ── Credit + notify (single entry point for every settlement path) ──────────
async function creditDeposit(txId, { mpesaRef = null, resultCode = null, resultDesc = null } = {}) {
  const { data, error } = await supabaseAdmin.rpc('savings_credit_deposit', {
    p_tx_id: txId,
    p_mpesa_ref: mpesaRef,
    p_result_code: resultCode,
    p_result_desc: resultDesc,
  });
  if (error) throw new Error(`savings_credit_deposit failed: ${error.message}`);

  // Notify in the background — callers (Safaricom/Pesapal webhooks, polling
  // clients) shouldn't wait on PDF rendering, SMTP and Twilio.
  notifyDepositCredited(txId).catch((err) =>
    logger.error('[savings] notifyDepositCredited failed', { txId, error: err.message })
  );
  return data;
}

async function markTx(txId, fields, { onlyIfPending = true } = {}) {
  let q = supabaseAdmin
    .from('savings_transactions')
    .update({ ...fields, updated_at: new Date().toISOString() })
    .eq('id', txId);
  if (onlyIfPending) q = q.eq('status', 'PENDING');
  const { error } = await q;
  if (error) logger.error('[savings] tx update failed', { txId, error: error.message });
}

/** Ask Safaricom about a pending STK push and settle it if it has finished. */
export async function settleMpesaTx(tx) {
  if (tx.status !== 'PENDING' || !tx.checkout_request_id) return tx.status;
  let q;
  try {
    q = await stkQuery(tx.checkout_request_id);
  } catch (err) {
    // Daraja answers "The transaction is being processed" with an HTTP error
    // while the customer is still on the PIN prompt — that's not a failure.
    logger.info('[savings] stkQuery not final yet', { txId: tx.id, error: err.message });
    return 'PENDING';
  }
  const rc = String(q.ResultCode ?? q.resultCode ?? '');
  const desc = q.ResultDesc ?? q.resultDesc ?? null;
  if (rc === '0') {
    await creditDeposit(tx.id, { resultCode: '0', resultDesc: desc || 'Confirmed via STK query' });
    return 'SUCCESS';
  }
  if (rc === '') return 'PENDING';
  const status = rc === '1032' ? 'CANCELLED' : 'FAILED';
  await markTx(tx.id, { status, result_code: rc, result_desc: desc });
  return status;
}

/** Ask Pesapal about a card deposit and settle it if it has finished. */
export async function settleCardTx(tx) {
  if (tx.status === 'SUCCESS' || !tx.pesapal_order_tracking_id) return tx.status;
  const token = await getPesapalToken();
  const st = await queryTransaction(tx.pesapal_order_tracking_id, token);
  const desc = String(st?.payment_status_description || '').toUpperCase();

  if (desc === 'COMPLETED') {
    if (st.currency && st.currency !== 'KES') {
      await markTx(tx.id, { status: 'FAILED', result_desc: `Currency mismatch: ${st.currency}` }, { onlyIfPending: false });
      logger.error('[savings] card currency mismatch', { txId: tx.id, currency: st.currency });
      return 'FAILED';
    }
    const paid = Number(st.amount);
    if (Number.isFinite(paid) && Math.abs(paid - Number(tx.amount_kes)) > 1) {
      await markTx(tx.id, { status: 'FAILED', result_desc: `Amount mismatch: paid ${paid}`, metadata: { ...(tx.metadata || {}), paid_amount: paid } }, { onlyIfPending: false });
      logger.error('[savings] card amount mismatch — needs manual review', { txId: tx.id, expected: tx.amount_kes, paid });
      return 'FAILED';
    }
    await creditDeposit(tx.id, {
      mpesaRef: st.confirmation_code || null,
      resultCode: st.confirmation_code || '0',
      resultDesc: 'Pesapal: COMPLETED',
    });
    return 'SUCCESS';
  }

  if (tx.status !== 'PENDING') return tx.status;

  if (desc === 'FAILED' || desc === 'REVERSED') {
    await markTx(tx.id, { status: 'FAILED', result_desc: `Pesapal: ${desc}` });
    return 'FAILED';
  }
  // INVALID/empty is what Pesapal reports while the order is still unpaid.
  // Only give up after 30 minutes; a late IPN can still credit it afterwards.
  const ageMin = (Date.now() - new Date(tx.created_at).getTime()) / 60_000;
  if (desc === 'INVALID' && ageMin > 30) {
    await markTx(tx.id, { status: 'CANCELLED', result_desc: 'Pesapal: not completed' });
    return 'CANCELLED';
  }
  return 'PENDING';
}

// ── GET /api/savings/summary ─────────────────────────────────────────────────
export const getSummary = async (req, res) => {
  try {
    const userId = req.user.id;
    const [account, quote, passport] = await Promise.all([
      ensureSavingsAccount(userId),
      getSavingsQuote(),
      getPassportOnFile(userId),
    ]);

    const [{ data: txs }, { count: unread }, { data: pendingSurplus }, { data: savingsBookings }] = await Promise.all([
      supabaseAdmin.from('savings_transactions').select(TX_PUBLIC_FIELDS).eq('user_id', userId)
        .order('created_at', { ascending: false }).limit(15),
      supabaseAdmin.from('user_notifications').select('id', { count: 'exact', head: true })
        .eq('user_id', userId).is('read_at', null),
      supabaseAdmin.from('savings_surplus_requests').select('id, type, amount_kes, services, status, created_at')
        .eq('user_id', userId).eq('status', 'PENDING').limit(1),
      supabaseAdmin.from('bookings').select('id, package_id, amount_paid, confirmed_at, package:package_id(id, name, agent_name)')
        .eq('user_id', userId).eq('payment_method', 'SAVINGS').eq('status', 'confirmed')
        .order('confirmed_at', { ascending: false }).limit(5),
    ]);

    let goalPackage = null;
    if (account.goal_package_id) {
      const { data } = await supabaseAdmin.from('packages').select('id, name, agent_name').eq('id', account.goal_package_id).maybeSingle();
      goalPackage = data || null;
    }

    const goalKes = Number(account.goal_kes) || quote.targetMinKes;
    const balance = Number(account.balance_kes) || 0;

    return res.json({
      success: true,
      data: {
        account: {
          balanceKes: balance,
          totalDepositedKes: Number(account.total_deposited_kes) || 0,
          totalRedeemedKes: Number(account.total_redeemed_kes) || 0,
          totalWithdrawnKes: Number(account.total_withdrawn_kes) || 0,
          depositCount: account.deposit_count || 0,
          lastDepositAt: account.last_deposit_at,
          goalKes,
          customGoal: !!account.goal_kes,
          goalPackage,
          status: account.status,
        },
        progress: computeProgress(balance, goalKes),
        quote: {
          sellRate: Math.round(quote.sellRate * 100) / 100,
          targetMinUsd: quote.targetMinUsd,
          targetMaxUsd: quote.targetMaxUsd,
          targetMinKes: quote.targetMinKes,
          targetMaxKes: quote.targetMaxKes,
        },
        limits: {
          minDepositKes: SAVINGS.MIN_DEPOSIT_KES,
          maxMpesaDepositKes: SAVINGS.MAX_MPESA_DEPOSIT_KES,
          maxCardDepositKes: SAVINGS.MAX_CARD_DEPOSIT_KES,
        },
        passport: passportStatusView(passport),
        transactions: txs || [],
        unreadNotifications: unread || 0,
        pendingSurplusRequest: pendingSurplus?.[0] || null,
        savingsBookings: savingsBookings || [],
        registeredPhone: req.user.phone || null,
        extraServices: EXTRA_SERVICES,
      },
    });
  } catch (err) {
    logger.error('[savings] getSummary failed', { error: err.message });
    return fail(res, 500, 'Could not load your savings. Please try again.');
  }
};

// ── GET /api/savings/transactions ────────────────────────────────────────────
export const listTransactions = async (req, res) => {
  try {
    const limit = Math.min(100, Math.max(1, Number.parseInt(req.query.limit, 10) || 25));
    const offset = Math.max(0, Number.parseInt(req.query.offset, 10) || 0);
    const { data, error, count } = await supabaseAdmin
      .from('savings_transactions')
      .select(TX_PUBLIC_FIELDS, { count: 'exact' })
      .eq('user_id', req.user.id)
      .order('created_at', { ascending: false })
      .range(offset, offset + limit - 1);
    if (error) throw error;
    return res.json({ success: true, data: data || [], total: count || 0 });
  } catch (err) {
    logger.error('[savings] listTransactions failed', { error: err.message });
    return fail(res, 500, 'Could not load your transactions.');
  }
};

// ── PUT /api/savings/goal ────────────────────────────────────────────────────
export const updateGoal = async (req, res) => {
  try {
    const userId = req.user.id;
    const { goalKes, goalPackageId } = req.body || {};
    const update = { updated_at: new Date().toISOString() };

    if (goalPackageId) {
      if (!UUID_RE.test(goalPackageId)) return fail(res, 400, 'Invalid package.');
      const priced = await pricePackageForUser(goalPackageId, req.user.phone);
      if (priced.error) return fail(res, priced.status, priced.error);
      update.goal_package_id = goalPackageId;
      update.goal_kes = priced.amountKes;
    } else if (goalKes === null || goalKes === '' || goalKes === undefined) {
      update.goal_package_id = null;
      update.goal_kes = null; // back to the default (low end of a typical package)
    } else {
      const g = parseAmount(goalKes);
      if (!g || g < 1000 || g > 10_000_000) return fail(res, 400, 'Goal must be between KES 1,000 and KES 10,000,000.');
      update.goal_kes = g;
      update.goal_package_id = null;
    }

    await ensureSavingsAccount(userId);
    // A new, higher goal should be celebrated again when it's reached.
    update.goal_reached_notified_at = null;
    const { error } = await supabaseAdmin.from('savings_accounts').update(update).eq('user_id', userId);
    if (error) throw error;
    return res.json({ success: true, goalKes: update.goal_kes, goalPackageId: update.goal_package_id ?? null });
  } catch (err) {
    logger.error('[savings] updateGoal failed', { error: err.message });
    return fail(res, 500, 'Could not update your goal.');
  }
};

// ── POST /api/savings/deposits/mpesa ─────────────────────────────────────────
export const depositMpesa = async (req, res) => {
  const userId = req.user.id;
  try {
    const amount = parseAmount(req.body?.amount);
    const phone = normaliseKenyanPhone(req.body?.phone || req.user.phone);

    if (!amount || amount < SAVINGS.MIN_DEPOSIT_KES) {
      return fail(res, 400, `The minimum deposit is KES ${SAVINGS.MIN_DEPOSIT_KES}.`);
    }
    if (amount > SAVINGS.MAX_MPESA_DEPOSIT_KES) {
      return fail(res, 400, `M-Pesa allows at most KES ${SAVINGS.MAX_MPESA_DEPOSIT_KES.toLocaleString()} per transaction.`);
    }
    if (!phone || !MPESA_PHONE_RE.test(phone)) {
      return fail(res, 400, 'Enter a valid Safaricom number, e.g. 0712 345 678.');
    }

    const missing = ['MPESA_CONSUMER_KEY', 'MPESA_CONSUMER_SECRET', 'MPESA_SHORTCODE', 'MPESA_PASSKEY'].filter((k) => !process.env[k]);
    const callbackUrl = savingsMpesaCallbackUrl();
    if (missing.length || !callbackUrl) {
      logger.error('[savings] M-Pesa misconfigured', { missing, hasCallback: !!callbackUrl });
      return fail(res, 500, 'M-Pesa is temporarily unavailable. Please try card or contact support.');
    }

    const account = await ensureSavingsAccount(userId);
    if (account.status !== 'active') return fail(res, 403, 'Your savings account is not active. Please contact support.');

    // Resume an identical prompt sent in the last 60 seconds (double taps).
    const since = new Date(Date.now() - 60_000).toISOString();
    const { data: recent } = await supabaseAdmin
      .from('savings_transactions')
      .select('id, checkout_request_id, receipt_no')
      .eq('user_id', userId).eq('type', 'DEPOSIT').eq('method', 'MPESA').eq('status', 'PENDING')
      .eq('amount_kes', amount).eq('phone', phone)
      .not('checkout_request_id', 'is', null)
      .gte('created_at', since)
      .order('created_at', { ascending: false })
      .limit(1);
    if (recent?.[0]) {
      return res.json({ success: true, resumed: true, transactionId: recent[0].id, receiptNo: recent[0].receipt_no });
    }

    // Record first, then push — the callback can never arrive for a
    // transaction we don't know about.
    const { data: tx, error: insErr } = await supabaseAdmin
      .from('savings_transactions')
      .insert({ user_id: userId, type: 'DEPOSIT', direction: 'CREDIT', method: 'MPESA', status: 'PENDING', amount_kes: amount, phone })
      .select('id, receipt_no')
      .single();
    if (insErr) throw insErr;

    let daraja;
    try {
      daraja = await stkPush({
        phone,
        amount,
        accountRef: `LMM${tx.receipt_no.slice(-8)}`,
        description: 'Umrah savings',
        callbackUrl,
      });
    } catch (err) {
      await markTx(tx.id, { status: 'FAILED', result_desc: String(err.message).slice(0, 500) });
      logger.error('[savings] STK push failed', { txId: tx.id, error: err.message });
      return fail(res, 502, 'We could not send the M-Pesa prompt. Please check the number and try again.');
    }

    await supabaseAdmin.from('savings_transactions').update({
      checkout_request_id: daraja.CheckoutRequestID ?? daraja.checkoutRequestId,
      merchant_request_id: daraja.MerchantRequestID ?? daraja.merchantRequestId ?? null,
      updated_at: new Date().toISOString(),
    }).eq('id', tx.id);

    return res.json({
      success: true,
      transactionId: tx.id,
      receiptNo: tx.receipt_no,
      message: daraja.CustomerMessage || 'Check your phone and enter your M-Pesa PIN.',
    });
  } catch (err) {
    logger.error('[savings] depositMpesa failed', { userId, error: err.message });
    return fail(res, 500, 'Could not start the deposit. Please try again.');
  }
};

// ── POST /api/savings/deposits/card ──────────────────────────────────────────
export const depositCard = async (req, res) => {
  const userId = req.user.id;
  try {
    const amount = parseAmount(req.body?.amount);
    if (!amount || amount < SAVINGS.MIN_DEPOSIT_KES) {
      return fail(res, 400, `The minimum deposit is KES ${SAVINGS.MIN_DEPOSIT_KES}.`);
    }
    if (amount > SAVINGS.MAX_CARD_DEPOSIT_KES) {
      return fail(res, 400, `Card deposits are limited to KES ${SAVINGS.MAX_CARD_DEPOSIT_KES.toLocaleString()} each.`);
    }

    const missing = ['PESAPAL_CONSUMER_KEY', 'PESAPAL_CONSUMER_SECRET', 'PESAPAL_IPN_URL'].filter((k) => !process.env[k]);
    if (missing.length) {
      logger.error('[savings] Pesapal misconfigured', { missing });
      return fail(res, 500, 'Card payments are temporarily unavailable. Please use M-Pesa.');
    }

    const account = await ensureSavingsAccount(userId);
    if (account.status !== 'active') return fail(res, 403, 'Your savings account is not active. Please contact support.');

    let token, ipnId;
    try {
      token = await getPesapalToken();
      ipnId = await getIpnId(token);
    } catch (err) {
      logger.error('[savings] Pesapal auth/IPN failed', { error: err.message });
      return fail(res, 502, 'Card payments are temporarily unavailable. Please try again or use M-Pesa.');
    }

    const merchantRef = `LMM-${userId.slice(-6).toUpperCase()}-${Date.now()}`;
    const { data: tx, error: insErr } = await supabaseAdmin
      .from('savings_transactions')
      .insert({
        user_id: userId, type: 'DEPOSIT', direction: 'CREDIT', method: 'CARD', status: 'PENDING',
        amount_kes: amount, phone: req.user.phone || null, pesapal_merchant_ref: merchantRef,
      })
      .select('id, receipt_no')
      .single();
    if (insErr) throw insErr;

    let order;
    try {
      const { data } = await axios.post(
        `${PESAPAL_BASE_URL}/api/Transactions/SubmitOrderRequest`,
        {
          id: merchantRef,
          currency: 'KES',
          amount,
          description: `Lipa Mdogo Mdogo Umrah savings ${tx.receipt_no}`,
          callback_url: savingsPesapalCallbackUrl(),
          notification_id: ipnId,
          billing_address: {
            email_address: req.user.email || '',
            phone_number: req.user.phone || '',
            first_name: req.user.firstName || 'Pilgrim',
            last_name: req.user.lastName || '',
          },
        },
        { headers: { Authorization: `Bearer ${token}`, Accept: 'application/json', 'Content-Type': 'application/json' }, timeout: 15_000 }
      );
      order = data;
    } catch (err) {
      const detail = err.response?.data ? JSON.stringify(err.response.data) : err.message;
      await markTx(tx.id, { status: 'FAILED', result_desc: detail.slice(0, 500) });
      logger.error('[savings] Pesapal order failed', { txId: tx.id, detail });
      return fail(res, 502, 'Could not start the card payment. Please try again.');
    }

    if (!order?.redirect_url || !order?.order_tracking_id) {
      await markTx(tx.id, { status: 'FAILED', result_desc: 'Invalid Pesapal response' });
      return fail(res, 502, 'Could not start the card payment. Please try again.');
    }

    await supabaseAdmin.from('savings_transactions').update({
      pesapal_order_tracking_id: order.order_tracking_id,
      pesapal_redirect_url: order.redirect_url,
      updated_at: new Date().toISOString(),
    }).eq('id', tx.id);

    return res.json({
      success: true,
      transactionId: tx.id,
      receiptNo: tx.receipt_no,
      redirectUrl: order.redirect_url,
      orderTrackingId: order.order_tracking_id,
    });
  } catch (err) {
    logger.error('[savings] depositCard failed', { userId, error: err.message });
    return fail(res, 500, 'Could not start the deposit. Please try again.');
  }
};

// ── Shared status view after settling ────────────────────────────────────────
async function depositStatusResponse(res, userId, txId) {
  const { data: tx } = await supabaseAdmin
    .from('savings_transactions')
    .select(TX_PUBLIC_FIELDS)
    .eq('id', txId)
    .eq('user_id', userId)
    .maybeSingle();
  const { data: account } = await supabaseAdmin
    .from('savings_accounts')
    .select('balance_kes')
    .eq('user_id', userId)
    .maybeSingle();
  return res.json({ success: true, status: tx?.status || 'PENDING', transaction: tx, balanceKes: Number(account?.balance_kes) || 0 });
}

// ── GET /api/savings/deposits/:id/status ─────────────────────────────────────
export const getDepositStatus = async (req, res) => {
  const userId = req.user.id;
  const { id } = req.params;
  if (!UUID_RE.test(id)) return fail(res, 400, 'Invalid transaction.');
  try {
    const { data: tx } = await supabaseAdmin
      .from('savings_transactions')
      .select('*')
      .eq('id', id)
      .eq('user_id', userId)
      .eq('type', 'DEPOSIT')
      .maybeSingle();
    if (!tx) return fail(res, 404, 'Deposit not found.');

    if (tx.status === 'PENDING') {
      const ageSec = (Date.now() - new Date(tx.created_at).getTime()) / 1000;
      try {
        // Give the M-Pesa callback ~15s to land before asking Daraja directly.
        if (tx.method === 'MPESA' && ageSec > 15) await settleMpesaTx(tx);
        if (tx.method === 'CARD') await settleCardTx(tx);
      } catch (err) {
        logger.warn('[savings] status settle attempt failed', { txId: id, error: err.message });
      }
    }
    return depositStatusResponse(res, userId, id);
  } catch (err) {
    logger.error('[savings] getDepositStatus failed', { error: err.message });
    return fail(res, 500, 'Could not check the deposit status.');
  }
};

// ── POST /api/savings/deposits/card/verify  { orderTrackingId } ──────────────
// Called by the page Pesapal redirects back to.
export const verifyCardDeposit = async (req, res) => {
  const userId = req.user.id;
  const orderTrackingId = String(req.body?.orderTrackingId || '');
  if (!/^[a-zA-Z0-9-]{10,60}$/.test(orderTrackingId)) return fail(res, 400, 'Invalid payment reference.');
  try {
    const { data: tx } = await supabaseAdmin
      .from('savings_transactions')
      .select('*')
      .eq('pesapal_order_tracking_id', orderTrackingId)
      .eq('user_id', userId)
      .maybeSingle();
    if (!tx) return fail(res, 404, 'We could not find this deposit. If you were charged, contact support.');
    try {
      await settleCardTx(tx);
    } catch (err) {
      logger.warn('[savings] card verify settle failed', { txId: tx.id, error: err.message });
    }
    return depositStatusResponse(res, userId, tx.id);
  } catch (err) {
    logger.error('[savings] verifyCardDeposit failed', { error: err.message });
    return fail(res, 500, 'Could not verify the payment.');
  }
};

// ── Pesapal IPN (delegated from Cardcontroller.ipn) ─────────────────────────
export async function handleSavingsPesapalIpn(orderTrackingId) {
  const { data: tx } = await supabaseAdmin
    .from('savings_transactions')
    .select('*')
    .eq('pesapal_order_tracking_id', orderTrackingId)
    .maybeSingle();
  if (!tx) {
    logger.warn('[savings] IPN for unknown order', { orderTrackingId });
    return;
  }
  await settleCardTx(tx);
}

// ── POST /api/savings/mpesa/callback (public — Safaricom) ───────────────────
const SAFARICOM_IPS = new Set([
  '196.201.214.200', '196.201.214.206', '196.201.213.114', '196.201.214.207',
  '196.201.214.208', '196.201.213.44', '196.201.212.127', '196.201.212.138',
  '196.201.212.129', '196.201.212.136', '196.201.212.74', '196.201.212.69',
]);

export const mpesaCallback = async (req, res) => {
  const ack = () => res.json({ ResultCode: 0, ResultDesc: 'Accepted' });
  const ip = (req.headers['x-forwarded-for'] || req.socket?.remoteAddress || '').split(',')[0].trim();
  const isSandbox = (process.env.MPESA_ENV || 'sandbox').toLowerCase() !== 'production';
  if (!isSandbox && !SAFARICOM_IPS.has(ip)) {
    logger.warn('[savings] M-Pesa callback from unexpected IP ignored', { ip });
    return ack();
  }

  try {
    const cb = req.body?.Body?.stkCallback;
    if (!cb?.CheckoutRequestID) return ack();

    const { data: tx } = await supabaseAdmin
      .from('savings_transactions')
      .select('*')
      .eq('checkout_request_id', cb.CheckoutRequestID)
      .maybeSingle();
    if (!tx) {
      logger.warn('[savings] callback for unknown checkout', { checkoutRequestId: cb.CheckoutRequestID });
      return ack();
    }

    const resultCode = Number(cb.ResultCode);
    if (resultCode !== 0) {
      await markTx(tx.id, {
        status: resultCode === 1032 ? 'CANCELLED' : 'FAILED',
        result_code: String(cb.ResultCode),
        result_desc: cb.ResultDesc,
      });
      return ack();
    }

    const meta = {};
    (cb.CallbackMetadata?.Item || []).forEach((i) => { meta[i.Name] = i.Value; });
    const paid = Number(meta.Amount);
    if (Number.isFinite(paid) && Math.abs(paid - Number(tx.amount_kes)) > 1) {
      await markTx(tx.id, {
        status: 'FAILED',
        mpesa_ref: meta.MpesaReceiptNumber || null,
        result_desc: `Amount mismatch: paid ${paid}`,
        metadata: { ...(tx.metadata || {}), paid_amount: paid },
      }, { onlyIfPending: false });
      logger.error('[savings] M-Pesa amount mismatch — needs manual review', { txId: tx.id, expected: tx.amount_kes, paid });
      return ack();
    }

    await creditDeposit(tx.id, {
      mpesaRef: meta.MpesaReceiptNumber ? String(meta.MpesaReceiptNumber) : null,
      resultCode: '0',
      resultDesc: cb.ResultDesc,
    });
    return ack();
  } catch (err) {
    logger.error('[savings] M-Pesa callback failed', { error: err.message });
    return ack();
  }
};

// ── GET /api/savings/transactions/:id/receipt (PDF) ──────────────────────────
export const downloadReceipt = async (req, res) => {
  const userId = req.user.id;
  const { id } = req.params;
  if (!UUID_RE.test(id)) return fail(res, 400, 'Invalid transaction.');
  try {
    const { data: tx } = await supabaseAdmin
      .from('savings_transactions')
      .select('*')
      .eq('id', id)
      .eq('user_id', userId)
      .eq('type', 'DEPOSIT')
      .eq('status', 'SUCCESS')
      .maybeSingle();
    if (!tx) return fail(res, 404, 'Receipt not found.');

    const [profile, account, quote] = await Promise.all([loadProfile(userId), ensureSavingsAccount(userId), getSavingsQuote()]);
    const pdf = await renderDepositReceiptPdf({ tx, profile, goalKes: Number(account.goal_kes) || quote.targetMinKes, quote });
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${tx.receipt_no}.pdf"`);
    res.setHeader('Cache-Control', 'private, no-store');
    return res.send(pdf);
  } catch (err) {
    logger.error('[savings] downloadReceipt failed', { error: err.message });
    return fail(res, 500, 'Could not generate the receipt.');
  }
};

// ── Packages the saver can pick from ─────────────────────────────────────────
const PACKAGE_FIELDS = 'id, name, price, price_tiers, country_pricing, status, created_by, agent_name, available_from, available_to, duration, image_urls, inclusions, exclusions, makkah_hotel_name, madinah_hotel_name, type';

async function pricePackageForUser(packageId, userPhone) {
  const { data: pkg, error } = await supabaseAdmin.from('packages').select(PACKAGE_FIELDS).eq('id', packageId).maybeSingle();
  if (error) return { status: 500, error: 'Could not load the package.' };
  if (!pkg) return { status: 404, error: 'Package not found.' };
  if (!BOOKABLE_STATUSES.has(String(pkg.status || '').toLowerCase())) return { status: 400, error: 'This package is not available for booking.' };
  if (isPackageExpired(pkg)) return { status: 410, error: 'This package is no longer available for booking.' };

  let calc;
  try {
    calc = computeBookingAmount(pkg, { adult: 1 }, deriveClientCountry(userPhone));
  } catch (err) {
    return { status: err.status || 400, error: err.message };
  }
  const quote = await getSavingsQuote();
  return {
    pkg,
    travelers: calc.travelers,
    totalTravelers: calc.totalTravelers,
    amountUsd: calc.totalUSD,
    amountKes: usdToKes(calc.totalUSD, quote.sellRate),
    fxRate: quote.sellRate,
  };
}

const hasMeals = (pkg) => {
  const text = JSON.stringify(pkg.inclusions || '').toLowerCase();
  return /meal|breakfast|lunch|dinner|board|food/.test(text);
};

// GET /api/savings/packages
export const listPackages = async (req, res) => {
  try {
    const userId = req.user.id;
    const [{ data: pkgs, error }, account, quote] = await Promise.all([
      supabaseAdmin.from('packages').select(PACKAGE_FIELDS)
        .or([...BOOKABLE_STATUSES].map((s) => `status.ilike.${s}`).join(','))
        .limit(500),
      ensureSavingsAccount(userId),
      getSavingsQuote(),
    ]);
    if (error) throw error;

    const balance = Number(account.balance_kes) || 0;
    const country = deriveClientCountry(req.user.phone);
    const list = [];
    for (const pkg of pkgs || []) {
      if (isPackageExpired(pkg)) continue;
      let calc;
      try {
        calc = computeBookingAmount(pkg, { adult: 1 }, country);
      } catch {
        continue; // no price for this pilgrim's country
      }
      const amountKes = usdToKes(calc.totalUSD, quote.sellRate);
      list.push({
        id: pkg.id,
        name: pkg.name,
        agentName: pkg.agent_name,
        agentId: pkg.created_by,
        type: pkg.type,
        duration: pkg.duration,
        availableFrom: pkg.available_from,
        image: Array.isArray(pkg.image_urls) ? pkg.image_urls[0] || null : null,
        makkahHotel: pkg.makkah_hotel_name,
        madinahHotel: pkg.madinah_hotel_name,
        includesMeals: hasMeals(pkg),
        priceUsd: calc.totalUSD,
        priceKes: amountKes,
        affordable: balance >= amountKes,
        shortfallKes: Math.max(0, amountKes - balance),
        surplusKes: Math.max(0, balance - amountKes),
      });
    }
    list.sort((a, b) => (b.affordable - a.affordable) || (a.priceKes - b.priceKes));
    return res.json({ success: true, data: list, balanceKes: balance });
  } catch (err) {
    logger.error('[savings] listPackages failed', { error: err.message });
    return fail(res, 500, 'Could not load packages.');
  }
};

// ── POST /api/savings/redeem  { packageId } ──────────────────────────────────
export const redeem = async (req, res) => {
  const userId = req.user.id;
  const { packageId } = req.body || {};
  if (!packageId || !UUID_RE.test(packageId)) return fail(res, 400, 'Choose a valid package.');

  try {
    const priced = await pricePackageForUser(packageId, req.user.phone);
    if (priced.error) return fail(res, priced.status, priced.error);
    const { pkg, amountKes, amountUsd, fxRate, travelers, totalTravelers } = priced;

    // Passport must be on file and valid 6 months beyond travel.
    const passport = await getPassportOnFile(userId);
    if (!passport.onFile) {
      return fail(res, 403, 'Please upload your passport before booking your Umrah.', { code: 'PASSPORT_REQUIRED' });
    }
    const travelDate = parseDateOnly(pkg.available_from) || new Date();
    const minExpiry = addMonthsUTC(travelDate, SAVINGS.MIN_PASSPORT_VALIDITY_MONTHS);
    const expiry = parseDateOnly(passport.record.passport_expiry);
    if (!expiry || expiry < minExpiry) {
      return fail(res, 400, `Your passport must be valid until at least ${minExpiry.toISOString().slice(0, 10)} for this trip. Please renew it and upload the new one.`, { code: 'PASSPORT_VALIDITY' });
    }

    const { data: result, error: rpcErr } = await supabaseAdmin.rpc('savings_redeem', {
      p_user_id: userId,
      p_package_id: packageId,
      p_amount_kes: amountKes,
      p_amount_usd: amountUsd,
      p_fx_rate: fxRate,
      p_travelers: travelers,
      p_traveler_count: totalTravelers,
      p_phone: req.user.phone || null,
    });

    if (rpcErr) {
      const code = rpcErrorCode(rpcErr);
      if (code === 'SAVINGS_INSUFFICIENT') {
        const account = await ensureSavingsAccount(userId);
        const short = Math.max(0, amountKes - Number(account.balance_kes));
        return fail(res, 400, `You need KES ${short.toLocaleString()} more to book this package. Keep saving — you're nearly there!`, { code, shortfallKes: short });
      }
      if (code === 'SAVINGS_ALREADY_BOOKED') return fail(res, 400, 'You have already booked this package.', { code });
      if (code === 'SAVINGS_ACCOUNT_NOT_ACTIVE') return fail(res, 403, 'Your savings account is not active. Please contact support.', { code });
      logger.error('[savings] savings_redeem failed', { userId, packageId, error: rpcErr.message });
      return fail(res, 500, 'Could not complete the booking. Your savings have not been charged.');
    }

    // ── Post-booking side effects (booking is already committed) ──────────
    await copyPassportToBooking({ userId, packageId, bookingId: result.booking_id, passport, travelDate });

    const agentName = pkg.agent_name || 'Travel Agency';
    try {
      await createBookingMessage(result.booking_id, userId, pkg.created_by || null, pkg.name || 'Umrah package', agentName);
    } catch (err) {
      logger.error('[savings] booking message failed', { bookingId: result.booking_id, error: err.message });
    }
    sendBookingReceiptEmail({ paymentId: result.payment_id, bookingId: result.booking_id })
      .catch((err) => logger.error('[savings] booking receipt failed', { bookingId: result.booking_id, error: err.message }));
    notifyRedemption({
      userId,
      packageName: pkg.name || 'Umrah package',
      agentName,
      amountKes,
      balanceAfter: result.balance_after,
      receiptNo: result.receipt_no,
      bookingId: result.booking_id,
    }).catch((err) => logger.error('[savings] notifyRedemption failed', { error: err.message }));

    return res.json({
      success: true,
      booking: {
        id: result.booking_id,
        paymentId: result.payment_id,
        packageId,
        packageName: pkg.name,
        agentName,
        amountKes,
        includesMeals: hasMeals(pkg),
      },
      receiptNo: result.receipt_no,
      balanceKes: Number(result.balance_after) || 0,
      surplusKes: Number(result.balance_after) || 0,
    });
  } catch (err) {
    logger.error('[savings] redeem failed', { userId, packageId, error: err.message });
    return fail(res, 500, 'Could not complete the booking. Please try again.');
  }
};

/** Give the agent the passport on the booking, like a normal checkout does. */
async function copyPassportToBooking({ userId, packageId, bookingId, passport, travelDate }) {
  try {
    const { data: existing } = await supabaseAdmin
      .from('passport_verifications')
      .select('id')
      .eq('user_id', userId).eq('package_id', packageId).eq('traveler_index', 0)
      .limit(1);
    if (existing?.length) {
      await supabaseAdmin.from('passport_verifications').update({ booking_id: bookingId }).eq('id', existing[0].id);
      return;
    }
    const r = passport.record;
    const verified = r.verification_status === 'verified';
    const { error } = await supabaseAdmin.from('passport_verifications').insert({
      user_id: userId,
      package_id: packageId,
      booking_id: bookingId,
      traveler_index: 0,
      passport_number: r.passport_number,
      passport_country: r.passport_country || r.nationality || 'UNK',
      passport_expiry: r.passport_expiry,
      travel_date: travelDate.toISOString().slice(0, 10),
      surname: r.surname || null,
      given_names: r.given_names || null,
      full_name: r.full_name || [r.given_names, r.surname].filter(Boolean).join(' ') || null,
      date_of_birth: r.date_of_birth || null,
      nationality: r.nationality || null,
      passport_image_url: r.image_url || r.passport_image_url || 'pending://no-image',
      image_key: r.image_key || null,
      mrz_raw: r.mrz_raw || null,
      ocr_confidence: r.ocr_confidence ?? null,
      match_score: r.match_score ?? null,
      match_details: r.match_details || null,
      verification_status: r.verification_status,
      verified,
      verified_at: verified ? new Date().toISOString() : null,
      attempts: 1,
      last_attempt_at: new Date().toISOString(),
    });
    if (error) throw error;
  } catch (err) {
    logger.error('[savings] passport copy to booking failed — agent may need to request it', { userId, bookingId, error: err.message });
  }
}

// ── GET /api/savings/passport ────────────────────────────────────────────────
export const getPassport = async (req, res) => {
  try {
    const passport = await getPassportOnFile(req.user.id);
    return res.json({ success: true, data: passportStatusView(passport) });
  } catch (err) {
    logger.error('[savings] getPassport failed', { error: err.message });
    return fail(res, 500, 'Could not load your passport status.');
  }
};

// ── POST /api/savings/passport (multipart: passport + fields) ───────────────
export const uploadPassport = async (req, res) => {
  const userId = req.user.id;
  try {
    const { passportNumber, passportCountry, passportExpiry, surname, givenNames, dateOfBirth, nationality } = req.body;
    if (!req.passportFile?.buffer) return fail(res, 400, 'Passport image is required.');

    const { data: existing } = await supabaseAdmin.from('savings_passports').select('attempts, verification_status, passport_number').eq('user_id', userId).maybeSingle();
    // A new passport number (e.g. renewed passport) starts a fresh attempt count.
    const sameDoc = existing && String(existing.passport_number).toUpperCase() === String(passportNumber).toUpperCase();
    const prevAttempts = sameDoc ? (existing.attempts || 0) : 0;

    const expiry = parseDateOnly(passportExpiry);
    const minExpiry = addMonthsUTC(new Date(), SAVINGS.MIN_PASSPORT_VALIDITY_MONTHS);
    if (!expiry || expiry < minExpiry) {
      return fail(res, 400, 'Your passport must be valid for at least 6 more months. Please renew it before uploading.', { code: 'PASSPORT_VALIDITY' });
    }

    let ocr;
    try {
      ocr = await extractPassport(req.passportFile.buffer);
    } catch (err) {
      logger.error('[savings] OCR threw', { userId, error: err.message });
      ocr = { ok: false, confidence: 0, fields: {}, mrz: null };
    }

    let comparison = { score: 0, matched: false, details: {} };
    if (ocr.ok && ocr.confidence >= MIN_OCR_CONFIDENCE) {
      comparison = compareWithInput(ocr.fields, { passportNumber, expiry, surname, givenNames, nationality });
    }

    let stored = null;
    try {
      stored = await uploadPassportBuffer({
        buffer: req.passportFile.buffer,
        mime: req.passportFile.mime,
        ext: req.passportFile.ext,
        userId,
        packageId: 'savings',
        ip: req.ip,
      });
    } catch (err) {
      logger.error('[savings] passport image upload failed', { userId, error: err.message });
      return fail(res, 502, 'We could not store your passport image. Please try again.');
    }

    const attempts = prevAttempts + 1;
    const autoVerified = ocr.ok && ocr.confidence >= MIN_OCR_CONFIDENCE && comparison.matched;
    let status, message;
    if (autoVerified) {
      status = 'verified';
      message = 'Passport verified. You are ready to book as soon as your savings are complete.';
    } else if (attempts >= MAX_PASSPORT_ATTEMPTS) {
      status = 'manual_review';
      message = 'Thank you. We could not confirm the photo automatically, so our team will check it manually. You can still book when your savings are ready.';
    } else {
      status = 'pending';
      message = !ocr.ok
        ? 'We could not read the passport clearly. Please retake the photo in good light with the whole page flat and visible.'
        : 'The photo did not match the details you typed. Please check the details and try again.';
    }

    const row = {
      user_id: userId,
      passport_number: String(passportNumber).toUpperCase(),
      passport_country: passportCountry || ocr.fields?.issuingCountry || null,
      nationality: ocr.fields?.nationality || nationality || null,
      surname,
      given_names: givenNames || null,
      date_of_birth: dateOfBirth || null,
      passport_expiry: passportExpiry,
      image_key: stored.key,
      image_url: stored.url,
      verification_status: status,
      ocr_confidence: ocr.confidence ?? null,
      match_score: comparison.score ?? null,
      match_details: comparison.details || null,
      mrz_raw: ocr.mrz || null,
      attempts,
      last_attempt_at: new Date().toISOString(),
      verified_at: autoVerified ? new Date().toISOString() : null,
      updated_at: new Date().toISOString(),
    };
    const { error } = await supabaseAdmin.from('savings_passports').upsert(row, { onConflict: 'user_id' });
    if (error) throw error;

    const view = passportStatusView(await getPassportOnFile(userId));
    return res.json({ success: true, status, canProceed: status !== 'pending', message, data: view });
  } catch (err) {
    logger.error('[savings] uploadPassport failed', { userId, error: err.message });
    return fail(res, 500, 'Could not process your passport. Please try again.');
  }
};

// ── POST /api/savings/surplus ────────────────────────────────────────────────
export const requestSurplus = async (req, res) => {
  const userId = req.user.id;
  try {
    const type = String(req.body?.type || '').toUpperCase();
    const amount = parseAmount(req.body?.amount);
    const note = req.body?.note ? String(req.body.note).trim().slice(0, 500) : null;
    const bookingId = req.body?.bookingId || null;

    if (!['REFUND', 'EXTRAS'].includes(type)) return fail(res, 400, 'Choose refund or extra services.');
    if (!amount || amount < 1) return fail(res, 400, 'Enter a valid amount.');

    let services = [];
    let payoutPhone = null;
    let packageId = null;

    if (type === 'REFUND') {
      payoutPhone = normaliseKenyanPhone(req.body?.payoutPhone || req.user.phone);
      if (!payoutPhone || !MPESA_PHONE_RE.test(payoutPhone)) return fail(res, 400, 'Enter a valid M-Pesa number for the refund.');
    } else {
      services = Array.isArray(req.body?.services)
        ? [...new Set(req.body.services.map(String))].filter((s) => EXTRA_SERVICES[s])
        : [];
      if (!services.length) return fail(res, 400, 'Choose at least one extra service.');
      if (!bookingId || !UUID_RE.test(bookingId)) return fail(res, 400, 'Choose the booking these extras are for.');
    }

    if (bookingId) {
      if (!UUID_RE.test(bookingId)) return fail(res, 400, 'Invalid booking.');
      const { data: booking } = await supabaseAdmin
        .from('bookings').select('id, package_id').eq('id', bookingId).eq('user_id', userId).eq('status', 'confirmed').maybeSingle();
      if (!booking) return fail(res, 404, 'Booking not found.');
      packageId = booking.package_id;
    }

    const { data: result, error } = await supabaseAdmin.rpc('savings_request_surplus', {
      p_user_id: userId,
      p_type: type,
      p_amount_kes: amount,
      p_services: services,
      p_note: note,
      p_payout_phone: payoutPhone,
      p_booking_id: bookingId,
      p_package_id: packageId,
    });

    if (error) {
      const code = rpcErrorCode(error);
      if (code === 'SAVINGS_INSUFFICIENT') return fail(res, 400, 'That is more than your available savings balance.', { code });
      if (code === 'SAVINGS_SURPLUS_PENDING') return fail(res, 409, 'You already have a request being processed. Please wait for it to complete.', { code });
      logger.error('[savings] savings_request_surplus failed', { userId, error: error.message });
      return fail(res, 500, 'Could not submit your request.');
    }

    const request = { id: result.request_id, type, amount_kes: amount, services, note, payout_phone: payoutPhone };
    notifySurplusRequested({ userId, request })
      .catch((err) => logger.error('[savings] notifySurplusRequested failed', { error: err.message }));

    return res.json({ success: true, requestId: result.request_id, balanceKes: Number(result.balance_after) || 0 });
  } catch (err) {
    logger.error('[savings] requestSurplus failed', { userId, error: err.message });
    return fail(res, 500, 'Could not submit your request.');
  }
};

// ── Notifications ────────────────────────────────────────────────────────────
export const listNotifications = async (req, res) => {
  try {
    const { data, error } = await supabaseAdmin
      .from('user_notifications')
      .select('id, type, title, body, data, read_at, created_at')
      .eq('user_id', req.user.id)
      .order('created_at', { ascending: false })
      .limit(30);
    if (error) throw error;
    return res.json({ success: true, data: data || [] });
  } catch (err) {
    logger.error('[savings] listNotifications failed', { error: err.message });
    return fail(res, 500, 'Could not load notifications.');
  }
};

export const markNotificationsRead = async (req, res) => {
  try {
    const ids = Array.isArray(req.body?.ids) ? req.body.ids.filter((i) => UUID_RE.test(i)).slice(0, 100) : null;
    let q = supabaseAdmin.from('user_notifications').update({ read_at: new Date().toISOString() })
      .eq('user_id', req.user.id).is('read_at', null);
    if (ids?.length) q = q.in('id', ids);
    const { error } = await q;
    if (error) throw error;
    return res.json({ success: true });
  } catch (err) {
    logger.error('[savings] markNotificationsRead failed', { error: err.message });
    return fail(res, 500, 'Could not update notifications.');
  }
};
