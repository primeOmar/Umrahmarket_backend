// routes/savings.admin.routes.js — Lipa Mdogo Mdogo (superadmin)
// Base: /api/superadmin/savings   (mounted behind authenticateSuperadmin)
import express from 'express';
import { supabaseAdmin } from '../config/supabase.js';
import logger from '../config/logger.js';
import { notifySurplusResolved } from '../services/savings.service.js';

const router = express.Router();
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const sum = (rows, key) => (rows || []).reduce((s, r) => s + (Number(r[key]) || 0), 0);

async function profilesById(ids) {
  const unique = [...new Set(ids.filter(Boolean))];
  if (!unique.length) return new Map();
  const { data } = await supabaseAdmin
    .from('profiles')
    .select('id, first_name, last_name, email, phone')
    .in('id', unique);
  return new Map((data || []).map((p) => [p.id, p]));
}

const person = (p) => p
  ? { name: [p.first_name, p.last_name].filter(Boolean).join(' ') || '—', email: p.email, phone: p.phone }
  : { name: '—', email: null, phone: null };

// GET /overview — headline numbers
router.get('/overview', async (req, res) => {
  try {
    const startOfDay = new Date();
    startOfDay.setHours(0, 0, 0, 0);
    const startOfMonth = new Date(startOfDay.getFullYear(), startOfDay.getMonth(), 1);

    const [accounts, today, month, pending, surplus] = await Promise.all([
      supabaseAdmin.from('savings_accounts').select('balance_kes, total_deposited_kes, total_redeemed_kes, deposit_count'),
      supabaseAdmin.from('savings_transactions').select('amount_kes').eq('type', 'DEPOSIT').eq('status', 'SUCCESS').gte('paid_at', startOfDay.toISOString()),
      supabaseAdmin.from('savings_transactions').select('amount_kes').eq('type', 'DEPOSIT').eq('status', 'SUCCESS').gte('paid_at', startOfMonth.toISOString()),
      supabaseAdmin.from('savings_transactions').select('id', { count: 'exact', head: true }).eq('type', 'DEPOSIT').eq('status', 'PENDING'),
      supabaseAdmin.from('savings_surplus_requests').select('amount_kes').eq('status', 'PENDING'),
    ]);

    const err = [accounts, today, month, pending, surplus].find((r) => r.error);
    if (err) throw err.error;

    const rows = accounts.data || [];
    return res.json({
      success: true,
      data: {
        savers: rows.filter((r) => (r.deposit_count || 0) > 0).length,
        balanceHeldKes: sum(rows, 'balance_kes'),
        totalDepositedKes: sum(rows, 'total_deposited_kes'),
        totalRedeemedKes: sum(rows, 'total_redeemed_kes'),
        depositsTodayKes: sum(today.data, 'amount_kes'),
        depositsTodayCount: (today.data || []).length,
        depositsMonthKes: sum(month.data, 'amount_kes'),
        pendingDeposits: pending.count || 0,
        pendingSurplusCount: (surplus.data || []).length,
        pendingSurplusKes: sum(surplus.data, 'amount_kes'),
      },
    });
  } catch (error) {
    logger.error('[savings-admin] overview failed', { error: error.message });
    return res.status(500).json({ success: false, message: 'Could not load savings overview.' });
  }
});

// GET /savers?limit=&offset=
router.get('/savers', async (req, res) => {
  try {
    const limit = Math.min(200, Math.max(1, Number.parseInt(req.query.limit, 10) || 50));
    const offset = Math.max(0, Number.parseInt(req.query.offset, 10) || 0);
    const { data, error, count } = await supabaseAdmin
      .from('savings_accounts')
      .select('*', { count: 'exact' })
      .gt('deposit_count', 0)
      .order('balance_kes', { ascending: false })
      .range(offset, offset + limit - 1);
    if (error) throw error;

    const [profiles, passports] = await Promise.all([
      profilesById((data || []).map((a) => a.user_id)),
      supabaseAdmin.from('savings_passports').select('user_id, verification_status').in('user_id', (data || []).map((a) => a.user_id)),
    ]);
    const passportBy = new Map((passports.data || []).map((p) => [p.user_id, p.verification_status]));

    return res.json({
      success: true,
      total: count || 0,
      data: (data || []).map((a) => ({
        userId: a.user_id,
        ...person(profiles.get(a.user_id)),
        balanceKes: Number(a.balance_kes) || 0,
        totalDepositedKes: Number(a.total_deposited_kes) || 0,
        totalRedeemedKes: Number(a.total_redeemed_kes) || 0,
        depositCount: a.deposit_count,
        goalKes: a.goal_kes ? Number(a.goal_kes) : null,
        lastDepositAt: a.last_deposit_at,
        passportStatus: passportBy.get(a.user_id) || null,
        status: a.status,
      })),
    });
  } catch (error) {
    logger.error('[savings-admin] savers failed', { error: error.message });
    return res.status(500).json({ success: false, message: 'Could not load savers.' });
  }
});

// GET /transactions?status=&type=&limit=
router.get('/transactions', async (req, res) => {
  try {
    const limit = Math.min(200, Math.max(1, Number.parseInt(req.query.limit, 10) || 50));
    let q = supabaseAdmin
      .from('savings_transactions')
      .select('id, user_id, type, direction, method, status, amount_kes, balance_after_kes, receipt_no, phone, mpesa_ref, result_desc, created_at, paid_at')
      .order('created_at', { ascending: false })
      .limit(limit);
    if (req.query.status) q = q.eq('status', String(req.query.status).toUpperCase());
    if (req.query.type) q = q.eq('type', String(req.query.type).toUpperCase());
    const { data, error } = await q;
    if (error) throw error;
    const profiles = await profilesById((data || []).map((t) => t.user_id));
    return res.json({
      success: true,
      data: (data || []).map((t) => ({ ...t, saver: person(profiles.get(t.user_id)) })),
    });
  } catch (error) {
    logger.error('[savings-admin] transactions failed', { error: error.message });
    return res.status(500).json({ success: false, message: 'Could not load transactions.' });
  }
});

// GET /surplus-requests?status=PENDING
router.get('/surplus-requests', async (req, res) => {
  try {
    const status = String(req.query.status || 'PENDING').toUpperCase();
    let q = supabaseAdmin
      .from('savings_surplus_requests')
      .select('*, package:package_id(id, name, agent_name)')
      .order('created_at', { ascending: false })
      .limit(100);
    if (status !== 'ALL') q = q.eq('status', status);
    const { data, error } = await q;
    if (error) throw error;
    const profiles = await profilesById((data || []).map((r) => r.user_id));
    return res.json({
      success: true,
      data: (data || []).map((r) => ({ ...r, saver: person(profiles.get(r.user_id)) })),
    });
  } catch (error) {
    logger.error('[savings-admin] surplus list failed', { error: error.message });
    return res.status(500).json({ success: false, message: 'Could not load surplus requests.' });
  }
});

// POST /surplus-requests/:id/resolve  { status: COMPLETED|REJECTED, adminNote?, payoutRef? }
router.post('/surplus-requests/:id/resolve', async (req, res) => {
  try {
    const { id } = req.params;
    if (!UUID_RE.test(id)) return res.status(400).json({ success: false, message: 'Invalid request id.' });
    const status = String(req.body?.status || '').toUpperCase();
    if (!['COMPLETED', 'REJECTED'].includes(status)) {
      return res.status(400).json({ success: false, message: 'status must be COMPLETED or REJECTED.' });
    }
    const adminNote = req.body?.adminNote ? String(req.body.adminNote).trim().slice(0, 500) : null;
    const payoutRef = req.body?.payoutRef ? String(req.body.payoutRef).trim().slice(0, 60) : null;
    if (status === 'REJECTED' && !adminNote) {
      return res.status(400).json({ success: false, message: 'Add a note explaining why the request was rejected.' });
    }

    const admin = req.superadmin?.email || req.superadmin?.id || 'superadmin';
    const { data: result, error } = await supabaseAdmin.rpc('savings_resolve_surplus', {
      p_request_id: id,
      p_status: status,
      p_admin_note: adminNote,
      p_payout_ref: payoutRef,
      p_admin: String(admin),
    });
    if (error) {
      if (/SAVINGS_SURPLUS_ALREADY_RESOLVED/.test(error.message)) {
        return res.status(409).json({ success: false, message: 'This request has already been resolved.' });
      }
      if (/SAVINGS_SURPLUS_NOT_FOUND/.test(error.message)) {
        return res.status(404).json({ success: false, message: 'Request not found.' });
      }
      throw error;
    }

    notifySurplusResolved({ userId: result.user_id, result, adminNote })
      .catch((err) => logger.error('[savings-admin] notifySurplusResolved failed', { error: err.message }));

    logger.info('[savings-admin] surplus resolved', { id, status, admin });
    return res.json({ success: true, data: result });
  } catch (error) {
    logger.error('[savings-admin] resolve failed', { error: error.message });
    return res.status(500).json({ success: false, message: 'Could not resolve the request.' });
  }
});

export default router;
