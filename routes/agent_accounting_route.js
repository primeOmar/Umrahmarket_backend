/**
 * Agent Accounting Route
 * Mount under /api/accounting (or add to existing bookings/auth routes)
 * All endpoints are scoped to the authenticated agent's own packages only.
 */
import express from 'express';
import { supabaseAdmin as supabase } from '../config/supabase.js';
import { requireAuth } from '../middleware/auth.middleware.js';

const router = express.Router();
const DEFAULT_PROFIT_PERCENTAGE = Number(process.env.PLATFORM_PROFIT_PERCENTAGE ?? 10);

// ─── GET /api/accounting/summary ─────────────────────────────────────────────
// Returns totals: pending disbursement + paid/disbursed for this agent
router.get('/summary', requireAuth, async (req, res) => {
  try {
    const agentId = req.userId;

    const { data: payments, error } = await supabase
      .from('payments')
      .select(`
        id, amount_kes, disbursed,
        package:packages!inner(profit_percentage, created_by)
      `)
      .eq('status', 'SUCCESS')
      .eq('packages.created_by', agentId);

    if (error) throw error;

    let pendingAmount = 0, disbursedAmount = 0, pendingCount = 0, disbursedCount = 0;

    for (const p of payments ?? []) {
      const amount = Number(p.amount_kes ?? 0);
      const pct = Number(p.package?.profit_percentage ?? DEFAULT_PROFIT_PERCENTAGE);
      const agentShare = amount - (amount * pct) / 100;
      if (p.disbursed) {
        disbursedAmount += agentShare;
        disbursedCount++;
      } else {
        pendingAmount += agentShare;
        pendingCount++;
      }
    }

    return res.json({
      success: true,
      data: { pendingAmount, pendingCount, disbursedAmount, disbursedCount },
    });
  } catch (err) {
    console.error('[agent-accounting] Summary error:', err);
    return res.status(500).json({ success: false, message: 'Failed to fetch summary' });
  }
});

// ─── GET /api/accounting/transactions ────────────────────────────────────────
// Returns per-booking rows for this agent with disbursement status
router.get('/transactions', requireAuth, async (req, res) => {
  try {
    const agentId = req.userId;
    const limit = Math.min(Number(req.query.limit ?? 100), 500);
    const offset = Number(req.query.offset ?? 0);
    const statusFilter = req.query.status ?? 'all'; // 'all' | 'pending' | 'disbursed'

    let query = supabase
      .from('payments')
      .select(`
        id, user_id, amount_kes, status, paid_at, disbursed, disbursed_at, mpesa_ref,
        package:packages!inner(id, name, profit_percentage, created_by)
      `)
      .eq('status', 'SUCCESS')
      .eq('packages.created_by', agentId)
      .order('paid_at', { ascending: false })
      .range(offset, offset + limit - 1);

    if (statusFilter === 'pending') query = query.eq('disbursed', false);
    if (statusFilter === 'disbursed') query = query.eq('disbursed', true);

    const { data: payments, error } = await query;
    if (error) throw error;

    // Fetch client names
    const userIds = [...new Set((payments ?? []).map(p => p.user_id).filter(Boolean))];
    let clientMap = new Map();
    if (userIds.length > 0) {
      const { data: clients } = await supabase
        .from('profiles')
        .select('id, first_name, last_name')
        .in('id', userIds);
      if (clients) clientMap = new Map(clients.map(c => [c.id, c]));
    }

    const results = (payments ?? []).map(p => {
      const amount = Number(p.amount_kes ?? 0);
      const pct = Number(p.package?.profit_percentage ?? DEFAULT_PROFIT_PERCENTAGE);
      const platformFee = Math.round((amount * pct) / 100 * 100) / 100;
      const agentShare = Math.round((amount - platformFee) * 100) / 100;
      const client = clientMap.get(p.user_id);

      return {
        id: p.id,
        packageId: p.package?.id ?? null,
        packageName: p.package?.name ?? '—',
        clientName: client ? `${client.first_name} ${client.last_name}`.trim() : '—',
        amount,
        platformFee,
        agentShare,
        mpesaRef: p.mpesa_ref ?? null,
        paidAt: p.paid_at,
        disbursed: !!p.disbursed,
        disbursedAt: p.disbursed_at ?? null,
      };
    });

    return res.json({ success: true, data: results });
  } catch (err) {
    console.error('[agent-accounting] Transactions error:', err);
    return res.status(500).json({ success: false, message: 'Failed to fetch transactions' });
  }
});

export default router;