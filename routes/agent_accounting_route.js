/**
 * Agent Accounting Route
 * Mount under /api/accounting (or add to existing bookings/auth routes)
 * All endpoints are scoped to the authenticated agent's own packages only.
 */
import express from 'express';
import { supabaseAdmin as supabase } from '../config/supabase.js';
import { requireAuth } from '../middleware/auth.middleware.js';
import { getUsdKesRate, kesToUsd } from '../services/currency.service.js';

const router = express.Router();
const DEFAULT_PROFIT_PERCENTAGE = Number(process.env.PLATFORM_PROFIT_PERCENTAGE ?? 10);

// Older payments recorded before FX tracking was added won't have fx_rate_used.
// Fall back to the current live rate for those so USD figures are never blank.
async function resolveFallbackRate() {
  try {
    return await getUsdKesRate();
  } catch (err) {
    console.warn('[agent-accounting] Fallback FX rate unavailable:', err.message);
    return null;
  }
}

// ─── GET /api/accounting/summary ─────────────────────────────────────────────
// Returns totals: pending disbursement + paid/disbursed for this agent
router.get('/summary', requireAuth, async (req, res) => {
  try {
    const agentId = req.userId;

    const { data: payments, error } = await supabase
      .from('payments')
      .select(`
        id, amount_kes, amount_usd, fx_rate_used, disbursed,
        package:packages!inner(profit_percentage, created_by)
      `)
      .eq('status', 'SUCCESS')
      .eq('packages.created_by', agentId);

    if (error) throw error;

    const needsFallback = (payments ?? []).some(p => !p.fx_rate_used);
    const fallbackRate = needsFallback ? await resolveFallbackRate() : null;

    let pendingAmount = 0, disbursedAmount = 0, pendingCount = 0, disbursedCount = 0;
    let pendingAmountUsd = 0, disbursedAmountUsd = 0;

    for (const p of payments ?? []) {
      const amount = Number(p.amount_kes ?? 0);
      const pct = Number(p.package?.profit_percentage ?? DEFAULT_PROFIT_PERCENTAGE);
      const agentShare = amount - (amount * pct) / 100;

      const rate = Number(p.fx_rate_used) || fallbackRate;
      const agentShareUsd = rate ? kesToUsd(agentShare, rate) : null;

      if (p.disbursed) {
        disbursedAmount += agentShare;
        if (agentShareUsd != null) disbursedAmountUsd += agentShareUsd;
        disbursedCount++;
      } else {
        pendingAmount += agentShare;
        if (agentShareUsd != null) pendingAmountUsd += agentShareUsd;
        pendingCount++;
      }
    }

    return res.json({
      success: true,
      data: {
        pendingAmount, pendingCount, disbursedAmount, disbursedCount,
        pendingAmountUsd:   Math.round(pendingAmountUsd * 100) / 100,
        disbursedAmountUsd: Math.round(disbursedAmountUsd * 100) / 100,
      },
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
        id, user_id, amount_kes, amount_usd, fx_rate_used, status, paid_at, disbursed, disbursed_at, mpesa_ref,
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

    const needsFallback = (payments ?? []).some(p => !p.fx_rate_used);
    const fallbackRate = needsFallback ? await resolveFallbackRate() : null;

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

      const rate = Number(p.fx_rate_used) || fallbackRate;
      const amountUsd      = p.amount_usd != null ? Number(p.amount_usd) : (rate ? kesToUsd(amount, rate) : null);
      const platformFeeUsd = rate ? kesToUsd(platformFee, rate) : null;
      const agentShareUsd  = rate ? kesToUsd(agentShare, rate) : null;

      return {
        id: p.id,
        packageId: p.package?.id ?? null,
        packageName: p.package?.name ?? '—',
        clientName: client ? `${client.first_name} ${client.last_name}`.trim() : '—',
        amount,
        amountUsd,
        platformFee,
        platformFeeUsd,
        agentShare,
        agentShareUsd,
        fxRateUsed: rate ?? null,
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