// jobs/savingsReconcile.job.js
// Safety net for Lipa Mdogo Mdogo deposits whose M-Pesa callback or Pesapal
// IPN never arrived (network blips, provider retries exhausted, server
// restarts). Every few minutes, pending deposits are checked directly with
// the provider and settled. Crediting is idempotent (savings_credit_deposit),
// so overlapping with a late callback is harmless.
import cron from 'node-cron';
import { supabaseAdmin } from '../config/supabase.js';
import logger from '../config/logger.js';
import { settleMpesaTx, settleCardTx } from '../controllers/savings.controller.js';

const MIN_AGE_MS = 90 * 1000;          // let the normal callback land first
const MPESA_GIVE_UP_MS = 24 * 3600e3;  // Daraja stops answering queries for old pushes
const CARD_GIVE_UP_MS = 48 * 3600e3;   // abandoned Pesapal checkouts

let running = false;

export const runSavingsReconcile = async () => {
  if (running) return;
  running = true;
  try {
    const now = Date.now();
    const { data: pending, error } = await supabaseAdmin
      .from('savings_transactions')
      .select('*')
      .eq('type', 'DEPOSIT')
      .eq('status', 'PENDING')
      .lte('created_at', new Date(now - MIN_AGE_MS).toISOString())
      .order('created_at', { ascending: true })
      .limit(50);
    if (error) throw error;

    let settled = 0;
    for (const tx of pending || []) {
      const age = now - new Date(tx.created_at).getTime();
      try {
        if (tx.method === 'MPESA') {
          if (!tx.checkout_request_id || age > MPESA_GIVE_UP_MS) {
            await supabaseAdmin.from('savings_transactions')
              .update({ status: 'CANCELLED', result_desc: 'Expired — no confirmation from M-Pesa', updated_at: new Date().toISOString() })
              .eq('id', tx.id).eq('status', 'PENDING');
            continue;
          }
          const s = await settleMpesaTx(tx);
          if (s !== 'PENDING') settled++;
        } else if (tx.method === 'CARD') {
          if (!tx.pesapal_order_tracking_id || age > CARD_GIVE_UP_MS) {
            await supabaseAdmin.from('savings_transactions')
              .update({ status: 'CANCELLED', result_desc: 'Expired — card checkout not completed', updated_at: new Date().toISOString() })
              .eq('id', tx.id).eq('status', 'PENDING');
            continue;
          }
          const s = await settleCardTx(tx);
          if (s !== 'PENDING') settled++;
        }
      } catch (err) {
        logger.warn('[savings-reconcile] could not settle deposit', { txId: tx.id, error: err.message });
      }
    }
    if (settled) logger.info('[savings-reconcile] settled deposits', { settled, checked: pending?.length || 0 });
  } catch (err) {
    logger.error('[savings-reconcile] run failed', { error: err.message });
  } finally {
    running = false;
  }
};

export const startSavingsReconcileJob = () => {
  cron.schedule('*/3 * * * *', runSavingsReconcile);
};
