
import cron from 'node-cron';
import { supabaseAdmin } from '../config/supabase.js';
import { sendVerificationReminder } from '../services/agentVerification.service.js';
import logger from '../config/logger.js';

const MAX_REMINDERS = 5; // stop nagging after this many; surface to admin instead

export const runVerificationReminders = async () => {
  const cutoff = new Date(Date.now() - 48 * 60 * 60 * 1000).toISOString();

  // Pending, non-approved agents due for a reminder
  const { data: candidates, error } = await supabaseAdmin
    .from('profiles')
    .select('id, first_name, email, phone, reminder_count')
    .eq('role', 'agent')
    .eq('verification_status', 'pending')
    .eq('approved', false)
    .lte('last_reminder_sent_at', cutoff)
    .lt('reminder_count', MAX_REMINDERS);

  if (error) {
    logger.error('Verification reminder query failed', { error: error.message });
    return;
  }
  if (!candidates?.length) return;

  // Drop anyone who already has an agent_documents row (docs submitted,
  // even if not yet reviewed) — a single query for all candidate IDs.
  const ids = candidates.map((a) => a.id);
  const { data: submitted, error: docErr } = await supabaseAdmin
    .from('agent_documents')
    .select('user_id')
    .in('user_id', ids);

  if (docErr) {
    logger.error('agent_documents lookup failed during reminder run', { error: docErr.message });
    return;
  }

  const submittedIds = new Set((submitted || []).map((d) => d.user_id));
  const stillPending = candidates.filter((a) => !submittedIds.has(a.id));

  if (!stillPending.length) return;

  for (const agent of stillPending) {
    await sendVerificationReminder(
      { id: agent.id, firstName: agent.first_name, email: agent.email, phone: agent.phone, reminder_count: agent.reminder_count },
      supabaseAdmin,
    );
  }

  logger.info(`Sent verification reminders to ${stillPending.length} agent(s)`);
};

// Every hour, on the hour. Cheap query — only actually messages agents
// whose last_reminder_sent_at is 48h+ old.
cron.schedule('0 * * * *', runVerificationReminders);