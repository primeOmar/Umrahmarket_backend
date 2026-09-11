import cron from 'node-cron';
import { supabaseAdmin as supabase } from '../config/supabase.js';
import { sendTaskEmail, taskEmailTemplates } from '../services/taskEmail.service.js';
import logger from '../config/logger.js';

const OVERDUE_OFFSET_SENTINEL = -1;

async function getRecipients(task) {
  const { data: assignees } = await supabase
    .from('task_assignees')
    .select('superadmin_credentials(id, email, username, full_name)')
    .eq('task_id', task.id);

  const { data: creator } = await supabase
    .from('superadmin_credentials')
    .select('id, email, username, full_name')
    .eq('id', task.created_by)
    .single();

  const map = new Map();
  (assignees || []).forEach(a => {
    if (a.superadmin_credentials) map.set(a.superadmin_credentials.id, a.superadmin_credentials);
  });
  if (creator) map.set(creator.id, creator);
  return [...map.values()];
}

// Tries to claim a (task_id, offset_hours) slot. Returns true only for the
// caller that actually inserted the row — everyone else gets a unique-
// constraint violation and is told "already sent".
async function claimReminderSlot(taskId, offsetHours) {
  const { error } = await supabase
    .from('task_reminder_log')
    .insert({ task_id: taskId, offset_hours: offsetHours });
  return !error;
}

async function runReminderSweep() {
  const now = new Date();

  const { data: tasks, error } = await supabase
    .from('tasks')
    .select('*')
    .eq('status', 'active');

  if (error) {
    logger.error('[taskReminderJob] failed to load tasks', { error: error.message });
    return;
  }

  for (const task of tasks || []) {
    const deadline = new Date(task.deadline);
    const hoursUntilDeadline = (deadline.getTime() - now.getTime()) / 3_600_000;
    const offsets = Array.isArray(task.reminder_offsets_hours) && task.reminder_offsets_hours.length
      ? task.reminder_offsets_hours
      : [72, 24, 3];

    if (hoursUntilDeadline <= 0) {
      const claimed = await claimReminderSlot(task.id, OVERDUE_OFFSET_SENTINEL);
      if (!claimed) continue;

      const recipients = await getRecipients(task);
      await Promise.all(recipients.map(async (r) => {
        await supabase.from('task_notifications').insert({
          admin_id: r.id,
          task_id: task.id,
          type: 'overdue',
          message: `Overdue: "${task.title}" passed its deadline`,
        });
        const { subject, html } = taskEmailTemplates.overdue(task);
        await sendTaskEmail(r.email, subject, html);
      }));
      continue;
    }

    // Fire the largest offset we've now crossed (e.g. task is 20h out and
    // offsets are [72,24,3] → the 24h reminder fires once, when we cross
    // under 24h remaining).
    for (const offsetHours of [...offsets].sort((a, b) => b - a)) {
      if (hoursUntilDeadline > offsetHours) continue;

      const claimed = await claimReminderSlot(task.id, offsetHours);
      if (!claimed) continue;

      const recipients = await getRecipients(task);
      const roundedHours = Math.max(1, Math.round(hoursUntilDeadline));
      await Promise.all(recipients.map(async (r) => {
        await supabase.from('task_notifications').insert({
          admin_id: r.id,
          task_id: task.id,
          type: 'reminder',
          message: `Reminder: "${task.title}" is due in ~${roundedHours}h`,
        });
        const { subject, html } = taskEmailTemplates.reminder(task, roundedHours);
        await sendTaskEmail(r.email, subject, html);
      }));
    }
  }
}

export function startTaskReminderJob() {
  // Every hour, on the hour. Good enough granularity for the default
  // 72h/24h/3h offsets — tighten to '*/15 * * * *' if you add sub-hour offsets.
  cron.schedule('0 * * * *', () => {
    runReminderSweep().catch(e => logger.error('[taskReminderJob] sweep failed', { error: e.message }));
  });
  logger.info('[taskReminderJob] scheduled hourly deadline sweep');
}

export { runReminderSweep };