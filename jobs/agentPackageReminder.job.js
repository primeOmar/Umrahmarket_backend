import cron from 'node-cron';
import logger from '../config/logger.js';
import { sendAgentPackageReminders } from '../services/agentPackageReminder.service.js';

// Opt-in: set ENABLE_AGENT_PACKAGE_REMINDERS=true. Default schedule is Monday 09:00 Nairobi time.
export function startAgentPackageReminderJob() {
  if (process.env.ENABLE_AGENT_PACKAGE_REMINDERS !== 'true') {
    logger.info('[agentPackageReminderJob] disabled (set ENABLE_AGENT_PACKAGE_REMINDERS=true to enable)');
    return;
  }
  const schedule = process.env.AGENT_PACKAGE_REMINDER_CRON || '0 9 * * 1';
  if (!cron.validate(schedule)) {
    logger.error('[agentPackageReminderJob] invalid cron expression', { schedule });
    return;
  }
  cron.schedule(schedule, () => {
    sendAgentPackageReminders({ onlyWithoutPackages: true }).catch((e) =>
      logger.error('[agentPackageReminderJob] run failed', { error: e.message })
    );
  }, { timezone: 'Africa/Nairobi' });
  logger.info('[agentPackageReminderJob] scheduled', { schedule });
}
