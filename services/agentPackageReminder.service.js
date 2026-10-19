import { supabaseAdmin as supabase } from '../config/supabase.js';
import { sendWhatsAppBroadcast } from './whatsappService.js';
import logger from '../config/logger.js';

export const AGENT_PACKAGE_REMINDER_CATEGORY = 'agent_package_reminder';
const COOLDOWN_DAYS = Number(process.env.AGENT_REMINDER_COOLDOWN_DAYS || 6);
const MAX_RECIPIENTS = 2000;

const optedIn = (q) => q.or('whatsapp_opt_in.is.null,whatsapp_opt_in.eq.true');

/** Agent ids that own at least one non-deleted package. */
async function agentIdsWithPackages() {
  const ids = new Set();
  const PAGE = 1000;
  for (let from = 0; ; from += PAGE) {
    const { data, error } = await supabase
      .from('packages')
      .select('created_by')
      .range(from, from + PAGE - 1);
    if (error) throw error;
    (data || []).forEach((r) => r.created_by && ids.add(r.created_by));
    if (!data || data.length < PAGE) break;
  }
  return ids;
}

/** Agent ids already reminded within the cooldown window (prevents spamming). */
async function recentlyRemindedIds() {
  const since = new Date(Date.now() - COOLDOWN_DAYS * 86_400_000).toISOString();
  const { data, error } = await supabase
    .from('whatsapp_messages')
    .select('recipient_profile_id')
    .eq('category', AGENT_PACKAGE_REMINDER_CATEGORY)
    .neq('status', 'failed')
    .gte('created_at', since)
    .not('recipient_profile_id', 'is', null);
  if (error) throw error;
  return new Set((data || []).map((r) => r.recipient_profile_id));
}

/**
 * Resolve who should get the "add your packages" reminder.
 * Only agents that opted in, have a phone, and (optionally) have no packages yet.
 */
export async function resolveReminderRecipients({ onlyWithoutPackages = true, ignoreCooldown = false } = {}) {
  const { data, error } = await optedIn(
    supabase
      .from('profiles')
      .select('id, phone, first_name, last_name')
      .eq('role', 'agent')
      .not('phone', 'is', null)
  );
  if (error) throw error;

  const [withPackages, recent] = await Promise.all([
    onlyWithoutPackages ? agentIdsWithPackages() : Promise.resolve(new Set()),
    ignoreCooldown ? Promise.resolve(new Set()) : recentlyRemindedIds(),
  ]);

  return (data || [])
    .filter((p) => !withPackages.has(p.id) && !recent.has(p.id))
    .map((p) => ({
      id: p.id,
      phone: p.phone,
      type: 'agent',
      firstName: (p.first_name || '').trim(),
      name: `${p.first_name || ''} ${p.last_name || ''}`.trim(),
    }));
}

/**
 * Send the package reminder template. Template variables: {1} = agent first name.
 * Env: TWILIO_TEMPLATE_AGENT_PACKAGE_REMINDER_SID
 */
export async function sendAgentPackageReminders({ onlyWithoutPackages = true, ignoreCooldown = false, createdBy = null } = {}) {
  const templateSid = process.env.TWILIO_TEMPLATE_AGENT_PACKAGE_REMINDER_SID;
  if (!templateSid) {
    const err = new Error('TWILIO_TEMPLATE_AGENT_PACKAGE_REMINDER_SID is not set');
    err.status = 400;
    throw err;
  }

  const recipients = (await resolveReminderRecipients({ onlyWithoutPackages, ignoreCooldown })).slice(0, MAX_RECIPIENTS);
  if (recipients.length === 0) {
    return { recipientCount: 0, sentCount: 0, failedCount: 0, failed: [], broadcastId: null };
  }

  const { data: broadcast, error: bErr } = await supabase
    .from('whatsapp_broadcasts')
    .insert({
      created_by: createdBy,
      template_sid: templateSid,
      template_name: 'agent_package_reminder',
      variables_map: {},
      recipient_count: recipients.length,
      audience: 'agent_package_reminder',
    })
    .select()
    .single();
  if (bErr) throw bErr;

  const { sentCount, failedCount, failed } = await sendWhatsAppBroadcast({
    recipients,
    templateSid,
    templateName: 'agent_package_reminder',
    category: AGENT_PACKAGE_REMINDER_CATEGORY,
    broadcastId: broadcast.id,
    buildVariables: (r) => ({ 1: r.firstName || 'there' }),
  });

  await supabase
    .from('whatsapp_broadcasts')
    .update({ sent_count: sentCount, failed_count: failedCount })
    .eq('id', broadcast.id);

  logger.info('[agentPackageReminder] sent', { recipients: recipients.length, sentCount, failedCount });
  return { recipientCount: recipients.length, sentCount, failedCount, failed, broadcastId: broadcast.id };
}
