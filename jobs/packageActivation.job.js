import cron from 'node-cron';
import { supabaseAdmin } from '../config/supabase.js';
import logger from '../config/logger.js';
import { activationCutoffDate } from '../utils/packageActivation.js';

// Publishes Scheduled packages (pricing already confirmed by the agent) whose
// departure has entered the activation window. Idempotent — safe to run often.
export const runPackageActivation = async () => {
  const { data, error } = await supabaseAdmin
    .from('packages')
    .update({ status: 'Active', updated_at: new Date().toISOString() })
    .eq('status', 'Scheduled')
    .not('pricing_confirmed_at', 'is', null)
    .lte('available_from', activationCutoffDate())
    .select('id');

  if (error) {
    logger.error('Package activation failed', { error: error.message });
    return 0;
  }
  if (data?.length) logger.info('Packages activated', { count: data.length });
  return data?.length ?? 0;
};

export const startPackageActivationJob = () => {
  runPackageActivation();
  cron.schedule('15 * * * *', runPackageActivation);
};
