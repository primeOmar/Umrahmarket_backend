import express from 'express';
import twilio from 'twilio';
import { supabaseAdmin as supabase } from '../config/supabase.js';
import logger from '../config/logger.js';
import { sendWhatsAppBroadcast, handleStatusWebhook, toE164Kenya } from '../services/whatsappService.js';
import {
  resolveReminderRecipients,
  sendAgentPackageReminders,
} from '../services/agentPackageReminder.service.js';

// Mounted at /api/superadmin/whatsapp behind authenticateSuperadmin.
const router = express.Router();
// Mounted at /api/whatsapp (Twilio status callback, signature-verified).
const publicRouter = express.Router();

const MAX_RECIPIENTS = 2000;
const optedIn = (q) => q.or('whatsapp_opt_in.is.null,whatsapp_opt_in.eq.true');

/** Parse pasted numbers (comma / newline / semicolon separated) into unique E.164 numbers. */
export function parseNumbers(input) {
  const raw = Array.isArray(input) ? input : String(input || '').split(/[\n,;]+/);
  const valid = new Set();
  const invalid = [];
  for (const item of raw) {
    let n = String(item || '').trim().replace(/[\s\-().]/g, '');
    if (!n) continue;
    if (n.startsWith('00')) n = `+${n.slice(2)}`;
    const e164 = toE164Kenya(n);
    if (e164 && /^\+\d{8,15}$/.test(e164)) valid.add(e164);
    else invalid.push(String(item).trim());
  }
  return { valid: [...valid], invalid };
}

const fillVariables = (variables, recipient) => {
  const out = {};
  for (const [k, v] of Object.entries(variables || {})) {
    out[k] = String(v ?? '')
      .replace(/\{name\}/gi, recipient.firstName || 'there')
      .replace(/[\r\n\t]+/g, ' ') // WhatsApp rejects newlines/tabs in variables
      .replace(/ {4,}/g, '   ')
      .trim();
  }
  return out;
};

// GET /whatsapp/templates — approved Twilio Content Templates for the compose dropdown
router.get('/templates', async (_req, res) => {
  try {
    const client = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
    const contents = await client.content.v1.contents.list({ limit: 100 });
    const templates = contents.map((c) => {
      const t = c.types || {};
      const body = t['twilio/text']?.body || t['twilio/quick-reply']?.body || t['twilio/call-to-action']?.body || t['twilio/card']?.title || '';
      const vars = [...new Set([...body.matchAll(/\{\{\s*(\d+)\s*\}\}/g)].map((m) => m[1]))].sort((a, b) => a - b);
      return { sid: c.sid, name: c.friendlyName, body, variables: vars };
    });
    res.json({ success: true, templates });
  } catch (err) {
    logger.error('[whatsapp] list templates failed', { error: err.message });
    res.status(500).json({ success: false, message: 'Could not load templates from Twilio' });
  }
});

// GET /whatsapp/audience — counts shown in the compose UI
router.get('/audience', async (_req, res) => {
  try {
    const count = async (role) => {
      const { count: c, error } = await optedIn(
        supabase.from('profiles').select('id', { count: 'exact', head: true }).eq('role', role).not('phone', 'is', null)
      );
      if (error) throw error;
      return c || 0;
    };
    const [agents, clients, withoutPackages] = await Promise.all([
      count('agent'),
      count('client'),
      resolveReminderRecipients({ onlyWithoutPackages: true, ignoreCooldown: true }),
    ]);
    res.json({
      success: true,
      agents,
      clients,
      agentsWithoutPackages: withoutPackages.length,
      reminderTemplateConfigured: !!process.env.TWILIO_TEMPLATE_AGENT_PACKAGE_REMINDER_SID,
    });
  } catch (err) {
    logger.error('[whatsapp] audience failed', { error: err.message });
    res.status(500).json({ success: false, message: 'Could not load audience' });
  }
});

// GET /whatsapp/agents — agents selectable in the compose UI
router.get('/agents', async (_req, res) => {
  try {
    const { data, error } = await supabase
      .from('profiles')
      .select('id, first_name, last_name, phone, whatsapp_opt_in')
      .eq('role', 'agent')
      .order('first_name', { ascending: true })
      .limit(1000);
    if (error) throw error;
    res.json({
      success: true,
      agents: (data || []).map((a) => ({
        id: a.id,
        name: `${a.first_name || ''} ${a.last_name || ''}`.trim() || 'Unnamed agent',
        phone: a.phone,
        sendable: !!a.phone && a.whatsapp_opt_in !== false,
      })),
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Could not load agents' });
  }
});

// GET /whatsapp/broadcasts — history
router.get('/broadcasts', async (_req, res) => {
  try {
    const { data, error } = await supabase
      .from('whatsapp_broadcasts')
      .select('id, template_name, audience, recipient_count, sent_count, failed_count, created_at')
      .order('created_at', { ascending: false })
      .limit(50);
    if (error) throw error;
    res.json({ success: true, broadcasts: data || [] });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Could not load history' });
  }
});

// POST /whatsapp/broadcast
// { audience: 'selected_agents'|'all_agents'|'clients'|'numbers_only',
//   agentIds?: string[], extraNumbers?: string|string[], templateSid, templateName?, variables?: {"1": "..."} }
// "{name}" inside a variable value is replaced with each recipient's first name.
router.post('/broadcast', async (req, res) => {
  const { audience = 'numbers_only', agentIds = [], extraNumbers = [], templateSid, templateName, variables = {} } = req.body || {};

  if (!/^HX[0-9a-f]{32}$/i.test(templateSid || '')) {
    return res.status(400).json({ success: false, message: 'A valid Twilio template SID (HX…) is required' });
  }
  if (!['selected_agents', 'all_agents', 'clients', 'numbers_only'].includes(audience)) {
    return res.status(400).json({ success: false, message: 'Invalid audience' });
  }

  try {
    let recipients = [];

    if (audience === 'all_agents' || audience === 'clients') {
      const { data, error } = await optedIn(
        supabase.from('profiles').select('id, phone, first_name, last_name')
          .eq('role', audience === 'clients' ? 'client' : 'agent')
          .not('phone', 'is', null)
      );
      if (error) throw error;
      recipients = data;
    } else if (audience === 'selected_agents' && Array.isArray(agentIds) && agentIds.length) {
      const { data, error } = await optedIn(
        supabase.from('profiles').select('id, phone, first_name, last_name')
          .in('id', agentIds.slice(0, MAX_RECIPIENTS))
          .eq('role', 'agent')
          .not('phone', 'is', null)
      );
      if (error) throw error;
      recipients = data;
    }

    recipients = recipients.map((p) => ({
      id: p.id,
      phone: p.phone,
      type: audience === 'clients' ? 'client' : 'agent',
      firstName: (p.first_name || '').trim(),
    }));
    const profileCount = recipients.length;

    const { valid, invalid } = parseNumbers(extraNumbers);
    const known = new Set(recipients.map((r) => toE164Kenya(r.phone)));
    for (const phone of valid) {
      if (!known.has(phone)) {
        known.add(phone);
        recipients.push({ id: null, phone, type: 'external', firstName: '' });
      }
    }

    if (recipients.length === 0) {
      return res.status(400).json({ success: false, message: 'No valid recipients with a WhatsApp number', invalidNumbers: invalid });
    }
    if (recipients.length > MAX_RECIPIENTS) {
      return res.status(400).json({ success: false, message: `Too many recipients (max ${MAX_RECIPIENTS} per broadcast)` });
    }

    const { data: broadcast, error: bErr } = await supabase
      .from('whatsapp_broadcasts')
      .insert({
        created_by: req.superadmin?.id || null,
        template_sid: templateSid,
        template_name: templateName || templateSid,
        variables_map: variables,
        recipient_count: recipients.length,
        audience,
      })
      .select()
      .single();
    if (bErr) throw bErr;

    const { sentCount, failedCount, failed } = await sendWhatsAppBroadcast({
      recipients,
      templateSid,
      templateName: templateName || templateSid,
      category: 'marketing_broadcast',
      broadcastId: broadcast.id,
      buildVariables: (r) => fillVariables(variables, r),
    });

    await supabase.from('whatsapp_broadcasts').update({ sent_count: sentCount, failed_count: failedCount }).eq('id', broadcast.id);

    res.json({
      success: true,
      broadcastId: broadcast.id,
      recipientCount: recipients.length,
      profileRecipients: profileCount,
      externalRecipients: recipients.length - profileCount,
      sentCount,
      failedCount,
      failed,
      invalidNumbers: invalid,
    });
  } catch (err) {
    logger.error('[whatsapp] broadcast failed', { error: err.message });
    res.status(500).json({ success: false, message: 'Broadcast failed' });
  }
});

// POST /whatsapp/agent-package-reminder { onlyWithoutPackages?: boolean, ignoreCooldown?: boolean }
router.post('/agent-package-reminder', async (req, res) => {
  try {
    const { onlyWithoutPackages = true, ignoreCooldown = false } = req.body || {};
    const result = await sendAgentPackageReminders({
      onlyWithoutPackages: !!onlyWithoutPackages,
      ignoreCooldown: !!ignoreCooldown,
      createdBy: req.superadmin?.id || null,
    });
    res.json({ success: true, ...result });
  } catch (err) {
    if (err.status === 400) return res.status(400).json({ success: false, message: err.message });
    logger.error('[whatsapp] agent reminder failed', { error: err.message });
    res.status(500).json({ success: false, message: 'Could not send reminders' });
  }
});

// POST /api/whatsapp/status — Twilio delivery callback (public; signature verified)
publicRouter.post('/status', express.urlencoded({ extended: false }), async (req, res) => {
  const callbackUrl = process.env.TWILIO_STATUS_CALLBACK_URL;
  if (callbackUrl && process.env.TWILIO_AUTH_TOKEN) {
    const valid = twilio.validateRequest(
      process.env.TWILIO_AUTH_TOKEN,
      req.get('X-Twilio-Signature') || '',
      callbackUrl,
      req.body || {}
    );
    if (!valid) return res.sendStatus(403);
  }
  try {
    await handleStatusWebhook(req.body);
  } catch (err) {
    logger.error('[whatsapp] status webhook failed', { error: err.message });
  }
  res.sendStatus(200);
});

export default router;
export { publicRouter as publicWhatsappRoutes };
