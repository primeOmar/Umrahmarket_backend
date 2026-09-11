
import express from 'express';
import twilio from 'twilio';
import { supabase } from '../supabaseClient.js';
import { sendWhatsAppBroadcast, handleStatusWebhook, toE164Kenya } from '../services/whatsappService.js';

const router = express.Router();
const publicRouter = express.Router();

// ─────────────────────────────────────────────────────────────────────────
// GET /superadmin/whatsapp/templates
// Lists approved Content Templates from Twilio so the compose modal can
// offer a dropdown instead of the admin typing raw SIDs.
// ─────────────────────────────────────────────────────────────────────────
router.get('/whatsapp/templates', async (req, res) => {
  try {
    const client = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
    const contents = await client.content.v1.contents.list({ limit: 50 });

    const templates = contents.map((c) => ({
      sid: c.sid,
      name: c.friendlyName,
      body: c.types?.['twilio/text']?.body || c.types?.['twilio/quick-reply']?.body || '',
    }));

    res.json({ success: true, templates });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────
// POST /superadmin/agents/batch-whatsapp
// Mirrors /superadmin/agents/batch-email. Body:
// {
//   agentIds: string[],             // selected profiles.id (role='agent')
//   audience: 'selected_agents' | 'all_agents' | 'clients',
//   extraNumbers: string[],         // external WhatsApp numbers
//   templateSid: 'HXxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
//   templateName: 'ramadan_offer',
//   variables: { "1": "New Ramadan Umrah packages are live!" }  // shared vars for everyone
// }
// ─────────────────────────────────────────────────────────────────────────
router.post('/agents/batch-whatsapp', async (req, res) => {
  const { agentIds = [], audience = 'selected_agents', extraNumbers = [], templateSid, templateName, variables = {} } = req.body;

  if (!templateSid) {
    return res.status(400).json({ success: false, message: 'templateSid is required' });
  }

  // audience → which role(s) we're pulling from profiles.
  const roleForAudience = audience === 'clients' ? 'client' : 'agent';

  try {
    let recipients = [];

    if (audience === 'all_agents' || audience === 'clients') {
      const { data, error } = await supabase
        .from('profiles')
        .select('id, phone, first_name, last_name')
        .eq('role', roleForAudience)
        .eq('whatsapp_opt_in', true)
        .not('phone', 'is', null);
      if (error) throw error;
      recipients = data.map((p) => ({ id: p.id, phone: p.phone, type: roleForAudience, name: `${p.first_name} ${p.last_name}`.trim() }));
    } else if (agentIds.length > 0) {
      const { data, error } = await supabase
        .from('profiles')
        .select('id, phone, first_name, last_name')
        .in('id', agentIds)
        .eq('role', 'agent')
        .eq('whatsapp_opt_in', true)
        .not('phone', 'is', null);
      if (error) throw error;
      recipients = data.map((p) => ({ id: p.id, phone: p.phone, type: 'agent', name: `${p.first_name} ${p.last_name}`.trim() }));
    }

    const skippedNoPhone = audience === 'selected_agents' ? agentIds.length - recipients.length : 0;

    const externalRecipients = extraNumbers
      .map((n) => toE164Kenya(n) || (n.startsWith('+') ? n : null))
      .filter(Boolean)
      .map((phone) => ({ id: null, phone, type: 'external' }));

    recipients = [...recipients, ...externalRecipients];

    if (recipients.length === 0) {
      return res.status(400).json({ success: false, message: 'No valid recipients with a WhatsApp number' });
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
      buildVariables: () => variables, // same offer text for everyone; extend here for per-recipient personalisation
    });

    await supabase
      .from('whatsapp_broadcasts')
      .update({ sent_count: sentCount, failed_count: failedCount })
      .eq('id', broadcast.id);

    res.json({
      success: true,
      broadcastId: broadcast.id,
      recipientCount: recipients.length,
      sentCount,
      failedCount,
      failed,
      skippedNoPhone, // selected agents with no WhatsApp number on file, silently excluded
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────
// POST /api/whatsapp/status  — Twilio status callback (public, no auth;
// Twilio signs requests — validate with twilio.validateExpressRequest in
// production, see SETUP.md).
// ─────────────────────────────────────────────────────────────────────────
publicRouter.post('/status', express.urlencoded({ extended: false }), async (req, res) => {
  await handleStatusWebhook(req.body);
  res.sendStatus(200);
});

export default router;
export { publicRouter as publicWhatsappRoutes };