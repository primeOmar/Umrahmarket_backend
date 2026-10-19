import jwt from 'jsonwebtoken';
import { supabaseAdmin as supabase } from '../config/supabase.js';
import logger from '../config/logger.js';
import config from '../config/security.config.js';
import { sendGuestWhatsAppOtp, checkGuestWhatsAppOtp, toE164 } from '../services/guestVerification.service.js';
import { sendWhatsAppTemplate } from '../services/whatsappService.js';
import { sendCustomRequestReplyEmail } from '../services/email.service.js';

const GROUP_TYPES = ['family', 'friends', 'couple', 'solo', 'group', 'other'];
const ROUTES = ['makkah', 'makkah_madinah', 'makkah_madinah_jeddah'];
const CURRENCIES = ['USD', 'KES'];
const MAX_RECIPIENTS = 200;
const DAILY_LIMIT = 5;

// Guest verification tokens are short-lived and scoped to this one purpose —
// they only ever unlock POST /api/inquiries/guest, never general auth.
const GUEST_TOKEN_AUDIENCE = 'guest-inquiry';
const GUEST_TOKEN_TTL = '15m';
const GUEST_OTP_MAX_PER_PHONE_PER_DAY = 5;
const GUEST_OTP_MAX_PER_IP_PER_DAY = 15;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const FRONTEND_BASE_URL = (
  process.env.FRONTEND_URL ||
  process.env.APP_URL ||
  process.env.WEB_APP_URL ||
  'https://umrahmarket.net'
).replace(/\/$/, '');

const fail = (res, message, status = 400) => res.status(status).json({ success: false, message });
const serverError = (res, error, ctx) => {
  logger.error(`Custom request error: ${ctx}`, { error: error?.message });
  return res.status(500).json({ success: false, message: 'An internal server error occurred.' });
};

const int = (v, min, max) => {
  const n = parseInt(v, 10);
  return Number.isFinite(n) && n >= min && n <= max ? n : null;
};

// Clients sometimes paste phone numbers/emails into free text; requests are
// meant to be anonymous until the client chooses to engage, so mask them.
const maskContacts = (s) => s
  .replace(/[\w.+-]+@[\w-]+\.[\w.-]+/g, '[hidden]')
  .replace(/(?:\+?\d[\s().-]*){9,}/g, '[hidden]');

const cleanText = (v, max) => maskContacts(String(v ?? '')
  .replace(/<[^>]*>/g, '')
  .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '')
  .trim()).slice(0, max);

function sanitizeDetails(raw = {}) {
  const d = {};
  const month = /^\d{4}-(0[1-9]|1[0-2])$/.test(raw.travel_month ?? '') ? raw.travel_month : null;
  if (month) {
    const now = new Date();
    const cur = now.getUTCFullYear() * 12 + now.getUTCMonth();
    const [y, m] = month.split('-').map(Number);
    const diff = y * 12 + (m - 1) - cur;
    if (diff >= 0 && diff <= 24) d.travel_month = month;
  }
  if (raw.flexible_dates === true) d.flexible_dates = true;

  const adults = int(raw.adults, 0, 100);
  const children = int(raw.children, 0, 100);
  const infants = int(raw.infants, 0, 100);
  if (adults !== null) d.adults = adults;
  if (children) d.children = children;
  if (infants) d.infants = infants;
  if ((adults ?? 0) + (children ?? 0) + (infants ?? 0) > 150) return { error: 'Group is too large.' };

  if (GROUP_TYPES.includes(raw.group_type)) d.group_type = raw.group_type;
  if (ROUTES.includes(raw.route)) d.route = raw.route;
  const nights = int(raw.nights, 1, 60);
  if (nights) d.nights = nights;
  const mk = int(raw.makkah_stars, 1, 5);
  const md = int(raw.madinah_stars, 1, 5);
  if (mk) d.makkah_stars = mk;
  if (md) d.madinah_stars = md;
  const hotelPref = cleanText(raw.hotel_preference, 150);
  if (hotelPref) d.hotel_preference = hotelPref;

  const budget = Number(raw.budget);
  if (Number.isFinite(budget) && budget > 0 && budget < 1e9) {
    d.budget = Math.round(budget);
    d.budget_currency = CURRENCIES.includes(raw.budget_currency) ? raw.budget_currency : 'USD';
    d.budget_per_person = raw.budget_per_person !== false;
  }
  const notes = cleanText(raw.notes, 1500);
  if (notes) d.notes = notes;
  return { details: d };
}

const agentLabel = (p) => p?.company_name || [p?.first_name, p?.last_name].filter(Boolean).join(' ') || 'Agent';
const refCode = (id) => id.slice(0, 6).toUpperCase();
const customDashboardUrl = (requestId) => `${FRONTEND_BASE_URL}/client/dashboard?tab=custom${requestId ? `&request=${encodeURIComponent(requestId)}` : ''}`;

const money = (v) => {
  const n = Number(v);
  return Number.isFinite(n) && n > 0 && n < 1e9 ? Math.round(n * 100) / 100 : null;
};
const list = (v, maxItems, maxLen) => (Array.isArray(v) ? v : [])
  .map((x) => cleanText(x, maxLen)).filter(Boolean).slice(0, maxItems);

// The agent's editable version of the client's request.
function sanitizeOffer(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const o = {};
  if (ROUTES.includes(raw.route)) o.route = raw.route;
  const nights = int(raw.nights, 1, 60);
  if (nights) o.nights = nights;
  if (/^\d{4}-(0[1-9]|1[0-2])$/.test(raw.travel_month ?? '')) o.travel_month = raw.travel_month;
  for (const k of ['departure_date', 'return_date']) {
    if (/^\d{4}-\d{2}-\d{2}$/.test(raw[k] ?? '')) o[k] = raw[k];
  }
  const mkHotel = cleanText(raw.makkah_hotel, 120);
  const mdHotel = cleanText(raw.madinah_hotel, 120);
  if (mkHotel) o.makkah_hotel = mkHotel;
  if (mdHotel) o.madinah_hotel = mdHotel;
  const mk = int(raw.makkah_stars, 1, 5);
  const md = int(raw.madinah_stars, 1, 5);
  if (mk) o.makkah_stars = mk;
  if (md) o.madinah_stars = md;
  for (const k of ['adult_price', 'child_price', 'infant_price']) {
    const p = money(raw[k]);
    if (p) o[k] = p;
  }
  o.currency = 'USD';
  const inc = list(raw.inclusions, 40, 120);
  const exc = list(raw.exclusions, 40, 120);
  if (inc.length) o.inclusions = inc;
  if (exc.length) o.exclusions = exc;
  return o;
}

// ── Client ───────────────────────────────────────────────────────────────────

// GET /api/inquiries/agents — approved agents a client can address directly
export const listAgents = async (_req, res) => {
  try {
    const { data, error } = await supabase
      .from('profiles')
      .select('id, company_name, first_name, last_name, agent_number')
      .eq('role', 'agent').eq('approved', true)
      .order('company_name', { ascending: true })
      .limit(500);
    if (error) throw error;
    return res.json({
      success: true,
      agents: (data ?? []).map((a) => ({ id: a.id, name: agentLabel(a), agent_number: a.agent_number })),
    });
  } catch (e) { return serverError(res, e, 'listAgents'); }
};

// POST /api/inquiries  { audience: 'all'|'selected', agent_ids?: [], details: {...} }
export const createRequest = async (req, res) => {
  const clientId = req.user.id;
  const audience = req.body?.audience === 'all' ? 'all' : req.body?.audience === 'selected' ? 'selected' : null;
  if (!audience) return fail(res, 'Choose who should receive this request.');

  const parsed = sanitizeDetails(req.body?.details);
  if (parsed.error) return fail(res, parsed.error);

  try {
    const since = new Date(Date.now() - 86400000).toISOString();
    const { count } = await supabase.from('custom_package_requests')
      .select('id', { count: 'exact', head: true }).eq('client_id', clientId).gte('created_at', since);
    if ((count ?? 0) >= DAILY_LIMIT) return fail(res, 'You have reached the daily request limit. Please try again tomorrow.', 429);

    let q = supabase.from('profiles').select('id').eq('role', 'agent').eq('approved', true);
    if (audience === 'selected') {
      const ids = [...new Set((Array.isArray(req.body?.agent_ids) ? req.body.agent_ids : []).filter((i) => typeof i === 'string'))];
      if (ids.length === 0) return fail(res, 'Select at least one agent.');
      q = q.in('id', ids.slice(0, MAX_RECIPIENTS));
    }
    const { data: agents, error: agErr } = await q.limit(MAX_RECIPIENTS);
    if (agErr) throw agErr;
    if (!agents?.length) return fail(res, 'No eligible agents found for this request.', 404);

    const { data: reqRow, error } = await supabase.from('custom_package_requests')
      .insert([{ client_id: clientId, audience, details: parsed.details }]).select('id, created_at').single();
    if (error) throw error;

    const { error: rcpErr } = await supabase.from('custom_request_recipients')
      .insert(agents.map((a) => ({ request_id: reqRow.id, agent_id: a.id })));
    if (rcpErr) {
      await supabase.from('custom_package_requests').delete().eq('id', reqRow.id);
      throw rcpErr;
    }

    return res.status(201).json({ success: true, request_id: reqRow.id, notified_agents: agents.length });
  } catch (e) { return serverError(res, e, 'createRequest'); }
};

// GET /api/inquiries/mine — client's requests + agent proposals
export const listMyRequests = async (req, res) => {
  try {
    const { data: reqs, error } = await supabase.from('custom_package_requests')
      .select('id, audience, details, status, created_at')
      .eq('client_id', req.user.id).order('created_at', { ascending: false }).limit(50);
    if (error) throw error;
    if (!reqs?.length) return res.json({ success: true, requests: [] });

    const { data: rcps, error: rErr } = await supabase.from('custom_request_recipients')
      .select('id, request_id, agent_id, status, message, price, package_id, offer, client_decision, responded_at')
      .in('request_id', reqs.map((r) => r.id));
    if (rErr) throw rErr;

    const responded = (rcps ?? []).filter((r) => r.status === 'responded');
    const agentIds = [...new Set(responded.map((r) => r.agent_id))];
    const { data: profs } = agentIds.length
      ? await supabase.from('profiles').select('id, company_name, first_name, last_name, agent_number').in('id', agentIds)
      : { data: [] };
    const profMap = new Map((profs ?? []).map((p) => [p.id, p]));

    return res.json({
      success: true,
      requests: reqs.map((r) => {
        const mine = (rcps ?? []).filter((x) => x.request_id === r.id);
        return {
          ...r,
          ref: refCode(r.id),
          sent_to: mine.length,
          viewed_by: mine.filter((x) => x.status !== 'new').length,
          responses: mine.filter((x) => x.status === 'responded').map((x) => ({
            id: x.id,
            agent_name: agentLabel(profMap.get(x.agent_id)),
            agent_number: profMap.get(x.agent_id)?.agent_number ?? null,
            message: x.message, price: x.price, package_id: x.package_id, responded_at: x.responded_at,
            offer: x.offer ?? null, client_decision: x.client_decision ?? null,
          })),
        };
      }),
    });
  } catch (e) { return serverError(res, e, 'listMyRequests'); }
};

// POST /api/inquiries/:id/offers/:recipientId/decision { decision: 'accept'|'decline' }
export const decideOffer = async (req, res) => {
  const accept = req.body?.decision === 'accept';
  if (!accept && req.body?.decision !== 'decline') return fail(res, 'Invalid decision.');
  try {
    const { data: reqRow } = await supabase.from('custom_package_requests')
      .select('id, status').eq('id', req.params.id).eq('client_id', req.user.id).maybeSingle();
    if (!reqRow) return fail(res, 'Request not found.', 404);
    if (reqRow.status !== 'open') return fail(res, 'This request is no longer open.', 409);

    const { data: rcp } = await supabase.from('custom_request_recipients')
      .select('id, status, client_decision').eq('id', req.params.recipientId).eq('request_id', reqRow.id).maybeSingle();
    if (!rcp || rcp.status !== 'responded') return fail(res, 'Offer not found.', 404);
    if (rcp.client_decision) return fail(res, 'You have already responded to this offer.', 409);

    const now = new Date().toISOString();
    const { error } = await supabase.from('custom_request_recipients')
      .update({ client_decision: accept ? 'accepted' : 'declined', decided_at: now }).eq('id', rcp.id);
    if (error) throw error;
    if (accept) {
      await supabase.from('custom_package_requests')
        .update({ status: 'accepted', updated_at: now }).eq('id', reqRow.id);
    }
    return res.json({ success: true });
  } catch (e) { return serverError(res, e, 'decideOffer'); }
};

// POST /api/inquiries/:id/close
export const closeRequest = async (req, res) => {
  try {
    const { data, error } = await supabase.from('custom_package_requests')
      .update({ status: 'closed', updated_at: new Date().toISOString() })
      .eq('id', req.params.id).eq('client_id', req.user.id).select('id').maybeSingle();
    if (error) throw error;
    if (!data) return fail(res, 'Request not found.', 404);
    return res.json({ success: true });
  } catch (e) { return serverError(res, e, 'closeRequest'); }
};

// ── Agent ────────────────────────────────────────────────────────────────────

// GET /api/inquiries/agent/incoming — anonymised: no client identity
export const listIncoming = async (req, res) => {
  try {
    // Agents approved after a broadcast ("all agents") request was sent never
    // got a recipient row; attach them to still-open broadcasts on first load.
    const { data: me } = await supabase.from('profiles').select('role, approved').eq('id', req.user.id).maybeSingle();
    if (me?.role === 'agent' && me.approved) {
      const [{ data: open }, { data: have }] = await Promise.all([
        supabase.from('custom_package_requests').select('id').eq('audience', 'all').eq('status', 'open').limit(200),
        supabase.from('custom_request_recipients').select('request_id').eq('agent_id', req.user.id),
      ]);
      const haveSet = new Set((have ?? []).map((x) => x.request_id));
      const missing = (open ?? []).filter((x) => !haveSet.has(x.id));
      if (missing.length) {
        await supabase.from('custom_request_recipients').upsert(
          missing.map((x) => ({ request_id: x.id, agent_id: req.user.id })),
          { onConflict: 'request_id,agent_id', ignoreDuplicates: true },
        );
      }
    }

    const { data: rcps, error } = await supabase.from('custom_request_recipients')
      .select('id, request_id, status, message, price, package_id, offer, client_decision, responded_at, created_at')
      .eq('agent_id', req.user.id).order('created_at', { ascending: false }).limit(100);
    if (error) throw error;
    if (!rcps?.length) return res.json({ success: true, requests: [], unread: 0 });

    const { data: reqs, error: qErr } = await supabase.from('custom_package_requests')
      .select('id, audience, details, status, created_at').in('id', rcps.map((r) => r.request_id));
    if (qErr) throw qErr;
    const map = new Map((reqs ?? []).map((r) => [r.id, r]));

    const requests = rcps.filter((r) => map.has(r.request_id)).map((r) => {
      const q = map.get(r.request_id);
      return {
        recipient_id: r.id, ref: refCode(r.request_id), audience: q.audience, details: q.details,
        request_status: q.status, my_status: r.status, my_message: r.message, my_price: r.price,
        my_package_id: r.package_id, my_offer: r.offer ?? null, client_decision: r.client_decision ?? null,
        received_at: r.created_at, responded_at: r.responded_at,
      };
    });
    return res.json({ success: true, requests, unread: requests.filter((r) => r.my_status === 'new' && r.request_status === 'open').length });
  } catch (e) { return serverError(res, e, 'listIncoming'); }
};

// GET /api/inquiries/agent/unread-count — cheap, polled by the dashboard badge
export const unreadCount = async (req, res) => {
  try {
    const { count, error } = await supabase.from('custom_request_recipients')
      .select('id', { count: 'exact', head: true }).eq('agent_id', req.user.id).eq('status', 'new');
    if (error) throw error;
    return res.json({ success: true, unread: count ?? 0 });
  } catch (e) { return serverError(res, e, 'unreadCount'); }
};

// POST /api/inquiries/agent/:recipientId/view
export const markViewed = async (req, res) => {
  try {
    await supabase.from('custom_request_recipients')
      .update({ status: 'viewed', viewed_at: new Date().toISOString() })
      .eq('id', req.params.recipientId).eq('agent_id', req.user.id).eq('status', 'new');
    return res.json({ success: true });
  } catch (e) { return serverError(res, e, 'markViewed'); }
};

// POST /api/inquiries/agent/:recipientId/respond { decline?, message, price?, package_id? }
export const respond = async (req, res) => {
  const agentId = req.user.id;
  const decline = req.body?.decline === true;
  const message = cleanText(req.body?.message, 1500);
  const price = Number(req.body?.price);
  const offer = decline ? null : sanitizeOffer(req.body?.offer);
  const offerHasContent = !!offer && Object.keys(offer).some((k) => k !== 'currency');
  if (!decline && !message && !offerHasContent) return fail(res, 'Add offer details or a short message.');
  if (!decline && req.body?.price != null && req.body.price !== '' && !(price > 0 && price < 1e9)) return fail(res, 'Invalid price.');
  const headline = !decline ? (offer?.adult_price ?? (price > 0 ? price : null)) : null;

  try {
    const { data: rcp, error } = await supabase.from('custom_request_recipients')
      .select('id, request_id, client_decision').eq('id', req.params.recipientId).eq('agent_id', agentId).maybeSingle();
    if (error) throw error;
    if (!rcp) return fail(res, 'Request not found.', 404);
    if (rcp.client_decision) return fail(res, 'The client has already responded to this offer.', 409);

    const { data: reqRow } = await supabase.from('custom_package_requests')
      .select('id, status, client_id, guest_whatsapp, guest_email').eq('id', rcp.request_id).maybeSingle();
    if (reqRow?.status !== 'open') return fail(res, 'This request is closed.', 409);

    let package_id = null;
    if (!decline && typeof req.body?.package_id === 'string' && req.body.package_id) {
      const { data: pkg } = await supabase.from('packages').select('id')
        .eq('id', req.body.package_id).eq('created_by', agentId).maybeSingle();
      package_id = pkg?.id ?? null;
    }

    const { error: upErr } = await supabase.from('custom_request_recipients').update({
      status: decline ? 'declined' : 'responded',
      message: decline ? null : (message || null),
      price: headline,
      offer: offerHasContent ? offer : null,
      package_id,
      responded_at: new Date().toISOString(),
    }).eq('id', rcp.id);
    if (upErr) throw upErr;

    const { data: agent } = await supabase.from('profiles')
      .select('company_name, first_name, last_name').eq('id', agentId).maybeSingle();
    const agentName = agentLabel(agent);

    // Guests have no dashboard — push the reply out via WhatsApp + email.
    // Signed-in clients get a WhatsApp prompt to log in and review the offer.
    // Non-critical: failures here never fail the agent's request.
    if (!reqRow.client_id && (reqRow.guest_whatsapp || reqRow.guest_email)) {
      notifyGuestOfReply({
        ref: refCode(rcp.request_id),
        whatsapp: reqRow.guest_whatsapp,
        email: reqRow.guest_email,
        agentName,
        decline,
        message,
        price: !decline && price > 0 ? price : null,
      }).catch((e) => logger.error('Guest reply notification failed', { error: e?.message, requestId: rcp.request_id }));
    }
    if (reqRow.client_id) {
      notifyClientOfReply({
        requestId: reqRow.id,
        requestRef: refCode(reqRow.id),
        clientId: reqRow.client_id,
        agentName,
        decline,
        message,
        price: headline,
      }).catch((e) => logger.error('Client reply notification failed', { error: e?.message, requestId: rcp.request_id }));
    }

    return res.json({ success: true });
  } catch (e) { return serverError(res, e, 'respond'); }
};

// Pushes an agent's reply to a guest requester, who has no dashboard to
// check. WhatsApp requires an approved Content Template (business-initiated
// message, outside Twilio Verify's OTP-only scope) — configure its SID in
// TWILIO_TEMPLATE_CUSTOM_REQUEST_REPLY_SID. Email always attempts to send
// regardless of WhatsApp template availability.
async function notifyGuestOfReply({ ref, whatsapp, email, agentName, decline, message, price }) {
  const templateSid = process.env.TWILIO_TEMPLATE_CUSTOM_REQUEST_REPLY_SID;
  if (whatsapp && templateSid) {
    const summary = decline
      ? `${agentName} isn't able to take on your request this time. Other agents may still respond.`
      : `${agentName} sent an offer${price ? ` of $${price.toLocaleString('en-US')}` : ''}: ${(message || '').slice(0, 300)}`;
    await sendWhatsAppTemplate({
      to: whatsapp, templateSid, templateName: 'custom_request_reply',
      variables: { 1: ref, 2: summary }, category: 'other', meta: { recipientType: 'guest' },
    });
  } else if (whatsapp && !templateSid) {
    logger.warn('Custom request reply: TWILIO_TEMPLATE_CUSTOM_REQUEST_REPLY_SID not set — WhatsApp notification skipped, email only.');
  }

  if (email) {
    await sendCustomRequestReplyEmail({ to: email, ref, agentName, decline, message, price });
  }
}

async function notifyClientOfReply({ requestId, requestRef, clientId, agentName, decline, message, price }) {
  const { data: profile } = await supabase.from('profiles')
    .select('phone').eq('id', clientId).maybeSingle();
  const phone = profile?.phone;
  if (!phone) return;

  const templateSid = process.env.TWILIO_TEMPLATE_CUSTOM_REQUEST_REPLY_SID;
  if (!templateSid) {
    logger.warn('Client custom request reply: TWILIO_TEMPLATE_CUSTOM_REQUEST_REPLY_SID not set — WhatsApp notification skipped.');
    return;
  }

  const dashboardUrl = customDashboardUrl(requestId);
  const summary = decline
    ? `${agentName} declined this request. Open your dashboard to review other agent offers: ${dashboardUrl}`
    : `${agentName} sent an offer${price ? ` from $${price.toLocaleString('en-US')} per adult` : ''}. Log in to review, accept, upload passports, and pay: ${dashboardUrl}`;

  await sendWhatsAppTemplate({
    to: phone,
    templateSid,
    templateName: 'custom_request_reply',
    variables: { 1: requestRef, 2: summary },
    category: 'other',
    meta: { recipientType: 'client', recipientId: clientId },
  });
}

// ── Guest (unauthenticated) ──────────────────────────────────────────────────
// Guests may request a custom package without an account, but must verify a
// WhatsApp number (Twilio Verify OTP) and supply an email first. Agent
// replies are pushed out to both — there is no dashboard to check.

// POST /api/inquiries/guest/otp/send { whatsapp }
export const sendGuestOtp = async (req, res) => {
  const e164 = toE164(req.body?.whatsapp);
  if (!e164) return fail(res, 'Enter a valid WhatsApp number, including country code.');

  try {
    const since = new Date(Date.now() - 86400000).toISOString();
    const ip = String(req.ip || '').slice(0, 64);
    const { count: phoneCount } = await supabase.from('guest_otp_throttle')
      .select('id', { count: 'exact', head: true }).eq('phone', e164).gte('created_at', since);
    if ((phoneCount ?? 0) >= GUEST_OTP_MAX_PER_PHONE_PER_DAY) {
      return fail(res, 'Too many verification attempts for this number today. Please try again tomorrow.', 429);
    }
    if (ip) {
      const { count: ipCount } = await supabase.from('guest_otp_throttle')
        .select('id', { count: 'exact', head: true }).eq('ip', ip).gte('created_at', since);
      if ((ipCount ?? 0) >= GUEST_OTP_MAX_PER_IP_PER_DAY) {
        return fail(res, 'Too many verification attempts from this device today. Please try again tomorrow.', 429);
      }
    }

    const sent = await sendGuestWhatsAppOtp(e164);
    await supabase.from('guest_otp_throttle').insert([{ phone: e164, ip: ip || null }]);
    if (!sent.ok) return fail(res, sent.error || 'Could not send the verification code.', 502);

    return res.json({ success: true, message: 'A verification code was sent to your WhatsApp number.' });
  } catch (e) { return serverError(res, e, 'sendGuestOtp'); }
};

// POST /api/inquiries/guest/otp/verify { whatsapp, code } → short-lived token
export const verifyGuestOtp = async (req, res) => {
  const e164 = toE164(req.body?.whatsapp);
  const code = String(req.body?.code ?? '').trim();
  if (!e164) return fail(res, 'Enter a valid WhatsApp number, including country code.');
  if (!/^\d{4,10}$/.test(code)) return fail(res, 'Enter the verification code you received.');

  try {
    const checked = await checkGuestWhatsAppOtp(e164, code);
    if (!checked.ok) return fail(res, checked.error || 'Verification is temporarily unavailable.', 502);
    if (!checked.approved) return fail(res, 'That code is incorrect or has expired. Request a new one.');

    const token = jwt.sign(
      { purpose: 'guest_inquiry', whatsapp: e164 },
      config.jwt.accessTokenSecret,
      { expiresIn: GUEST_TOKEN_TTL, issuer: config.jwt.issuer, audience: GUEST_TOKEN_AUDIENCE },
    );
    return res.json({ success: true, token, expires_in: GUEST_TOKEN_TTL });
  } catch (e) { return serverError(res, e, 'verifyGuestOtp'); }
};

// POST /api/inquiries/guest { token, email, audience, agent_ids?, details }
export const createGuestRequest = async (req, res) => {
  let decoded;
  try {
    decoded = jwt.verify(req.body?.token, config.jwt.accessTokenSecret, {
      audience: GUEST_TOKEN_AUDIENCE, issuer: config.jwt.issuer,
    });
    if (decoded?.purpose !== 'guest_inquiry' || !decoded?.whatsapp) throw new Error('bad token');
  } catch {
    // 409, not 401 — this is an unauthenticated public endpoint, and a 401
    // here would otherwise trip the frontend's session-expiry/auth-refresh
    // interceptor meant for logged-in users.
    return fail(res, 'Your WhatsApp verification has expired. Please verify your number again.', 409);
  }
  const whatsapp = decoded.whatsapp;

  const email = String(req.body?.email ?? '').trim().toLowerCase();
  if (!EMAIL_RE.test(email) || email.length > 160) return fail(res, 'Enter a valid email address.');

  const audience = req.body?.audience === 'all' ? 'all' : req.body?.audience === 'selected' ? 'selected' : null;
  if (!audience) return fail(res, 'Choose who should receive this request.');

  const parsed = sanitizeDetails(req.body?.details);
  if (parsed.error) return fail(res, parsed.error);

  try {
    const since = new Date(Date.now() - 86400000).toISOString();
    const { count } = await supabase.from('custom_package_requests')
      .select('id', { count: 'exact', head: true }).eq('guest_whatsapp', whatsapp).gte('created_at', since);
    if ((count ?? 0) >= DAILY_LIMIT) return fail(res, 'You have reached the daily request limit. Please try again tomorrow.', 429);

    let q = supabase.from('profiles').select('id').eq('role', 'agent').eq('approved', true);
    if (audience === 'selected') {
      const ids = [...new Set((Array.isArray(req.body?.agent_ids) ? req.body.agent_ids : []).filter((i) => typeof i === 'string'))];
      if (ids.length === 0) return fail(res, 'Select at least one agent.');
      q = q.in('id', ids.slice(0, MAX_RECIPIENTS));
    }
    const { data: agents, error: agErr } = await q.limit(MAX_RECIPIENTS);
    if (agErr) throw agErr;
    if (!agents?.length) return fail(res, 'No eligible agents found for this request.', 404);

    const { data: reqRow, error } = await supabase.from('custom_package_requests')
      .insert([{
        client_id: null, audience, details: parsed.details,
        guest_whatsapp: whatsapp, guest_email: email, guest_verified_at: new Date().toISOString(),
      }]).select('id, created_at').single();
    if (error) throw error;

    const { error: rcpErr } = await supabase.from('custom_request_recipients')
      .insert(agents.map((a) => ({ request_id: reqRow.id, agent_id: a.id })));
    if (rcpErr) {
      await supabase.from('custom_package_requests').delete().eq('id', reqRow.id);
      throw rcpErr;
    }

    return res.status(201).json({
      success: true, request_id: reqRow.id, ref: refCode(reqRow.id), notified_agents: agents.length,
    });
  } catch (e) { return serverError(res, e, 'createGuestRequest'); }
};
