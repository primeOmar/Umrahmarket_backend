/**
 * Agent-facing document verification status + review requests.
 
 * These are called by the AGENT (requireAuth / verifyToken), not the
 * superadmin. Contrast with superadmin_routes.js, which is the admin-side
 * verify/reject UI.
 */
import express from 'express';
import { body } from 'express-validator';
import { requireAuth } from '../middleware/auth.middleware.js';
import { handleValidationErrors } from '../middleware/validation.middleware.js';
import { uploadRateLimiter } from '../middleware/security.middleware.js';
import { supabaseAdmin as supabase } from '../config/supabase.js';
import { sanitizeInput } from '../utils/securityUtils.js';

const router = express.Router();

const DOC_ITEM_KEYS = ['incorporation', 'tourism', 'krapin', 'director_id', 'office_photo'];
// MUST match REQUIRED_DOC_KEYS in superadmin_routes.js exactly. Confirmed
// via DocumentsTab.jsx that a real director_id upload UI exists, so it's
// required again (was briefly excluded before that evidence was available).
const REQUIRED_ITEM_KEYS = ['incorporation', 'tourism', 'krapin', 'director_id'];

// ── GET /api/agent-documents/status ──────────────────────────────────────────
// Drives the AgentDashboard gate: tells the frontend exactly which documents
// are missing, which are pending/approved/rejected, and whether a review
// has already been requested — so it can show the right call-to-action
// ("upload documents" vs "request review" vs "fix rejected item") instead
// of a flat "you're not verified" message.
router.get('/status', requireAuth, async (req, res) => {
  // Prevent browsers and Render's edge cache from serving a stale
  // "isApproved: false" after a superadmin approves the agent's documents.
  // Without this the browser returns a 304 and the agent can never post
  // packages even though the DB already has them approved.
  res.set('Cache-Control', 'no-store');

  try {
    const agentId = req.user?.id ?? req.userId;

    // Fetch both tables in parallel — profiles is the authoritative source
    // for isApproved because requireApprovedAgent middleware reads from there,
    // and agent_documents holds the per-item detail rows.
    const [{ data: doc, error }, { data: profile }] = await Promise.all([
      supabase
        .from('agent_documents')
        .select('*')
        .eq('user_id', agentId)
        .maybeSingle(),
      supabase
        .from('profiles')
        .select('approved, verification_status')
        .eq('id', agentId)
        .maybeSingle(),
    ]);

    if (error) throw error;

    // isApproved derived from profiles — exactly the same condition the
    // requireApprovedAgent middleware checks, so frontend and backend can
    // never disagree on whether the gate should open.
    const isApproved = !!(profile?.approved && profile?.verification_status === 'approved');

    if (!doc) {
      return res.json({
        success: true,
        hasUploadedDocuments: false,
        isApproved,
        reviewRequested: false,
        overallStatus: profile?.verification_status || 'pending',
        items: DOC_ITEM_KEYS.reduce((acc, k) => ({ ...acc, [k]: { uploaded: false, status: 'pending', notes: null } }), {}),
      });
    }

    const fieldMap = {
      incorporation: { url: 'incorporation_doc', status: 'incorporation_status', notes: 'incorporation_notes' },
      tourism:       { url: 'tourism_doc',       status: 'tourism_status',       notes: 'tourism_notes' },
      krapin:        { url: 'krapin_doc',        status: 'krapin_status',        notes: 'krapin_notes' },
      director_id:   { url: 'director_id_doc',   status: 'director_id_status',   notes: 'director_id_notes' },
      office_photo:  { url: 'office_photo',      status: 'office_photo_status',  notes: 'office_photo_notes' },
    };

    const items = {};
    for (const key of DOC_ITEM_KEYS) {
      const f = fieldMap[key];
      items[key] = {
        uploaded: !!doc[f.url],
        status: doc[f.status] || 'pending',
        notes: doc[f.notes] || null,
      };
    }

    const hasUploadedAny = DOC_ITEM_KEYS.some(k => items[k].uploaded);
    const hasUploadedAllRequired = REQUIRED_ITEM_KEYS.every(k => items[k].uploaded);
    const anyRejected = REQUIRED_ITEM_KEYS.some(k => items[k].status === 'rejected');

    // FLAT response — matches the convention used by GET /passport/status
    // (see passport.controller.js / getAgentVerificationStatus's caller in
    // AgentDashboard.jsx, which reads data.isApproved directly, the same
    // way BookingFlow.jsx reads res?.canProceed). The previous shape wrapped
    // everything under an extra `data` key — {success, data: {isApproved}}
    // — which meant `data.isApproved` was always undefined on the frontend,
    // so the verification gate fired on every click regardless of the
    // agent's real status. Do NOT re-nest this under `data` again without
    // also updating every caller in AgentDashboard.jsx.
    res.json({
      success: true,
      hasUploadedDocuments: hasUploadedAny,
      hasUploadedAllRequired,
      isApproved,
      anyRejected,
      reviewRequested: !!doc.review_requested_at,
      reviewRequestedAt: doc.review_requested_at,
      overallStatus: doc.status || 'pending',
      items,
    });
  } catch (err) {
    console.error('[agent-documents/status] error:', err);
    res.status(500).json({ success: false, message: 'Failed to load verification status' });
  }
});

// ── POST /api/agent-documents/request-review ─────────────────────────────────
// "Fast-track" button for an agent who already uploaded documents and is
// just waiting. Doesn't re-upload anything — only stamps review_requested_at
// so the admin list sorts them to the top (see superadmin_routes.js GET
// /documents ordering). Rate-limited so it can't be spammed into a denial
// of service against the admin queue.
router.post(
  '/request-review',
  requireAuth,
  uploadRateLimiter,
  handleValidationErrors,
  async (req, res) => {
    try {
      const agentId = req.user?.id ?? req.userId;

      const { data: doc, error: fetchError } = await supabase
        .from('agent_documents')
        .select('id, status, incorporation_doc, tourism_doc, krapin_doc, director_id_doc, review_requested_at')
        .eq('user_id', agentId)
        .maybeSingle();

      if (fetchError) throw fetchError;

      if (!doc) {
        return res.status(422).json({
          success: false,
          message: 'You need to upload your documents before requesting a review.',
        });
      }

      if (doc.status === 'approved') {
        return res.status(409).json({ success: false, message: 'Your account is already verified.' });
      }

      const hasUploadedAllRequired = [doc.incorporation_doc, doc.tourism_doc, doc.krapin_doc, doc.director_id_doc]
        .every(Boolean);

      if (!hasUploadedAllRequired) {
        return res.status(422).json({
          success: false,
          message: 'Please upload all required documents (Incorporation, Tourism License, KRA PIN, Director ID) before requesting a review.',
        });
      }

      // Simple cooldown — avoid an agent hammering the button hourly and
      // burying genuinely new requests under repeat pings from the same one.
      if (doc.review_requested_at) {
        const hoursSince = (Date.now() - new Date(doc.review_requested_at).getTime()) / 36e5;
        if (hoursSince < 24) {
          return res.status(429).json({
            success: false,
            message: 'You already requested a review recently. Our team has been notified — please allow 24 hours.',
          });
        }
      }

      const { error: updateError } = await supabase
        .from('agent_documents')
        .update({ review_requested_at: new Date().toISOString() })
        .eq('id', doc.id);

      if (updateError) throw updateError;

      res.json({ success: true, message: 'Review requested. Our team will prioritize your documents shortly.' });
    } catch (err) {
      console.error('[agent-documents/request-review] error:', err);
      res.status(500).json({ success: false, message: 'Failed to request review' });
    }
  },
);

export default router;