/**
 * Agent verification gate.
 *
 * Blocks any route from running unless the authenticated agent's documents
 * are fully approved (every REQUIRED document type — see superadmin_routes.js
 * DOC_FIELD_MAP / REQUIRED_DOC_KEYS — independently marked 'approved').
 *
 * Use this AFTER verifyToken/requireAuth (it needs req.user / req.userId)
 * and BEFORE any handler that lets an agent create or publish something
 * that should only be visible once the agency is confirmed genuine.
 *
 * Current usage: routes/packages/packages.route.js → POST /create-packages
 */
import { supabaseAdmin as supabase } from '../config/supabase.js';

export const requireApprovedAgent = async (req, res, next) => {
  try {
    const agentId = req.user?.id ?? req.userId;
    if (!agentId) {
      return res.status(401).json({ success: false, message: 'Authentication required' });
    }

    const { data: profile, error: profileError } = await supabase
      .from('profiles')
      .select('approved, verification_status, role')
      .eq('id', agentId)
      .single();

    if (profileError || !profile) {
      return res.status(403).json({
        success: false,
        code: 'AGENT_NOT_VERIFIED',
        message: 'Could not verify your agency status. Please contact support.',
      });
    }

    if (profile.role !== 'agent') {
      // Not an agent account at all — let downstream auth/role checks handle it.
      return next();
    }

    if (profile.approved && profile.verification_status === 'approved') {
      return next();
    }

    // Not approved yet — tell the frontend exactly why, so it can route the
    // agent to either "upload documents" or "request review" rather than
    // just a generic 403.
    const { data: docRow } = await supabase
      .from('agent_documents')
      .select('id, status, review_requested_at, incorporation_doc, tourism_doc, krapin_doc, director_id_doc')
      .eq('user_id', agentId)
      .maybeSingle();

    const hasUploadedAny = !!(
      docRow && (docRow.incorporation_doc || docRow.tourism_doc || docRow.krapin_doc || docRow.director_id_doc)
    );

    return res.status(403).json({
      success: false,
      code: 'AGENT_NOT_VERIFIED',
      message: profile.verification_status === 'rejected'
        ? 'One or more of your documents was not approved. Please review the feedback and re-upload.'
        : hasUploadedAny
          ? 'Your documents are still under review. You can request a priority review or wait for the team to finish.'
          : 'You need to upload your verification documents before you can post packages.',
      data: {
        verificationStatus: profile.verification_status || 'pending',
        hasUploadedDocuments: hasUploadedAny,
        reviewRequested: !!docRow?.review_requested_at,
      },
    });
  } catch (err) {
    
    return res.status(500).json({ success: false, message: 'Failed to verify agent status' });
  }
};

export default requireApprovedAgent;