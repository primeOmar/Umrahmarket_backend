/**
 * Public agent directory — powers AgentsPage.jsx and AgentDetailPage.jsx.
 * No auth: these are public profiles, unlike agent_documents.routes.js
 * (self-service, requireAuth, scoped to req.user.id).
 *
 * Office photo is the one exception to "everything lives on profiles" —
 * it's uploaded via document.routes.js into the agent_documents table as
 * R2 object keys, not public URLs, so it needs the same signed-URL dance
 * document.routes.js does for GET /api/documents.
 * */
import express from 'express';
import { S3Client, GetObjectCommand } from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import { supabaseAdmin as supabase } from '../config/supabase.js';

const router = express.Router();

// ─── R2 client (read-only — presigned URLs), same config as document.routes.js ─
const R2 = new S3Client({
  region: 'auto',
  endpoint: `https://${process.env.CLOUDFLARE_ACCOUNT_ID}.r2.cloudflarestorage.com`,
  credentials: {
    accessKeyId:     process.env.CLOUDFLARE_R2_ACCESS_KEY_ID,
    secretAccessKey: process.env.CLOUDFLARE_R2_SECRET_ACCESS_KEY,
  },
});
const BUCKET = process.env.CLOUDFLARE_R2_BUCKET_NAME;

// Office photo is agent-submitted KYC material, not something re-uploaded
// through the profile editor — so unlike bio/logo, only show it publicly
// once it isn't rejected. Treat missing/pending status as "still show it"
// (matches the rest of this file's "not gated by verification" approach);
// flip to `=== 'approved'` only if you want it hidden until reviewed.
const getOfficePhotoUrls = async (agentId) => {
  try {
    const { data: docRow } = await supabase
      .from('agent_documents')
      .select('office_photo, office_photo_status')
      .eq('user_id', agentId)
      .maybeSingle();

    if (!docRow || docRow.office_photo_status === 'rejected') return [];

    const keys = Array.isArray(docRow.office_photo)
      ? docRow.office_photo
      : (docRow.office_photo ? [docRow.office_photo] : []);

    if (keys.length === 0) return [];

    const urls = await Promise.all(
      keys.map((key) =>
        getSignedUrl(R2, new GetObjectCommand({ Bucket: BUCKET, Key: key }), { expiresIn: 3600 })
          .catch((err) => {
            console.warn(`[agents] office photo signed URL failed for ${key}:`, err.message);
            return null;
          })
      )
    );

    return urls.filter(Boolean);
  } catch (err) {
    console.warn(`[agents] office photo lookup failed for ${agentId}:`, err.message);
    return [];
  }
};

// ── GET /api/agents ───────────────────────────────────────────────────────
// Public list of all agents. Not gated by verification status — the
// frontend badge shows verified/pending per-agent instead.
router.get('/', async (req, res) => {
  try {
    const { data: agents, error } = await supabase
      .from('profiles')
      .select('id, first_name, last_name, company_name, verification_status, approved, agent_number, office_maps_url, created_at, bio, logo_url, years_experience, specialties, website_url')
      .eq('role', 'agent');

    if (error) throw error;

    const agentIds = agents.map((a) => a.id);
    let countMap = {};

    if (agentIds.length > 0) {
      const { data: pkgRows, error: pkgErr } = await supabase
        .from('packages')
        .select('created_by')
        .in('created_by', agentIds);

      if (pkgErr) throw pkgErr;
      countMap = pkgRows.reduce((acc, p) => {
        acc[p.created_by] = (acc[p.created_by] || 0) + 1;
        return acc;
      }, {});
    }

    const result = agents.map((a) => ({
      id: a.id,
      businessName: a.company_name,
      firstName: a.first_name,
      lastName: a.last_name,
      verificationStatus: a.verification_status,
      approved: a.approved,
      agentNumber: a.agent_number,
      officeMapsUrl: a.office_maps_url,
      bio: a.bio,
      logoUrl: a.logo_url,
      yearsExperience: a.years_experience,
      specialties: a.specialties || [],
      websiteUrl: a.website_url,
      packageCount: countMap[a.id] || 0,
    }));

    res.json({ success: true, agents: result });
  } catch (err) {
    console.error('[agents] list error:', err);
    res.status(500).json({ success: false, message: 'Failed to load agents' });
  }
});

// ── GET /api/agents/:id ────────────────────────────────────────────────────
// Public agent profile + the packages they've posted (via packages.created_by).
router.get('/:id', async (req, res) => {
  try {
    const { id } = req.params;

    const { data: agent, error } = await supabase
      .from('profiles')
      .select('id, first_name, last_name, company_name, verification_status, approved, agent_number, office_maps_url, created_at, bio, logo_url, years_experience, specialties, website_url')
      .eq('id', id)
      .eq('role', 'agent')
      .maybeSingle();

    if (error) throw error;
    if (!agent) {
      return res.status(404).json({ success: false, message: 'Agent not found' });
    }

    const { data: packages, error: pkgErr } = await supabase
      .from('packages')
      .select('id, name, price, original_price, discount, duration, image_urls, status, location')
      .eq('created_by', id)
      .order('created_at', { ascending: false });

    if (pkgErr) throw pkgErr;

    const officePhotos = await getOfficePhotoUrls(id);

    res.json({
      success: true,
      agent: {
        id: agent.id,
        businessName: agent.company_name,
        firstName: agent.first_name,
        lastName: agent.last_name,
        verificationStatus: agent.verification_status,
        approved: agent.approved,
        agentNumber: agent.agent_number,
        officeMapsUrl: agent.office_maps_url,
        bio: agent.bio,
        logoUrl: agent.logo_url,
        yearsExperience: agent.years_experience,
        specialties: agent.specialties || [],
        websiteUrl: agent.website_url,
        officePhotos,
        memberSince: agent.created_at ? new Date(agent.created_at).getFullYear() : null,
        packages: (packages || []).map((p) => ({
          id: p.id,
          title: p.name,
          price: p.price,
          originalPrice: p.original_price,
          discount: p.discount,
          duration: p.duration,
          image: Array.isArray(p.image_urls) ? p.image_urls[0] : null,
          status: p.status,
          location: p.location,
        })),
      },
    });
  } catch (err) {
    console.error('[agents] detail error:', err);
    res.status(500).json({ success: false, message: 'Failed to load agent' });
  }
});

export default router;