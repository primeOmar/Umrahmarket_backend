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
import { S3Client, GetObjectCommand, ListObjectsV2Command } from '@aws-sdk/client-s3';
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
//
// Mirrors document.routes.js's GET / exactly: the DB column doesn't
// reliably hold a signable R2 key, so we list what's actually in the
// bucket under the agent's office_photo prefix and sign THOSE keys.
// Only if that listing comes up empty do we fall back to the raw stored
// value, used as-is (it's already a usable URL in that case, not a key —
// signing it again is what broke the images last time).
const getOfficePhotoUrls = async (agentId) => {
  let docRow = null;
  try {
    const { data } = await supabase
      .from('agent_documents')
      .select('office_photo, office_photo_status')
      .eq('user_id', agentId)
      .maybeSingle();
    docRow = data;
  } catch (err) {
    console.warn(`[agents] office photo lookup failed for ${agentId}:`, err.message);
    return [];
  }

  if (!docRow || docRow.office_photo_status === 'rejected') return [];

  const prefix = `documents/${agentId}/office_photo/`;
  try {
    const { Contents } = await R2.send(new ListObjectsV2Command({ Bucket: BUCKET, Prefix: prefix }));
    if (Contents && Contents.length > 0) {
      const sorted = Contents.sort((a, b) => new Date(b.LastModified) - new Date(a.LastModified));
      const signed = (
        await Promise.all(
          sorted.map((obj) =>
            getSignedUrl(R2, new GetObjectCommand({ Bucket: BUCKET, Key: obj.Key }), { expiresIn: 3600 })
              .catch((err) => {
                console.warn(`[agents] signed URL failed for ${obj.Key}:`, err.message);
                return null;
              })
          )
        )
      ).filter(Boolean);
      if (signed.length > 0) return signed;
    }
  } catch (err) {
    console.warn(`[agents] office photo R2 listing failed for ${agentId}:`, err.message);
  }

  // Fallback — nothing found under the R2 prefix; use the stored value(s)
  // directly, unsigned (same as document.routes.js's fallback branch).
  const stored = Array.isArray(docRow.office_photo)
    ? docRow.office_photo
    : (docRow.office_photo ? [docRow.office_photo] : []);
  return stored.filter(Boolean);
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