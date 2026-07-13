/**
 * Public agent directory — powers AgentsPage.jsx and AgentDetailPage.jsx.
 * No auth: these are public profiles, unlike agent_documents.routes.js
 * (self-service, requireAuth, scoped to req.user.id).
 *
 * */
import express from 'express';
import { supabaseAdmin as supabase } from '../config/supabase.js';

const router = express.Router();

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