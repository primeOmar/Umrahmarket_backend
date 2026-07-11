/**
 * Public agent directory — powers AgentsPage.jsx and AgentDetailPage.jsx.
 * ASSUMPTIONS — verify against actual schema before wiring in:
 *   - profiles table has a `role` column with value 'agent'
 *   - profiles columns: business_name, first_name, last_name, avatar_url,
 *     city, country, phone, email, bio, verification_status, rating,
 *     created_at
 *   - packages table has an `agent_id` FK to profiles.id, plus
 *     title, price, image, duration, status
 * Adjust `.select(...)` field lists and table/column names to match your
 * actual Supabase schema if these are off.
 */
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
      .select('id, business_name, first_name, last_name, avatar_url, city, country, verification_status, rating, created_at')
      .eq('role', 'agent');

    if (error) throw error;

    const agentIds = agents.map((a) => a.id);
    let countMap = {};

    if (agentIds.length > 0) {
      const { data: pkgRows, error: pkgErr } = await supabase
        .from('packages')
        .select('agent_id')
        .in('agent_id', agentIds);

      if (pkgErr) throw pkgErr;
      countMap = pkgRows.reduce((acc, p) => {
        acc[p.agent_id] = (acc[p.agent_id] || 0) + 1;
        return acc;
      }, {});
    }

    const result = agents.map((a) => ({
      id: a.id,
      businessName: a.business_name,
      firstName: a.first_name,
      lastName: a.last_name,
      avatar: a.avatar_url,
      city: a.city,
      country: a.country,
      location: [a.city, a.country].filter(Boolean).join(', '),
      verificationStatus: a.verification_status,
      packageCount: countMap[a.id] || 0,
      rating: a.rating || 0,
    }));

    res.json({ success: true, agents: result });
  } catch (err) {
    console.error('[agents] list error:', err);
    res.status(500).json({ success: false, message: 'Failed to load agents' });
  }
});

// ── GET /api/agents/:id ────────────────────────────────────────────────────
// Public agent profile + the packages they've posted.
router.get('/:id', async (req, res) => {
  try {
    const { id } = req.params;

    const { data: agent, error } = await supabase
      .from('profiles')
      .select('id, business_name, first_name, last_name, avatar_url, city, country, phone, email, bio, verification_status, rating, created_at')
      .eq('id', id)
      .eq('role', 'agent')
      .maybeSingle();

    if (error) throw error;
    if (!agent) {
      return res.status(404).json({ success: false, message: 'Agent not found' });
    }

    const { data: packages, error: pkgErr } = await supabase
      .from('packages')
      .select('id, title, price, image, duration, status')
      .eq('agent_id', id)
      .order('created_at', { ascending: false });

    if (pkgErr) throw pkgErr;

    res.json({
      success: true,
      agent: {
        id: agent.id,
        businessName: agent.business_name,
        firstName: agent.first_name,
        lastName: agent.last_name,
        avatar: agent.avatar_url,
        city: agent.city,
        country: agent.country,
        location: [agent.city, agent.country].filter(Boolean).join(', '),
        phone: agent.phone,
        email: agent.email,
        bio: agent.bio,
        verificationStatus: agent.verification_status,
        rating: agent.rating || 0,
        memberSince: agent.created_at ? new Date(agent.created_at).getFullYear() : null,
        packages: packages || [],
      },
    });
  } catch (err) {
    console.error('[agents] detail error:', err);
    res.status(500).json({ success: false, message: 'Failed to load agent' });
  }
});

export default router;