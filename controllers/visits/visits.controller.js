// controllers/visits/visits.controller.js
import { supabaseAdmin } from '../../config/supabase.js';

// POST /agentvisits
export const logAgentVisit = async (req, res) => {
  try {
    const { visitorInfo = {}, agentInfo = {} } = req.body || {};

    if (!agentInfo.agentId || !agentInfo.agentName) {
      return res.status(400).json({ error: 'agentInfo.agentId and agentInfo.agentName are required' });
    }

    const row = {
      visit_type: 'agent',

      agent_id: agentInfo.agentId,
      agent_name: agentInfo.agentName,
      verification_status: agentInfo.verificationStatus ?? null,
      years_experience: agentInfo.yearsExperience ?? null,

      visitor_username: visitorInfo.username || 'Anonymous',
      browser: visitorInfo.browser,
      os: visitorInfo.os,
      device: visitorInfo.device,
      screen_resolution: visitorInfo.screenResolution,
      language: visitorInfo.language,
      continent: visitorInfo.location?.continent,
      city: visitorInfo.location?.city,
      time_zone: visitorInfo.location?.timeZone,
      utc_offset: visitorInfo.location?.utcOffset,
    };

    const { data, error } = await supabaseAdmin
      .from('agent_visits')
      .insert([row])
      .select()
      .single();

    if (error) throw error;

    const { count, error: countError } = await supabaseAdmin
      .from('agent_visits')
      .select('*', { count: 'exact', head: true })
      .eq('visit_type', 'agent')
      .eq('agent_id', agentInfo.agentId);

    if (countError) throw countError;

    res.status(201).json('Thank you!');
  } catch (err) {
    console.error('[logAgentVisit]', err);
    res.status(500).json({ error: 'Failed to log agent visit' });
  }
};

// POST /packagevisits
export const logPackageVisit = async (req, res) => {
  try {
    const { visitorInfo = {}, packageInfo = {} } = req.body || {};

    if (!packageInfo.packageId || !packageInfo.packageName) {
      return res.status(400).json({ error: 'packageInfo.packageId and packageInfo.packageName are required' });
    }

    const row = {
      visit_type: 'package',

      package_id: packageInfo.packageId,
      package_name: packageInfo.packageName,
      price: packageInfo.price ?? null,
      duration_days: packageInfo.duration ?? null,
      available_from: packageInfo.availableFrom ?? null,
      available_to: packageInfo.availableTo ?? null,

      agent_id: packageInfo.agentId ?? null,
      agent_name: packageInfo.agentName ?? null,

      visitor_username: visitorInfo.username || 'Anonymous',
      browser: visitorInfo.browser,
      os: visitorInfo.os,
      device: visitorInfo.device,
      screen_resolution: visitorInfo.screenResolution,
      language: visitorInfo.language,
      continent: visitorInfo.location?.continent,
      city: visitorInfo.location?.city,
      time_zone: visitorInfo.location?.timeZone,
      utc_offset: visitorInfo.location?.utcOffset,
    };

    const { data, error } = await supabaseAdmin
      .from('agent_visits')
      .insert([row])
      .select()
      .single();

    if (error) throw error;

    const { count, error: countError } = await supabaseAdmin
      .from('agent_visits')
      .select('*', { count: 'exact', head: true })
      .eq('visit_type', 'package')
      .eq('package_id', packageInfo.packageId);

    if (countError) throw countError;

    res.status(201).json('Thank you!');
  } catch (err) {
    console.error('[logPackageVisit]', err);
    res.status(500).json({ error: 'Failed to log package visit' });
  }
}

export const getAgentVisits = async (req, res) => {
  try {
    const { agentId } = req.query;

    let query = supabaseAdmin
      .from('agent_visits')
      .select('*')
      .order('visited_at', { ascending: false });

    if (agentId) query = query.eq('agent_id', agentId);

    const { data, error } = await query;
    if (error) throw error;

    if (agentId) {
      return res.json({ visits: data, totalVisits: data.length });
    }

    // Group by agent_name, not agent_id: "package"-type rows always have
    // agent_id === null (packages aren't tied to a real agent record the
    // way profile-page visits are), so keying the Map by agent_id collapses
    // every agency's package visits into a single null-keyed bucket. Every
    // row — package or agent type — carries a real agent_name, so that's
    // the stable identity to group on. agent_id/verification/experience are
    // then backfilled opportunistically from whichever row in the group
    // actually has them (i.e. its "agent"-type rows).
    const byAgent = new Map();
    for (const row of data) {
      const key = (row.agent_name || 'unknown').trim().toLowerCase();

      if (!byAgent.has(key)) {
        byAgent.set(key, {
          agentId: null,
          agentName: row.agent_name,
          verificationStatus: null,
          yearsExperience: null,
          totalVisits: 0,
          visits: [],
        });
      }

      const entry = byAgent.get(key);
      entry.totalVisits += 1;
      entry.visits.push(row);

      if (!entry.agentId && row.agent_id) entry.agentId = row.agent_id;
      if (!entry.verificationStatus && row.verification_status) {
        entry.verificationStatus = row.verification_status;
      }
      if (entry.yearsExperience == null && row.years_experience != null) {
        entry.yearsExperience = row.years_experience;
      }
    }

    const agents = [...byAgent.values()].sort(
      (a, b) => b.totalVisits - a.totalVisits
    );

    res.json({ agents, totalVisits: data.length });
  } catch (err) {
    console.error('[getAgentVisits]', err);
    res.status(500).json({ error: 'Failed to fetch agent visits' });
  }
};