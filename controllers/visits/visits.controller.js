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
};

// GET /getagentvisits?agentId=<uuid>
//   - with agentId  -> unchanged shape: { visits: [...], totalVisits }
//   - without agentId -> NEW shape: one entry per agent, each carrying its
//     own full visit history + denormalized details, in a single query.
//     Replaces the old "latest 100 rows, then N follow-up calls per agent"
//     pattern the frontend was doing.
export const getAgentVisits = async (req, res) => {
  try {
    const { agentId } = req.query;

    let query = supabaseAdmin
      .from('agent_visits')
      .select('*')
      .eq('visit_type', 'agent')
      .order('visited_at', { ascending: false });

    if (agentId) query = query.eq('agent_id', agentId);

    const { data, error } = await query;
    if (error) throw error;

    if (agentId) {
      return res.json({ visits: data, totalVisits: data.length });
    }

    const byAgent = new Map();
    for (const row of data) {
      if (!byAgent.has(row.agent_id)) {
        byAgent.set(row.agent_id, {
          agentId: row.agent_id,
          agentName: row.agent_name,
          verificationStatus: row.verification_status,
          yearsExperience: row.years_experience,
          totalVisits: 0,
          visits: [],
        });
      }
      const entry = byAgent.get(row.agent_id);
      entry.totalVisits += 1;
      entry.visits.push(row);
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