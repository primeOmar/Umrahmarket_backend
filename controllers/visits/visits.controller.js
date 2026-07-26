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

// GET /getagentvisits?agentId=<uuid>   (agentId optional — omit for the latest across all agents)
export const getAgentVisits = async (req, res) => {
  try {
    const { agentId } = req.query;

    let query = supabaseAdmin
      .from('agent_visits')
      .select('*', { count: 'exact' })
      .eq('visit_type', 'agent')
      .order('visited_at', { ascending: false });

    if (agentId) query = query.eq('agent_id', agentId);
    else query = query.limit(100); // guard against dumping the whole table when unfiltered

    const { data, error, count } = await query;
    if (error) throw error;

    res.json({ visits: data, totalVisits: count ?? 0 });
  } catch (err) {
    console.error('[getAgentVisits]', err);
    res.status(500).json({ error: 'Failed to fetch agent visits' });
  }
};

// GET /getpackagesvisits?packageId=<uuid>   (packageId optional — omit for the latest across all packages)
export const getPackageAgentVisits = async (req, res) => {
  try {
    const { packageId } = req.query;

    let query = supabaseAdmin
      .from('agent_visits')
      .select('*', { count: 'exact' })
      .eq('visit_type', 'package')
      .order('visited_at', { ascending: false });

    if (packageId) query = query.eq('package_id', packageId);
    else query = query.limit(100);

    const { data, error, count } = await query;
    if (error) throw error;

    res.json({ visits: data, totalVisits: count ?? 0 });
  } catch (err) {
    console.error('[getPackageAgentVisits]', err);
    res.status(500).json({ error: 'Failed to fetch package visits' });
  }
};