import supabase from '../../config/supabase.js';
import { handleDatabaseError } from './createpackages.controller.js';

// ─────────────────────────────────────────────────────────────────────────────
// getAllActivePackages  GET /api/packages/all-active
// Public route — no auth required
// ─────────────────────────────────────────────────────────────────────────────
export const getAllActivePackages = async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('packages')
      .select(
        `id, name, type, location, description,
         price, original_price, discount, duration,
         image_urls, highlights, inclusions,
         makkah_hotel_rating, status`
      )
      .eq('status', 'Active')
      .order('created_at', { ascending: false });

    if (error) {
      console.error('Supabase select error:', error);
      throw error;
    }

    return res.status(200).json({
      success:  true,
      packages: data ?? [],
      total:    data?.length ?? 0,
    });

  } catch (error) {
    return handleDatabaseError(res, error);
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// getAgentPackages  GET /api/packages/getagentpackages
//
// Returns only the packages created by the currently authenticated agent,
// matched by both agent_name and agent_number for safety.
// ─────────────────────────────────────────────────────────────────────────────
export const getAgentPackages = async (req, res) => {
  const { firstName, lastName, agentName, agentNumber } = req.user;
  const createdBy = `${firstName} ${lastName}`;

  try {
    const { data, error } = await supabase
      .from('packages')
      .select(
        `id, name, type, location, description,
         price, original_price, discount, duration,
         available_from, available_to, min_group_size, max_group_size,
         makkah_hotel_name, makkah_hotel_rating, makkah_hotel_distance,
         makkah_hotel_address, makkah_check_in_date, makkah_check_out_date,
         madinah_hotel_name, madinah_hotel_rating, madinah_hotel_distance,
         madinah_hotel_address, madinah_check_in_date, madinah_check_out_date,
         highlights, inclusions, exclusions,
         image_urls, created_by, agent_name, agent_number,
         status, created_at, updated_at`
      )
      // Match on agent_name + agent_number so two agents with the same full
      // name can never see each other's packages.
      .eq('agent_name',   agentName)
      .eq('agent_number', agentNumber)
      .order('created_at', { ascending: false });

    if (error) {
      console.error('Supabase select error:', error);
      throw error;
    }

    return res.status(200).json({
      success:  true,
      packages: data ?? [],
      total:    data?.length ?? 0,
    });

  } catch (error) {
    return handleDatabaseError(res, error);
  }
};