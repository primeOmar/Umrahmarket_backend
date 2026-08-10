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
        `id, name, type, location, cities, city_hotels, description,
         price, price_tiers, original_price, discount, duration,
         available_from, available_to,
         makkah_hotel_rating, makkah_hotel_distance,
         makkah_check_in_date, makkah_check_out_date,
         madinah_check_in_date, madinah_check_out_date,
         image_urls, highlights, inclusions,
         agent_name, agent_number,
         status`
      )
      .eq('status', 'Active')
      .order('created_at', { ascending: false });

    if (error) {
      // Log but respond gracefully — never let a DB error become a 500 on a public route
      
      return res.status(200).json({
        success:  true,
        packages: [],
        total:    0,
        _warning: 'Could not load packages at this time.',
      });
    }

    return res.status(200).json({
      success:  true,
      packages: data ?? [],
      total:    data?.length ?? 0,
    });

  } catch (error) {
    // Unexpected crash — log and return empty list, not a 500
    
    return res.status(200).json({
      success:  true,
      packages: [],
      total:    0,
      _warning: 'Could not load packages at this time.',
    });
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// getPackageById  GET /api/packages/:id
//
// Single-package fetch used by the frontend's fallback path (packagesApi.js
// getPackageById) whenever a package isn't already in the preloaded public
// list — direct links, page refreshes, or an agent previewing their own
// Draft/Inactive package. Selects the SAME columns as getAllActivePackages,
// including price_tiers, so the client-side normalise() always has real
// per-tier pricing to work with instead of silently falling back every
// tier to the adult price.
//
// Visibility: Active packages are public. Non-Active packages (draft,
// inactive, pending review) are only returned to the agent who owns them —
// everyone else gets a 404, same as if the package didn't exist, so this
// never leaks an unpublished listing.
// ─────────────────────────────────────────────────────────────────────────────
export const getPackageById = async (req, res) => {
  const { id } = req.params;

  try {
    const { data, error } = await supabase
      .from('packages')
      .select(
        `id, name, type, location, cities, city_hotels, description,
         price, price_tiers, original_price, discount, duration,
         available_from, available_to, min_group_size, max_group_size,
         makkah_hotel_name, makkah_hotel_rating, makkah_hotel_distance,
         makkah_hotel_address, makkah_check_in_date, makkah_check_out_date,
         madinah_hotel_name, madinah_hotel_rating, madinah_hotel_distance,
         madinah_hotel_address, madinah_check_in_date, madinah_check_out_date,
         highlights, inclusions, exclusions,
         image_urls, created_by, agent_name, agent_number,
         status, created_at, updated_at`
      )
      .eq('id', id)
      .maybeSingle();

    if (error) {
      return handleDatabaseError(res, error);
    }

    if (!data) {
      return res.status(404).json({ success: false, message: 'Package not found.' });
    }

    // Gate non-Active packages to their owning agent only.
    if (data.status !== 'Active') {
      const requester = req.user; // present only if verifyToken ran and a valid token was sent
      const isOwner =
        requester &&
        requester.agentName   === data.agent_name &&
        requester.agentNumber === data.agent_number;

      if (!isOwner) {
        return res.status(404).json({ success: false, message: 'Package not found.' });
      }
    }

    return res.status(200).json({ success: true, package: data });

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
        `id, name, type, location, cities, city_hotels, description,
         price, price_tiers, original_price, discount, duration,
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