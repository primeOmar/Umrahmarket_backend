import supabase from '../../config/supabase.js';
import { handleDatabaseError } from './createpackages.controller.js';

// ─────────────────────────────────────────────────────────────────────────────
// getAllActivePackages  GET /api/packages/all-active
//
// Public endpoint — returns all packages with status = 'Active'
// from every agent, ordered newest first.
// ─────────────────────────────────────────────────────────────────────────────
export const getAllActivePackages = async (req, res) => {
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
         image_urls, created_by, agent_name,
         status, created_at, updated_at`
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