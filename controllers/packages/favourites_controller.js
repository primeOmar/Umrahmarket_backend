import supabase from '../../config/supabase.js';

// ─────────────────────────────────────────────────────────────────────────────
// Toggle favourite  POST /api/favourites/toggle
// Body: { packageId }
// Returns: { favourited: true|false }
// ─────────────────────────────────────────────────────────────────────────────
export const toggleFavourite = async (req, res) => {
  const userId    = req.user.id;
  const { packageId } = req.body;

  if (!packageId) {
    return res.status(400).json({ success: false, message: 'packageId is required' });
  }

  try {
    // Check if already favourited
    const { data: existing } = await supabase
      .from('favourites')
      .select('id')
      .eq('user_id', userId)
      .eq('package_id', packageId)
      .maybeSingle();

    if (existing) {
      // Remove favourite
      await supabase.from('favourites').delete().eq('id', existing.id);
      return res.json({ success: true, favourited: false });
    }

    // Add favourite
    const { error } = await supabase
      .from('favourites')
      .insert({ user_id: userId, package_id: packageId, created_at: new Date().toISOString() });

    if (error) throw error;

    return res.json({ success: true, favourited: true });
  } catch (error) {
    console.error('[toggleFavourite]', error.message);
    return res.status(500).json({ success: false, message: 'Failed to update favourite' });
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// Get user favourites  GET /api/favourites
// Returns: { success, favourites: Package[], packageIds: string[] }
// ─────────────────────────────────────────────────────────────────────────────
export const getFavourites = async (req, res) => {
  const userId = req.user.id;

  try {
    const { data, error } = await supabase
      .from('favourites')
      .select(`
        id,
        created_at,
        package:package_id (
          id, name, type, location, description,
          price, original_price, discount, duration,
          image_urls, highlights, inclusions,
          makkah_hotel_rating, makkah_hotel_distance, status
        )
      `)
      .eq('user_id', userId)
      .order('created_at', { ascending: false });

    if (error) throw error;

    // Filter out any rows where the package was deleted
    const favourites = (data ?? [])
      .filter(row => row.package && row.package.status === 'Active')
      .map(row => row.package);

    const packageIds = favourites.map(p => p.id);

    return res.json({ success: true, favourites, packageIds });
  } catch (error) {
    console.error('[getFavourites]', error.message);
    return res.status(500).json({ success: false, message: 'Failed to fetch favourites' });
  }
};