import supabase from '../../config/supabase.js';

// GET /api/packages/:id/itinerary  — public
export const getItinerary = async (req, res) => {
  const { id } = req.params;

  const { data, error } = await supabase
    .from('packages')
    .select('itinerary')
    .eq('id', id)
    .single();

  if (error) return res.status(404).json({ success: false, message: 'Package not found.' });

  return res.json({ success: true, days: data.itinerary ?? [] });
};

// POST /api/packages/:id/itinerary  — agent only
export const saveItinerary = async (req, res) => {
  const { id } = req.params;
  const { days } = req.body;

  if (!Array.isArray(days)) {
    return res.status(400).json({ success: false, message: '`days` must be an array.' });
  }

  // Verify ownership
  const { data: pkg, error: fetchErr } = await supabase
    .from('packages')
    .select('id, created_by')
    .eq('id', id)
    .single();

  if (fetchErr || !pkg) return res.status(404).json({ success: false, message: 'Package not found.' });
  if (pkg.created_by !== req.user.id) return res.status(403).json({ success: false, message: 'Forbidden.' });

  // Sanitise days: strip to allowed shape only
  const clean = days.slice(0, 60).map((d, i) => ({
    day: i + 1,
    title: String(d.title ?? '').replace(/<[^>]*>/g, '').slice(0, 120),
    activities: Array.isArray(d.activities)
      ? d.activities.slice(0, 20).map((a) => String(a).replace(/<[^>]*>/g, '').slice(0, 200)).filter(Boolean)
      : [],
  }));

  const { error: updateErr } = await supabase
    .from('packages')
    .update({ itinerary: clean, updated_at: new Date().toISOString() })
    .eq('id', id);

  if (updateErr) {
    console.error('[saveItinerary]', updateErr);
    return res.status(500).json({ success: false, message: 'Failed to save itinerary.' });
  }

  return res.json({ success: true, message: 'Itinerary saved.', days: clean });
};
