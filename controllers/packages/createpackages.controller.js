import supabase from '../../config/supabase.js';
import { deleteImagesFromR2 } from '../../middleware/uploads/Uploadtocloudflare.js';

export const handleDatabaseError = (res, error) => {
  console.error('Database error:', error);
  return res.status(500).json({ success: false, message: 'An internal server error occurred.' });
};

const ALLOWED_TYPES     = ['umrah', 'hajj'];
// A package's `location` is one of three coverage tiers, not an independent
// single city — keep in sync with validatePackage.js's ALLOWED_LOCATIONS.
const ALLOWED_LOCATIONS = ['makkah', 'makkah_madinah', 'makkah_madinah_jeddah'];

function sanitizeText(value = '', maxLen = 120) {
  return String(value)
    .replace(/\0/g, '')
    .replace(/<[^>]*>/g, '')
    .replace(/&(?:#x?[\da-f]+|[a-z]+);/gi, '')
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '')
    .replace(/[ \t]+/g, ' ')
    .trimStart()
    .slice(0, maxLen);
}

function sanitizeNumber(value) {
  const n = parseFloat(String(value).replace(/[^\d.]/g, ''));
  return isNaN(n) ? null : n;
}

function sanitizeDate(value = '') {
  return /^\d{4}-\d{2}-\d{2}$/.test(String(value).trim()) ? value.trim() : null;
}

// DB has check_dates_makkah / check_dates_madinah constraints requiring each
// pair to be either both null or a valid range (check_out after check_in).
// A lone date (only one of the pair set) or an inverted range would violate
// that constraint and fail the whole write — so instead of letting the DB
// reject the entire update, silently drop an invalid/incomplete pair here.
function sanitizeDatePair(inRaw, outRaw) {
  const inD  = sanitizeDate(inRaw);
  const outD = sanitizeDate(outRaw);
  if (!inD || !outD) return { in: null, out: null };
  if (new Date(outD) <= new Date(inD)) return { in: null, out: null };
  return { in: inD, out: outD };
}

function sanitizeTags(arr, maxLen = 80, maxCount = 30) {
  if (!Array.isArray(arr)) return [];
  return arr.slice(0, maxCount).map((t) => sanitizeText(t, maxLen)).filter(Boolean);
}

// Used by both create (duplicate carries photos over) and update (agent kept
// some existing images) — client sends the URLs it wants to keep as JSON,
// newly uploaded files always come through req.imageUrls from uploadImagesToR2.
function parseImageUrls(raw) {
  if (!raw) return [];
  try {
    const arr = JSON.parse(raw);
    if (!Array.isArray(arr)) return [];
    return arr.filter((u) => typeof u === 'string' && /^https?:\/\//.test(u)).slice(0, 10);
  } catch {
    return [];
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// createPackage  POST /api/packages
// ─────────────────────────────────────────────────────────────────────────────
export const createPackage = async (req, res) => {
  const userId = req.user.id;
  const { firstName, lastName, agentName, agentNumber } = req.user;

  // Validate required agent data
  if (!agentNumber) {
    return res.status(400).json({
      success: false,
      message: 'Agent number is required. Please complete your agent profile.'
    });
  }

  const parseArray = (field) => {
    const raw = req.body[field];
    if (!raw) return [];
    if (Array.isArray(raw)) return raw;
    try { return JSON.parse(raw); } catch { return []; }
  };

  // ── Sanitise ────────────────────────────────────────────────────────────────
  const name          = sanitizeText(req.body.name, 120);
  const type          = ALLOWED_TYPES.includes(req.body.type) ? req.body.type : null;
  const location      = ALLOWED_LOCATIONS.includes(req.body.location) ? req.body.location : null;
  const description   = sanitizeText(req.body.description, 1200);

  const price          = sanitizeNumber(req.body.price);
  const original_price = sanitizeNumber(req.body.original_price);
  const discount       = sanitizeNumber(req.body.discount);
  const duration       = sanitizeNumber(req.body.duration);

  const min_group_size = sanitizeNumber(req.body.min_group_size) ?? 1;
  const max_group_size = sanitizeNumber(req.body.max_group_size) ?? 50;

  const available_from = sanitizeDate(req.body.available_from);
  const available_to   = sanitizeDate(req.body.available_to);

  const makkah_hotel_name     = sanitizeText(req.body.makkah_hotel_name, 120);
  const makkah_hotel_rating   = sanitizeNumber(req.body.makkah_hotel_rating)?.toString();
  const makkah_hotel_distance = sanitizeText(req.body.makkah_hotel_distance, 30);
  const makkah_hotel_address  = sanitizeText(req.body.makkah_hotel_address, 120);
  const { in: makkah_check_in_date, out: makkah_check_out_date } =
    sanitizeDatePair(req.body.makkah_check_in_date, req.body.makkah_check_out_date);

 const madinah_hotel_name     = sanitizeText(req.body.madinah_hotel_name, 120)     || null;
  const madinah_hotel_rating   = sanitizeNumber(req.body.madinah_hotel_rating)?.toString();
const madinah_hotel_distance = sanitizeText(req.body.madinah_hotel_distance, 30)  || null;
  const madinah_hotel_address  = sanitizeText(req.body.madinah_hotel_address, 120)  || null;
  const { in: madinah_check_in_date, out: madinah_check_out_date } =
    sanitizeDatePair(req.body.madinah_check_in_date, req.body.madinah_check_out_date);

  const highlights = sanitizeTags(parseArray('highlights'));
  const inclusions = sanitizeTags(parseArray('inclusions'));
  const exclusions = sanitizeTags(parseArray('exclusions'));

  // existing_image_urls carries over photos when duplicating a package;
  // req.imageUrls is whatever uploadImagesToR2 just uploaded fresh.
  const keptImageUrls = parseImageUrls(req.body.existing_image_urls);
  const uploadedUrls  = Array.isArray(req.imageUrls) ? req.imageUrls : [];
  const image_urls    = [...keptImageUrls, ...uploadedUrls].slice(0, 10);

  // ── Build record ────────────────────────────────────────────────────────────
  const currentTime = new Date().toISOString();

  const newPackage = {
    name, type, location, description,
    price, original_price, discount, duration,
    available_from, available_to,
    min_group_size, max_group_size,
    makkah_hotel_name, makkah_hotel_rating, makkah_hotel_distance,
    makkah_hotel_address, makkah_check_in_date, makkah_check_out_date,
    madinah_hotel_name, madinah_hotel_rating, madinah_hotel_distance,
    madinah_hotel_address, madinah_check_in_date, madinah_check_out_date,
    highlights, inclusions, exclusions,
    image_urls,
    created_by:  userId,
    agent_name: agentName,
    agent_number: agentNumber,
    status: 'Active',
    created_at: currentTime,
    updated_at: currentTime,
  };

  // ── Validate required fields ─────────────────────────────────────────────────
  if (!name || !type || !location || !price || !duration) {
    return res.status(400).json({
      success: false,
      message: 'Missing required fields: name, type, location, price, duration are required.'
    });
  }

  // ── Insert ──────────────────────────────────────────────────────────────────
  try {
    // Build package with all fields, filtering out null/undefined values for optional fields
    const packageToInsert = {
      name,
      type,
      location,
      description: description || null,
      price,
      original_price: original_price || null,
      discount: discount || null,
      duration,
      available_from: available_from || null,
      available_to: available_to || null,
      min_group_size,
      max_group_size,
      makkah_hotel_name: makkah_hotel_name || null,
      makkah_hotel_rating: makkah_hotel_rating || null,
      makkah_hotel_distance: makkah_hotel_distance || null,
      makkah_hotel_address: makkah_hotel_address || null,
      makkah_check_in_date: makkah_check_in_date || null,
      makkah_check_out_date: makkah_check_out_date || null,
      madinah_hotel_name: madinah_hotel_name || null,
      madinah_hotel_rating: madinah_hotel_rating || null,
      madinah_hotel_distance: madinah_hotel_distance || null,
      madinah_hotel_address: madinah_hotel_address || null,
      madinah_check_in_date: madinah_check_in_date || null,
      madinah_check_out_date: madinah_check_out_date || null,
      highlights: highlights.length > 0 ? highlights : null,
      inclusions: inclusions.length > 0 ? inclusions : null,
      exclusions: exclusions.length > 0 ? exclusions : null,
      image_urls: image_urls.length > 0 ? image_urls : null,
      created_by: userId,
      agent_name: agentName,
      agent_number: agentNumber,
      status: 'Active',
      created_at: currentTime,
      updated_at: currentTime,
    };

    console.log('[createPackage] Inserting package:', { name, type, location, price, duration });

    const { data, error } = await supabase
      .from('packages')
      .insert([packageToInsert])
      .select('id, name, type, location, price, duration, status, created_by, agent_name, agent_number');

    if (error) {
      console.error('[createPackage] Supabase insert error:', error);
      console.error('[createPackage] Error details:', {
        message: error.message,
        code: error.code,
        details: error.details,
        hint: error.hint,
      });
      throw error;
    }

    const record = data?.[0] ?? null;
    console.log('Package created successfully:', record);

    return res.status(201).json({
      success:      true,
      message:      `Package "${name}" has been created successfully.`,
      package:      record,
      totalRecords: data?.length ?? 0,
    });

  } catch (error) {
    if (error.code === '23505') {
      const match = error.details?.match(/Key \(([^)]+)\)/);
      const field = match?.[1] ?? 'field';
      return res.status(409).json({
        success: false,
        message: `A package with this ${field} already exists.`,
      });
    }
    return handleDatabaseError(res, error);
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// updatePackage  PUT /api/packages/:id
// Agent can edit every field of a package they own. Ownership is re-verified
// server-side (never trust the :id + client-side state alone). Images: the
// client sends `existing_image_urls` (JSON array) for photos it wants to
// keep, plus any new files in the multipart body — the two are merged here.
// ─────────────────────────────────────────────────────────────────────────────
export const updatePackage = async (req, res) => {
  const { id } = req.params;
  const userId = req.user.id;

  const { data: existing, error: fetchErr } = await supabase
    .from('packages')
    .select('id, created_by, image_urls')
    .eq('id', id)
    .single();

  if (fetchErr || !existing) {
    return res.status(404).json({ success: false, message: 'Package not found.' });
  }
  if (existing.created_by !== userId) {
    return res.status(403).json({ success: false, message: 'You do not have permission to edit this package.' });
  }

  const parseArray = (field) => {
    const raw = req.body[field];
    if (!raw) return [];
    if (Array.isArray(raw)) return raw;
    try { return JSON.parse(raw); } catch { return []; }
  };

  // ── Sanitise (mirrors createPackage) ──────────────────────────────────────
  const name          = sanitizeText(req.body.name, 120);
  const type          = ALLOWED_TYPES.includes(req.body.type) ? req.body.type : null;
  const location      = ALLOWED_LOCATIONS.includes(req.body.location) ? req.body.location : null;
  const description   = sanitizeText(req.body.description, 1200);

  const price          = sanitizeNumber(req.body.price);
  const original_price = sanitizeNumber(req.body.original_price);
  const discount       = sanitizeNumber(req.body.discount);
  const duration       = sanitizeNumber(req.body.duration);

  const min_group_size = sanitizeNumber(req.body.min_group_size) ?? 1;
  const max_group_size = sanitizeNumber(req.body.max_group_size) ?? 50;

  const available_from = sanitizeDate(req.body.available_from);
  const available_to   = sanitizeDate(req.body.available_to);

  const makkah_hotel_name     = sanitizeText(req.body.makkah_hotel_name, 120);
  const makkah_hotel_rating   = sanitizeNumber(req.body.makkah_hotel_rating)?.toString();
  const makkah_hotel_distance = sanitizeText(req.body.makkah_hotel_distance, 30);
  const makkah_hotel_address  = sanitizeText(req.body.makkah_hotel_address, 120);
  const { in: makkah_check_in_date, out: makkah_check_out_date } =
    sanitizeDatePair(req.body.makkah_check_in_date, req.body.makkah_check_out_date);

  const madinah_hotel_name     = sanitizeText(req.body.madinah_hotel_name, 120)     || null;
  const madinah_hotel_rating   = sanitizeNumber(req.body.madinah_hotel_rating)?.toString();
  const madinah_hotel_distance = sanitizeText(req.body.madinah_hotel_distance, 30)  || null;
  const madinah_hotel_address  = sanitizeText(req.body.madinah_hotel_address, 120)  || null;
  const { in: madinah_check_in_date, out: madinah_check_out_date } =
    sanitizeDatePair(req.body.madinah_check_in_date, req.body.madinah_check_out_date);

  const highlights = sanitizeTags(parseArray('highlights'));
  const inclusions = sanitizeTags(parseArray('inclusions'));
  const exclusions = sanitizeTags(parseArray('exclusions'));

  const keptImageUrls = parseImageUrls(req.body.existing_image_urls);
  const uploadedUrls  = Array.isArray(req.imageUrls) ? req.imageUrls : [];
  const image_urls    = [...keptImageUrls, ...uploadedUrls].slice(0, 10);

  if (!name || !type || !location || !price || !duration) {
    return res.status(400).json({
      success: false,
      message: 'Missing required fields: name, type, location, price, duration are required.'
    });
  }

  try {
    const packageToUpdate = {
      name, type, location,
      description: description || null,
      price,
      original_price: original_price || null,
      discount: discount || null,
      duration,
      available_from: available_from || null,
      available_to: available_to || null,
      min_group_size,
      max_group_size,
      makkah_hotel_name: makkah_hotel_name || null,
      makkah_hotel_rating: makkah_hotel_rating || null,
      makkah_hotel_distance: makkah_hotel_distance || null,
      makkah_hotel_address: makkah_hotel_address || null,
      makkah_check_in_date: makkah_check_in_date || null,
      makkah_check_out_date: makkah_check_out_date || null,
      madinah_hotel_name: madinah_hotel_name || null,
      madinah_hotel_rating: madinah_hotel_rating || null,
      madinah_hotel_distance: madinah_hotel_distance || null,
      madinah_hotel_address: madinah_hotel_address || null,
      madinah_check_in_date: madinah_check_in_date || null,
      madinah_check_out_date: madinah_check_out_date || null,
      highlights: highlights.length > 0 ? highlights : null,
      inclusions: inclusions.length > 0 ? inclusions : null,
      exclusions: exclusions.length > 0 ? exclusions : null,
      image_urls: image_urls.length > 0 ? image_urls : null,
      updated_at: new Date().toISOString(),
    };

    const { data, error } = await supabase
      .from('packages')
      .update(packageToUpdate)
      .eq('id', id)
      .select('id, name, type, location, price, duration, status, created_by, agent_name, agent_number, image_urls');

    if (error) {
      console.error('[updatePackage] Supabase update error:', error);
      throw error;
    }

    const record = data?.[0] ?? null;

    // Any image that was on the package before but isn't in the new
    // image_urls is one the agent removed (or replaced) — clean it up from
    // R2. Fire-and-forget: the update already succeeded, so a cleanup
    // failure here shouldn't turn into a failed response.
    const previousUrls = Array.isArray(existing.image_urls) ? existing.image_urls : [];
    const removedUrls = previousUrls.filter((u) => !image_urls.includes(u));
    if (removedUrls.length > 0) {
      deleteImagesFromR2(removedUrls).catch((err) =>
        console.error('[updatePackage] R2 cleanup failed:', err.message)
      );
    }

    return res.status(200).json({
      success: true,
      message: `Package "${name}" has been updated successfully.`,
      package: record,
    });

  } catch (error) {
    if (error.code === '23505') {
      const match = error.details?.match(/Key \(([^)]+)\)/);
      const field = match?.[1] ?? 'field';
      return res.status(409).json({
        success: false,
        message: `A package with this ${field} already exists.`,
      });
    }
    return handleDatabaseError(res, error);
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// deletePackage  DELETE /api/packages/:id
// Agent can delete their own package. Ownership re-verified server-side —
// the frontend already had a delete confirmation modal + packagesApi call
// wired up, but there was no matching route, so it silently failed (404).
// Also cleans up the package's images from R2 after the row is gone.
// ─────────────────────────────────────────────────────────────────────────────
export const deletePackage = async (req, res) => {
  const { id } = req.params;
  const userId = req.user.id;

  const { data: existing, error: fetchErr } = await supabase
    .from('packages')
    .select('id, created_by, name, image_urls')
    .eq('id', id)
    .single();

  if (fetchErr || !existing) {
    return res.status(404).json({ success: false, message: 'Package not found.' });
  }
  if (existing.created_by !== userId) {
    return res.status(403).json({ success: false, message: 'You do not have permission to delete this package.' });
  }

  try {
    const { error } = await supabase
      .from('packages')
      .delete()
      .eq('id', id);

    if (error) {
      console.error('[deletePackage] Supabase delete error:', error);
      throw error;
    }

    // Row is gone either way at this point — cleanup is best-effort and
    // shouldn't turn into a failed response if R2 hiccups.
    if (Array.isArray(existing.image_urls) && existing.image_urls.length > 0) {
      deleteImagesFromR2(existing.image_urls).catch((err) =>
        console.error('[deletePackage] R2 cleanup failed:', err.message)
      );
    }

    return res.status(200).json({
      success: true,
      message: `Package "${existing.name}" has been deleted.`,
    });
  } catch (error) {
    return handleDatabaseError(res, error);
  }
};