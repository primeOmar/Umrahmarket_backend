import supabase from '../../config/supabase.js';

export const handleDatabaseError = (res, error) => {
  console.error('Database error:', error);
  return res.status(500).json({ success: false, message: 'An internal server error occurred.' });
};

const ALLOWED_TYPES     = ['umrah', 'hajj'];
const ALLOWED_LOCATIONS = ['makkah', 'madinah', 'jeddah'];

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

function sanitizeTags(arr, maxLen = 80, maxCount = 30) {
  if (!Array.isArray(arr)) return [];
  return arr.slice(0, maxCount).map((t) => sanitizeText(t, maxLen)).filter(Boolean);
}

// ─────────────────────────────────────────────────────────────────────────────
// createPackage  POST /api/packages
// ─────────────────────────────────────────────────────────────────────────────
export const createPackage = async (req, res) => {
  const { firstName, lastName, agentName, agentNumber } = req.user;

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
  const makkah_hotel_rating   = sanitizeNumber(req.body.makkah_hotel_rating);
  const makkah_hotel_distance = sanitizeText(req.body.makkah_hotel_distance, 30);
  const makkah_hotel_address  = sanitizeText(req.body.makkah_hotel_address, 120);
  const makkah_check_in_date  = sanitizeDate(req.body.makkah_check_in_date);
  const makkah_check_out_date = sanitizeDate(req.body.makkah_check_out_date);

  const madinah_hotel_name     = sanitizeText(req.body.madinah_hotel_name, 120);
  const madinah_hotel_rating   = sanitizeNumber(req.body.madinah_hotel_rating);
  const madinah_hotel_distance = sanitizeText(req.body.madinah_hotel_distance, 30);
  const madinah_hotel_address  = sanitizeText(req.body.madinah_hotel_address, 120);
  const madinah_check_in_date  = sanitizeDate(req.body.madinah_check_in_date);
  const madinah_check_out_date = sanitizeDate(req.body.madinah_check_out_date);

  const highlights = sanitizeTags(parseArray('highlights'));
  const inclusions = sanitizeTags(parseArray('inclusions'));
  const exclusions = sanitizeTags(parseArray('exclusions'));
  const image_urls = req.imageUrls ?? [];

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
    created_by:  `${firstName} ${lastName}`,
    agent_name: agentName,
    agent_number: agentNumber,
    status:      'Active',
    created_at:  currentTime,
    updated_at:  currentTime,
  };

  // ── Insert ──────────────────────────────────────────────────────────────────
  try {
    const { data, error } = await supabase
      .from('packages')
      .insert([newPackage])
      .select(
        `id, name, type, location, description,
         price, original_price, discount, duration,
         available_from, available_to, min_group_size, max_group_size,
         makkah_hotel_name, makkah_hotel_rating, makkah_hotel_distance,
         makkah_hotel_address, makkah_check_in_date, makkah_check_out_date,
         madinah_hotel_name, madinah_hotel_rating, madinah_hotel_distance,
         madinah_hotel_address, madinah_check_in_date, madinah_check_out_date,
         highlights, inclusions, exclusions,
         image_urls, created_by, status, created_at`
      );

    if (error) {
      console.error('Supabase insert error:', error);
      throw error;
    }

    const record = data?.[0] ?? null;
    console.log('Package created successfully:', name);

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


