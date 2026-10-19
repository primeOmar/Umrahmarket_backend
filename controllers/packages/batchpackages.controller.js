import { randomUUID } from 'crypto';
import supabase from '../../config/supabase.js';
import {
  handleDatabaseError, sanitizeText, sanitizeNumber, sanitizeDate, sanitizeTags,
  sanitizePriceTiers, sanitizeCountryPricing, sanitizeCities, sanitizeCityHotels, parseImageUrls,
} from './createpackages.controller.js';
import { normaliseName } from '../../utils/packageNaming.js';
import {
  ACTIVATION_LEAD_DAYS, MAX_BATCH_HORIZON_DAYS, MAX_BATCH_SIZE,
  addDays, todayUtc, activationDateFor, isInActivationWindow,
} from '../../utils/packageActivation.js';
import { EXPIRY_DAYS } from '../../utils/packageExpiry.js';

const SELECT = 'id, name, type, location, cities, price, price_tiers, duration, available_from, available_to, status, batch_id, pricing_confirmed_at, makkah_hotel_name, makkah_hotel_rating';
const MIN_NIGHTS = 2;
const MAX_NIGHTS = 60;
const DAY_MS = 86400000;
const MONTHS = ['January', 'February', 'March', 'April', 'May', 'June', 'July',
  'August', 'September', 'October', 'November', 'December'];
const MAX_NAME_LEN = 120;

const fail = (res, message, status = 400) => res.status(status).json({ success: false, message });

const withActivation = (p) => ({ ...p, activates_at: activationDateFor(p.available_from) });

// Accepts either a parsed object (JSON body) or a JSON string (multipart field).
const parseJson = (raw, fallback) => {
  if (raw == null || raw === '') return fallback;
  if (typeof raw !== 'string') return raw;
  try { return JSON.parse(raw); } catch { return fallback; }
};

const nightsBetween = (from, to) => Math.round((Date.parse(`${to}T00:00:00Z`) - Date.parse(`${from}T00:00:00Z`)) / DAY_MS);

const deriveLocation = (cities) => {
  if (cities.includes('jeddah')) return 'makkah_madinah_jeddah';
  if (cities.includes('madinah')) return 'makkah_madinah';
  return 'makkah';
};

const cityLabel = (city) => city
  .split('_')
  .map((s) => s.charAt(0).toUpperCase() + s.slice(1))
  .join(' ');

function distinctBatchName({ type, cities, duration, departure, stars, hotel }, taken) {
  const [y, m, d] = departure.split('-').map(Number);
  const when = `${d} ${MONTHS[(m || 1) - 1]} ${y}`;
  const typeLabel = type === 'hajj' ? 'Hajj' : 'Umrah';
  const route = cities.map(cityLabel).join(', ');
  const starsPart = stars ? ` (${stars}★ Hotels)` : '';
  const hotelPart = hotel ? ` · ${hotel}` : '';
  const base = `${duration}-Day ${typeLabel} Package ${when} — ${route}${starsPart}${hotelPart} | Book from Kenya`;
  const clipped = base.length <= MAX_NAME_LEN ? base : base.slice(0, MAX_NAME_LEN).trimEnd();

  if (!taken.has(normaliseName(clipped))) {
    taken.add(normaliseName(clipped));
    return clipped;
  }
  for (let n = 2; n < 1000; n += 1) {
    const suffix = ` #${n}`;
    const candidate = clipped.slice(0, MAX_NAME_LEN - suffix.length).trimEnd() + suffix;
    if (!taken.has(normaliseName(candidate))) {
      taken.add(normaliseName(candidate));
      return candidate;
    }
  }
  throw new Error('Could not generate a unique package name');
}

const cleanHotel = (src) => ({
  name: sanitizeText(src?.name, 120) || null,
  rating: sanitizeNumber(src?.rating) || null,
  distance: sanitizeText(src?.distance, 30) || null,
  address: sanitizeText(src?.address, 120) || null,
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/packages/batch   (multipart: template, departures, images[])
// One shared template (cities, hotels, pricing incl. TZ/SO, inclusions,
// exclusions, images) + a list of departures, each with its own departure and
// return date (nights are derived) → one Draft package per departure.
// Nothing is public until the agent confirms pricing (see confirmBatchPricing).
// ─────────────────────────────────────────────────────────────────────────────
export const createPackageBatch = async (req, res) => {
  const { id: userId, agentName, agentNumber } = req.user;
  if (!agentNumber) return fail(res, 'Agent number is required. Please complete your agent profile.');

  const t = parseJson(req.body?.template, {}) || {};
  const rawDepartures = parseJson(req.body?.departures, []);

  const type = t.type === 'hajj' ? 'hajj' : t.type === 'umrah' ? 'umrah' : null;
  const cities = sanitizeCities(t.cities);
  const location = deriveLocation(cities);
  const price = sanitizeNumber(t.price_tiers?.adult ?? t.price);
  if (!type || !location || !Array.isArray(cities) || cities.length === 0) {
    return fail(res, 'Template needs a package type, location (Makkah or Makkah & Madinah), and valid city list.');
  }
  if (!price || price <= 0) return fail(res, 'Template needs an adult price.');

  if (!Array.isArray(rawDepartures) || rawDepartures.length === 0) return fail(res, 'Add at least one departure.');
  if (rawDepartures.length > MAX_BATCH_SIZE) return fail(res, `A batch can hold at most ${MAX_BATCH_SIZE} departures.`);

  const today = todayUtc();
  const earliest = addDays(today, EXPIRY_DAYS + 1);
  const latest = addDays(today, MAX_BATCH_HORIZON_DAYS);
  const seen = new Set();
  const departures = [];

  for (const d of rawDepartures) {
    // Stay dates are chosen per city; the departure/return dates and the total
    // nights are derived from them.
    const stays = {};
    for (const c of cities) {
      const ci = sanitizeDate(d?.hotels?.[c]?.check_in_date);
      const co = sanitizeDate(d?.hotels?.[c]?.check_out_date);
      const label = c.replace(/_/g, ' ');
      if (!ci || !co || Number.isNaN(Date.parse(ci)) || Number.isNaN(Date.parse(co))) {
        return fail(res, `Pick check-in and check-out dates for ${label}.`);
      }
      if (nightsBetween(ci, co) < 1) return fail(res, `${label}: check-out must be after check-in.`);
      stays[c] = { in: ci, out: co };
    }
    const date = Object.values(stays).map((s) => s.in).sort()[0];
    const returnDate = Object.values(stays).map((s) => s.out).sort().at(-1);
    if (date < earliest || date > latest) {
      return fail(res, `Departure ${date} must be between ${earliest} and ${latest} (max one year ahead).`);
    }
    if (seen.has(date)) return fail(res, `Departure ${date} is listed twice.`);
    seen.add(date);

    const nights = nightsBetween(date, returnDate);
    if (nights < MIN_NIGHTS || nights > MAX_NIGHTS) {
      return fail(res, `Departure ${date}: trip must be ${MIN_NIGHTS}-${MAX_NIGHTS} nights (got ${nights}).`);
    }

    // Every departure carries its own hotels so packages can be distinct
    // even in the same month (different hotels/city setup).
    const hotels = {};
    for (const c of cities) {
      const o = cleanHotel(d?.hotels?.[c]);
      hotels[c] = {
        name: o.name,
        rating: o.rating,
        distance: o.distance,
        address: o.address,
      };
      if (!hotels[c].name || !hotels[c].rating) {
        return fail(res, `Departure ${date}: add a hotel name and star rating for ${c.replace(/_/g, ' ')}.`);
      }
    }

      departures.push({ date, returnDate, nights, hotels, stays, adult: price, tiers: t.price_tiers ?? { adult: price } });
    }
  departures.sort((a, b) => a.date.localeCompare(b.date));

  const baseTiers = sanitizePriceTiers(t.price_tiers, price);
  const country_pricing = sanitizeCountryPricing(t.country_pricing);
  const uploaded = Array.isArray(req.imageUrls) ? req.imageUrls : [];
  const image_urls = [...parseImageUrls(JSON.stringify(t.image_urls ?? [])), ...uploaded].slice(0, 10);
  const description = sanitizeText(t.description, 1200) || null;
  const highlights = sanitizeTags(t.highlights);
  const inclusions = sanitizeTags(t.inclusions);
  const exclusions = sanitizeTags(t.exclusions);
  const min_group_size = sanitizeNumber(t.min_group_size) ?? 1;
  const max_group_size = sanitizeNumber(t.max_group_size) ?? 50;

  try {
    // Redundancy guard: names already used + departures already created.
    const { data: existing, error: exErr } = await supabase
      .from('packages')
      .select('name, available_from, type, location, makkah_hotel_name')
      .eq('created_by', userId);
    if (exErr) throw exErr;

    const taken = new Set((existing ?? []).map((p) => normaliseName(p.name)));
    const isDuplicate = (date, hotelName) => (existing ?? []).some((p) =>
      String(p.available_from).slice(0, 10) === date && p.type === type &&
      p.location === location && normaliseName(p.makkah_hotel_name || '') === normaliseName(hotelName));

    const batch_id = randomUUID();
    const now = new Date().toISOString();
    const skipped = [];
    const rows = [];

    for (const dep of departures) {
      if (isDuplicate(dep.date, dep.hotels.makkah.name)) { skipped.push(dep.date); continue; }

      const tiers = baseTiers;

      const stays = dep.stays;

      const stars = Math.max(...['makkah', 'madinah']
        .filter((c) => cities.includes(c))
        .map((c) => dep.hotels[c].rating || 0)) || null;

      const hasMadinah = cities.includes('madinah');
      const extraHotels = {};
      cities.filter((c) => c !== 'makkah' && c !== 'madinah').forEach((c) => {
        const h = dep.hotels[c];
        extraHotels[c] = {
          hotel_name: h.name, hotel_rating: h.rating, hotel_distance: h.distance, hotel_address: h.address,
          check_in_date: stays[c].in, check_out_date: stays[c].out,
        };
      });

      rows.push({
        name: distinctBatchName({ type, cities, duration: dep.nights, departure: dep.date, stars, hotel: dep.hotels.makkah.name }, taken),
        type, location,
        cities,
        city_hotels: sanitizeCityHotels(extraHotels, cities),
        description,
        price: tiers.adult,
        price_tiers: tiers,
        country_pricing,
        duration: dep.nights,
        available_from: dep.date,
        available_to: dep.returnDate,
        min_group_size, max_group_size,
        makkah_hotel_name: dep.hotels.makkah.name,
        makkah_hotel_rating: String(dep.hotels.makkah.rating),
        makkah_hotel_distance: dep.hotels.makkah.distance,
        makkah_hotel_address: dep.hotels.makkah.address,
        makkah_check_in_date: stays.makkah.in,
        makkah_check_out_date: stays.makkah.out,
        madinah_hotel_name: hasMadinah ? dep.hotels.madinah.name : null,
        madinah_hotel_rating: hasMadinah ? String(dep.hotels.madinah.rating) : null,
        madinah_hotel_distance: hasMadinah ? dep.hotels.madinah.distance : null,
        madinah_hotel_address: hasMadinah ? dep.hotels.madinah.address : null,
        madinah_check_in_date: hasMadinah ? stays.madinah.in : null,
        madinah_check_out_date: hasMadinah ? stays.madinah.out : null,
        highlights: highlights.length ? highlights : null,
        inclusions: inclusions.length ? inclusions : null,
        exclusions: exclusions.length ? exclusions : null,
        image_urls: image_urls.length ? image_urls : null,
        created_by: userId,
        agent_name: agentName,
        agent_number: agentNumber,
        status: 'Draft',
        batch_id,
        pricing_confirmed_at: null,
        created_at: now,
        updated_at: now,
      });
    }

    if (rows.length === 0) return fail(res, 'All of those departures already exist.', 409);

    const { data, error } = await supabase.from('packages').insert(rows).select(SELECT);
    if (error) throw error;

    return res.status(201).json({
      success: true,
      batch_id,
      activation_lead_days: ACTIVATION_LEAD_DAYS,
      packages: (data ?? []).map(withActivation),
      skipped_duplicates: skipped,
    });
  } catch (error) {
    return handleDatabaseError(res, error);
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/packages/batch/confirm
// body: { batch_id? , package_ids?: [], prices?: { [id]: price_tiers } }
// Confirms pricing for the agent's Draft packages. Each goes Active right
// away if its departure is already inside the activation window, otherwise
// Scheduled — the activation job publishes it when the window opens.
// ─────────────────────────────────────────────────────────────────────────────
export const confirmBatchPricing = async (req, res) => {
  const userId = req.user.id;
  const { batch_id } = req.body ?? {};
  const ids = Array.isArray(req.body?.package_ids) ? req.body.package_ids.filter((i) => typeof i === 'string') : [];
  const prices = req.body?.prices && typeof req.body.prices === 'object' ? req.body.prices : {};
  if (!batch_id && ids.length === 0) return fail(res, 'Provide a batch_id or package_ids.');

  try {
    let q = supabase.from('packages').select('id, price, price_tiers, available_from, status').eq('created_by', userId).eq('status', 'Draft');
    if (batch_id) q = q.eq('batch_id', String(batch_id));
    if (ids.length) q = q.in('id', ids);
    const { data: drafts, error } = await q;
    if (error) throw error;
    if (!drafts?.length) return fail(res, 'No unconfirmed packages found.', 404);

    const now = new Date();
    const stamp = now.toISOString();
    const confirmed = [];

    for (const p of drafts) {
      const tiers = prices[p.id] ? sanitizePriceTiers(prices[p.id], null) : (p.price_tiers ?? null);
      const adult = tiers?.adult ?? Number(p.price);
      if (!adult || adult <= 0) continue; // never publish a package without a real price
      const status = isInActivationWindow(p.available_from, now) ? 'Active' : 'Scheduled';
      const patch = { status, pricing_confirmed_at: stamp, updated_at: stamp };
      if (prices[p.id]) { patch.price_tiers = tiers; patch.price = adult; }

      const { data: row, error: upErr } = await supabase
        .from('packages').update(patch).eq('id', p.id).eq('created_by', userId).eq('status', 'Draft')
        .select(SELECT).maybeSingle();
      if (upErr) throw upErr;
      if (row) confirmed.push(withActivation(row));
    }

    return res.status(200).json({ success: true, confirmed, count: confirmed.length });
  } catch (error) {
    return handleDatabaseError(res, error);
  }
};
