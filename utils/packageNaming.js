// Server-side SEO package naming (mirrors the dashboard's buildSeoPackageName)
// plus collision-free resolution so two packages by one agent never share a
// title — duplicate titles dilute search ranking and confuse buyers.

const LOCATION_LABELS = {
  makkah: 'Makkah',
  makkah_madinah: 'Makkah & Madinah',
  makkah_madinah_jeddah: 'Makkah, Madinah & Jeddah',
};

const SEO_TARGET_MARKET = 'Kenya';
const MAX_NAME_LEN = 120;

const MONTHS = ['January', 'February', 'March', 'April', 'May', 'June', 'July',
  'August', 'September', 'October', 'November', 'December'];

const norm = (s) => String(s).toLowerCase().replace(/\s+/g, ' ').trim();

// level 0: month+year · 1: exact departure day · 2: + hotel name
function build({ type, location, duration, departure, stars, hotel }, level) {
  const typeLabel = type === 'hajj' ? 'Hajj' : 'Umrah';
  const locationLabel = LOCATION_LABELS[location] || LOCATION_LABELS.makkah_madinah;
  const [y, m, d] = departure.split('-').map(Number);
  const when = level >= 1 ? `${d} ${MONTHS[m - 1]} ${y}` : `${MONTHS[m - 1]} ${y}`;
  const days = duration > 0 ? `${duration}-Day ` : '';
  const starPart = stars ? ` (${stars}★ Hotels)` : '';
  const hotelPart = level >= 2 && hotel ? ` · ${hotel}` : '';
  const name = `${days}${typeLabel} Package ${when} — ${locationLabel}${starPart}${hotelPart} | Book from ${SEO_TARGET_MARKET}`;
  return name.length <= MAX_NAME_LEN ? name : name.slice(0, MAX_NAME_LEN).trimEnd();
}

// `taken` is a Set of normalised names (existing agent packages + earlier
// names in this batch); the chosen name is added to it.
export function uniquePackageName(spec, taken) {
  for (let level = 0; level <= 2; level++) {
    const candidate = build(spec, level);
    if (!taken.has(norm(candidate))) {
      taken.add(norm(candidate));
      return candidate;
    }
  }
  const base = build(spec, 2);
  for (let n = 2; n < 1000; n++) {
    const suffix = ` #${n}`;
    const candidate = base.slice(0, MAX_NAME_LEN - suffix.length).trimEnd() + suffix;
    if (!taken.has(norm(candidate))) {
      taken.add(norm(candidate));
      return candidate;
    }
  }
  throw new Error('Could not generate a unique package name');
}

export const normaliseName = norm;
