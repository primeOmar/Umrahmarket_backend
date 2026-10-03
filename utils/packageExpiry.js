// A package stops being bookable EXPIRY_DAYS before its departure date
// (available_from). Expiry is derived from the date on every read — no cron
// or stored flag — so it can never drift and editing the date revives it.
// Packages with no departure date never expire. Dates are compared as UTC
// calendar days (YYYY-MM-DD).

const parsed = parseInt(process.env.PACKAGE_EXPIRY_DAYS ?? '3', 10);
export const EXPIRY_DAYS = Number.isFinite(parsed) && parsed >= 0 ? parsed : 3;

const DAY_MS = 86400000;

// Packages with available_from <= this date are expired.
export function expiryCutoffDate(now = new Date()) {
  return new Date(now.getTime() + EXPIRY_DAYS * DAY_MS).toISOString().slice(0, 10);
}

export function isPackageExpired(pkg, now = new Date()) {
  const dep = pkg?.available_from ? String(pkg.available_from).slice(0, 10) : null;
  return !!dep && dep <= expiryCutoffDate(now);
}

// PostgREST filter that keeps only non-expired packages.
export function notExpiredFilter(now = new Date()) {
  return `available_from.is.null,available_from.gt.${expiryCutoffDate(now)}`;
}

export function withExpiry(pkg) {
  return { ...pkg, is_expired: isPackageExpired(pkg) };
}
