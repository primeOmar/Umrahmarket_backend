// Batch-created packages go live ACTIVATION_LEAD_DAYS before departure
// (available_from) — and only after the agent has confirmed pricing.
//   Draft     — created, pricing not confirmed (never public)
//   Scheduled — pricing confirmed, waiting for its activation window
//   Active    — public & bookable
// Dates are compared as UTC calendar days (YYYY-MM-DD).

const parsed = parseInt(process.env.PACKAGE_ACTIVATION_LEAD_DAYS ?? '150', 10);
export const ACTIVATION_LEAD_DAYS = Number.isFinite(parsed) && parsed >= 0 ? parsed : 150;

export const MAX_BATCH_HORIZON_DAYS = 366; // "up to one year" of departures
export const MAX_BATCH_SIZE = 60;

const DAY_MS = 86400000;

const isoDay = (d) => d.toISOString().slice(0, 10);

export function addDays(dateStr, days) {
  return isoDay(new Date(new Date(`${dateStr}T00:00:00Z`).getTime() + days * DAY_MS));
}

export function todayUtc(now = new Date()) {
  return isoDay(now);
}

// Packages with available_from <= this date are inside their activation window.
export function activationCutoffDate(now = new Date()) {
  return addDays(todayUtc(now), ACTIVATION_LEAD_DAYS);
}

// Date a package with this departure becomes public.
export function activationDateFor(availableFrom) {
  return availableFrom ? addDays(String(availableFrom).slice(0, 10), -ACTIVATION_LEAD_DAYS) : null;
}

export function isInActivationWindow(availableFrom, now = new Date()) {
  return !!availableFrom && String(availableFrom).slice(0, 10) <= activationCutoffDate(now);
}
