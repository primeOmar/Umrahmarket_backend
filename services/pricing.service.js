
export const TRAVELER_TIERS = ['adult', 'child', 'minor_child', 'infant'];

// Hard ceiling per booking — generous enough for real group bookings while
// preventing a single request from being abused to create an absurd amount
// (either an accidental fat-finger or a deliberate probe).
const MAX_TRAVELERS_PER_BOOKING = 30;

/**
 * Normalises whatever the client sent for `travelers` into a safe, complete
 * { adult, child, minor_child, infant } object of non-negative integers.
 * Never throws — always returns usable counts, defaulting a totally missing
 * or malformed payload to a single adult (today's existing "book alone"
 * behaviour), so this is backward compatible with any caller that doesn't
 * send `travelers` at all.
 */
export function sanitizeTravelers(raw) {
  let parsed = raw;
  if (typeof raw === 'string') {
    try { parsed = JSON.parse(raw); } catch { parsed = null; }
  }
  if (!parsed || typeof parsed !== 'object') parsed = {};

  const out = {};
  for (const tier of TRAVELER_TIERS) {
    const n = Math.floor(Number(parsed[tier]));
    out[tier] = Number.isFinite(n) && n > 0 ? Math.min(n, MAX_TRAVELERS_PER_BOOKING) : 0;
  }

  const total = TRAVELER_TIERS.reduce((sum, t) => sum + out[t], 0);
  // Nobody selected — treat as a single adult so "book alone" (the default,
  // most common case) keeps working with zero required frontend changes.
  if (total === 0) out.adult = 1;

  return out;
}

export function travelerTotal(travelers) {
  return TRAVELER_TIERS.reduce((sum, t) => sum + (travelers[t] || 0), 0);
}

/**
 * sanitizePriceTiers mirrors createpackages.controller.js's own logic:
 * any tier missing/invalid on the package row falls back to the adult
 * price, so every tier always resolves to a real, non-null number.
 */
export function resolvePriceTiers(pkg) {
  const adult = Number(pkg?.price_tiers?.adult ?? pkg?.price ?? 0);
  const tierOrFallback = (key) => {
    const n = Number(pkg?.price_tiers?.[key]);
    return Number.isFinite(n) && n >= 0 ? n : adult;
  };
  return {
    adult,
    child:       tierOrFallback('child'),
    minor_child: tierOrFallback('minor_child'),
    infant:      tierOrFallback('infant'),
  };
}

/**
 * computeBookingAmount(pkg, rawTravelers) →
 *   { travelers, totalTravelers, totalUSD, breakdown }
 *
 * `pkg` must include `price` and (optionally) `price_tiers`.
 * Throws a plain Error with a `.status` for the controller to turn straight
 * into an HTTP response — keeps every initiate() endpoint's error handling
 * identical.
 */
export function computeBookingAmount(pkg, rawTravelers) {
  const travelers = sanitizeTravelers(rawTravelers);
  const totalTravelers = travelerTotal(travelers);

  if (totalTravelers < 1) {
    const err = new Error('At least one traveler is required to book.');
    err.status = 400;
    throw err;
  }
  if (totalTravelers > MAX_TRAVELERS_PER_BOOKING) {
    const err = new Error(`A single booking supports at most ${MAX_TRAVELERS_PER_BOOKING} travelers. For larger groups, please contact the agency directly.`);
    err.status = 400;
    throw err;
  }

  const tiers = resolvePriceTiers(pkg);

  const breakdown = TRAVELER_TIERS
    .filter((t) => travelers[t] > 0)
    .map((t) => ({
      tier:        t,
      count:       travelers[t],
      unitPrice:   tiers[t],
      subtotal:    Math.round(tiers[t] * travelers[t] * 100) / 100,
    }));

  const totalUSD = Math.round(breakdown.reduce((sum, b) => sum + b.subtotal, 0) * 100) / 100;

  if (totalUSD <= 0) {
    const err = new Error('Package has no valid price for the selected travelers.');
    err.status = 400;
    throw err;
  }

  return { travelers, totalTravelers, totalUSD, breakdown, tiers };
}