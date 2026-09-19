
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
 *
 * `country`, if given (e.g. 'TZ', 'SO'), swaps in that country's own
 * price_tiers override from pkg.country_pricing instead of the default
 * (Kenyan) price_tiers — mirrors CreatePackageModal's per-nationality
 * pricing. Falls back to the default tiers if that country has no override
 * (callers should have already refused the booking via
 * isCountryPricingAvailable in that case — this is just belt-and-suspenders).
 */
export function resolvePriceTiers(pkg, country) {
  const override = (country && country !== 'KE' && country !== 'OTHER')
    ? pkg?.country_pricing?.[country]
    : null;
  const source = (override && Number(override.adult) > 0) ? override : pkg?.price_tiers;
  const adult = Number(source?.adult ?? pkg?.price ?? 0);
  const tierOrFallback = (key) => {
    const n = Number(source?.[key]);
    return Number.isFinite(n) && n >= 0 ? n : adult;
  };
  return {
    adult,
    child:       tierOrFallback('child'),
    minor_child: tierOrFallback('minor_child'),
    infant:      tierOrFallback('infant'),
  };
}

// A client's account phone number is the only "which country is this
// pilgrim from" signal available at booking time — mirrors
// BookingFlow.jsx's deriveClientCountry so client and server never
// disagree. +254 Kenya, +255 Tanzania, +252 Somalia; anything else
// (no phone on file, Uganda, etc.) is treated as unrestricted, since only
// Tanzania/Somalia can ever have a distinct opt-in price on a package.
export function deriveClientCountry(phone) {
  const digits = String(phone || '').replace(/\D/g, '');
  if (!digits) return null;
  if (digits.startsWith('254')) return 'KE';
  if (digits.startsWith('255')) return 'TZ';
  if (digits.startsWith('252')) return 'SO';
  return 'OTHER';
}

// Kenyan pilgrims (and anyone whose country isn't TZ/SO) always book at the
// package's default price. A Tanzanian/Somali pilgrim can only book if the
// agent explicitly opted that country into its own pricing.
export function isCountryPricingAvailable(pkg, country) {
  if (!country || country === 'KE' || country === 'OTHER') return true;
  const entry = pkg?.country_pricing?.[country];
  return !!(entry && Number(entry.adult) > 0);
}


/**
 * computeBookingAmount(pkg, rawTravelers, country) →
 *   { travelers, totalTravelers, totalUSD, breakdown }
 *
 * `pkg` must include `price` and (optionally) `price_tiers`/`country_pricing`.
 * `country` (e.g. 'TZ', 'SO') is only used to pick that country's own price
 * tiers if the package has one — see resolvePriceTiers. Booking is refused
 * (403) for a Tanzanian/Somali pilgrim if the package has no pricing for
 * their country, since the client-side gate in BookingFlow.jsx can be
 * bypassed by calling this endpoint directly.
 * Throws a plain Error with a `.status` for the controller to turn straight
 * into an HTTP response — keeps every initiate() endpoint's error handling
 * identical.
 */
export function computeBookingAmount(pkg, rawTravelers, country) {
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

  if (!isCountryPricingAvailable(pkg, country)) {
    const err = new Error('This package does not have pricing set for your country yet.');
    err.status = 403;
    throw err;
  }

  const tiers = resolvePriceTiers(pkg, country);

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