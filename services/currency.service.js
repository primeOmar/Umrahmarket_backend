// services/currency.service.js
// Fetches live USD/KES rate with 3-source fallback chain and sanity validation.
// getUsdKesRate() returns a plain number — safe to use directly in arithmetic.
// Source metadata available via getUsdKesRateMeta() if needed for logging.

const CACHE_TTL_MS = 10 * 60 * 1000; // 10 min
const SANITY_MIN   = 50;              // reject if below — broken API response
const SANITY_MAX   = 300;             // reject if above — broken API response

let cache = { rate: null, fetchedAt: 0, source: null };

function isSane(rate) {
  return typeof rate === 'number' && isFinite(rate) && rate >= SANITY_MIN && rate <= SANITY_MAX;
}

async function fetchFromOpenExchangeRates() {
  // Free, no API key, updates hourly
  const res  = await fetch('https://open.er-api.com/v6/latest/USD', { signal: AbortSignal.timeout(5000) });
  const json = await res.json();
  const rate = Number(json?.rates?.KES);
  if (!isSane(rate)) throw new Error(`open.er-api bad rate: ${rate}`);
  return { rate, source: 'open.er-api' };
}

async function fetchFromFrankfurter() {
  // ECB data via frankfurter.app — free, no key
  const res  = await fetch('https://api.frankfurter.app/latest?from=USD&to=KES', { signal: AbortSignal.timeout(5000) });
  const json = await res.json();
  const rate = Number(json?.rates?.KES);
  if (!isSane(rate)) throw new Error(`frankfurter bad rate: ${rate}`);
  return { rate, source: 'frankfurter' };
}

async function fetchFromFawazahmed() {
  // CDN-hosted currency API — free, no key, no rate limit
  const res  = await fetch('https://cdn.jsdelivr.net/npm/@fawazahmed0/currency-api@latest/v1/currencies/usd.json', { signal: AbortSignal.timeout(5000) });
  const json = await res.json();
  const rate = Number(json?.usd?.kes);
  if (!isSane(rate)) throw new Error(`fawazahmed0 bad rate: ${rate}`);
  return { rate, source: 'fawazahmed0-cdn' };
}

async function _fetchRate() {
  // Return from cache if still fresh
  if (cache.rate && Date.now() - cache.fetchedAt < CACHE_TTL_MS) {
    return { rate: cache.rate, source: cache.source, cached: true };
  }

  const sources = [fetchFromOpenExchangeRates, fetchFromFrankfurter, fetchFromFawazahmed];

  for (const fn of sources) {
    try {
      const result = await fn();
      cache = { rate: result.rate, fetchedAt: Date.now(), source: result.source };
      console.info(`[FX] USD/KES = ${result.rate} via ${result.source}`);
      return { rate: result.rate, source: result.source, cached: false };
    } catch (err) {
      console.warn(`[FX] Source failed: ${err.message}`);
    }
  }

  // All live sources failed — use stale cache if available
  if (cache.rate) {
    const ageMin = Math.round((Date.now() - cache.fetchedAt) / 60_000);
    console.warn(`[FX] All sources failed — using stale cache: ${cache.rate} (${ageMin}m old, source: ${cache.source})`);
    return { rate: cache.rate, source: `${cache.source}:stale`, cached: true };
  }

  // No data at all
  throw new Error('USD/KES rate unavailable — all sources failed and no cache exists');
}

/**
 * Returns the live USD/KES rate as a plain number.
 * Throws if all sources fail and no cache exists.
 * Use this in controllers: const rate = await getUsdKesRate();
 */
export async function getUsdKesRate() {
  const { rate } = await _fetchRate();
  return rate;
}

/**
 * Returns rate + metadata { rate, source, cached }.
 * Use this in the /fx/rate endpoint.
 */
export async function getUsdKesRateMeta() {
  return _fetchRate();
}

/**
 * Convert USD amount to KES integer (what Daraja/Pesapal receives).
 */
export function usdToKes(usdAmount, rate) {
  return Math.round(usdAmount * rate);
}

/**
 * Convert KES amount back to USD (for agent/admin display).
 */
export function kesToUsd(kesAmount, rate) {
  return parseFloat((kesAmount / rate).toFixed(2));
}