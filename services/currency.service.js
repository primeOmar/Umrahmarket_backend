// services/currency.service.js
const CACHE_TTL_MS = 10 * 60 * 1000;
const SANITY_MIN   = 50;
const SANITY_MAX   = 300;

// Last-resort static rate. Only used when every live source AND the cache
// are unavailable (e.g. cold start + all 3 FX APIs down/blocked at once).
// Set KES_PER_USD in env to keep this current; it's a safety net, not a
// pricing source, so it deliberately never expires or auto-updates.
const FALLBACK_RATE = Number(process.env.KES_PER_USD) || 130;

let cache = { rate: null, fetchedAt: 0, source: null };

function isSane(rate) {
  return typeof rate === 'number' && isFinite(rate) && rate >= SANITY_MIN && rate <= SANITY_MAX;
}

function fetchWithTimeout(url, ms = 5000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);
  return fetch(url, { signal: controller.signal }).finally(() => clearTimeout(timer));
}

async function fetchFromOpenExchangeRates() {
  const res  = await fetchWithTimeout('https://open.er-api.com/v6/latest/USD');
  const json = await res.json();
  const rate = Number(json?.rates?.KES);
  if (!isSane(rate)) throw new Error(`open.er-api bad rate: ${rate}`);
  return { rate, source: 'open.er-api' };
}

async function fetchFromFrankfurter() {
  const res  = await fetchWithTimeout('https://api.frankfurter.app/latest?from=USD&to=KES');
  const json = await res.json();
  const rate = Number(json?.rates?.KES);
  if (!isSane(rate)) throw new Error(`frankfurter bad rate: ${rate}`);
  return { rate, source: 'frankfurter' };
}

async function fetchFromFawazahmed() {
  const res  = await fetchWithTimeout('https://cdn.jsdelivr.net/npm/@fawazahmed0/currency-api@latest/v1/currencies/usd.json');
  const json = await res.json();
  const rate = Number(json?.usd?.kes);
  if (!isSane(rate)) throw new Error(`fawazahmed0 bad rate: ${rate}`);
  return { rate, source: 'fawazahmed0-cdn' };
}

async function _fetchRate() {
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

  if (cache.rate) {
    const ageMin = Math.round((Date.now() - cache.fetchedAt) / 60_000);
    console.warn(`[FX] All sources failed — stale cache: ${cache.rate} (${ageMin}m old)`);
    return { rate: cache.rate, source: `${cache.source}:stale`, cached: true };
  }

  // No live source and no cache (e.g. fresh cold-start instance). Never
  // throw here — a checkout must not 500 because an FX API hiccupped.
  // Use the static fallback and log loudly so it's visible in Render logs.
  console.error(
    `[FX] ALL sources failed and no cache exists — using static fallback rate ${FALLBACK_RATE}. ` +
    `Check network egress / API status ASAP, this rate will not reflect the live market.`
  );
  return { rate: FALLBACK_RATE, source: 'static-fallback', cached: false };
}

export async function getUsdKesRate() {
  const { rate } = await _fetchRate();
  return rate;
}

export async function getUsdKesRateMeta() {
  return _fetchRate();
}

export function usdToKes(usdAmount, rate) {
  return Math.round(usdAmount * rate);
}

export function kesToUsd(kesAmount, rate) {
  return parseFloat((kesAmount / rate).toFixed(2));
}