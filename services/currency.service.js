// services/currency.service.js
import { supabaseAdmin } from '../config/supabase.js';

const CACHE_TTL_MS   = 10 * 60 * 1000;   // in-memory cache freshness window
const STALE_MAX_MS    = 48 * 60 * 60 * 1000; // stale cache/DB rate is still usable up to 48h old
const SANITY_MIN      = 50;
const SANITY_MAX      = 300;
// Reject a "live" quote that jumps more than this % from the last rate we
// trusted — a real USD/KES move of >12% between 10-minute polls basically
// never happens, so a jump that big almost always means a bad/garbled API
// response, not a real market move. Guards against a corrupted number that
// still happens to fall inside SANITY_MIN..SANITY_MAX.
const MAX_JUMP_PCT    = 0.12;

// Last-resort static rate. Only used when every live source, the in-memory
// cache, AND the DB-persisted rate are all unavailable (e.g. a genuinely
// fresh deploy with all 3 FX APIs down/blocked at once). Set KES_PER_USD in
// env to keep this current; it's a safety net, not a pricing source, so it
// deliberately never expires or auto-updates on its own.
const FALLBACK_RATE = Number(process.env.KES_PER_USD) || 130;

// ── Selling / buying margin ─────────────────────────────────────────────────
// We never charge or pay out at the raw mid-market rate. A spread is applied
// on top of it, same as any forex bureau:
//   - SELLING rate (mid + sell margin)  → what a KES-paying customer is
//     charged for a USD-priced package. The margin is the buffer that
//     absorbs FX movement between quote time and settlement, rounding on the
//     payment gateway's side, and any risk from momentarily being on a
//     stale/fallback rate — so small FX noise can never turn into a loss.
//   - BUYING rate (mid − buy margin) → what we use when converting value
//     back the other way, e.g. paying an agent out. Buying low / selling
//     high is what turns the spread into margin instead of a wash.
// Both are tunable via env without a deploy.
const SELL_MARGIN_PCT = Number(process.env.FX_SELL_MARGIN_PCT ?? 1.5) / 100; // default 1.5%
const BUY_MARGIN_PCT  = Number(process.env.FX_BUY_MARGIN_PCT  ?? 1.0) / 100; // default 1.0%

// Optional ops alert — POSTs a one-line message when we're forced onto a
// stale or static rate, so someone can check the FX sources / bump
// KES_PER_USD before it matters. Entirely best-effort: never throws, never
// blocks, never slows down a checkout.
async function alertOps(message) {
  const url = process.env.FX_ALERT_WEBHOOK_URL;
  if (!url) return;
  try {
    await fetchWithTimeout(url, 4000, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ text: `[FX] ${message}` }),
    });
  } catch { /* best-effort — never let alerting break pricing */ }
}

let cache = { rate: null, fetchedAt: 0, source: null };
// Guards against every concurrent request during a cold start each firing
// their own DB read / live-source waterfall at once.
let _hydratePromise = null;

function isSane(rate) {
  return typeof rate === 'number' && isFinite(rate) && rate >= SANITY_MIN && rate <= SANITY_MAX;
}

// A quote only fails the jump check if we actually have something recent
// enough to compare it to — otherwise the very first rate of the process
// would have nothing to be "sane relative to" and would wrongly be rejected.
function isPlausibleJump(rate) {
  if (!cache.rate) return true;
  const delta = Math.abs(rate - cache.rate) / cache.rate;
  return delta <= MAX_JUMP_PCT;
}

function fetchWithTimeout(url, ms = 5000, opts = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);
  return fetch(url, { ...opts, signal: controller.signal }).finally(() => clearTimeout(timer));
}

// ── Live sources — Frankfurter (frankfurter.dev, blended central-bank data)
// tried first: no API key, generous uptime. NOTE: the older v1/ECB-only
// endpoint only covers ~31 major currencies and does NOT include KES — the
// v2 `/rate/{base}/{quote}` endpoint is required here, since it blends in
// KES's actual publishing central bank (CBK) alongside ECB/others. ──
async function fetchFromFrankfurter() {
  const res  = await fetchWithTimeout('https://api.frankfurter.dev/v2/rate/USD/KES');
  const json = await res.json();
  const rate = Number(json?.rate);
  if (!isSane(rate)) throw new Error(`frankfurter bad rate: ${rate}`);
  return { rate, source: 'frankfurter' };
}

async function fetchFromOpenExchangeRates() {
  const res  = await fetchWithTimeout('https://open.er-api.com/v6/latest/USD');
  const json = await res.json();
  const rate = Number(json?.rates?.KES);
  if (!isSane(rate)) throw new Error(`open.er-api bad rate: ${rate}`);
  return { rate, source: 'open.er-api' };
}

async function fetchFromFawazahmed() {
  const res  = await fetchWithTimeout('https://cdn.jsdelivr.net/npm/@fawazahmed0/currency-api@latest/v1/currencies/usd.json');
  const json = await res.json();
  const rate = Number(json?.usd?.kes);
  if (!isSane(rate)) throw new Error(`fawazahmed0 bad rate: ${rate}`);
  return { rate, source: 'fawazahmed0-cdn' };
}

// ── Durable persistence ─────────────────────────────────────────────────────
// The in-memory cache above is lost on every deploy/restart/scale-event. If
// that happens to coincide with all 3 live sources being unreachable, the
// old code had nothing to fall back to except the hardcoded static rate —
// which could be months stale. Persisting the last good rate to Supabase
// means a cold start instead resumes from the last real market rate, not a
// fixed number set at deploy time. This is entirely best-effort: if the
// table doesn't exist yet or the write/read fails, we silently continue on
// the in-memory/static path exactly as before — pricing must never depend
// on this succeeding.
//
// Expected table (create once):
//   create table fx_rates (
//     pair        text primary key,        -- always 'USD_KES'
//     rate        numeric not null,
//     source      text,
//     fetched_at  timestamptz not null
//   );
async function persistRate(rate, source) {
  if (!supabaseAdmin) return;
  try {
    await supabaseAdmin.from('fx_rates').upsert({
      pair:       'USD_KES',
      rate,
      source,
      fetched_at: new Date().toISOString(),
    }, { onConflict: 'pair' });
  } catch { /* best-effort */ }
}

async function loadPersistedRate() {
  if (!supabaseAdmin) return null;
  try {
    const { data } = await supabaseAdmin
      .from('fx_rates')
      .select('rate, source, fetched_at')
      .eq('pair', 'USD_KES')
      .maybeSingle();
    if (!data || !isSane(Number(data.rate))) return null;
    return {
      rate:      Number(data.rate),
      source:    data.source || 'db-persisted',
      fetchedAt: new Date(data.fetched_at).getTime(),
    };
  } catch {
    return null;
  }
}

// On the very first call in a fresh process, prime the in-memory cache from
// the DB so we're not starting from nothing if a live fetch fails.
async function hydrateFromDbOnce() {
  if (cache.rate) return; // already have something in memory this process
  if (!_hydratePromise) {
    _hydratePromise = loadPersistedRate().then((persisted) => {
      if (persisted && !cache.rate) {
        cache = persisted;
      }
    });
  }
  await _hydratePromise;
}

async function _fetchRate() {
  await hydrateFromDbOnce();

  if (cache.rate && Date.now() - cache.fetchedAt < CACHE_TTL_MS) {
    return { rate: cache.rate, source: cache.source, cached: true };
  }

  const sources = [fetchFromFrankfurter, fetchFromOpenExchangeRates, fetchFromFawazahmed];

  for (const fn of sources) {
    try {
      const result = await fn();
      if (!isPlausibleJump(result.rate)) {
        
        continue; // try the next source rather than trust an implausible jump
      }
      cache = { rate: result.rate, fetchedAt: Date.now(), source: result.source };
      persistRate(result.rate, result.source); // fire-and-forget, never awaited into the hot path
      return { rate: result.rate, source: result.source, cached: false };
    } catch (err) {
      
    }
  }

  // Every live source failed (or was rejected as an implausible jump). Fall
  // back to whatever we last trusted — in-memory first, since it's the most
  // recent — as long as it isn't older than STALE_MAX_MS. Anything staler
  // than that is more likely to be actively wrong than helpful, so it's
  // better to drop through to the static floor and alert loudly than to
  // silently keep serving a rate that's days old.
  if (cache.rate && Date.now() - cache.fetchedAt < STALE_MAX_MS) {
    const ageMin = Math.round((Date.now() - cache.fetchedAt) / 60_000);
    alertOps(`All live FX sources failed — serving cached rate ${cache.rate} (${cache.source}, ${ageMin}m old).`);
    return { rate: cache.rate, source: `${cache.source}:stale`, cached: true };
  }

  alertOps(`All live FX sources AND cache unavailable/too stale — falling back to static rate ${FALLBACK_RATE}. Check KES_PER_USD is current.`);
  return { rate: FALLBACK_RATE, source: 'static-fallback', cached: false };
}

export async function getUsdKesRate() {
  const { rate } = await _fetchRate();
  return rate;
}

export async function getUsdKesRateMeta() {
  return _fetchRate();
}

// ── Pure conversion helpers (unchanged signature — take an explicit rate) ──
export function usdToKes(usdAmount, rate) {
  return Math.round(usdAmount * rate);
}

export function kesToUsd(kesAmount, rate) {
  return parseFloat((kesAmount / rate).toFixed(2));
}

// ── Margin-adjusted rates ───────────────────────────────────────────────────
export function applySellMargin(midRate) {
  return midRate * (1 + SELL_MARGIN_PCT);
}

export function applyBuyMargin(midRate) {
  return midRate * (1 - BUY_MARGIN_PCT);
}

// What a KES-paying customer is actually charged per USD of package price.
// Use this (not the raw mid rate) anywhere we're SELLING a package.
export async function getSellingRate() {
  const mid = await getUsdKesRate();
  return applySellMargin(mid);
}

// What we use when converting value the other way — e.g. an agent payout.
// Use this (not the raw mid rate) anywhere we're BUYING/paying out.
export async function getBuyingRate() {
  const mid = await getUsdKesRate();
  return applyBuyMargin(mid);
}

export async function usdToKesSelling(usdAmount) {
  const sellRate = await getSellingRate();
  return { amountKes: usdToKes(usdAmount, sellRate), rate: sellRate };
}

export async function usdToKesBuying(usdAmount) {
  const buyRate = await getBuyingRate();
  return { amountKes: usdToKes(usdAmount, buyRate), rate: buyRate };
}