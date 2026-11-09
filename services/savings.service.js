// services/savings.service.js
// Lipa Mdogo Mdogo — shared savings logic: configuration, FX quotes,
// encouragement messages, passport-on-file lookup, PDF receipts and the
// email / WhatsApp / in-app notifications sent around deposits and
// redemptions.
//
// Optional env vars:
//   SAVINGS_MIN_DEPOSIT_KES        (default 100)
//   SAVINGS_MAX_CARD_DEPOSIT_KES   (default 1,000,000)
//   SAVINGS_TARGET_MIN_USD         (default 1000)  — low end of a typical Umrah package
//   SAVINGS_TARGET_MAX_USD         (default 1500)  — high end of a typical Umrah package
//   SAVINGS_OPS_EMAIL              — gets an email for every surplus request
//   FRONTEND_URL                   (default https://umrahmarket.net)
//   WHATSAPP_TEMPLATE_SAVINGS_DEPOSIT            HX… (see docs/LIPA_MDOGO_MDOGO.md)
//   WHATSAPP_TEMPLATE_SAVINGS_PASSPORT_REMINDER  HX…
//   WHATSAPP_TEMPLATE_SAVINGS_GOAL_REACHED       HX…
//   WHATSAPP_TEMPLATE_SAVINGS_REDEEMED           HX…

import PDFDocument from 'pdfkit';
import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';
import { supabaseAdmin } from '../config/supabase.js';
import logger from '../config/logger.js';
import { getUsdKesRate, applySellMargin, usdToKes } from './currency.service.js';
import { sendBrandedEmail, escapeEmailHtml as esc } from './email.service.js';
import { sendWhatsAppTemplate } from './whatsappService.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ── Configuration ────────────────────────────────────────────────────────────
const num = (v, fallback) => {
  const n = Number(v);
  return Number.isFinite(n) && n > 0 ? n : fallback;
};

export const SAVINGS = Object.freeze({
  MIN_DEPOSIT_KES: num(process.env.SAVINGS_MIN_DEPOSIT_KES, 100),
  // Safaricom caps a single M-Pesa transaction at KES 250,000.
  MAX_MPESA_DEPOSIT_KES: 250_000,
  MAX_CARD_DEPOSIT_KES: num(process.env.SAVINGS_MAX_CARD_DEPOSIT_KES, 1_000_000),
  TARGET_MIN_USD: num(process.env.SAVINGS_TARGET_MIN_USD, 1000),
  TARGET_MAX_USD: num(process.env.SAVINGS_TARGET_MAX_USD, 1500),
  MIN_PASSPORT_VALIDITY_MONTHS: 6,
});

export const FRONTEND_URL = (process.env.FRONTEND_URL || 'https://umrahmarket.net').replace(/\/$/, '');
export const SAVINGS_PAGE_URL = `${FRONTEND_URL}/lipa-mdogo-mdogo`;

export const EXTRA_SERVICES = Object.freeze({
  meals: 'Meals (full board)',
  ziyarah: 'Ziyarah tours',
  airport_transfer: 'Airport transfers',
  hotel_upgrade: 'Hotel upgrade',
  travel_insurance: 'Travel insurance',
  wheelchair: 'Wheelchair / mobility assistance',
  zamzam: 'Zamzam water allowance',
  other: 'Other services',
});

export const fmtKes = (n) =>
  `KES ${Number(n || 0).toLocaleString('en-KE', { minimumFractionDigits: 0, maximumFractionDigits: 2 })}`;

export const fmtUsd = (n) =>
  `USD ${Number(n || 0).toLocaleString('en-US', { maximumFractionDigits: 0 })}`;

// ── FX quote (selling rate — same as the booking payment flows) ─────────────
export async function getSavingsQuote() {
  let mid = null;
  try {
    mid = await getUsdKesRate();
  } catch (err) {
    logger.warn('[savings] FX rate fetch failed, using fallback', { error: err.message });
  }
  if (!mid || !Number.isFinite(mid) || mid <= 0) mid = num(process.env.KES_PER_USD, 130);
  const sellRate = applySellMargin(mid);
  return {
    sellRate,
    targetMinUsd: SAVINGS.TARGET_MIN_USD,
    targetMaxUsd: SAVINGS.TARGET_MAX_USD,
    targetMinKes: usdToKes(SAVINGS.TARGET_MIN_USD, sellRate),
    targetMaxKes: usdToKes(SAVINGS.TARGET_MAX_USD, sellRate),
  };
}

// ── Encouragement (rotates by deposit count) ────────────────────────────────
// Kept short and single-line so each one also fits a WhatsApp template
// variable (Twilio rejects newlines inside variables).
export const ENCOURAGEMENTS = Object.freeze([
  {
    text: 'The most beloved of deeds to Allah are those that are consistent, even if they are small.',
    source: 'Prophet Muhammad (peace be upon him), Sahih al-Bukhari 6464 & Sahih Muslim 783',
  },
  {
    text: 'Umrah is an expiation for the sins committed between it and the previous one.',
    source: 'Prophet Muhammad (peace be upon him), Sahih al-Bukhari 1773',
  },
  {
    text: 'And complete the Hajj and Umrah for Allah.',
    source: "Qur'an 2:196",
  },
  {
    text: 'And whoever relies upon Allah, then He is sufficient for him.',
    source: "Qur'an 65:3",
  },
  {
    text: 'Follow up Hajj and Umrah, for they remove poverty and sins as the bellows removes impurity from iron, gold and silver.',
    source: "Prophet Muhammad (peace be upon him), Jami' at-Tirmidhi 810",
  },
  {
    text: 'Indeed, Allah does not allow the reward of those who do good to be lost.',
    source: "Qur'an 9:120",
  },
  {
    text: 'Indeed, with hardship comes ease.',
    source: "Qur'an 94:6",
  },
  {
    text: 'Umrah in Ramadan is equal to Hajj in reward.',
    source: 'Prophet Muhammad (peace be upon him), Sahih al-Bukhari 1782',
  },
]);

export function pickEncouragement(seed = 0) {
  const i = Math.abs(Number.parseInt(seed, 10) || 0) % ENCOURAGEMENTS.length;
  return ENCOURAGEMENTS[i];
}

export function computeProgress(balanceKes, goalKes) {
  const balance = Number(balanceKes) || 0;
  const goal = Number(goalKes) || 0;
  if (goal <= 0) return { percent: 0, remainingKes: 0, reached: false };
  const percent = Math.min(100, Math.floor((balance / goal) * 100));
  return { percent, remainingKes: Math.max(0, Math.ceil(goal - balance)), reached: balance >= goal };
}

// ── Accounts ─────────────────────────────────────────────────────────────────
export async function ensureSavingsAccount(userId) {
  const { error } = await supabaseAdmin
    .from('savings_accounts')
    .upsert({ user_id: userId }, { onConflict: 'user_id', ignoreDuplicates: true });
  if (error) throw error;
  const { data, error: selErr } = await supabaseAdmin
    .from('savings_accounts')
    .select('*')
    .eq('user_id', userId)
    .single();
  if (selErr) throw selErr;
  return data;
}

export async function loadProfile(userId) {
  const { data } = await supabaseAdmin
    .from('profiles')
    .select('id, first_name, last_name, email, phone, whatsapp_opt_in')
    .eq('id', userId)
    .maybeSingle();
  return data || null;
}

const displayName = (p) => [p?.first_name, p?.last_name].filter(Boolean).join(' ') || 'Pilgrim';

// ── Passport on file ─────────────────────────────────────────────────────────
const PASSPORT_OK = new Set(['verified', 'manual_review']);

function todayUTC() {
  const n = new Date();
  return new Date(Date.UTC(n.getUTCFullYear(), n.getUTCMonth(), n.getUTCDate()));
}

export function addMonthsUTC(date, months) {
  const d = new Date(date.getTime());
  d.setUTCMonth(d.getUTCMonth() + months);
  return d;
}

export function parseDateOnly(s) {
  if (!s) return null;
  const m = String(s).match(/^(\d{4})-(\d{2})-(\d{2})/);
  if (!m) return null;
  return new Date(Date.UTC(+m[1], +m[2] - 1, +m[3]));
}

/**
 * Does this saver have a usable passport on file? Checks the savings passport
 * first, then falls back to a passport already verified on an earlier booking
 * so returning pilgrims aren't asked twice. An expired passport doesn't count.
 */
export async function getPassportOnFile(userId) {
  const { data: sp } = await supabaseAdmin
    .from('savings_passports')
    .select('*')
    .eq('user_id', userId)
    .maybeSingle();

  const notExpired = (expiry) => {
    const d = parseDateOnly(expiry);
    return !!d && d >= todayUTC();
  };

  if (sp && PASSPORT_OK.has(sp.verification_status) && notExpired(sp.passport_expiry)) {
    return { onFile: true, source: 'savings', status: sp.verification_status, record: sp, attemptsUsed: sp.attempts || 0 };
  }

  const { data: rows } = await supabaseAdmin
    .from('passport_verifications')
    .select('passport_number, passport_country, nationality, surname, given_names, full_name, date_of_birth, passport_expiry, passport_image_url, image_key, verification_status, verified, mrz_raw, ocr_confidence, match_score, match_details, updated_at')
    .eq('user_id', userId)
    .eq('traveler_index', 0)
    .in('verification_status', [...PASSPORT_OK])
    .order('updated_at', { ascending: false })
    .limit(5);

  const prior = (rows || []).find((r) => notExpired(r.passport_expiry));
  if (prior) {
    return { onFile: true, source: 'booking', status: prior.verification_status, record: prior, attemptsUsed: 0 };
  }

  const expired = sp && PASSPORT_OK.has(sp.verification_status) && !notExpired(sp.passport_expiry);
  return {
    onFile: false,
    source: null,
    status: expired ? 'expired' : (sp?.verification_status || null),
    record: null,
    attemptsUsed: sp?.attempts || 0,
  };
}

/** Public, PII-light view of the passport status for the frontend. */
export function passportStatusView(p) {
  const r = p.record;
  return {
    onFile: p.onFile,
    status: p.status,
    source: p.source,
    attemptsUsed: p.attemptsUsed || 0,
    attemptsRemaining: Math.max(0, 3 - (p.attemptsUsed || 0)),
    expiry: r?.passport_expiry || null,
    // Last 3 characters only — enough for the pilgrim to recognise it.
    numberHint: r?.passport_number ? `•••${String(r.passport_number).slice(-3)}` : null,
  };
}

// ── In-app notifications ─────────────────────────────────────────────────────
export async function createNotification(userId, { type, title, body, data = {} }) {
  const { error } = await supabaseAdmin
    .from('user_notifications')
    .insert({ user_id: userId, type, title, body, data });
  if (error) logger.error('[savings] notification insert failed', { userId, type, error: error.message });
}

// ── WhatsApp (approved templates only — see docs/LIPA_MDOGO_MDOGO.md) ───────
async function sendSavingsWhatsApp({ profile, userId, envKey, templateName, variables }) {
  const templateSid = process.env[envKey];
  if (!templateSid) {
    logger.info(`[savings] ${envKey} not set — WhatsApp "${templateName}" skipped`);
    return { ok: false, skipped: true };
  }
  if (!profile?.phone) return { ok: false, skipped: true, error: 'No phone on file' };
  if (profile.whatsapp_opt_in === false) return { ok: false, skipped: true, error: 'Opted out' };

  // Twilio rejects variables with newlines, tabs or 4+ consecutive spaces.
  const clean = Object.fromEntries(
    Object.entries(variables).map(([k, v]) => [k, String(v ?? '').replace(/\s+/g, ' ').trim().slice(0, 900)])
  );

  return sendWhatsAppTemplate({
    to: profile.phone,
    templateSid,
    templateName,
    variables: clean,
    category: 'savings',
    meta: { recipientType: 'client', recipientId: userId },
  });
}

// ── PDF receipt ──────────────────────────────────────────────────────────────
const BRAND = {
  emerald: '#0B6B4E',
  emeraldSoft: '#E6F4EF',
  gold: '#D4AF37',
  ink: '#0F172A',
  muted: '#64748B',
  hairline: '#E2E8F0',
};

let cachedLogo;
async function loadLogo() {
  if (cachedLogo !== undefined) return cachedLogo;
  try {
    cachedLogo = await fs.readFile(path.resolve(__dirname, '..', 'assets', 'umrahmarket.png'));
  } catch {
    cachedLogo = null;
  }
  return cachedLogo;
}

const METHOD_LABEL = { MPESA: 'M-Pesa', CARD: 'Bank card', INTERNAL: 'Savings wallet' };

/**
 * Render a single-page A4 receipt for a successful deposit.
 * Everything is placed at absolute positions with margin 0 so PDFKit never
 * auto-adds a second page (same approach as bookingReceipt.service.js).
 */
export async function renderDepositReceiptPdf({ tx, profile, goalKes, quote }) {
  const logo = await loadLogo();
  const amount = Number(tx.amount_kes) || 0;
  const balanceAfter = Number(tx.balance_after_kes) || 0;
  const previous = Math.max(0, balanceAfter - amount);
  const progress = computeProgress(balanceAfter, goalKes);
  const paidAt = tx.paid_at ? new Date(tx.paid_at) : new Date(tx.created_at || Date.now());
  const quoteLine = pickEncouragement(tx.receipt_no?.charCodeAt?.(tx.receipt_no.length - 1) || 0);

  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ size: 'A4', margin: 0 });
    const chunks = [];
    doc.on('data', (c) => chunks.push(c));
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);

    const W = doc.page.width;
    const H = doc.page.height;
    const M = 48;
    const CW = W - M * 2;

    // Header band
    const HEADER_H = 96;
    const grad = doc.linearGradient(0, 0, W, HEADER_H);
    grad.stop(0, '#E6F4EC').stop(0.55, '#FDFDFC').stop(1, '#F5EFDD');
    doc.rect(0, 0, W, HEADER_H).fill(grad);

    doc.roundedRect(M, 18, 60, 60, 10).fillAndStroke('#FFFFFF', '#E7E2D6');
    if (logo) {
      try { doc.image(logo, M + 6, 24, { fit: [48, 48], align: 'center', valign: 'center' }); } catch { /* fall through */ }
    }
    doc.fontSize(17).font('Helvetica-Bold')
      .fillColor(BRAND.gold).text('UMRAH ', M + 74, 26, { continued: true })
      .fillColor(BRAND.emerald).text('MARKET');
    doc.fillColor(BRAND.muted).fontSize(7.5).font('Helvetica')
      .text('LIPA MDOGO MDOGO  ·  UMRAH SAVINGS', M + 74, 48, { characterSpacing: 1 })
      .text('www.umrahmarket.net', M + 74, 60);

    doc.fillColor(BRAND.ink).fontSize(13).font('Helvetica-Bold')
      .text('SAVINGS RECEIPT', W - M - 220, 24, { width: 220, align: 'right', characterSpacing: 1.2 });
    doc.fillColor(BRAND.muted).fontSize(8.5).font('Helvetica')
      .text(`No. ${tx.receipt_no}`, W - M - 220, 44, { width: 220, align: 'right' })
      .text(paidAt.toLocaleString('en-KE', { timeZone: 'Africa/Nairobi', day: '2-digit', month: 'long', year: 'numeric', hour: '2-digit', minute: '2-digit' }), W - M - 220, 56, { width: 220, align: 'right' });
    doc.roundedRect(W - M - 64, 70, 64, 16, 8).fill(BRAND.emerald);
    doc.fillColor('#FFFFFF').fontSize(8).font('Helvetica-Bold')
      .text('RECEIVED', W - M - 64, 74.5, { width: 64, align: 'center', characterSpacing: 1 });

    const rule = doc.linearGradient(0, HEADER_H, W, HEADER_H);
    rule.stop(0, BRAND.gold).stop(0.5, BRAND.ink).stop(1, BRAND.emerald);
    doc.rect(0, HEADER_H, W, 3).fill(rule);

    let y = HEADER_H + 30;

    // Saver + payment details
    const colW = (CW - 20) / 2;
    doc.roundedRect(M, y, CW, 96, 8).fillAndStroke('#FAFAF8', BRAND.hairline);
    doc.roundedRect(M, y, 4, 96, 2).fill(BRAND.gold);
    const label = (t, x, yy) => doc.fillColor(BRAND.muted).fontSize(7.5).font('Helvetica-Bold').text(t, x, yy, { characterSpacing: 0.5 });
    const value = (t, x, yy, opts = {}) => doc.fillColor(BRAND.ink).fontSize(opts.size || 10).font(opts.bold ? 'Helvetica-Bold' : 'Helvetica').text(t, x, yy, { width: colW - 16 });

    label('RECEIVED FROM', M + 20, y + 16);
    value(displayName(profile), M + 20, y + 30, { bold: true, size: 10.5 });
    value(profile?.email || '—', M + 20, y + 46, { size: 8.5 });
    value(tx.phone || profile?.phone || '—', M + 20, y + 60, { size: 8.5 });

    const c2 = M + 20 + colW + 10;
    label('PAYMENT', c2, y + 16);
    value(`Method: ${METHOD_LABEL[tx.method] || tx.method || '—'}`, c2, y + 30, { size: 9 });
    value(`Reference: ${tx.mpesa_ref || tx.result_code || tx.pesapal_merchant_ref || '—'}`, c2, y + 44, { size: 9 });
    value('Purpose: Umrah savings deposit', c2, y + 58, { size: 9 });

    y += 96 + 26;

    // Amount box
    doc.roundedRect(M, y, CW, 44, 6).fill(BRAND.emeraldSoft);
    doc.roundedRect(M, y, CW, 44, 6).lineWidth(1).stroke(BRAND.emerald);
    doc.fillColor(BRAND.emerald).fontSize(9).font('Helvetica-Bold')
      .text('AMOUNT SAVED TODAY', M + 16, y + 17, { characterSpacing: 0.5 });
    doc.fontSize(17).text(fmtKes(amount), M, y + 13, { width: CW - 16, align: 'right' });
    y += 44 + 22;

    // Balance table
    const rows = [
      ['Previous savings balance', fmtKes(previous)],
      ['This deposit', `+ ${fmtKes(amount)}`],
      ['New savings balance', fmtKes(balanceAfter)],
    ];
    rows.forEach(([k, v], i) => {
      const last = i === rows.length - 1;
      doc.fillColor(last ? BRAND.ink : BRAND.muted).fontSize(last ? 11 : 10).font(last ? 'Helvetica-Bold' : 'Helvetica')
        .text(k, M + 4, y)
        .text(v, M, y, { width: CW - 4, align: 'right' });
      y += 20;
      if (i < rows.length - 1) doc.moveTo(M, y - 5).lineTo(M + CW, y - 5).lineWidth(0.5).stroke(BRAND.hairline);
    });
    y += 14;

    // Progress bar
    doc.fillColor(BRAND.ink).fontSize(9.5).font('Helvetica-Bold')
      .text(`Progress to your Umrah goal (${fmtKes(goalKes)})`, M, y);
    doc.fillColor(BRAND.emerald).text(`${progress.percent}%`, M, y, { width: CW, align: 'right' });
    y += 16;
    doc.roundedRect(M, y, CW, 10, 5).fill('#EEF2F0');
    if (progress.percent > 0) {
      const barGrad = doc.linearGradient(M, y, M + CW, y);
      barGrad.stop(0, BRAND.emerald).stop(1, BRAND.gold);
      doc.roundedRect(M, y, Math.max(10, (CW * progress.percent) / 100), 10, 5).fill(barGrad);
    }
    y += 20;
    doc.fillColor(BRAND.muted).fontSize(8.5).font('Helvetica').text(
      progress.reached
        ? 'Alhamdulillah, you have reached your goal. Log in to choose your Umrah package and agent.'
        : `${fmtKes(progress.remainingKes)} to go. A typical Umrah package costs ${fmtUsd(quote.targetMinUsd)} - ${fmtUsd(quote.targetMaxUsd)} (about ${fmtKes(quote.targetMinKes)} - ${fmtKes(quote.targetMaxKes)}).`,
      M, y, { width: CW, lineGap: 2 }
    );
    y += 40;

    // Encouragement
    doc.roundedRect(M, y, CW, 70, 8).fillAndStroke('#FBF8EE', '#EADFB8');
    doc.fillColor(BRAND.ink).fontSize(10.5).font('Helvetica-Oblique')
      .text(`"${quoteLine.text}"`, M + 18, y + 14, { width: CW - 36, lineGap: 2 });
    doc.fillColor(BRAND.muted).fontSize(8).font('Helvetica')
      .text(`- ${quoteLine.source}`, M + 18, y + 50, { width: CW - 36 });

    // Footer
    const fy = H - 96;
    doc.rect(0, fy, W, 2).fill(rule);
    doc.fillColor(BRAND.muted).fontSize(7.8).font('Helvetica')
      .text('Al Mukarram Shopping Mall, Captain Mungai Street, Eastleigh, Nairobi  ·  +254 700 111 106  ·  info@umrahmarket.net', M, fy + 18, { width: CW, align: 'center' })
      .text('Your savings are held by Umrah Market for your Umrah. This is a system-generated receipt and does not require a signature.', M, fy + 34, { width: CW, align: 'center' });

    doc.end();
  });
}

// ── Email building blocks ────────────────────────────────────────────────────
const p = (html) => `<p style="margin:0 0 14px;font-size:14px;line-height:22px;color:#475467;">${html}</p>`;

const button = (href, label) => `
  <table role="presentation" cellpadding="0" cellspacing="0" style="margin:8px 0 4px;">
    <tr><td style="border-radius:10px;background:#0f9f6e;">
      <a href="${href}" style="display:inline-block;padding:12px 26px;font-size:14px;font-weight:600;color:#ffffff;text-decoration:none;border-radius:10px;">${esc(label)}</a>
    </td></tr>
  </table>`;

const quoteBox = (q) => `
  <div style="margin:18px 0;padding:16px 18px;background:#fbf8ee;border:1px solid #eadfb8;border-radius:12px;">
    <p style="margin:0 0 6px;font-size:14px;line-height:22px;color:#1f2937;font-style:italic;">&ldquo;${esc(q.text)}&rdquo;</p>
    <p style="margin:0;font-size:12px;color:#6b7280;">— ${esc(q.source)}</p>
  </div>`;

const progressBar = (percent) => `
  <div style="margin:6px 0 4px;background:#eef2f0;border-radius:999px;height:12px;overflow:hidden;">
    <div style="width:${Math.max(2, percent)}%;height:12px;background:linear-gradient(90deg,#0b6b4e,#d4af37);border-radius:999px;"></div>
  </div>`;

const detailRows = (rows) => `
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin:6px 0 18px;border:1px solid #edf2ee;border-radius:12px;">
    ${rows.map(([k, v], i) => `
      <tr>
        <td style="padding:10px 14px;font-size:13px;color:#667085;${i ? 'border-top:1px solid #f1f5f2;' : ''}">${esc(k)}</td>
        <td style="padding:10px 14px;font-size:13px;color:#101828;font-weight:600;text-align:right;${i ? 'border-top:1px solid #f1f5f2;' : ''}">${esc(v)}</td>
      </tr>`).join('')}
  </table>`;

const passportBox = () => `
  <div style="margin:18px 0;padding:14px 16px;background:#fff7ed;border:1px solid #fed7aa;border-radius:12px;">
    <p style="margin:0 0 6px;font-size:14px;font-weight:700;color:#9a3412;">Please upload your passport</p>
    <p style="margin:0;font-size:13px;line-height:20px;color:#9a3412;">
      To be ready to travel the moment your savings are complete, upload a clear photo of your passport's photo page in your Lipa Mdogo Mdogo account. It needs to be valid for at least 6 months after your travel date.
    </p>
  </div>`;

// ── Deposit notifications ────────────────────────────────────────────────────
/**
 * Send the receipt + encouragement for a deposit that was just credited.
 * Claims the transaction first (notified_at) so concurrent callers — the
 * M-Pesa callback, a status poll and the reconcile job can all race here —
 * never send the same receipt twice. Each channel fails independently.
 */
export async function notifyDepositCredited(txId) {
  const { data: tx, error: claimErr } = await supabaseAdmin
    .from('savings_transactions')
    .update({ notified_at: new Date().toISOString() })
    .eq('id', txId)
    .eq('status', 'SUCCESS')
    .is('notified_at', null)
    .select('*')
    .maybeSingle();

  if (claimErr) {
    logger.error('[savings] could not claim deposit for notification', { txId, error: claimErr.message });
    return;
  }
  if (!tx) return; // already notified (or not a success)

  const userId = tx.user_id;
  const [profile, account, quote, passport] = await Promise.all([
    loadProfile(userId),
    ensureSavingsAccount(userId),
    getSavingsQuote(),
    getPassportOnFile(userId),
  ]);

  const goalKes = Number(account.goal_kes) || quote.targetMinKes;
  const balance = Number(tx.balance_after_kes) || 0;
  const amount = Number(tx.amount_kes) || 0;
  const progress = computeProgress(balance, goalKes);
  const q = pickEncouragement(account.deposit_count);
  const name = profile?.first_name || 'Pilgrim';

  const encouragementLine = progress.reached
    ? 'Alhamdulillah, you have saved enough for an Umrah package. Log in to choose your package.'
    : `You are ${progress.percent}% of the way. An Umrah package costs ${fmtUsd(quote.targetMinUsd)} - ${fmtUsd(quote.targetMaxUsd)}. Keep going, insha'Allah!`;

  // 1) In-app
  await createNotification(userId, {
    type: 'savings_deposit',
    title: `We have received your ${fmtKes(amount)} deposit`,
    body: `Receipt ${tx.receipt_no}. New balance ${fmtKes(balance)}. ${encouragementLine}`,
    data: { transactionId: tx.id, receiptNo: tx.receipt_no, balanceKes: balance },
  });
  if (!passport.onFile) {
    await createNotification(userId, {
      type: 'savings_passport_reminder',
      title: 'Upload your passport',
      body: 'Upload your passport now so you are ready to book your Umrah as soon as your savings are complete.',
      data: { action: 'upload_passport' },
    });
  }

  // 2) Email with PDF receipt
  if (profile?.email) {
    try {
      const pdf = await renderDepositReceiptPdf({ tx, profile, goalKes, quote });
      const bodyHtml = `
        <h1 style="margin:0 0 12px;font-size:20px;font-weight:700;color:#101828;">We have received your Lipa Mdogo Mdogo deposit</h1>
        ${p(`Assalamu Alaikum ${esc(name)},`)}
        ${p(`Jazakallahu khairan! We have received <strong>${esc(fmtKes(amount))}</strong> into your Umrah savings. Your receipt is attached.`)}
        ${detailRows([
          ['Receipt number', tx.receipt_no],
          ['Amount', fmtKes(amount)],
          ['Paid via', `${METHOD_LABEL[tx.method] || tx.method}${tx.mpesa_ref ? ` · ${tx.mpesa_ref}` : ''}`],
          ['New savings balance', fmtKes(balance)],
        ])}
        <p style="margin:0 0 4px;font-size:13px;font-weight:600;color:#101828;">Progress to your goal of ${esc(fmtKes(goalKes))}: ${progress.percent}%</p>
        ${progressBar(progress.percent)}
        ${p(progress.reached
          ? '<strong>Alhamdulillah, you have saved enough for an Umrah package!</strong> Log in to choose your package and agent. The cost will be deducted from your savings.'
          : `Continue saving with us. An Umrah package costs between <strong>${esc(fmtUsd(quote.targetMinUsd))} and ${esc(fmtUsd(quote.targetMaxUsd))}</strong> (about ${esc(fmtKes(quote.targetMinKes))} – ${esc(fmtKes(quote.targetMaxKes))}). You have <strong>${esc(fmtKes(progress.remainingKes))}</strong> to go.`)}
        ${quoteBox(q)}
        ${passport.onFile ? '' : passportBox()}
        ${button(SAVINGS_PAGE_URL, progress.reached ? 'Choose my Umrah package' : 'Continue saving')}
        ${p('<span style="font-size:12px;color:#98a2b3;">May Allah accept your intention and make the journey easy for you.</span>')}
      `;
      await sendBrandedEmail({
        to: profile.email,
        subject: `Lipa Mdogo Mdogo receipt ${tx.receipt_no} — ${fmtKes(amount)} received`,
        preheader: `We received ${fmtKes(amount)}. New savings balance ${fmtKes(balance)}.`,
        bodyHtml,
        text: `Assalamu Alaikum ${name},\n\nWe have received your Lipa Mdogo Mdogo deposit of ${fmtKes(amount)}.\nReceipt: ${tx.receipt_no}\nNew balance: ${fmtKes(balance)}\nProgress: ${progress.percent}% of ${fmtKes(goalKes)}\n\n"${q.text}" — ${q.source}\n\n${passport.onFile ? '' : 'Please upload your passport in your Lipa Mdogo Mdogo account.\n\n'}Continue saving: ${SAVINGS_PAGE_URL}\n\nUmrah Market`,
        attachments: [{ filename: `${tx.receipt_no}.pdf`, content: pdf, contentType: 'application/pdf' }],
      });
    } catch (err) {
      logger.error('[savings] deposit email failed', { txId, error: err.message });
    }
  }

  // 3) WhatsApp receipt (+ passport reminder)
  try {
    await sendSavingsWhatsApp({
      profile, userId,
      envKey: 'WHATSAPP_TEMPLATE_SAVINGS_DEPOSIT',
      templateName: 'savings_deposit_received',
      variables: {
        1: name,
        2: fmtKes(amount),
        3: tx.receipt_no,
        4: fmtKes(balance),
        5: `${encouragementLine} "${q.text}" (${q.source})`,
      },
    });
    if (!passport.onFile) {
      await sendSavingsWhatsApp({
        profile, userId,
        envKey: 'WHATSAPP_TEMPLATE_SAVINGS_PASSPORT_REMINDER',
        templateName: 'savings_passport_reminder',
        variables: { 1: name, 2: SAVINGS_PAGE_URL },
      });
    }
  } catch (err) {
    logger.error('[savings] deposit WhatsApp failed', { txId, error: err.message });
  }

  // 4) Goal reached (once per account)
  if (progress.reached && !account.goal_reached_notified_at) {
    await notifyGoalReached({ userId, profile, balance, goalKes, quote });
  }
}

async function notifyGoalReached({ userId, profile, balance, goalKes, quote }) {
  const { data: claimed } = await supabaseAdmin
    .from('savings_accounts')
    .update({ goal_reached_notified_at: new Date().toISOString() })
    .eq('user_id', userId)
    .is('goal_reached_notified_at', null)
    .select('user_id')
    .maybeSingle();
  if (!claimed) return;

  const name = profile?.first_name || 'Pilgrim';
  await createNotification(userId, {
    type: 'savings_goal_reached',
    title: 'Alhamdulillah — you can now book your Umrah!',
    body: `Your savings of ${fmtKes(balance)} have reached your goal. Choose your Umrah package and agent; the cost will be deducted from your savings.`,
    data: { balanceKes: balance },
  });

  if (profile?.email) {
    try {
      await sendBrandedEmail({
        to: profile.email,
        subject: 'Alhamdulillah! Your Umrah savings goal is complete',
        preheader: `You have saved ${fmtKes(balance)}. Choose your Umrah package now.`,
        bodyHtml: `
          <h1 style="margin:0 0 12px;font-size:20px;font-weight:700;color:#101828;">Alhamdulillah, ${esc(name)}!</h1>
          ${p(`Your Lipa Mdogo Mdogo savings have reached <strong>${esc(fmtKes(balance))}</strong>, meeting your goal of ${esc(fmtKes(goalKes))}.`)}
          ${p('You can now choose your Umrah package and travel agent. The package price is deducted from your savings, and any surplus stays yours — you can have it refunded or use it for extras like meals or Ziyarah tours.')}
          ${quoteBox({ text: 'And proclaim to the people the Hajj; they will come to you on foot and on every lean camel; they will come from every distant pass.', source: "Qur'an 22:27" })}
          ${button(SAVINGS_PAGE_URL, 'Choose my Umrah package')}
        `,
        text: `Alhamdulillah ${name}! Your savings of ${fmtKes(balance)} have reached your goal. Choose your Umrah package: ${SAVINGS_PAGE_URL}`,
      });
    } catch (err) {
      logger.error('[savings] goal email failed', { userId, error: err.message });
    }
  }

  try {
    await sendSavingsWhatsApp({
      profile, userId,
      envKey: 'WHATSAPP_TEMPLATE_SAVINGS_GOAL_REACHED',
      templateName: 'savings_goal_reached',
      variables: { 1: name, 2: fmtKes(balance), 3: SAVINGS_PAGE_URL },
    });
  } catch (err) {
    logger.error('[savings] goal WhatsApp failed', { userId, error: err.message });
  }
}

// ── Redemption notification ──────────────────────────────────────────────────
export async function notifyRedemption({ userId, packageName, agentName, amountKes, balanceAfter, receiptNo, bookingId }) {
  const profile = await loadProfile(userId);
  const name = profile?.first_name || 'Pilgrim';
  const surplus = Number(balanceAfter) || 0;
  const surplusLine = surplus > 0
    ? `You have a surplus of ${fmtKes(surplus)} left in your savings. You can have it refunded, or use it for extra services such as meals or Ziyarah tours.`
    : 'Your savings covered the package exactly.';

  await createNotification(userId, {
    type: 'savings_redeemed',
    title: `Your Umrah is booked: ${packageName}`,
    body: `${fmtKes(amountKes)} was deducted from your savings to pay ${agentName}. ${surplusLine}`,
    data: { bookingId, receiptNo, surplusKes: surplus },
  });
  if (surplus > 0) {
    await createNotification(userId, {
      type: 'savings_surplus',
      title: `You have ${fmtKes(surplus)} surplus`,
      body: 'Choose whether to get it refunded or use it for extra services like meals, Ziyarah tours or airport transfers.',
      data: { action: 'surplus', surplusKes: surplus, bookingId },
    });
  }

  if (profile?.email) {
    try {
      await sendBrandedEmail({
        to: profile.email,
        subject: `Your Umrah is booked — paid from your Lipa Mdogo Mdogo savings`,
        preheader: `${fmtKes(amountKes)} paid to ${agentName}.`,
        bodyHtml: `
          <h1 style="margin:0 0 12px;font-size:20px;font-weight:700;color:#101828;">Mabrook, ${esc(name)}! Your Umrah is booked</h1>
          ${p('Your Lipa Mdogo Mdogo savings have paid for your Umrah package. Your booking receipt is in a separate email.')}
          ${detailRows([
            ['Package', packageName],
            ['Travel agent', agentName],
            ['Paid from savings', fmtKes(amountKes)],
            ['Savings transaction', receiptNo],
            ['Remaining savings', fmtKes(surplus)],
          ])}
          ${p(esc(surplusLine))}
          ${quoteBox({ text: 'Umrah is an expiation for the sins committed between it and the previous one.', source: 'Prophet Muhammad (peace be upon him), Sahih al-Bukhari 1773' })}
          ${button(SAVINGS_PAGE_URL, surplus > 0 ? 'Decide what to do with my surplus' : 'View my savings')}
        `,
        text: `Mabrook ${name}! ${fmtKes(amountKes)} from your savings paid for ${packageName} with ${agentName}. ${surplusLine} ${SAVINGS_PAGE_URL}`,
      });
    } catch (err) {
      logger.error('[savings] redemption email failed', { userId, error: err.message });
    }
  }

  try {
    await sendSavingsWhatsApp({
      profile, userId,
      envKey: 'WHATSAPP_TEMPLATE_SAVINGS_REDEEMED',
      templateName: 'savings_redeemed',
      variables: { 1: name, 2: packageName, 3: agentName, 4: fmtKes(amountKes), 5: surplusLine },
    });
  } catch (err) {
    logger.error('[savings] redemption WhatsApp failed', { userId, error: err.message });
  }
}

// ── Surplus notifications ────────────────────────────────────────────────────
export async function notifySurplusRequested({ userId, request }) {
  const profile = await loadProfile(userId);
  const name = profile?.first_name || 'Pilgrim';
  const isRefund = request.type === 'REFUND';
  const services = (request.services || []).map((s) => EXTRA_SERVICES[s] || s).join(', ');

  await createNotification(userId, {
    type: 'savings_surplus_requested',
    title: isRefund ? 'Refund request received' : 'Extra services request received',
    body: isRefund
      ? `We will send ${fmtKes(request.amount_kes)} to ${request.payout_phone || 'your M-Pesa number'} shortly.`
      : `Our team will arrange ${services || 'your extra services'} worth ${fmtKes(request.amount_kes)} with your agent.`,
    data: { requestId: request.id },
  });

  const ops = process.env.SAVINGS_OPS_EMAIL;
  if (ops) {
    try {
      await sendBrandedEmail({
        to: ops,
        subject: `[Lipa Mdogo Mdogo] ${isRefund ? 'Refund' : 'Extras'} request — ${fmtKes(request.amount_kes)}`,
        bodyHtml: `
          <h1 style="margin:0 0 12px;font-size:18px;font-weight:700;color:#101828;">New surplus request</h1>
          ${detailRows([
            ['Pilgrim', displayName(profile)],
            ['Email', profile?.email || '—'],
            ['Phone', profile?.phone || '—'],
            ['Type', isRefund ? 'Refund to M-Pesa' : 'Extra services'],
            ['Amount', fmtKes(request.amount_kes)],
            ['Payout phone', request.payout_phone || '—'],
            ['Services', services || '—'],
            ['Note', request.note || '—'],
          ])}
          ${p('Resolve it from the Superadmin dashboard → Lipa Mdogo Mdogo.')}
        `,
        text: `New ${request.type} request for ${fmtKes(request.amount_kes)} from ${displayName(profile)} (${profile?.email}).`,
      });
    } catch (err) {
      logger.error('[savings] ops surplus email failed', { error: err.message });
    }
  }

  if (profile?.email) {
    try {
      await sendBrandedEmail({
        to: profile.email,
        subject: isRefund ? 'We have received your refund request' : 'We have received your extra services request',
        bodyHtml: `
          <h1 style="margin:0 0 12px;font-size:20px;font-weight:700;color:#101828;">Request received</h1>
          ${p(`Assalamu Alaikum ${esc(name)},`)}
          ${p(isRefund
            ? `We have set aside <strong>${esc(fmtKes(request.amount_kes))}</strong> from your savings and will send it to <strong>${esc(request.payout_phone || 'your M-Pesa number')}</strong>. You will get a confirmation once it is sent.`
            : `We have set aside <strong>${esc(fmtKes(request.amount_kes))}</strong> from your savings for: <strong>${esc(services || 'extra services')}</strong>. Our team will arrange these with your travel agent and confirm with you.`)}
          ${button(SAVINGS_PAGE_URL, 'View my savings')}
        `,
        text: `Your ${isRefund ? 'refund' : 'extra services'} request for ${fmtKes(request.amount_kes)} has been received.`,
      });
    } catch (err) {
      logger.error('[savings] surplus confirmation email failed', { userId, error: err.message });
    }
  }
}

export async function notifySurplusResolved({ userId, result, adminNote }) {
  const profile = await loadProfile(userId);
  const name = profile?.first_name || 'Pilgrim';
  const done = result.status === 'COMPLETED';
  const isRefund = result.type === 'REFUND';

  const title = done
    ? (isRefund ? `Refund of ${fmtKes(result.amount_kes)} sent` : 'Your extra services are arranged')
    : 'Your surplus request was not completed';
  const body = done
    ? (isRefund ? `We have sent ${fmtKes(result.amount_kes)} to you.` : `${fmtKes(result.amount_kes)} has been applied to your extra services.`)
    : `${fmtKes(result.amount_kes)} has been returned to your savings balance.${adminNote ? ` Note: ${adminNote}` : ''}`;

  await createNotification(userId, { type: 'savings_surplus_resolved', title, body, data: { requestId: result.request_id } });

  if (profile?.email) {
    try {
      await sendBrandedEmail({
        to: profile.email,
        subject: title,
        bodyHtml: `
          <h1 style="margin:0 0 12px;font-size:20px;font-weight:700;color:#101828;">${esc(title)}</h1>
          ${p(`Assalamu Alaikum ${esc(name)},`)}
          ${p(esc(body))}
          ${button(SAVINGS_PAGE_URL, 'View my savings')}
        `,
        text: `${title}. ${body}`,
      });
    } catch (err) {
      logger.error('[savings] surplus resolution email failed', { userId, error: err.message });
    }
  }
}
