import PDFDocument from 'pdfkit';
import nodemailer from 'nodemailer';
import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';
import { supabaseAdmin } from '../config/supabase.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const BRAND = {
  emerald: '#0B6B4E',
  emeraldSoft: '#E6F4EF',
  gold: '#D4AF37',
  navy: '#0F172A',
  ink: '#0F172A',
  muted: '#64748B',
  hairline: '#E2E8F0',
};

// 1) Logo bundled inside this backend repo (sibling of services/): assets/umrahmarket.png
const BUNDLED_LOGO_PATH = path.resolve(__dirname, '..', 'assets', 'umrahmarket.png');

// 2) Fallback: fetch over HTTP. Prefer the backend's own static route
//    (set BACKEND_PUBLIC_URL to this backend's deployed domain) over the
//    frontend's domain, since the backend controls its own uptime/deploys.
const DEFAULT_LOGO_URL =
  process.env.BOOKING_RECEIPT_LOGO_URL ||
  `${process.env.BACKEND_PUBLIC_URL || 'http://localhost:5000'}/assets/umrahmarket.png`;

const hasSmtpConfig = () => Boolean(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS);

const isValidEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email || '').trim());

const fmtMoney = (n) => `KES ${Number(n || 0).toLocaleString('en-KE', { minimumFractionDigits: 2 })}`;

// Cache across invocations so we don't hit disk/network on every receipt.
let cachedLogoBuffer = null;
let cachedLogoAttempted = false;

async function loadLogoBuffer() {
  if (cachedLogoAttempted) return cachedLogoBuffer;
  cachedLogoAttempted = true;

  // 1) Logo bundled inside this backend repo — no dependency on a sibling
  //    frontend folder or on process.cwd(), so it works regardless of
  //    deploy layout or working directory.
  try {
    cachedLogoBuffer = await fs.readFile(BUNDLED_LOGO_PATH);
    return cachedLogoBuffer;
  } catch (err) {
    console.warn(`[bookingReceipt] bundled logo not found at ${BUNDLED_LOGO_PATH}: ${err.message}`);
  }

  // 2) Fallback: fetch from the backend's own static route (or an
  //    explicit override), with a timeout so a slow/broken host never
  //    stalls receipt generation.
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);
    const resp = await fetch(DEFAULT_LOGO_URL, { signal: controller.signal });
    clearTimeout(timeout);
    if (!resp.ok) {
      console.warn(`[bookingReceipt] logo URL fetch failed: ${resp.status} ${DEFAULT_LOGO_URL}`);
      return null;
    }
    const ab = await resp.arrayBuffer();
    cachedLogoBuffer = Buffer.from(ab);
    return cachedLogoBuffer;
  } catch (err) {
    console.warn(`[bookingReceipt] logo URL fetch threw: ${err.message}`);
    return null;
  }
}

// Agency display name/contact. `packages.agent_name` is the denormalized
// field already used everywhere else in the codebase (Cardcontroller.js,
// mpesaController.js) — that's the primary source and needs no join at all.
// `agentProfile` (fetched separately via packages.created_by) only fills in
// phone/email, and is optional — its absence should never affect the name.
function resolveAgency(packageAgentName, agentProfile) {
  const name =
    packageAgentName ||
    agentProfile?.business_name ||
    agentProfile?.agency_name ||
    agentProfile?.company_name ||
    [agentProfile?.first_name, agentProfile?.last_name].filter(Boolean).join(' ') ||
    'Umrah Market Partner Agency';
  const phone = agentProfile?.phone || agentProfile?.business_phone || agentProfile?.contact_phone || null;
  const email = agentProfile?.business_email || agentProfile?.email || null;
  return { name, phone, email };
}

async function renderBookingReceiptPdf({ payment, booking, clientProfile, agentProfile }) {
  const logoBuffer = await loadLogoBuffer();
  const agency = resolveAgency(payment?.package?.agent_name, agentProfile);

  return await new Promise((resolve, reject) => {
    // IMPORTANT: margin is 0 and every element below is placed with an
    // explicit absolute y. PDFKit's automatic page-break logic keys off the
    // page margin — with a non-zero margin, any text call whose y lands
    // near (page.height - margin) silently triggers doc.addPage(), which is
    // what produced the blank trailing page in the previous version. With
    // margin 0 that threshold effectively disappears, and since nothing
    // here uses flowing/continued text, a second page can never be added.
    const doc = new PDFDocument({ size: 'A4', margin: 0, bufferPages: true });
    const chunks = [];
    doc.on('data', (c) => chunks.push(c));
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);

    const PAGE_W = doc.page.width;   // 595.28
    const PAGE_H = doc.page.height;  // 841.89
    const M = 48;                    // content margin, applied manually
    const CW = PAGE_W - M * 2;       // content width

    const clientName = [clientProfile?.first_name, clientProfile?.last_name].filter(Boolean).join(' ') || 'Client';
    const packageName = payment?.package?.name || 'Umrah Package';
    const paidAt = payment.paid_at ? new Date(payment.paid_at) : new Date();
    const travelerCount = Number(booking?.traveler_count ?? payment?.traveler_count ?? 1) || 1;
    const receiptNo = `DA-${String(payment.id).replace(/-/g, '').slice(0, 8).toUpperCase()}`;

    // ───────────────────────── Letterhead-style header (gradient, compact) ─────────────────────────
    const HEADER_H = 92;

    // Top accent bar — navy → emerald → gold, the same brand palette read
    // left to right, giving the header an immediate splash of colour.
    const topBar = doc.linearGradient(0, 0, PAGE_W, 0);
    topBar.stop(0, BRAND.navy).stop(0.5, BRAND.emerald).stop(1, BRAND.gold);
    doc.rect(0, 0, PAGE_W, 5).fill(topBar);

    // Soft gradient wash across the header body — near-white fading into a
    // faint emerald tint, so the header reads as a distinct panel without
    // fighting the dark ink text sitting on top of it.
    const headerWash = doc.linearGradient(0, 5, PAGE_W, HEADER_H);
    headerWash.stop(0, '#FFFFFF').stop(0.6, '#FBFBF8').stop(1, BRAND.emeraldSoft);
    doc.rect(0, 5, PAGE_W, HEADER_H - 5).fill(headerWash);

    // Gradient corner accent, echoing the lattice motif on the printed
    // letterhead — a filled gold→emerald wedge instead of flat lines.
    doc.save();
    doc.rect(0, 0, PAGE_W, HEADER_H).clip();
    const cornerGrad = doc.linearGradient(PAGE_W - 130, 0, PAGE_W, 90);
    cornerGrad.stop(0, BRAND.gold).stop(1, BRAND.emerald);
    doc.opacity(0.08);
    doc.polygon([PAGE_W - 130, 0], [PAGE_W, 0], [PAGE_W, 90]).fill(cornerGrad);
    doc.opacity(1);
    doc.restore();

    // Logo mark
    const LOGO_S = 46, LOGO_X = M, LOGO_Y = 24;
    doc.roundedRect(LOGO_X, LOGO_Y, LOGO_S, LOGO_S, 8).lineWidth(1).stroke('#E7E2D6');
    if (logoBuffer) {
      try {
        doc.image(logoBuffer, LOGO_X + 5, LOGO_Y + 5, { fit: [LOGO_S - 10, LOGO_S - 10], align: 'center', valign: 'center' });
      } catch {
        doc.fillColor(BRAND.emerald).fontSize(20).font('Helvetica-Bold')
          .text('U', LOGO_X, LOGO_Y + 12, { width: LOGO_S, align: 'center' });
      }
    } else {
      doc.fillColor(BRAND.emerald).fontSize(20).font('Helvetica-Bold')
        .text('U', LOGO_X, LOGO_Y + 12, { width: LOGO_S, align: 'center' });
    }

    // Wordmark — gold "UMRAH" + emerald "MARKET", matching the letterhead
    const TEXT_X = LOGO_X + LOGO_S + 14;
    doc.fontSize(17).font('Helvetica-Bold')
      .fillColor(BRAND.gold).text('UMRAH ', TEXT_X, LOGO_Y, { continued: true })
      .fillColor(BRAND.emerald).text('MARKET');
    doc.fillColor(BRAND.muted).fontSize(7).font('Helvetica')
      .text('YOUR TRUSTED PILGRIMAGE MARKET', TEXT_X, LOGO_Y + 21, { characterSpacing: 1 });
    doc.fillColor(BRAND.muted).fontSize(8).font('Helvetica')
      .text('www.umrahmarket.net', TEXT_X, LOGO_Y + 33);

    // Right side: title, receipt no, date, compact outlined PAID badge
    const RIGHT_W = 200;
    const RIGHT_X = PAGE_W - M - RIGHT_W;
    doc.fillColor(BRAND.ink).fontSize(13).font('Helvetica-Bold')
      .text('RECEIPT', RIGHT_X, 24, { width: RIGHT_W, align: 'right', characterSpacing: 1.5 });
    doc.fillColor(BRAND.muted).fontSize(8.5).font('Helvetica')
      .text(`No. ${receiptNo}`, RIGHT_X, 42, { width: RIGHT_W, align: 'right' })
      .text(paidAt.toLocaleDateString('en-KE', { day: '2-digit', month: 'long', year: 'numeric' }), RIGHT_X, 54, { width: RIGHT_W, align: 'right' });

    const badgeW = 54, badgeH = 16;
    const badgeGrad = doc.linearGradient(RIGHT_X + RIGHT_W - badgeW, 70, RIGHT_X + RIGHT_W, 70 + badgeH);
    badgeGrad.stop(0, BRAND.emerald).stop(1, '#0E8A63');
    doc.roundedRect(RIGHT_X + RIGHT_W - badgeW, 70, badgeW, badgeH, 8).fill(badgeGrad);
    doc.fillColor('#FFFFFF').fontSize(8).font('Helvetica-Bold')
      .text('PAID', RIGHT_X + RIGHT_W - badgeW, 70 + 4.5, { width: badgeW, align: 'center', characterSpacing: 1 });

    // Divider: gold → emerald → navy gradient rule, echoing the header's
    // top accent bar and giving a stronger, more modern hand-off into the
    // body than a flat single-colour line.
    const dividerGrad = doc.linearGradient(0, HEADER_H, PAGE_W, HEADER_H);
    dividerGrad.stop(0, BRAND.gold).stop(0.5, BRAND.navy).stop(1, BRAND.emerald);
    doc.rect(0, HEADER_H, PAGE_W, 3).fill(dividerGrad);

    let y = HEADER_H + 3 + 26;

    // ───────────────────────── Billed To / Agency / Booking details (three columns) ─────────────────────────
    const gap = 20;
    const colW = (CW - gap * 2) / 3;
    const c1 = M, c2 = M + colW + gap, c3 = M + 2 * (colW + gap);

    // Card background with a thin hairline border so the three columns read
    // as one grouped block against the page rather than floating text.
    const cardTop = y;
    const cardH = 92;
    doc.roundedRect(M, cardTop, CW, cardH, 8).fillAndStroke('#FAFAF8', BRAND.hairline);
    // Slim gold accent on the card's left edge for a touch of colour.
    doc.roundedRect(M, cardTop, 4, cardH, 2).fill(BRAND.gold);
    // Vertical hairline separators between the three columns.
    doc.moveTo(c2 - gap / 2, cardTop + 14).lineTo(c2 - gap / 2, cardTop + cardH - 14).stroke(BRAND.hairline);
    doc.moveTo(c3 - gap / 2, cardTop + 14).lineTo(c3 - gap / 2, cardTop + cardH - 14).stroke(BRAND.hairline);

    y += 18;
    const sectionTop = y;

    doc.fillColor(BRAND.muted).fontSize(7.5).font('Helvetica-Bold')
      .text('BILLED TO', c1, y, { characterSpacing: 0.5 });
    doc.fillColor(BRAND.muted).fontSize(7.5).font('Helvetica-Bold')
      .text('TRAVEL AGENCY', c2, y, { characterSpacing: 0.5 });
    doc.fillColor(BRAND.muted).fontSize(7.5).font('Helvetica-Bold')
      .text('BOOKING DETAILS', c3, y, { characterSpacing: 0.5 });
    y += 14;

    doc.fillColor(BRAND.ink).fontSize(10.5).font('Helvetica-Bold').text(clientName, c1, y, { width: colW });
    doc.fillColor(BRAND.ink).fontSize(10.5).font('Helvetica-Bold').text(agency.name, c2, y, { width: colW });
    doc.fillColor(BRAND.ink).fontSize(10.5).font('Helvetica-Bold').text(packageName, c3, y, { width: colW });
    y += 14;

    doc.fillColor(BRAND.muted).fontSize(8.5).font('Helvetica')
      .text(clientProfile?.email || '—', c1, y, { width: colW });
    // Show phone and email together when both are on file; fall back
    // gracefully to whichever one is available.
    const agencyContact = [agency.phone, agency.email].filter(Boolean).join('  ·  ') || '—';
    doc.fillColor(BRAND.muted).fontSize(8.5).font('Helvetica')
      .text(agencyContact, c2, y, { width: colW, lineGap: 1 });
    doc.fillColor(BRAND.muted).fontSize(8.5).font('Helvetica')
      .text(`Booking ID: ${booking?.id ? String(booking.id).slice(0, 8).toUpperCase() : '—'}`, c3, y, { width: colW });
    y += 13;

    doc.fillColor(BRAND.muted).fontSize(8.5).font('Helvetica')
      .text(`Payment: ${(payment?.method || booking?.payment_method || '—').toString().toUpperCase()}`, c3, y, { width: colW });
    y += 13;

    doc.fillColor(BRAND.muted).fontSize(8.5).font('Helvetica')
      .text(`Paid on: ${paidAt.toLocaleString('en-KE', { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' })}`, c3, y, { width: colW });

    y = cardTop + cardH + 24; // clear the card background, then breathing room

    // ───────────────────────── Itemized summary table ─────────────────────────
    const tableTop = y;
    const rowH = 30;
    const col = { desc: M + 12, qty: M + CW - 190, price: M + CW - 120, total: M + CW - 12 };

    const headerGrad = doc.linearGradient(M, tableTop, M + CW, tableTop);
    headerGrad.stop(0, '#EFF4F1').stop(1, '#E9F1EC');
    doc.roundedRect(M, tableTop, CW, rowH, 6).fill(headerGrad);
    doc.fillColor(BRAND.ink).fontSize(8.5).font('Helvetica-Bold')
      .text('DESCRIPTION', col.desc, tableTop + 10, { characterSpacing: 0.3 })
      .text('TRAVELERS', col.qty - 60, tableTop + 10, { width: 60, align: 'right', characterSpacing: 0.3 })
      .text('UNIT PRICE', col.price - 70, tableTop + 10, { width: 70, align: 'right', characterSpacing: 0.3 })
      .text('AMOUNT', col.total - 90, tableTop + 10, { width: 90, align: 'right', characterSpacing: 0.3 });

    y = tableTop + rowH;
    const lineRowH = 52;
    // Light bordered row under the header so the single line item still
    // reads as a distinct table row rather than loose floating text.
    doc.roundedRect(M, y, CW, lineRowH, 4).lineWidth(1).stroke(BRAND.hairline);
    y += 12;
    const unitPrice = Number(payment.amount_kes || 0) / travelerCount;
    doc.fillColor(BRAND.ink).fontSize(10).font('Helvetica-Bold')
      .text(packageName, col.desc, y, { width: col.qty - col.desc - 70 });
    doc.fillColor(BRAND.muted).fontSize(8.5).font('Helvetica')
      .text(`Umrah pilgrimage package booking · ${agency.name}`, col.desc, y + 14, { width: col.qty - col.desc - 70 });
    doc.fillColor(BRAND.ink).fontSize(10).font('Helvetica')
      .text(String(travelerCount), col.qty - 60, y + 2, { width: 60, align: 'right' })
      .text(fmtMoney(unitPrice), col.price - 70, y + 2, { width: 70, align: 'right' })
      .font('Helvetica-Bold')
      .text(fmtMoney(payment.amount_kes), col.total - 90, y + 2, { width: 90, align: 'right' });

    y += lineRowH - 12 + 16;
    doc.moveTo(M, y).lineTo(M + CW, y).stroke(BRAND.hairline);
    y += 16;

    // Total paid — a slim, bordered summary line with a gradient wash so it
    // still stands out as the key figure without becoming a heavy block.
    const totalBoxH = 36;
    doc.lineWidth(1);
    const totalGrad = doc.linearGradient(M, y, M + CW, y + totalBoxH);
    totalGrad.stop(0, BRAND.emeraldSoft).stop(1, '#EFF7E9');
    doc.roundedRect(M, y, CW, totalBoxH, 4).fill(totalGrad);
    doc.roundedRect(M, y, CW, totalBoxH, 4).lineWidth(1).stroke(BRAND.emerald);
    doc.fillColor(BRAND.emerald).fontSize(8.5).font('Helvetica-Bold')
      .text('TOTAL AMOUNT PAID', M + 14, y + 13, { characterSpacing: 0.5 });
    doc.fillColor(BRAND.emerald).fontSize(14).font('Helvetica-Bold')
      .text(fmtMoney(payment.amount_kes), M, y + 10, { width: CW - 16, align: 'right' });
    y += totalBoxH + 20;

    // ───────────────────────── Notes ─────────────────────────
    doc.fillColor(BRAND.muted).fontSize(8.5).font('Helvetica')
      .text(
        'This receipt confirms that payment for the above booking has been successfully received and processed. Please retain this document for your records; it may be requested during travel document verification.',
        M, y, { width: CW, lineGap: 2 }
      );

    // ───────────────────────── Footer (letterhead-style: Address / Phone / Email) ─────────────────────────
    const footerY = PAGE_H - 128;
    doc.moveTo(M, footerY).lineTo(M + CW, footerY).stroke(BRAND.hairline);

    const footerColW = CW / 3;
    const fy = footerY + 16;
    const footerCols = [
      { label: 'ADDRESS', value: 'Al Mukarram Shopping Mall, Captain Mungai Street, Eastleigh, Nairobi' },
      { label: 'PHONE', value: '+254 700 111 106' },
      { label: 'EMAIL', value: 'info@umrahmarket.net' },
    ];
    footerCols.forEach((colItem, i) => {
      const x = M + i * footerColW;
      const textW = footerColW - (i < 2 ? 24 : 4);
      doc.rect(x, fy + 2, 6, 6).fill(BRAND.gold);
      doc.fillColor(BRAND.ink).fontSize(7.5).font('Helvetica-Bold')
        .text(colItem.label, x + 12, fy, { characterSpacing: 0.5 });
      doc.fillColor(BRAND.muted).fontSize(7.8).font('Helvetica')
        .text(colItem.value, x + 12, fy + 11, { width: textW, lineGap: 1 });
      if (i < 2) {
        doc.moveTo(x + footerColW - 14, fy - 2).lineTo(x + footerColW - 14, fy + 40).stroke(BRAND.hairline);
      }
    });

    const closingY = footerY + 78;
    doc.moveTo(M, closingY).lineTo(M + CW, closingY).stroke(BRAND.hairline);
    doc.fillColor(BRAND.muted).fontSize(7.5).font('Helvetica')
      .text('Thank you for choosing Umrah Market · This is a system-generated receipt and does not require a signature.', M, closingY + 10, { width: CW, align: 'center' });

    doc.end();
  });
}

export async function sendBookingReceiptEmail({ paymentId, bookingId = null, force = false }) {
  if (!paymentId) {
    console.warn('[bookingReceipt] skipped: missing_payment_id');
    return { success: false, reason: 'missing_payment_id' };
  }
  if (!hasSmtpConfig()) {
    console.warn('[bookingReceipt] skipped: smtp_not_configured — check SMTP_HOST/SMTP_USER/SMTP_PASS env vars on the backend host', { paymentId });
    return { success: false, reason: 'smtp_not_configured' };
  }

  const { data: payment, error: payErr } = await supabaseAdmin
    .from('payments')
    .select('id, user_id, package_id, method, amount_kes, status, paid_at, receipt_generated, traveler_count, package:packages(name, agent_name, created_by)')
    .eq('id', paymentId)
    .maybeSingle();

  if (payErr || !payment) {
    console.error('[bookingReceipt] skipped: payment_not_found', { paymentId, supabaseError: payErr?.message });
    return { success: false, reason: 'payment_not_found' };
  }
  if (payment.status !== 'SUCCESS') {
    console.warn('[bookingReceipt] skipped: payment_not_success', { paymentId, status: payment.status });
    return { success: false, reason: 'payment_not_success' };
  }
  if (!force && payment.receipt_generated) {
    console.info('[bookingReceipt] skipped: already_sent', { paymentId });
    return { success: true, skipped: true, reason: 'already_sent' };
  }

  const { data: clientProfile } = await supabaseAdmin
    .from('profiles')
    .select('first_name, last_name, email')
    .eq('id', payment.user_id)
    .maybeSingle();

  const recipient = String(clientProfile?.email || '').trim();
  if (!isValidEmail(recipient)) {
    console.error('[bookingReceipt] skipped: invalid_recipient_email', { paymentId, userId: payment.user_id, rawEmail: clientProfile?.email });
    return { success: false, reason: 'invalid_recipient_email' };
  }

  let booking = null;
  if (bookingId) {
    const { data } = await supabaseAdmin
      .from('bookings')
      .select('id, payment_method, traveler_count')
      .eq('id', bookingId)
      .maybeSingle();
    booking = data || null;
  }

  // Agency contact details (phone/email) — best-effort, purely additive.
  // The agency NAME itself already comes from packages.agent_name above and
  // does not depend on this lookup succeeding.
  let agentProfile = null;
  const agentId = payment?.package?.created_by;
  if (agentId) {
    try {
      const { data } = await supabaseAdmin
        .from('profiles')
        .select('*')
        .eq('id', agentId)
        .maybeSingle();
      agentProfile = data || null;
    } catch (err) {
      console.warn(`[bookingReceipt] agent profile fetch failed: ${err.message}`);
    }
  }

  const pdfBuffer = await renderBookingReceiptPdf({ payment, booking, clientProfile, agentProfile });

  const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT ?? 587),
    secure: process.env.SMTP_SECURE === 'true',
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
  });

  const info = await transporter.sendMail({
    from: process.env.SMTP_FROM || process.env.SMTP_USER,
    to: recipient,
    subject: `Umrah Market Booking Receipt #${String(payment.id).slice(0, 8).toUpperCase()}`,
    text: `Assalamu Alaikum ${[clientProfile?.first_name, clientProfile?.last_name].filter(Boolean).join(' ') || ''},\n\nYour booking payment has been received successfully. Your receipt is attached as a PDF.\n\nPackage: ${payment?.package?.name || 'Umrah Package'}\nAmount Paid: ${fmtMoney(payment.amount_kes)}\n\nJazakum Allahu Khairan,\nUmrah Market`,
    attachments: [{
      filename: `booking-receipt-${String(payment.id).slice(0, 8)}.pdf`,
      content: pdfBuffer,
      contentType: 'application/pdf',
    }],
  });

  await supabaseAdmin.from('payments').update({ receipt_generated: true }).eq('id', payment.id);
  console.info('[bookingReceipt] sent', { paymentId, recipient, messageId: info?.messageId || null });
  return { success: true, recipient, messageId: info?.messageId || null };
}