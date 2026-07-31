import PDFDocument from 'pdfkit';
import nodemailer from 'nodemailer';
import fs from 'fs/promises';
import path from 'path';
import { supabaseAdmin } from '../config/supabase.js';

const BRAND = {
  emerald: '#0B6B4E',
  emeraldSoft: '#E6F4EF',
  gold: '#D4AF37',
  ink: '#0F172A',
  muted: '#64748B',
};

const DEFAULT_LOGO_URL = process.env.BOOKING_RECEIPT_LOGO_URL || 'https://www.umrahmarket.net/umrahmarket.png';

const hasSmtpConfig = () => Boolean(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS);

const isValidEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email || '').trim());

const fmtMoney = (n) => `KES ${Number(n || 0).toLocaleString('en-KE', { minimumFractionDigits: 2 })}`;

async function loadLogoBuffer() {
  const localLogoPath = path.resolve(process.cwd(), '..', 'umrah-market', 'src', 'assets', 'umramarket.png');
  try {
    return await fs.readFile(localLogoPath);
  } catch {
    // Fallback to URL when backend is deployed without sibling frontend files.
  }

  try {
    const resp = await fetch(DEFAULT_LOGO_URL);
    if (!resp.ok) return null;
    const ab = await resp.arrayBuffer();
    return Buffer.from(ab);
  } catch {
    return null;
  }
}

async function renderBookingReceiptPdf({ payment, booking, clientProfile }) {
  const logoBuffer = await loadLogoBuffer();

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

    // ───────────────────────── Letterhead ─────────────────────────
    const HEADER_H = 138;
    doc.rect(0, 0, PAGE_W, HEADER_H).fill(BRAND.emerald);
    // subtle darker diagonal panel for depth, then the gold accent line
    doc.save();
    doc.fillOpacity(0.10);
    doc.polygon([PAGE_W * 0.55, 0], [PAGE_W, 0], [PAGE_W, HEADER_H], [PAGE_W * 0.8, HEADER_H]).fill('#000000');
    doc.restore();
    doc.rect(0, HEADER_H, PAGE_W, 4).fill(BRAND.gold);

    // Logo mark
    const LOGO_X = M, LOGO_Y = 30, LOGO_S = 56;
    doc.roundedRect(LOGO_X, LOGO_Y, LOGO_S, LOGO_S, 12).fill('#FFFFFF');
    if (logoBuffer) {
      try {
        doc.image(logoBuffer, LOGO_X + 6, LOGO_Y + 6, { fit: [LOGO_S - 12, LOGO_S - 12], align: 'center', valign: 'center' });
      } catch {
        doc.fill(BRAND.emerald).fontSize(26).font('Helvetica-Bold')
          .text('U', LOGO_X, LOGO_Y + 14, { width: LOGO_S, align: 'center' });
      }
    } else {
      doc.fill(BRAND.emerald).fontSize(26).font('Helvetica-Bold')
        .text('U', LOGO_X, LOGO_Y + 14, { width: LOGO_S, align: 'center' });
    }

    doc.fill('#FFFFFF').fontSize(21).font('Helvetica-Bold')
      .text('UMRAH MARKET', LOGO_X + LOGO_S + 16, LOGO_Y + 4, { characterSpacing: 0.3 });
    doc.fillColor('#CDE8DE').fontSize(9).font('Helvetica')
      .text('Your Trusted Pilgrimage Partner', LOGO_X + LOGO_S + 16, LOGO_Y + 28);
    doc.fillColor('#CDE8DE').fontSize(8).font('Helvetica')
      .text('www.umrahmarket.net  ·  support@umrahmarket.net', LOGO_X + LOGO_S + 16, LOGO_Y + 42);

    // Right side: title, receipt no, date, PAID badge
    const RIGHT_W = 190;
    const RIGHT_X = PAGE_W - M - RIGHT_W;
    doc.fillColor('#FFFFFF').fontSize(15).font('Helvetica-Bold')
      .text('RECEIPT', RIGHT_X, 30, { width: RIGHT_W, align: 'right', characterSpacing: 1 });
    doc.fillColor('#CDE8DE').fontSize(9).font('Helvetica')
      .text(`No. ${receiptNo}`, RIGHT_X, 50, { width: RIGHT_W, align: 'right' })
      .text(paidAt.toLocaleDateString('en-KE', { day: '2-digit', month: 'long', year: 'numeric' }), RIGHT_X, 63, { width: RIGHT_W, align: 'right' });

    const badgeW = 64, badgeH = 22;
    doc.roundedRect(RIGHT_X + RIGHT_W - badgeW, 84, badgeW, badgeH, 11).fill(BRAND.gold);
    doc.fillColor(BRAND.ink).fontSize(10).font('Helvetica-Bold')
      .text('PAID', RIGHT_X + RIGHT_W - badgeW, 84 + 6, { width: badgeW, align: 'center', characterSpacing: 1 });

    // ───────────────────────── Confirmation strip ─────────────────────────
    let y = HEADER_H + 4 + 20;
    doc.rect(M, y, CW, 34).fill(BRAND.emeraldSoft);
    doc.fillColor(BRAND.emerald).fontSize(10.5).font('Helvetica-Bold')
      .text(`✓  Payment received — your booking is confirmed for ${travelerCount} traveler${travelerCount === 1 ? '' : 's'}.`, M + 14, y + 11);
    y += 34 + 26;

    // ───────────────────────── Billed To / Booking details (two columns) ─────────────────────────
    const colW = (CW - 24) / 2;
    const col1X = M, col2X = M + colW + 24;

    doc.fillColor(BRAND.muted).fontSize(8).font('Helvetica-Bold')
      .text('BILLED TO', col1X, y, { characterSpacing: 0.5 });
    doc.fillColor(BRAND.muted).fontSize(8).font('Helvetica-Bold')
      .text('BOOKING DETAILS', col2X, y, { characterSpacing: 0.5 });
    y += 16;

    doc.fillColor(BRAND.ink).fontSize(11.5).font('Helvetica-Bold').text(clientName, col1X, y, { width: colW });
    doc.fillColor(BRAND.ink).fontSize(11.5).font('Helvetica-Bold').text(packageName, col2X, y, { width: colW });
    y += 17;

    doc.fillColor(BRAND.muted).fontSize(9).font('Helvetica')
      .text(clientProfile?.email || '—', col1X, y, { width: colW });
    doc.fillColor(BRAND.muted).fontSize(9).font('Helvetica')
      .text(`Booking ID: ${booking?.id ? String(booking.id).slice(0, 8).toUpperCase() : '—'}`, col2X, y, { width: colW });
    y += 15;

    doc.fillColor(BRAND.muted).fontSize(9).font('Helvetica')
      .text(`Payment method: ${(payment?.method || booking?.payment_method || '—').toString().toUpperCase()}`, col2X, y, { width: colW });
    y += 15;

    doc.fillColor(BRAND.muted).fontSize(9).font('Helvetica')
      .text(`Paid on: ${paidAt.toLocaleString('en-KE', { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' })}`, col2X, y, { width: colW });

    y += 30;

    // ───────────────────────── Itemized summary table ─────────────────────────
    const tableTop = y;
    const rowH = 30;
    const col = { desc: M + 12, qty: M + CW - 190, price: M + CW - 120, total: M + CW - 12 };

    doc.roundedRect(M, tableTop, CW, rowH, 6).fill('#F1F5F3');
    doc.fillColor(BRAND.ink).fontSize(8.5).font('Helvetica-Bold')
      .text('DESCRIPTION', col.desc, tableTop + 10, { characterSpacing: 0.3 })
      .text('TRAVELERS', col.qty - 60, tableTop + 10, { width: 60, align: 'right', characterSpacing: 0.3 })
      .text('UNIT PRICE', col.price - 70, tableTop + 10, { width: 70, align: 'right', characterSpacing: 0.3 })
      .text('AMOUNT', col.total - 90, tableTop + 10, { width: 90, align: 'right', characterSpacing: 0.3 });

    y = tableTop + rowH + 12;
    const unitPrice = Number(payment.amount_kes || 0) / travelerCount;
    doc.fillColor(BRAND.ink).fontSize(10).font('Helvetica-Bold')
      .text(packageName, col.desc, y, { width: col.qty - col.desc - 70 });
    doc.fillColor(BRAND.muted).fontSize(8.5).font('Helvetica')
      .text('Umrah pilgrimage package booking', col.desc, y + 14, { width: col.qty - col.desc - 70 });
    doc.fillColor(BRAND.ink).fontSize(10).font('Helvetica')
      .text(String(travelerCount), col.qty - 60, y + 2, { width: 60, align: 'right' })
      .text(fmtMoney(unitPrice), col.price - 70, y + 2, { width: 70, align: 'right' })
      .font('Helvetica-Bold')
      .text(fmtMoney(payment.amount_kes), col.total - 90, y + 2, { width: 90, align: 'right' });

    y += 40;
    doc.moveTo(M, y).lineTo(M + CW, y).stroke('#E2E8F0');
    y += 16;

    // Total paid — highlighted panel
    const totalBoxH = 54;
    doc.roundedRect(M, y, CW, totalBoxH, 8).fill(BRAND.emerald);
    doc.fillColor('#CDE8DE').fontSize(9).font('Helvetica')
      .text('TOTAL AMOUNT PAID', M + 16, y + 14, { characterSpacing: 0.5 });
    doc.fillColor('#FFFFFF').fontSize(20).font('Helvetica-Bold')
      .text(fmtMoney(payment.amount_kes), M, y + 14, { width: CW - 16, align: 'right' });
    y += totalBoxH + 22;

    // ───────────────────────── Notes ─────────────────────────
    doc.fillColor(BRAND.muted).fontSize(8.5).font('Helvetica')
      .text(
        'This receipt confirms that payment for the above booking has been successfully received and processed. Please retain this document for your records; it may be requested during travel document verification.',
        M, y, { width: CW, lineGap: 2 }
      );

    // ───────────────────────── Footer (pinned near bottom, well within page) ─────────────────────────
    const footerY = PAGE_H - 96;
    doc.moveTo(M, footerY).lineTo(M + CW, footerY).stroke('#E2E8F0');
    doc.fillColor(BRAND.ink).fontSize(10).font('Helvetica-Bold')
      .text('Thank you for choosing Umrah Market', M, footerY + 14, { width: CW, align: 'center' });
    doc.fillColor(BRAND.muted).fontSize(8).font('Helvetica')
      .text('Need help with this booking? Contact support@umrahmarket.net', M, footerY + 30, { width: CW, align: 'center' })
      .text('Umrah Market · This is a system-generated receipt and does not require a signature.', M, footerY + 44, { width: CW, align: 'center' });

    doc.end();
  });
}

export async function sendBookingReceiptEmail({ paymentId, bookingId = null, force = false }) {
  if (!paymentId) return { success: false, reason: 'missing_payment_id' };
  if (!hasSmtpConfig()) {
    
    return { success: false, reason: 'smtp_not_configured' };
  }

  const { data: payment, error: payErr } = await supabaseAdmin
    .from('payments')
    .select('id, user_id, package_id, method, amount_kes, status, paid_at, receipt_generated, traveler_count, package:packages(name)')
    .eq('id', paymentId)
    .maybeSingle();

  if (payErr || !payment) return { success: false, reason: 'payment_not_found' };
  if (payment.status !== 'SUCCESS') return { success: false, reason: 'payment_not_success' };
  if (!force && payment.receipt_generated) {
    
    return { success: true, skipped: true, reason: 'already_sent' };
  }

  const { data: clientProfile } = await supabaseAdmin
    .from('profiles')
    .select('first_name, last_name, email')
    .eq('id', payment.user_id)
    .maybeSingle();

  const recipient = String(clientProfile?.email || '').trim();
  if (!isValidEmail(recipient)) {
    
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

  const pdfBuffer = await renderBookingReceiptPdf({ payment, booking, clientProfile });

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
  
  return { success: true, recipient, messageId: info?.messageId || null };
}