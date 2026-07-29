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

const DEFAULT_LOGO_URL = process.env.BOOKING_RECEIPT_LOGO_URL || 'https://www.umrahmarket.net/umramarket.png';

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
    const doc = new PDFDocument({ size: 'A4', margin: 56 });
    const chunks = [];
    doc.on('data', (c) => chunks.push(c));
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);

    const clientName = [clientProfile?.first_name, clientProfile?.last_name].filter(Boolean).join(' ') || 'Client';
    const packageName = payment?.package?.name || 'Umrah Package';
    const paidAt = payment.paid_at ? new Date(payment.paid_at) : new Date();
    const travelerCount = Number(
      booking?.traveler_count ??
      payment?.traveler_count ??
      1
    ) || 1;

    doc.rect(0, 0, doc.page.width, 104).fill(BRAND.emerald);
    doc.rect(0, 104, doc.page.width, 3).fill(BRAND.gold);

    if (logoBuffer) {
      try {
        doc.rect(56, 24, 56, 56).fill('#FFFFFF');
        doc.image(logoBuffer, 60, 28, { fit: [48, 48], align: 'center', valign: 'center' });
      } catch {
        doc.fill('#FFFFFF').fontSize(24).font('Helvetica-Bold').text('U', 78, 42, { align: 'center' });
      }
    } else {
      doc.fill('#FFFFFF').fontSize(24).font('Helvetica-Bold').text('U', 78, 42, { align: 'center' });
    }

    doc.fill('#FFFFFF').fontSize(22).font('Helvetica-Bold').text('UMRAH MARKET', 126, 34);
    doc.fontSize(9).font('Helvetica').fill('#CDE8DE').text('Booking Receipt', 126, 62);

    doc.fill(BRAND.ink).fontSize(10).font('Helvetica-Bold')
      .text(`Receipt #${String(payment.id).slice(0, 8).toUpperCase()}`, doc.page.width - 190, 32, { width: 130, align: 'right' })
      .text(paidAt.toLocaleDateString('en-KE', { day: '2-digit', month: 'long', year: 'numeric' }), doc.page.width - 190, 50, { width: 130, align: 'right' });

    doc.rect(56, 124, doc.page.width - 112, 30).fill(BRAND.emeraldSoft);
    doc.fill(BRAND.emerald).fontSize(10).font('Helvetica-Bold')
      .text(`Payment received. Your booking is confirmed for ${travelerCount} traveler${travelerCount === 1 ? '' : 's'}.`, 68, 134);

    const label = (name, value, y) => {
      doc.fill(BRAND.muted).fontSize(8).font('Helvetica').text(name, 56, y);
      doc.fill(BRAND.ink).fontSize(10).font('Helvetica-Bold').text(String(value || '—'), 56, y + 12, { width: doc.page.width - 112 });
    };

    let y = 176;
    label('Client', clientName, y);
    y += 38;
    label('Email', clientProfile?.email || '—', y);
    y += 38;
    label('Package', packageName, y);
    y += 38;
    label('Payment Method', payment?.method || booking?.payment_method || '—', y);
    y += 38;
    label('Booking ID', booking?.id || '—', y);
    y += 44;

    doc.rect(56, y, doc.page.width - 112, 88).fill('#F8FAFC');
    doc.fill(BRAND.ink).fontSize(9).font('Helvetica-Bold').text('PAYMENT SUMMARY', 68, y + 10);
    doc.fill(BRAND.muted).fontSize(9).font('Helvetica').text('Total Paid', 68, y + 34);
    doc.fill(BRAND.emerald).fontSize(15).font('Helvetica-Bold').text(fmtMoney(payment.amount_kes), doc.page.width - 220, y + 28, { width: 152, align: 'right' });

    doc.fill(BRAND.muted).fontSize(8).font('Helvetica')
      .text(`Paid on ${paidAt.toLocaleString('en-KE')}`, 68, y + 58)
      .text('This is a system-generated receipt from Umrah Market.', 68, y + 70);

    doc.moveTo(56, doc.page.height - 72).lineTo(doc.page.width - 56, doc.page.height - 72).stroke('#E2E8F0');
    doc.fill(BRAND.muted).fontSize(8).font('Helvetica')
      .text('Need help? Contact support@umrahmarket.net', 56, doc.page.height - 60, { width: doc.page.width - 112, align: 'center' });

    doc.end();
  });
}

export async function sendBookingReceiptEmail({ paymentId, bookingId = null, force = false }) {
  if (!paymentId) return { success: false, reason: 'missing_payment_id' };
  if (!hasSmtpConfig()) {
    console.warn('[booking-receipt] Skipped: SMTP not configured');
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
    console.info(`[booking-receipt] Skipped: already sent for payment ${payment.id}`);
    return { success: true, skipped: true, reason: 'already_sent' };
  }

  const { data: clientProfile } = await supabaseAdmin
    .from('profiles')
    .select('first_name, last_name, email')
    .eq('id', payment.user_id)
    .maybeSingle();

  const recipient = String(clientProfile?.email || '').trim();
  if (!isValidEmail(recipient)) {
    console.warn(`[booking-receipt] Skipped: invalid recipient email for payment ${payment.id}`);
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
  console.info(`[booking-receipt] Sent to ${recipient} for payment ${payment.id} (messageId: ${info?.messageId || 'n/a'})`);
  return { success: true, recipient, messageId: info?.messageId || null };
}