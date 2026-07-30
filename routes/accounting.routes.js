/**
 * accounting_routes.js
 * Mount under /api/superadmin (all routes are prefixed /accounting/...)
 */
import express from 'express';
import PDFDocument from 'pdfkit';
import jwt from 'jsonwebtoken';
import { supabaseAdmin as supabase } from '../config/supabase.js';
import { hashToken, AUDIT_ACTIONS } from '../utils/securityUtils.js';

const router = express.Router();
const DEFAULT_PROFIT_PERCENTAGE = Number(process.env.PLATFORM_PROFIT_PERCENTAGE ?? 10);

const getClientIp = (req) =>
  (req.headers['x-forwarded-for'] || '').split(',')[0].trim() ||
  req.socket?.remoteAddress ||
  req.ip ||
  'unknown';

const logAudit = async (superadminId, action, resourceType, resourceId, reason = '', status = 'success', errorMsg = '', req = null) => {
  try {
    await supabase.from('superadmin_audit_logs').insert({
      superadmin_id: superadminId,
      action,
      resource_type: resourceType,
      resource_id:   String(resourceId),
      reason,
      status,
      error_message: errorMsg,
      ip_address:    req ? getClientIp(req) : 'unknown',
      user_agent:    req ? (req.get('user-agent') || 'unknown') : 'unknown',
    });
  } catch (err) {
    
  }
};

const authenticateSuperadmin = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '').trim();
    if (!token) return res.status(401).json({ success: false, message: 'No token provided' });

    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch {
      return res.status(401).json({ success: false, message: 'Invalid or expired token' });
    }

    const { data: superadmin, error } = await supabase
      .from('superadmin_credentials')
      .select('*')
      .eq('id', decoded.superadminId)
      .single();

    if (error || !superadmin || superadmin.status !== 'active') {
      return res.status(403).json({ success: false, message: 'Unauthorized' });
    }

    const { data: session } = await supabase
      .from('superadmin_sessions')
      .select('*')
      .eq('token_hash', hashToken(token))
      .is('revoked_at', null)
      .single();

    if (!session || new Date(session.expires_at) < new Date()) {
      return res.status(401).json({ success: false, message: 'Session expired' });
    }

    supabase.from('superadmin_sessions')
      .update({ last_activity: new Date().toISOString() })
      .eq('id', session.id)
      .then(() => {}).catch(() => {});

    req.superadmin = superadmin;
    req.session    = session;
    next();
  } catch (err) {
    
    res.status(401).json({ success: false, message: 'Authentication failed' });
  }
};

// ─── GET /accounting/summary ────────────────────────────────────────────────
router.get('/summary', authenticateSuperadmin, async (req, res) => {
  try {
    const { data: payments, error } = await supabase
      .from('payments')
      .select(`id, amount_kes, status, paid_at, disbursed, package:packages(price, profit_percentage)`)
      .eq('status', 'SUCCESS')
      .order('paid_at', { ascending: false });

    if (error) throw error;

    let totalRevenue = 0, totalProfit = 0, pendingAmt = 0, disbursedAmt = 0, pendingCount = 0, disbursedCount = 0;
    for (const p of payments ?? []) {
      const amount = Number(p.amount_kes ?? 0);
      const pct = Number(p.package?.profit_percentage ?? DEFAULT_PROFIT_PERCENTAGE);
      const profit = (amount * pct) / 100;
      const agentShare = amount - profit;
      totalRevenue += amount;
      totalProfit += profit;
      if (p.disbursed) {
        disbursedAmt += agentShare;
        disbursedCount++;
      } else {
        pendingAmt += agentShare;
        pendingCount++;
      }
    }

    res.json({
      success: true,
      data: {
        totalRevenue,
        totalProfit,
        pendingAmount: pendingAmt,
        pendingCount,
        disbursedAmount: disbursedAmt,
        disbursedCount,
        transactionCount: (payments ?? []).length,
      },
    });
  } catch (err) {
    
    res.status(500).json({ success: false, message: 'Failed to fetch accounting summary' });
  }
});

// ─── GET /accounting/transactions ───────────────────────────────────────────
router.get('/transactions', authenticateSuperadmin, async (req, res) => {
  try {
    const limit = Math.min(Number(req.query.limit ?? 200), 1000);
    const offset = Number(req.query.offset ?? 0);
    const status = req.query.status ?? 'all';
    const from = req.query.from;
    const to = req.query.to;
    const q = (req.query.q ?? '').trim().toLowerCase();

    let query = supabase
      .from('payments')
      .select(`
        id, user_id, package_id, amount_kes, status, phone, mpesa_ref,
        paid_at, created_at, updated_at, disbursed, disbursed_at, disbursed_by, receipt_generated,
        package:packages(id, name, price, profit_percentage, created_by,
          agent:profiles!packages_created_by_fkey(id, first_name, last_name, email, agent_number))
      `)
      .eq('status', 'SUCCESS')
      .order('paid_at', { ascending: false })
      .range(offset, offset + limit - 1);

    if (status === 'pending') query = query.eq('disbursed', false);
    if (status === 'disbursed') query = query.eq('disbursed', true);
    if (from) query = query.gte('paid_at', new Date(from).toISOString());
    if (to) query = query.lte('paid_at', new Date(to + 'T23:59:59').toISOString());

    const { data: payments, error, count } = await query;
    if (error) throw error;

    // Fetch client profiles separately
    const userIds = [...new Set((payments || []).map(p => p.user_id).filter(Boolean))];
    let clientMap = new Map();
    if (userIds.length > 0) {
      const { data: clients, error: clientErr } = await supabase
        .from('profiles')
        .select('id, first_name, last_name, email')
        .in('id', userIds);
      if (!clientErr && clients) {
        clientMap = new Map(clients.map(c => [c.id, c]));
      }
    }

    const results = (payments ?? []).map(p => {
      const amount = Number(p.amount_kes ?? 0);
      const pct = Number(p.package?.profit_percentage ?? DEFAULT_PROFIT_PERCENTAGE);
      const profit = Math.round((amount * pct) / 100 * 100) / 100;
      const agentShare = Math.round((amount - profit) * 100) / 100;
      const client = clientMap.get(p.user_id);
      const agentProfile = p.package?.agent;

      return {
        id: p.id,
        packageId: p.package_id,
        packageName: p.package?.name ?? '—',
        clientId: p.user_id,
        clientName: client ? `${client.first_name} ${client.last_name}`.trim() : null,
        clientEmail: client?.email ?? null,
        agentId: agentProfile?.id ?? null,
        agentName: agentProfile ? `${agentProfile.first_name} ${agentProfile.last_name}`.trim() : null,
        agentEmail: agentProfile?.email ?? null,
        agentNumber: agentProfile?.agent_number ?? null,
        amount,
        percentage: pct,
        profit,
        agentShare,
        mpesaRef: p.mpesa_ref ?? null,
        paidAt: p.paid_at,
        disbursed: !!p.disbursed,
        disbursedAt: p.disbursed_at ?? null,
        disbursedBy: p.disbursed_by ?? null,
        receiptGenerated: !!p.receipt_generated,
        createdAt: p.created_at,
      };
    }).filter(t => {
      if (!q) return true;
      return (
        t.id.toLowerCase().includes(q) ||
        (t.packageName ?? '').toLowerCase().includes(q) ||
        (t.clientName ?? '').toLowerCase().includes(q) ||
        (t.clientEmail ?? '').toLowerCase().includes(q) ||
        (t.agentName ?? '').toLowerCase().includes(q) ||
        (t.agentEmail ?? '').toLowerCase().includes(q) ||
        (t.agentNumber ?? '').toLowerCase().includes(q)
      );
    });

    res.json({ success: true, data: results, total: count ?? results.length });
  } catch (err) {
    
    res.status(500).json({ success: false, message: 'Failed to fetch transactions' });
  }
});

// ─── POST /accounting/transactions/:id/disburse ─────────────────────────────
router.post('/transactions/:id/disburse', authenticateSuperadmin, async (req, res) => {
  const { id } = req.params;
  if (!id || typeof id !== 'string' || id.length > 100) {
    return res.status(422).json({ success: false, message: 'Invalid transaction id' });
  }

  try {
    const { data: payment, error: fetchErr } = await supabase
      .from('payments')
      .select(`id, status, disbursed, amount_kes, package:packages(name, profit_percentage)`)
      .eq('id', id)
      .single();

    if (fetchErr || !payment) return res.status(404).json({ success: false, message: 'Transaction not found' });
    if (payment.status !== 'SUCCESS') return res.status(422).json({ success: false, message: 'Payment is not successful – cannot disburse' });
    if (payment.disbursed) return res.status(409).json({ success: false, message: 'Funds already disbursed for this transaction' });

    const { error: updateErr } = await supabase
      .from('payments')
      .update({ disbursed: true, disbursed_at: new Date().toISOString(), disbursed_by: String(req.superadmin.id) })
      .eq('id', id)
      .eq('disbursed', false);

    if (updateErr) throw updateErr;

    const amount = Number(payment.amount_kes ?? 0);
    const pct = Number(payment.package?.profit_percentage ?? DEFAULT_PROFIT_PERCENTAGE);
    const agentShare = amount - (amount * pct) / 100;

    await logAudit(req.superadmin.id, 'DISBURSE_TRANSACTION', 'transaction', id, `Disbursed KES ${agentShare.toLocaleString()} to agent. Package: ${payment.package?.name ?? id}`, 'success', '', req);
    res.json({ success: true, message: 'Transaction marked as disbursed', data: { id, disbursedAt: new Date().toISOString(), disbursedBy: req.superadmin.id, agentShare } });
  } catch (err) {
    
    await logAudit(req.superadmin.id, 'DISBURSE_TRANSACTION', 'transaction', id, '', 'failed', err.message, req);
    res.status(500).json({ success: false, message: 'Failed to mark as disbursed' });
  }
});

// ─── GET /accounting/transactions/:id/receipt ───────────────────────────────
router.get('/transactions/:id/receipt', authenticateSuperadmin, async (req, res) => {
  const { id } = req.params;
  const inline = req.query.inline === '1';
  if (!id) return res.status(422).json({ success: false, message: 'Missing transaction id' });

  try {
    const { data: payment, error: fetchErr } = await supabase
      .from('payments')
      .select(`
        id, user_id, amount_kes, status, paid_at, disbursed, disbursed_at, mpesa_ref,
        package:packages(id, name, type, profit_percentage,
          agent:profiles!packages_created_by_fkey(first_name, last_name, email, agent_number))
      `)
      .eq('id', id)
      .single();

    if (fetchErr || !payment) return res.status(404).json({ success: false, message: 'Transaction not found' });

    // Fetch client profile manually
    let clientProfile = null;
    if (payment.user_id) {
      const { data: clientData } = await supabase
        .from('profiles')
        .select('first_name, last_name, email')
        .eq('id', payment.user_id)
        .single();
      clientProfile = clientData;
    }

    const amount = Number(payment.amount_kes ?? 0);
    const pct = Number(payment.package?.profit_percentage ?? DEFAULT_PROFIT_PERCENTAGE);
    const profit = Math.round((amount * pct) / 100 * 100) / 100;
    const agentShare = amount - profit;
    const agentProfile = payment.package?.agent;
    const agentName = agentProfile ? `${agentProfile.first_name} ${agentProfile.last_name}`.trim() : '—';
    const clientName = clientProfile ? `${clientProfile.first_name} ${clientProfile.last_name}`.trim() : '—';

    const doc = new PDFDocument({ size: 'A4', margin: 60, bufferPages: true });
    const disposition = inline ? `inline; filename="receipt-${id}.pdf"` : `attachment; filename="receipt-${id}.pdf"`;
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', disposition);
    res.setHeader('X-Content-Type-Options', 'nosniff');
    doc.pipe(res);

    // Header
    doc.rect(0, 0, doc.page.width, 100).fill('#0F172A');
    doc.fill('#FFFFFF').fontSize(22).font('Helvetica-Bold').text('UMRAH MARKET', 60, 30);
    doc.fontSize(9).font('Helvetica').fill('#94A3B8').text('Official Agent Disbursement Receipt', 60, 58);
    doc.fill('#FFFFFF').fontSize(9)
      .text(`Receipt #${id.slice(0, 8).toUpperCase()}`, doc.page.width - 180, 35, { width: 120, align: 'right' })
      .text(new Date().toLocaleDateString('en-KE', { day: '2-digit', month: 'long', year: 'numeric' }), doc.page.width - 180, 52, { width: 120, align: 'right' });

    // Banner
    const bannerColor = payment.disbursed ? '#DCFCE7' : '#FEF3C7';
    const bannerText = payment.disbursed ? `✓  Funds Disbursed on ${payment.disbursed_at ? new Date(payment.disbursed_at).toLocaleDateString('en-KE') : '—'}` : '⏳  Disbursement Pending – Agent Has NOT Yet Received Funds';
    doc.rect(60, 115, doc.page.width - 120, 32).fill(bannerColor);
    doc.fontSize(9).font('Helvetica-Bold').fill(payment.disbursed ? '#166534' : '#92400E').text(bannerText, 72, 124, { width: doc.page.width - 144 });

    // Client / Agent info
    const col1 = 60, col2 = doc.page.width / 2 + 20;
    let y = 168;
    const field = (label, value, x, yPos) => {
      doc.fontSize(8).font('Helvetica').fill('#64748B').text(label, x, yPos);
      doc.fontSize(9).font('Helvetica-Bold').fill('#0F172A').text(String(value ?? '—'), x, yPos + 13, { width: 185 });
      return yPos + 32;
    };
    doc.fontSize(7).font('Helvetica-Bold').fill('#64748B').text('CLIENT DETAILS', col1, y, { characterSpacing: 0.8 });
    doc.moveTo(col1, y + 12).lineTo(col1 + 180, y + 12).stroke('#E2E8F0');
    let y1 = y + 18;
    y1 = field('Full Name', clientName, col1, y1);
    y1 = field('Email', clientProfile?.email ?? '—', col1, y1);
    y1 = field('Package', payment.package?.name ?? '—', col1, y1);
    y1 = field('Package Type', (payment.package?.type ?? '—').toUpperCase(), col1, y1);

    doc.fontSize(7).font('Helvetica-Bold').fill('#64748B').text('AGENT DETAILS', col2, y, { characterSpacing: 0.8 });
    doc.moveTo(col2, y + 12).lineTo(col2 + 180, y + 12).stroke('#E2E8F0');
    let y2 = y + 18;
    y2 = field('Full Name', agentName, col2, y2);
    y2 = field('Email', agentProfile?.email ?? '—', col2, y2);
    y2 = field('Agent No.', agentProfile?.agent_number ?? '—', col2, y2);

    // Financial breakdown
    const tableTop = Math.max(y1, y2) + 20;
    doc.rect(col1, tableTop, doc.page.width - 120, 22).fill('#F8FAFC');
    doc.fontSize(8).font('Helvetica-Bold').fill('#475569').text('FINANCIAL BREAKDOWN', col1 + 8, tableTop + 7);
    const rows = [
      { label: 'Package Revenue (Client Paid)', value: `KES ${amount.toLocaleString('en-KE', { minimumFractionDigits: 2 })}`, bold: false },
      { label: `Platform Fee (${pct}%)`, value: `KES ${profit.toLocaleString('en-KE', { minimumFractionDigits: 2 })}`, bold: false },
      { label: 'Agent Disbursement', value: `KES ${agentShare.toLocaleString('en-KE', { minimumFractionDigits: 2 })}`, bold: true },
    ];
    let ry = tableTop + 28;
    rows.forEach((row, idx) => {
      if (idx === rows.length - 1) doc.rect(col1, ry - 2, doc.page.width - 120, 26).fill('#EFF6FF');
      doc.fontSize(9).font(row.bold ? 'Helvetica-Bold' : 'Helvetica').fill(row.bold ? '#1D4ED8' : '#334155')
        .text(row.label, col1 + 8, ry + 4)
        .text(row.value, col1 + 8, ry + 4, { width: doc.page.width - 136, align: 'right' });
      ry += row.bold ? 28 : 22;
    });

    ry += 16;
    doc.fontSize(7).font('Helvetica').fill('#94A3B8')
      .text(`Payment Date: ${payment.paid_at ? new Date(payment.paid_at).toLocaleString('en-KE') : '—'}`, col1, ry)
      .text(`M-Pesa Ref: ${payment.mpesa_ref ?? '—'}`, col1, ry + 14)
      .text(`Transaction ID: ${id}`, col1, ry + 28);

    const footerY = doc.page.height - 70;
    doc.moveTo(60, footerY).lineTo(doc.page.width - 60, footerY).stroke('#E2E8F0');
    doc.fontSize(7.5).font('Helvetica').fill('#94A3B8')
      .text('This receipt is system-generated by Umrah Market and does not require a signature.', 60, footerY + 8, { align: 'center', width: doc.page.width - 120 })
      .text(`Generated by Superadmin on ${new Date().toLocaleString('en-KE')}`, 60, footerY + 22, { align: 'center', width: doc.page.width - 120 });

    doc.end();
    supabase.from('payments').update({ receipt_generated: true }).eq('id', id).then(() => {}).catch(() => {});
    await logAudit(req.superadmin.id, 'GENERATE_RECEIPT', 'transaction', id, `Receipt ${inline ? 'previewed' : 'downloaded'}`, 'success', '', req);
  } catch (err) {
    
    if (!res.headersSent) res.status(500).json({ success: false, message: 'Failed to generate receipt' });
  }
});

// ─── POST /accounting/transactions/:id/email ────────────────────────────────
router.post('/transactions/:id/email', authenticateSuperadmin, async (req, res) => {
  const { id } = req.params;
  if (!id) return res.status(422).json({ success: false, message: 'Missing transaction id' });
  if (!process.env.SMTP_HOST || !process.env.SMTP_USER || !process.env.SMTP_PASS)
    return res.status(501).json({ success: false, message: 'Email service is not configured on this server' });

  try {
    const { data: payment, error: fetchErr } = await supabase
      .from('payments')
      .select(`
        id, user_id, amount_kes, status, paid_at, disbursed, mpesa_ref,
        package:packages(name, profit_percentage,
          agent:profiles!packages_created_by_fkey(first_name, last_name, email))
      `)
      .eq('id', id)
      .single();

    if (fetchErr || !payment) return res.status(404).json({ success: false, message: 'Transaction not found' });

    // Fetch client profile manually
    let clientProfile = null;
    if (payment.user_id) {
      const { data: clientData } = await supabase
        .from('profiles')
        .select('first_name, last_name, email')
        .eq('id', payment.user_id)
        .single();
      clientProfile = clientData;
    }

    const recipient = (req.body.email || payment.package?.agent?.email || clientProfile?.email || '').trim();
    if (!recipient || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(recipient))
      return res.status(422).json({ success: false, message: 'No valid recipient email provided' });

    const pdfBuffer = await new Promise((resolve, reject) => {
      const doc = new PDFDocument({ size: 'A4', margin: 60 });
      const chunks = [];
      doc.on('data', c => chunks.push(c));
      doc.on('end', () => resolve(Buffer.concat(chunks)));
      doc.on('error', reject);
      const amount = Number(payment.amount_kes ?? 0);
      const pct = Number(payment.package?.profit_percentage ?? DEFAULT_PROFIT_PERCENTAGE);
      const profit = (amount * pct) / 100;
      const agentShare = amount - profit;
      const clientName = clientProfile ? `${clientProfile.first_name} ${clientProfile.last_name}`.trim() : '—';
      const agentName = payment.package?.agent ? `${payment.package.agent.first_name} ${payment.package.agent.last_name}`.trim() : '—';
      doc.rect(0, 0, doc.page.width, 100).fill('#0F172A');
      doc.fill('#FFFFFF').fontSize(22).font('Helvetica-Bold').text('UMRAH MARKET', 60, 30);
      doc.fontSize(9).font('Helvetica').fill('#94A3B8').text('Agent Disbursement Receipt', 60, 58);
      doc.fill('#000000').fontSize(11).font('Helvetica').moveDown(6);
      doc.text(`Receipt ID:   ${id.slice(0, 8).toUpperCase()}`, 60, 120);
      doc.text(`Package:      ${payment.package?.name ?? '—'}`, 60, 140);
      doc.text(`Client:       ${clientName}`, 60, 160);
      doc.text(`Agent:        ${agentName}`, 60, 180);
      doc.text(`Payment Date: ${payment.paid_at ? new Date(payment.paid_at).toLocaleDateString('en-KE') : '—'}`, 60, 200);
      doc.moveTo(60, 230).lineTo(535, 230).stroke('#E2E8F0');
      doc.text(`Revenue (Client Paid): KES ${amount.toLocaleString('en-KE', { minimumFractionDigits: 2 })}`, 60, 245);
      doc.text(`Platform Fee (${pct}%):  KES ${profit.toLocaleString('en-KE', { minimumFractionDigits: 2 })}`, 60, 265);
      doc.font('Helvetica-Bold').text(`Agent Disbursement:    KES ${agentShare.toLocaleString('en-KE', { minimumFractionDigits: 2 })}`, 60, 285);
      doc.font('Helvetica').moveDown(2);
      doc.fontSize(9).fill('#64748B').text(payment.disbursed ? '✓ Funds have been disbursed to this agent.' : '⏳ Disbursement is still pending.', 60, 320);
      doc.end();
    });

    const nodemailer = await import('nodemailer');
    const transporter = nodemailer.default.createTransport({
      host: process.env.SMTP_HOST, port: Number(process.env.SMTP_PORT ?? 587),
      secure: process.env.SMTP_SECURE === 'true',
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
    });
    await transporter.sendMail({
      from: process.env.SMTP_FROM || process.env.SMTP_USER,
      to: recipient,
      subject: `Umrah Market – Receipt for Transaction ${id.slice(0, 8).toUpperCase()}`,
      text: `Dear ${recipient},\n\nPlease find attached your receipt for transaction ${id.slice(0, 8).toUpperCase()}.\n\nThank you for partnering with Umrah Market.`,
      attachments: [{ filename: `receipt-${id.slice(0, 8)}.pdf`, content: pdfBuffer }],
    });

    await supabase.from('payments').update({ receipt_generated: true }).eq('id', id);
    await logAudit(req.superadmin.id, 'EMAIL_RECEIPT', 'transaction', id, `Emailed to ${recipient}`, 'success', '', req);
    res.json({ success: true, message: `Receipt emailed to ${recipient}` });
  } catch (err) {
    
    await logAudit(req.superadmin.id, 'EMAIL_RECEIPT', 'transaction', id, '', 'failed', err.message, req);
    res.status(500).json({ success: false, message: 'Failed to send receipt email' });
  }
});

// ─── GET /accounting/export ─────────────────────────────────────────────────
router.get('/export', authenticateSuperadmin, async (req, res) => {
  try {
    const { data: payments, error } = await supabase
      .from('payments')
      .select(`
        id, user_id, amount_kes, status, paid_at, disbursed, disbursed_at, mpesa_ref,
        package:packages(name, profit_percentage,
          agent:profiles!packages_created_by_fkey(first_name, last_name, email, agent_number))
      `)
      .eq('status', 'SUCCESS')
      .order('paid_at', { ascending: false });

    if (error) throw error;

    const userIds = [...new Set((payments || []).map(p => p.user_id).filter(Boolean))];
    let clientMap = new Map();
    if (userIds.length > 0) {
      const { data: clients, error: clientErr } = await supabase
        .from('profiles')
        .select('id, first_name, last_name, email')
        .in('id', userIds);
      if (!clientErr && clients) {
        clientMap = new Map(clients.map(c => [c.id, c]));
      }
    }

    const csvCell = (v) => {
      if (v == null) return '';
      const s = String(v);
      return s.includes(',') || s.includes('"') || s.includes('\n') ? `"${s.replace(/"/g, '""')}"` : s;
    };
    const columns = ['transaction_id', 'package_name', 'client_name', 'client_email', 'agent_name', 'agent_email', 'agent_number', 'revenue_kes', 'profit_pct', 'profit_kes', 'agent_share_kes', 'mpesa_ref', 'paid_at', 'disbursed', 'disbursed_at'];
    const rows = (payments ?? []).map(p => {
      const amount = Number(p.amount_kes ?? 0);
      const pct = Number(p.package?.profit_percentage ?? DEFAULT_PROFIT_PERCENTAGE);
      const profit = Math.round((amount * pct) / 100 * 100) / 100;
      const agentShare = amount - profit;
      const client = clientMap.get(p.user_id);
      const agent = p.package?.agent;
      return {
        transaction_id: p.id,
        package_name: p.package?.name ?? '',
        client_name: client ? `${client.first_name} ${client.last_name}`.trim() : '',
        client_email: client?.email ?? '',
        agent_name: agent ? `${agent.first_name} ${agent.last_name}`.trim() : '',
        agent_email: agent?.email ?? '',
        agent_number: agent?.agent_number ?? '',
        revenue_kes: amount,
        profit_pct: pct,
        profit_kes: profit,
        agent_share_kes: agentShare,
        mpesa_ref: p.mpesa_ref ?? '',
        paid_at: p.paid_at ? new Date(p.paid_at).toISOString() : '',
        disbursed: p.disbursed ? 'YES' : 'NO',
        disbursed_at: p.disbursed_at ? new Date(p.disbursed_at).toISOString() : '',
      };
    });
    const header = columns.join(',');
    const body = rows.map(r => columns.map(c => csvCell(r[c])).join(',')).join('\n');
    const csv = `${header}\n${body}`;

    await logAudit(req.superadmin.id, 'EXPORT_ACCOUNTING', 'accounting_export', 'all', `Exported ${rows.length} transactions`, 'success', '', req);
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="accounting-export-${Date.now()}.csv"`);
    res.send(csv);
  } catch (err) {
    
    res.status(500).json({ success: false, message: 'Export failed' });
  }
});

export default router;