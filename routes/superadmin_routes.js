import express from 'express';
import jwt from 'jsonwebtoken';
import { S3Client, ListObjectsV2Command, GetObjectCommand, DeleteObjectCommand } from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import { supabaseAdmin as supabase } from '../config/supabase.js';
import {
  hashPassword, verifyPassword, generateToken, hashToken,
  loginRateLimiter, validateEmail, sanitizeInput, AUDIT_ACTIONS,
} from '../utils/securityUtils.js';

import Payment from '../models/Payment.js';
import Booking from '../models/Booking.js';
import PDFDocument from 'pdfkit';

const R2 = new S3Client({
  region: 'auto',
  endpoint: `https://${process.env.CLOUDFLARE_ACCOUNT_ID}.r2.cloudflarestorage.com`,
  credentials: {
    accessKeyId:     process.env.CLOUDFLARE_R2_ACCESS_KEY_ID,
    secretAccessKey: process.env.CLOUDFLARE_R2_SECRET_ACCESS_KEY,
  },
});

const R2_BUCKET = process.env.CLOUDFLARE_R2_BUCKET_NAME;
const DOCUMENT_KEYS = ['incorporation', 'tourism', 'krapin', 'director_id', 'office_photo'];
const R2_SIGNED_URL_EXPIRES = 3600;

const router = express.Router();

// ─────────────────────────────────────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────────────────────────────────────

const getClientIp = (req) =>
  (req.headers['x-forwarded-for'] || '').split(',')[0].trim() ||
  req.socket?.remoteAddress ||
  req.ip ||
  'unknown';

const logAuditAction = async (
  superadminId, action, resourceType, resourceId,
  reason = '', status = 'success', errorMsg = '', req = null,
) => {
  try {
    await supabase.from('superadmin_audit_logs').insert({
      superadmin_id:  superadminId,
      action,
      resource_type:  resourceType,
      resource_id:    String(resourceId),
      reason,
      status,
      error_message:  errorMsg,
      ip_address:     req ? getClientIp(req) : 'unknown',
      user_agent:     req ? (req.get('user-agent') || 'unknown') : 'unknown',
    });
  } catch (err) {
    console.error('Failed to log audit action:', err);
  }
};

const getAgentDocumentUrls = async (agentId) => {
  if (!agentId || !R2_BUCKET) return {};

  try {
    const { Contents } = await R2.send(new ListObjectsV2Command({
      Bucket: R2_BUCKET,
      Prefix: `documents/${agentId}/`,
    }));

    if (!Contents || Contents.length === 0) return {};

    const grouped = Contents.reduce((acc, item) => {
      const parts = item.Key.split('/');
      if (parts.length < 3) return acc;
      const key = parts[2];
      if (!DOCUMENT_KEYS.includes(key)) return acc;
      acc[key] = acc[key] || [];
      acc[key].push(item);
      return acc;
    }, {});

    const result = {};

    for (const [key, objects] of Object.entries(grouped)) {
      const sorted = objects.sort((a, b) => new Date(b.LastModified) - new Date(a.LastModified));
      if (key === 'office_photo') {
        result.office_photo = await Promise.all(sorted.map(async (item) => ({
          path: item.Key,
          publicUrl: await getSignedUrl(
            R2,
            new GetObjectCommand({ Bucket: R2_BUCKET, Key: item.Key }),
            { expiresIn: R2_SIGNED_URL_EXPIRES }
          ),
          uploadedAt: item.LastModified,
        })));
      } else {
        result[key] = {
          path: sorted[0].Key,
          publicUrl: await getSignedUrl(
            R2,
            new GetObjectCommand({ Bucket: R2_BUCKET, Key: sorted[0].Key }),
            { expiresIn: R2_SIGNED_URL_EXPIRES }
          ),
          uploadedAt: sorted[0].LastModified,
        };
      }
    }

    return result;
  } catch (err) {
    console.error(`Failed to fetch R2 documents for agent ${agentId}:`, err);
    return {};
  }
};

const R2_PUBLIC_URL = process.env.CLOUDFLARE_R2_PUBLIC_URL || '';

const listR2AgentIds = async () => {
  if (!R2_BUCKET) return [];

  const agentIds = new Set();
  let nextToken;

  do {
    const response = await R2.send(new ListObjectsV2Command({
      Bucket: R2_BUCKET,
      Prefix: 'documents/',
      ContinuationToken: nextToken,
      MaxKeys: 1000,
    }));

    (response.Contents || []).forEach(item => {
      const parts = item.Key.split('/');
      if (parts.length >= 3 && parts[1]) {
        agentIds.add(parts[1]);
      }
    });

    nextToken = response.IsTruncated ? response.NextContinuationToken : undefined;
  } while (nextToken);

  return Array.from(agentIds);
};

const buildPublicUrl = (objectKey) => {
  if (!objectKey) return null;
  return R2_PUBLIC_URL ? `${R2_PUBLIC_URL}/${objectKey}` : null;
};

const reconcileAgentDocumentsFromR2 = async () => {
  try {
    const r2AgentIds = await listR2AgentIds();
    if (!r2AgentIds.length) return 0;

    const { data: existingRows, error: existingError } = await supabase
      .from('agent_documents')
      .select('user_id')
      .in('user_id', r2AgentIds);

    if (existingError) {
      console.error('Failed to read existing agent_documents for reconciliation:', existingError);
      return 0;
    }

    const existingIds = new Set((existingRows || []).map(row => row.user_id));
    const missingIds = r2AgentIds.filter(id => !existingIds.has(id));
    if (!missingIds.length) return 0;

    const { data: profiles, error: profileError } = await supabase
      .from('profiles')
      .select('id')
      .in('id', missingIds)
      .eq('role', 'agent');

    if (profileError) {
      console.error('Failed to query agent profiles during reconciliation:', profileError);
      return 0;
    }

    const validAgentIds = (profiles || []).map(profile => profile.id);
    if (!validAgentIds.length) return 0;

    const insertPayload = [];
    for (const agentId of validAgentIds) {
      const urls = await getAgentDocumentUrls(agentId);
      if (!urls || Object.keys(urls).length === 0) continue;

      const officePhotoUrls = Array.isArray(urls.office_photo)
        ? urls.office_photo.map(photo => buildPublicUrl(photo.path) || photo.publicUrl)
        : null;

      const allUploadDates = [];
      Object.entries(urls).forEach(([key, value]) => {
        if (key === 'office_photo' && Array.isArray(value)) {
          value.forEach(photo => { if (photo.uploadedAt) allUploadDates.push(new Date(photo.uploadedAt)); });
        } else if (value?.uploadedAt) {
          allUploadDates.push(new Date(value.uploadedAt));
        }
      });

      const submittedAt = allUploadDates.length
        ? new Date(Math.max(...allUploadDates.map(date => date.getTime()))).toISOString()
        : new Date().toISOString();

      insertPayload.push({
        user_id:          agentId,
        incorporation_doc: urls.incorporation?.path ? (buildPublicUrl(urls.incorporation.path) || urls.incorporation.publicUrl) : null,
        tourism_doc:       urls.tourism?.path ? (buildPublicUrl(urls.tourism.path) || urls.tourism.publicUrl) : null,
        krapin_doc:        urls.krapin?.path ? (buildPublicUrl(urls.krapin.path) || urls.krapin.publicUrl) : null,
        director_id_doc:   urls.director_id?.path ? (buildPublicUrl(urls.director_id.path) || urls.director_id.publicUrl) : null,
        office_photo:      officePhotoUrls,
        status:            'pending',
        submitted_at:      submittedAt,
      });
    }

    if (!insertPayload.length) return 0;

    const { error: insertError } = await supabase.from('agent_documents').insert(insertPayload);
    if (insertError) {
      console.error('Failed to insert reconciled agent_documents rows:', insertError);
      return 0;
    }

    return insertPayload.length;
  } catch (err) {
    console.error('Reconciliation error:', err);
    return 0;
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// MIDDLEWARE – authenticateSuperadmin
// ─────────────────────────────────────────────────────────────────────────────

const authenticateSuperadmin = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '').trim();
    if (!token) {
      return res.status(401).json({ success: false, message: 'No token provided' });
    }

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

    supabase
      .from('superadmin_sessions')
      .update({ last_activity: new Date().toISOString() })
      .eq('id', session.id)
      .then(() => {});

    req.superadmin = superadmin;
    req.session    = session;
    next();
  } catch (err) {
    console.error('Auth middleware error:', err);
    res.status(401).json({ success: false, message: 'Authentication failed' });
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// AUTH – REGISTER
// ─────────────────────────────────────────────────────────────────────────────

router.post('/register', async (req, res) => {
  try {
    const { username, email, fullName, password, confirmPassword, registerSecret } = req.body;

    const expectedSecret = process.env.SUPERADMIN_REGISTER_SECRET;
    if (!expectedSecret) {
      return res.status(503).json({ success: false, message: 'Registration is disabled' });
    }
    if (!registerSecret || registerSecret !== expectedSecret) {
      return res.status(403).json({ success: false, message: 'Invalid registration secret' });
    }

    if (!validateEmail(email)) {
      return res.status(422).json({ success: false, message: 'Invalid email address' });
    }
    if (!username || username.trim().length < 3) {
      return res.status(422).json({ success: false, message: 'Username must be at least 3 characters' });
    }
    if (!password || password.length < 8) {
      return res.status(422).json({ success: false, message: 'Password must be at least 8 characters' });
    }
    if (password !== confirmPassword) {
      return res.status(422).json({ success: false, message: 'Passwords do not match' });
    }
    const strongPassword = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{8,}$/.test(password);
    if (!strongPassword) {
      return res.status(422).json({
        success: false,
        message: 'Password must contain uppercase, lowercase, number and special character',
      });
    }

    const { data: existing } = await supabase
      .from('superadmin_credentials')
      .select('id')
      .or(`email.eq.${email.toLowerCase()},username.eq.${username.trim()}`)
      .maybeSingle();

    if (existing) {
      return res.status(409).json({ success: false, message: 'Email or username already registered' });
    }

    const passwordHash = hashPassword(password);
    const { data: newAdmin, error } = await supabase
      .from('superadmin_credentials')
      .insert({
        username:           sanitizeInput(username.trim()),
        email:              email.trim().toLowerCase(),
        full_name:          sanitizeInput(fullName?.trim() || ''),
        password_hash:      passwordHash,
        status:             'active',
        two_factor_enabled: false,
      })
      .select('id, username, email, full_name')
      .single();

    if (error) throw error;

    const defaultPermissions = [
      'view_agents', 'manage_agents',
      'view_clients', 'manage_clients',
      'view_chats', 'close_chats',
      'view_documents', 'verify_documents',
      'view_packages', 'delete_packages',
      'view_audit_logs', 'export_data',
    ];
    await supabase.from('superadmin_permissions').insert(
      defaultPermissions.map(key => ({ superadmin_id: newAdmin.id, permission_key: key })),
    );

    await logAuditAction(newAdmin.id, 'REGISTER', 'superadmin', newAdmin.id, 'Initial registration', 'success', '', req);

    res.status(201).json({
      success: true,
      message: 'Superadmin account created successfully',
      user: {
        id:       newAdmin.id,
        username: newAdmin.username,
        email:    newAdmin.email,
        fullName: newAdmin.full_name,
      },
    });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ success: false, message: 'Registration failed' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// AUTH – LOGIN
// ─────────────────────────────────────────────────────────────────────────────

router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const clientIp  = getClientIp(req);
    const userAgent = req.get('user-agent') || 'unknown';

    if (!validateEmail(email)) {
      return res.status(422).json({ success: false, message: 'Invalid email' });
    }
    if (!password || password.length < 8) {
      return res.status(422).json({ success: false, message: 'Invalid password' });
    }

    if (loginRateLimiter.isLimited(email)) {
      await logAuditAction(null, AUDIT_ACTIONS.LOGIN, 'superadmin', email, '', 'failed', 'Rate limit exceeded', req);

      const { data: creds } = await supabase
        .from('superadmin_credentials')
        .select('locked_until')
        .eq('email', email.toLowerCase())
        .single();

      if (creds?.locked_until && new Date(creds.locked_until) > new Date()) {
        return res.status(429).json({
          success: false,
          message: 'Too many failed attempts. Account locked.',
          remainingAttempts: 0,
          lockedUntil: creds.locked_until,
        });
      }
    }

    const { data: superadmin, error } = await supabase
      .from('superadmin_credentials')
      .select('*')
      .eq('email', email.toLowerCase())
      .single();

    if (error || !superadmin) {
      await logAuditAction(null, AUDIT_ACTIONS.LOGIN, 'superadmin', email, '', 'failed', 'User not found', req);
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    if (superadmin.status === 'suspended') {
      return res.status(403).json({ success: false, message: 'Account suspended' });
    }
    if (superadmin.status === 'inactive') {
      return res.status(403).json({ success: false, message: 'Account inactive' });
    }

    if (superadmin.locked_until && new Date(superadmin.locked_until) > new Date()) {
      return res.status(429).json({
        success: false,
        message: 'Account locked',
        lockedUntil: superadmin.locked_until,
      });
    }

    const passwordMatch = verifyPassword(password, superadmin.password_hash);
    if (!passwordMatch) {
      const newFailedAttempts = (superadmin.failed_login_attempts || 0) + 1;
      const updatePayload     = { failed_login_attempts: newFailedAttempts };
      if (newFailedAttempts >= 5) {
        updatePayload.locked_until = new Date(Date.now() + 15 * 60 * 1000);
      }
      await supabase.from('superadmin_credentials').update(updatePayload).eq('id', superadmin.id);
      await logAuditAction(superadmin.id, AUDIT_ACTIONS.LOGIN, 'superadmin', superadmin.id, '', 'failed', 'Invalid password', req);
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    // 2FA path
    if (superadmin.two_factor_enabled) {
      const tempToken = generateToken();
      const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

      await supabase.from('superadmin_2fa_pending').insert({
        superadmin_id: superadmin.id,
        token_hash:    hashToken(tempToken),
        expires_at:    expiresAt,
      });

      return res.json({
        success:      true,
        requires2FA:  true,
        sessionToken: tempToken,
      });
    }

    // Full login
    const accessToken  = jwt.sign({ superadminId: superadmin.id }, process.env.JWT_SECRET, { expiresIn: '24h' });
    const refreshToken = generateToken();
    const sessionExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000);

    await supabase.from('superadmin_sessions').insert({
      superadmin_id:       superadmin.id,
      token_hash:          hashToken(accessToken),
      refresh_token_hash:  hashToken(refreshToken),
      ip_address:          clientIp,
      user_agent:          userAgent,
      expires_at:          sessionExpiry,
    });

    await supabase
      .from('superadmin_credentials')
      .update({
        failed_login_attempts: 0,
        locked_until:          null,
        last_login:            new Date().toISOString(),
        last_ip_address:       clientIp,
      })
      .eq('id', superadmin.id);

    const { data: permissions } = await supabase
      .from('superadmin_permissions')
      .select('permission_key')
      .eq('superadmin_id', superadmin.id);

    await logAuditAction(superadmin.id, AUDIT_ACTIONS.LOGIN, 'superadmin', superadmin.id, 'Successful login', 'success', '', req);

    res.json({
      success:     true,
      requires2FA: false,
      token:       accessToken,
      refreshToken,
      user: {
        id:          superadmin.id,
        username:    superadmin.username,
        email:       superadmin.email,
        fullName:    superadmin.full_name,
        permissions: (permissions || []).map(p => p.permission_key),
      },
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ success: false, message: 'Login failed' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// AUTH – VERIFY 2FA
// ─────────────────────────────────────────────────────────────────────────────

router.post('/verify-2fa', async (req, res) => {
  try {
    const { sessionToken, code } = req.body;
    const clientIp  = getClientIp(req);
    const userAgent = req.get('user-agent') || 'unknown';

    if (!sessionToken) {
      return res.status(422).json({ success: false, message: 'Missing session token' });
    }
    if (!code || code.length !== 6) {
      return res.status(422).json({ success: false, message: 'Invalid code format' });
    }

    const { data: pending, error: pendingErr } = await supabase
      .from('superadmin_2fa_pending')
      .select('*, superadmin_credentials(*)')
      .eq('token_hash', hashToken(sessionToken))
      .single();

    if (pendingErr || !pending) {
      return res.status(401).json({ success: false, message: 'Invalid or expired session token' });
    }
    if (new Date(pending.expires_at) < new Date()) {
      await supabase.from('superadmin_2fa_pending').delete().eq('id', pending.id);
      return res.status(401).json({ success: false, message: '2FA session expired, please log in again' });
    }

    const superadmin = pending.superadmin_credentials;

    const accessToken   = jwt.sign({ superadminId: superadmin.id }, process.env.JWT_SECRET, { expiresIn: '24h' });
    const refreshToken  = generateToken();
    const sessionExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000);

    await supabase.from('superadmin_sessions').insert({
      superadmin_id:      superadmin.id,
      token_hash:         hashToken(accessToken),
      refresh_token_hash: hashToken(refreshToken),
      ip_address:         clientIp,
      user_agent:         userAgent,
      expires_at:         sessionExpiry,
    });

    await supabase.from('superadmin_2fa_pending').delete().eq('id', pending.id);

    await supabase
      .from('superadmin_credentials')
      .update({
        failed_login_attempts: 0,
        locked_until:          null,
        last_login:            new Date().toISOString(),
        last_ip_address:       clientIp,
      })
      .eq('id', superadmin.id);

    const { data: permissions } = await supabase
      .from('superadmin_permissions')
      .select('permission_key')
      .eq('superadmin_id', superadmin.id);

    await logAuditAction(superadmin.id, AUDIT_ACTIONS.LOGIN, 'superadmin', superadmin.id, '2FA verified', 'success', '', req);

    res.json({
      success:     true,
      token:       accessToken,
      refreshToken,
      user: {
        id:          superadmin.id,
        username:    superadmin.username,
        email:       superadmin.email,
        fullName:    superadmin.full_name,
        permissions: (permissions || []).map(p => p.permission_key),
      },
    });
  } catch (err) {
    console.error('2FA error:', err);
    res.status(500).json({ success: false, message: '2FA verification failed' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// AUTH – REFRESH TOKEN
// ─────────────────────────────────────────────────────────────────────────────

router.post('/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) {
      return res.status(401).json({ success: false, message: 'No refresh token provided' });
    }

    const { data: session, error } = await supabase
      .from('superadmin_sessions')
      .select('*, superadmin_credentials(*)')
      .eq('refresh_token_hash', hashToken(refreshToken))
      .is('revoked_at', null)
      .single();

    if (error || !session) {
      return res.status(401).json({ success: false, message: 'Invalid refresh token' });
    }
    if (new Date(session.expires_at) < new Date()) {
      await supabase.from('superadmin_sessions').update({ revoked_at: new Date().toISOString() }).eq('id', session.id);
      return res.status(401).json({ success: false, message: 'Refresh token expired, please log in again' });
    }

    const superadmin = session.superadmin_credentials;
    if (!superadmin || superadmin.status !== 'active') {
      return res.status(403).json({ success: false, message: 'Account inactive or suspended' });
    }

    const newAccessToken = jwt.sign({ superadminId: superadmin.id }, process.env.JWT_SECRET, { expiresIn: '24h' });

    await supabase
      .from('superadmin_sessions')
      .update({
        token_hash:    hashToken(newAccessToken),
        last_activity: new Date().toISOString(),
      })
      .eq('id', session.id);

    res.json({ success: true, data: { accessToken: newAccessToken } });
  } catch (err) {
    console.error('Refresh error:', err);
    res.status(401).json({ success: false, message: 'Token refresh failed' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// AUTH – LOGOUT
// ─────────────────────────────────────────────────────────────────────────────

router.post('/logout', authenticateSuperadmin, async (req, res) => {
  try {
    await supabase
      .from('superadmin_sessions')
      .update({ revoked_at: new Date().toISOString() })
      .eq('id', req.session.id);

    await logAuditAction(req.superadmin.id, AUDIT_ACTIONS.LOGOUT, 'superadmin', req.superadmin.id, 'Logout', 'success', '', req);

    res.json({ success: true, message: 'Logged out' });
  } catch (err) {
    console.error('Logout error:', err);
    res.status(500).json({ success: false, message: 'Logout failed' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// STATISTICS
// ─────────────────────────────────────────────────────────────────────────────

router.get('/stats', authenticateSuperadmin, async (req, res) => {
  try {
    const [agents, clients, chats, docs] = await Promise.all([
      supabase.from('profiles').select('id', { count: 'exact', head: true }).eq('role', 'agent'),
      supabase.from('profiles').select('id', { count: 'exact', head: true }).eq('role', 'client'),
      supabase.from('messages').select('id', { count: 'exact', head: true }).is('closed_at', null),
      supabase.from('agent_documents').select('id', { count: 'exact', head: true }).eq('status', 'pending'),
    ]);

    res.json({
      success: true,
      totalAgents:      agents.count   || 0,
      totalClients:     clients.count  || 0,
      activeChats:      chats.count    || 0,
      pendingDocuments: docs.count     || 0,
      agentsTrend:      5,
      clientsTrend:     12,
      chatsTrend:       -3,
      docsTrend:        8,
    });
  } catch (err) {
    console.error('Stats error:', err);
    res.status(500).json({ success: false, message: 'Failed to fetch stats' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// AUDIT LOGS
// ─────────────────────────────────────────────────────────────────────────────

router.get('/audit-logs', authenticateSuperadmin, async (req, res) => {
  try {
    const limit  = Math.min(parseInt(req.query.limit)  || 50, 500);
    const offset = Math.max(parseInt(req.query.offset) || 0,  0);

    const { data: logs, error, count } = await supabase
      .from('superadmin_audit_logs')
      .select('*, superadmin_credentials(username)', { count: 'exact' })
      .order('created_at', { ascending: false })
      .range(offset, offset + limit - 1);

    if (error) throw error;

    const normalized = (logs || []).map(log => ({
      id:                  log.id,
      action:              log.action,
      resourceType:        log.resource_type,
      resourceId:          log.resource_id,
      reason:              log.reason,
      status:              log.status,
      errorMessage:        log.error_message,
      ipAddress:           log.ip_address,
      createdAt:           log.created_at,
      superadminUsername:  log.superadmin_credentials?.username,
    }));

    res.json({ success: true, data: normalized, total: count || 0 });
  } catch (err) {
    console.error('Audit logs error:', err);
    res.status(500).json({ success: false, message: 'Failed to fetch audit logs' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// CLIENTS (FIXED)
// ─────────────────────────────────────────────────────────────────────────────

router.get('/clients', authenticateSuperadmin, async (req, res) => {
  try {
    const { data: clients, error } = await supabase
      .from('profiles')
      .select('id, first_name, last_name, email, phone, approved, verification_status, created_at')
      .eq('role', 'client')
      .order('created_at', { ascending: false });

    if (error) throw error;

    const normalized = (clients || []).map(c => ({
      id:        c.id,
      name:      `${c.first_name || ''} ${c.last_name || ''}`.trim(),
      email:     c.email,
      phone:     c.phone,
      status:    c.approved && c.verification_status === 'approved' ? 'active' : 'pending',
      createdAt: c.created_at,
    }));

    res.json({ success: true, data: normalized });
  } catch (err) {
    console.error('Clients error:', err);
    res.status(500).json({ success: false, message: 'Failed to fetch clients' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// AGENTS (FIXED)
// ─────────────────────────────────────────────────────────────────────────────

router.get('/agents', authenticateSuperadmin, async (req, res) => {
  try {
    const { data: agents, error } = await supabase
      .from('profiles')
      .select('id, first_name, last_name, email, phone, approved, verification_status, created_at')
      .eq('role', 'agent')
      .order('created_at', { ascending: false });

    if (error) throw error;

    const normalized = (agents || []).map(a => ({
      id:        a.id,
      name:      `${a.first_name || ''} ${a.last_name || ''}`.trim(),
      email:     a.email,
      phone:     a.phone,
      status:    a.approved && a.verification_status === 'approved' ? 'active' : 'pending',
      createdAt: a.created_at,
    }));

    res.json({ success: true, data: normalized });
  } catch (err) {
    console.error('Agents error:', err);
    res.status(500).json({ success: false, message: 'Failed to fetch agents' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// CHATS
// ─────────────────────────────────────────────────────────────────────────────

router.get('/chats', authenticateSuperadmin, async (req, res) => {
  try {
    const { data: rows, error } = await supabase
      .from('messages')
      .select('id, booking_id, sender_id, sender_type, agent_id, client_id, message, created_at, is_closed, closed_at')
      .order('created_at', { ascending: false })
      .limit(500);

    if (error) throw error;

    const threads = {};
    const profileIds = new Set();

    for (const row of rows || []) {
      if (!threads[row.booking_id]) {
        threads[row.booking_id] = {
          bookingId:    row.booking_id,
          lastMessage:  row.message,
          lastActivity: row.created_at,
          isClosed:     row.is_closed,
          closedAt:     row.closed_at,
          messageCount: 0,
          agentId:      row.agent_id,
          clientId:     row.client_id,
        };
      }

      const thread = threads[row.booking_id];
      thread.messageCount += 1;
      if (!thread.agentId && row.agent_id) thread.agentId = row.agent_id;
      if (!thread.clientId && row.client_id) thread.clientId = row.client_id;
      if (row.agent_id) profileIds.add(row.agent_id);
      if (row.client_id) profileIds.add(row.client_id);
    }

    const profileMap = {};
    if (profileIds.size > 0) {
      const { data: profiles, error: profileErr } = await supabase
        .from('profiles')
        .select('id, first_name, last_name, email')
        .in('id', Array.from(profileIds));
      if (profileErr) throw profileErr;
      (profiles || []).forEach(p => {
        profileMap[p.id] = p;
      });
    }

    const normalized = Object.values(threads).map(thread => {
      const agent = profileMap[thread.agentId];
      const client = profileMap[thread.clientId];
      return {
        id:           thread.bookingId,
        bookingId:    thread.bookingId,
        lastMessage:  thread.lastMessage || '',
        messageCount: thread.messageCount,
        clientName:   client ? `${client.first_name || ''} ${client.last_name || ''}`.trim() || client.email : 'Client',
        agentName:    agent ? `${agent.first_name || ''} ${agent.last_name || ''}`.trim() || agent.email : 'Agent',
        status:       thread.isClosed ? 'closed' : 'active',
        lastActivity: thread.lastActivity,
        closedAt:     thread.closedAt,
      };
    });

    res.json({ success: true, data: normalized });
  } catch (err) {
    console.error('Chats error:', err);
    res.status(500).json({ success: false, message: 'Failed to fetch chats' });
  }
});

router.get('/chats/:bookingId/messages', authenticateSuperadmin, async (req, res) => {
  try {
    const { bookingId } = req.params;
    const { data: messages, error } = await supabase
      .from('messages')
      .select('id, booking_id, sender_id, sender_type, agent_id, client_id, message, created_at, is_closed')
      .eq('booking_id', bookingId)
      .order('created_at', { ascending: true });

    if (error) throw error;

    const profileIds = new Set();
    for (const msg of messages || []) {
      if (msg.sender_id) profileIds.add(msg.sender_id);
      if (msg.agent_id) profileIds.add(msg.agent_id);
      if (msg.client_id) profileIds.add(msg.client_id);
    }

    const profileMap = {};
    if (profileIds.size > 0) {
      const { data: profiles, error: profileErr } = await supabase
        .from('profiles')
        .select('id, first_name, last_name, email')
        .in('id', Array.from(profileIds));
      if (profileErr) throw profileErr;
      (profiles || []).forEach(p => {
        profileMap[p.id] = p;
      });
    }

    const normalized = (messages || []).map(msg => {
      const profile = profileMap[msg.sender_id];
      return {
        id:         msg.id,
        bookingId:  msg.booking_id,
        senderId:   msg.sender_id,
        senderType: msg.sender_type,
        senderName: profile ? `${profile.first_name || ''} ${profile.last_name || ''}`.trim() || profile.email : msg.sender_type || 'System',
        message:    msg.message,
        createdAt:  msg.created_at,
        isClosed:   msg.is_closed,
      };
    });

    res.json({ success: true, data: normalized });
  } catch (err) {
    console.error('Chat messages error:', err);
    res.status(500).json({ success: false, message: 'Failed to fetch chat messages' });
  }
});

router.post('/chats/:bookingId/close', authenticateSuperadmin, async (req, res) => {
  try {
    const { bookingId } = req.params;
    const { reason } = req.body;

    if (!reason || reason.trim().length === 0) {
      return res.status(422).json({ success: false, message: 'Reason required' });
    }

    const { data: messages, error: msgErr } = await supabase
      .from('messages')
      .select('id')
      .eq('booking_id', bookingId)
      .order('created_at', { ascending: false })
      .limit(1);

    if (msgErr) throw msgErr;
    if (!messages || messages.length === 0) {
      return res.status(404).json({ success: false, message: 'Chat not found' });
    }

    const latestMessage = messages[0];

    const { error } = await supabase
      .from('messages')
      .update({
        is_closed:    true,
        closed_by:    req.superadmin.id,
        close_reason: sanitizeInput(reason),
        closed_at:    new Date().toISOString(),
      })
      .eq('booking_id', bookingId);

    if (error) throw error;

    await supabase.from('chat_closures').insert({
      message_id: latestMessage.id,
      booking_id: bookingId,
      closed_by:  req.superadmin.id,
      reason:     sanitizeInput(reason),
    });

    await logAuditAction(req.superadmin.id, AUDIT_ACTIONS.CLOSE_CHAT, 'chat', bookingId, reason, 'success', '', req);

    res.json({ success: true, message: 'Chat closed' });
  } catch (err) {
    console.error('Close chat error:', err);
    await logAuditAction(req.superadmin?.id || null, AUDIT_ACTIONS.CLOSE_CHAT, 'chat', req.params.bookingId, '', 'failed', err.message, req);
    res.status(500).json({ success: false, message: 'Failed to close chat' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// DEBUG – Check R2 connectivity and agent documents status
// ─────────────────────────────────────────────────────────────────────────────
router.get('/debug/documents-status', authenticateSuperadmin, async (req, res) => {
  try {
    const checks = {
      r2Connected: false,
      r2Bucket: R2_BUCKET ? 'configured' : 'missing',
      agentDocumentsRecords: 0,
      r2DocumentsCount: 0,
      errors: [],
    };

    // Check R2 connectivity
    try {
      const allDocs = await R2.send(new ListObjectsV2Command({
        Bucket: R2_BUCKET,
        Prefix: 'documents/',
      }));
      checks.r2Connected = true;
      checks.r2DocumentsCount = (allDocs.Contents || []).length;
    } catch (r2Err) {
      checks.errors.push(`R2 connection failed: ${r2Err.message}`);
    }

    // Check DB records
    try {
      const { count } = await supabase
        .from('agent_documents')
        .select('id', { count: 'exact', head: true });
      checks.agentDocumentsRecords = count || 0;
    } catch (dbErr) {
      checks.errors.push(`DB query failed: ${dbErr.message}`);
    }

    res.json({ success: true, data: checks });
  } catch (err) {
    console.error('Debug status error:', err);
    res.status(500).json({ success: false, message: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// DOCUMENTS 
// ─────────────────────────────────────────────────────────────────────────────

router.post('/documents/reconcile', authenticateSuperadmin, async (req, res) => {
  try {
    const reconciledCount = await reconcileAgentDocumentsFromR2();
    res.json({
      success: true,
      message: `Reconciled ${reconciledCount} missing agent document record(s) from R2`,
      reconciledCount,
    });
  } catch (err) {
    console.error('Reconcile documents error:', err);
    res.status(500).json({ success: false, message: 'Failed to reconcile documents' });
  }
});

router.get('/documents', authenticateSuperadmin, async (req, res) => {
  try {
    const status = req.query.status;
    const reconcile = req.query.reconcile === 'true';
    const buildDocumentQuery = () => {
      let q = supabase
        .from('agent_documents')
        .select(`
          *,
          agent:profiles!user_id (first_name, last_name, email),
          reviewer:profiles!reviewed_by (first_name, last_name)
        `)
        .order('submitted_at', { ascending: false });

      if (status && status !== 'all') {
        q = q.eq('status', status);
      }

      return q;
    };

    if (reconcile && R2_BUCKET) {
      await reconcileAgentDocumentsFromR2();
    }

    let { data: documents, error } = await buildDocumentQuery();
    if (error) throw error;

    if ((!documents || documents.length === 0) && R2_BUCKET) {
      const reconciledCount = await reconcileAgentDocumentsFromR2();
      if (reconciledCount > 0) {
        const refreshed = await buildDocumentQuery();
        documents = refreshed.data;
        if (refreshed.error) throw refreshed.error;
      }
    }

    const r2Results = await Promise.all(
      (documents || []).map(doc => getAgentDocumentUrls(doc.user_id))
    );

    const normalized = (documents || []).map((doc, index) => {
      const r2 = r2Results[index] || {};
      return {
        id:               doc.id,
        agentId:          doc.user_id,
        agentName:        `${doc.agent?.first_name || ''} ${doc.agent?.last_name || ''}`.trim(),
        agentEmail:       doc.agent?.email,
        incorporationDoc: r2.incorporation?.publicUrl || doc.incorporation_doc,
        tourismDoc:       r2.tourism?.publicUrl || doc.tourism_doc,
        kraPin:           r2.krapin?.publicUrl || doc.krapin_doc,
        directorIdDoc:    r2.director_id?.publicUrl || doc.director_id_doc || null,
        officePhoto:      r2.office_photo || doc.office_photo,
        status:           doc.status,
        reviewNotes:      doc.review_notes,
        submittedAt:      doc.submitted_at,
        reviewedAt:       doc.reviewed_at,
        reviewedBy:       doc.reviewed_by,
        reviewerName:     doc.reviewer ? `${doc.reviewer.first_name || ''} ${doc.reviewer.last_name || ''}`.trim() : null,
      };
    });

    res.json({ success: true, data: normalized });
  } catch (err) {
    console.error('Documents error:', err);
    res.status(500).json({ success: false, message: err.message || 'Failed to fetch documents' });
  }
});

router.post('/documents/:docId/verify', authenticateSuperadmin, async (req, res) => {
  const { docId } = req.params;
  const { status, notes } = req.body;
  const allowedStatuses = ['approved', 'rejected'];
  const safeStatus = sanitizeInput((status || '').toString()).toLowerCase();
  const auditAction = allowedStatuses.includes(safeStatus)
    ? (safeStatus === 'approved' ? AUDIT_ACTIONS.VERIFY_DOCUMENT : AUDIT_ACTIONS.REJECT_DOCUMENT)
    : AUDIT_ACTIONS.VERIFY_DOCUMENT;
  const auditResourceId = docId || 'unknown';

  if (!docId || typeof docId !== 'string' || !docId.trim()) {
    await logAuditAction(req.superadmin.id, auditAction, 'document', auditResourceId, 'Invalid document id', 'failed', 'Missing or invalid document id', req);
    return res.status(422).json({ success: false, message: 'Invalid document id' });
  }

  if (!allowedStatuses.includes(safeStatus)) {
    await logAuditAction(req.superadmin.id, AUDIT_ACTIONS.VERIFY_DOCUMENT, 'document', auditResourceId, 'Invalid status', 'failed', `Invalid status: ${status}`, req);
    return res.status(422).json({ success: false, message: 'Invalid status' });
  }

  try {
    const updatePayload = {
      status: safeStatus,
      review_notes: sanitizeInput(notes || ''),
      reviewed_by: req.superadmin.id,
      reviewed_at: new Date().toISOString(),
    };

    const { data: updatedDoc, error: docError } = await supabase
      .from('agent_documents')
      .update(updatePayload)
      .eq('id', docId)
      .select('user_id')
      .single();

    if (docError) {
      await logAuditAction(req.superadmin.id, auditAction, 'document', auditResourceId, 'Document update failed', 'failed', docError.message || 'Unexpected Supabase error', req);
      throw docError;
    }

    if (!updatedDoc || !updatedDoc.user_id) {
      await logAuditAction(req.superadmin.id, auditAction, 'document', auditResourceId, 'Document not found', 'failed', 'No matching document row', req);
      return res.status(404).json({ success: false, message: 'Document not found' });
    }

    const profilePayload = {
      approved: safeStatus === 'approved',
      verification_status: safeStatus,
      updated_at: new Date().toISOString(),
    };

    const { data: profileData, error: profileError } = await supabase
      .from('profiles')
      .update(profilePayload)
      .eq('id', updatedDoc.user_id)
      .select('id')
      .single();

    if (profileError) {
      await logAuditAction(req.superadmin.id, auditAction, 'document', auditResourceId, 'Profile update failed', 'failed', profileError.message || 'Unexpected Supabase error', req);
      throw profileError;
    }

    if (!profileData) {
      await logAuditAction(req.superadmin.id, auditAction, 'document', auditResourceId, 'Profile not found', 'failed', `Profile not found for user ${updatedDoc.user_id}`, req);
      return res.status(404).json({ success: false, message: 'Associated agent profile not found' });
    }

    await logAuditAction(req.superadmin.id, auditAction, 'document', auditResourceId, notes || '', 'success', '', req);
    return res.json({ success: true, message: `Document ${safeStatus}` });
  } catch (err) {
    console.error('Document verify error:', err);
    await logAuditAction(req.superadmin.id, auditAction, 'document', auditResourceId, 'Document verification failed', 'failed', err.message || 'Unknown error', req);
    return res.status(500).json({ success: false, message: err?.message || 'Failed to verify document' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// DELETE – Remove documents from R2 and/or database
// ─────────────────────────────────────────────────────────────────────────────

router.delete('/documents/:agentId/:docType', authenticateSuperadmin, async (req, res) => {
  try {
    const { agentId, docType } = req.params;

    // Validate inputs
    if (!agentId || typeof agentId !== 'string' || !agentId.trim()) {
      await logAuditAction(req.superadmin.id, 'DELETE_DOCUMENT', 'document', agentId || 'unknown', 'Invalid agent ID', 'failed', 'Missing or invalid agent ID', req);
      return res.status(422).json({ success: false, message: 'Invalid agent ID' });
    }

    if (!docType || !DOCUMENT_KEYS.includes(docType.toLowerCase())) {
      await logAuditAction(req.superadmin.id, 'DELETE_DOCUMENT', 'document', agentId, 'Invalid document type', 'failed', `Invalid type: ${docType}`, req);
      return res.status(422).json({ success: false, message: `Invalid document type. Allowed: ${DOCUMENT_KEYS.join(', ')}` });
    }

    const safeDoctType = docType.toLowerCase();

    // Step 1: List all documents of this type for this agent in R2
    const { Contents } = await R2.send(new ListObjectsV2Command({
      Bucket: R2_BUCKET,
      Prefix: `documents/${agentId}/${safeDoctType}/`,
    }));

    const filesToDelete = (Contents || []).map(obj => obj.Key);

    // Step 2: Delete from R2
    let deletedCount = 0;
    if (filesToDelete.length > 0) {
      for (const key of filesToDelete) {
        try {
          await R2.send(new DeleteObjectCommand({
            Bucket: R2_BUCKET,
            Key: key,
          }));
          deletedCount++;
          console.log(`[DELETE] Deleted R2 object: ${key}`);
        } catch (r2Err) {
          console.error(`[DELETE] Failed to delete R2 object ${key}:`, r2Err);
        }
      }
    }

    // Step 3: Update database to clear the reference
    const updatePayload = {};
    if (safeDoctType === 'office_photo') {
      updatePayload.office_photo = null;
    } else {
      updatePayload[`${safeDoctType}_doc`] = null;
    }

    const { error: dbError } = await supabase
      .from('agent_documents')
      .update(updatePayload)
      .eq('user_id', agentId);

    if (dbError) {
      console.error('Failed to update agent_documents after R2 delete:', dbError);
      // Log but don't fail — R2 delete succeeded
    }

    await logAuditAction(req.superadmin.id, 'DELETE_DOCUMENT', 'document', agentId, `Deleted ${safeDoctType}: ${deletedCount} file(s)`, 'success', '', req);

    res.json({
      success: true,
      message: `Deleted ${deletedCount} ${safeDoctType} document(s)`,
      deletedCount,
    });
  } catch (err) {
    console.error('Document delete error:', err);
    await logAuditAction(req.superadmin.id, 'DELETE_DOCUMENT', 'document', req.params.agentId || 'unknown', 'Delete failed', 'failed', err.message, req);
    res.status(500).json({ success: false, message: err.message || 'Failed to delete document(s)' });
  }
});

router.delete('/documents/:agentId', authenticateSuperadmin, async (req, res) => {
  try {
    const { agentId } = req.params;

    if (!agentId || typeof agentId !== 'string' || !agentId.trim()) {
      await logAuditAction(req.superadmin.id, 'DELETE_DOCUMENT', 'document', agentId || 'unknown', 'Invalid agent ID', 'failed', 'Missing or invalid agent ID', req);
      return res.status(422).json({ success: false, message: 'Invalid agent ID' });
    }

    // List all documents for this agent in R2
    const { Contents } = await R2.send(new ListObjectsV2Command({
      Bucket: R2_BUCKET,
      Prefix: `documents/${agentId}/`,
    }));

    const filesToDelete = (Contents || []).map(obj => obj.Key);

    // Delete all from R2
    let deletedCount = 0;
    if (filesToDelete.length > 0) {
      for (const key of filesToDelete) {
        try {
          await R2.send(new DeleteObjectCommand({
            Bucket: R2_BUCKET,
            Key: key,
          }));
          deletedCount++;
          console.log(`[DELETE] Deleted R2 object: ${key}`);
        } catch (r2Err) {
          console.error(`[DELETE] Failed to delete R2 object ${key}:`, r2Err);
        }
      }
    }

    // Clear all document fields in database
    const { error: dbError } = await supabase
      .from('agent_documents')
      .update({
        incorporation_doc: null,
        tourism_doc: null,
        krapin_doc: null,
        director_id_doc: null,
        office_photo: null,
      })
      .eq('user_id', agentId);

    if (dbError) {
      console.error('Failed to clear agent_documents after R2 delete:', dbError);
    }

    await logAuditAction(req.superadmin.id, 'DELETE_DOCUMENT', 'document', agentId, `Deleted all agent documents: ${deletedCount} file(s)`, 'success', '', req);

    res.json({
      success: true,
      message: `Deleted all ${deletedCount} document(s) for agent ${agentId}`,
      deletedCount,
    });
  } catch (err) {
    console.error('Bulk document delete error:', err);
    await logAuditAction(req.superadmin.id, 'DELETE_DOCUMENT', 'document', req.params.agentId || 'unknown', 'Bulk delete failed', 'failed', err.message, req);
    res.status(500).json({ success: false, message: err.message || 'Failed to delete all documents' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// PACKAGES
// ─────────────────────────────────────────────────────────────────────────────

router.get('/packages', authenticateSuperadmin, async (req, res) => {
  try {
    const { data: packages, error } = await supabase
      .from('packages')
      .select(`
        id, name, type, price, created_at, created_by,
        agent:profiles!packages_created_by_fkey (first_name, last_name, email)
      `)
      .order('created_at', { ascending: false });

    if (error) throw error;

    const normalized = (packages || []).map(pkg => ({
      id:            pkg.id,
      name:          pkg.name,
      type:          pkg.type,
      price:         pkg.price,
      createdAt:     pkg.created_at,
      agentId:       pkg.created_by,
      agentName:     pkg.agent ? `${pkg.agent.first_name || ''} ${pkg.agent.last_name || ''}`.trim() : 'Unknown',
      bookingCount:  0,
    }));

    res.json({ success: true, data: normalized });
  } catch (err) {
    console.error('Packages error:', err);
    res.status(500).json({ success: false, message: 'Failed to fetch packages' });
  }
});

router.delete('/packages/:packageId', authenticateSuperadmin, async (req, res) => {
  try {
    const { packageId } = req.params;
    const { reason }    = req.body;

    const { data: bookings } = await supabase
      .from('bookings')
      .select('id')
      .eq('package_id', packageId)
      .neq('status', 'cancelled');

    if (bookings && bookings.length > 0) {
      return res.status(422).json({
        success: false,
        message: `Cannot delete package with ${bookings.length} active booking(s)`,
      });
    }

    const { error } = await supabase.from('packages').delete().eq('id', packageId);
    if (error) throw error;

    await logAuditAction(req.superadmin.id, AUDIT_ACTIONS.DELETE_PACKAGE, 'package', packageId, reason || '', 'success', '', req);

    res.json({ success: true, message: 'Package deleted' });
  } catch (err) {
    console.error('Delete package error:', err);
    res.status(500).json({ success: false, message: 'Failed to delete package' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// DASHBOARD CLOSURES
// ─────────────────────────────────────────────────────────────────────────────

router.post('/dashboards/close', authenticateSuperadmin, async (req, res) => {
  try {
    const { userId, type, reason } = req.body;

    if (!['agent', 'client'].includes(type)) {
      return res.status(422).json({ success: false, message: 'Invalid dashboard type' });
    }

    await supabase.from('dashboard_closures').insert({
      user_id:        userId,
      dashboard_type: type,
      closed_by:      req.superadmin.id,
      reason:         sanitizeInput(reason),
      closed_at:      new Date().toISOString(),
    });

    await logAuditAction(req.superadmin.id, AUDIT_ACTIONS.CLOSE_DASHBOARD, 'dashboard', userId, reason, 'success', '', req);

    res.json({ success: true, message: 'Dashboard closed' });
  } catch (err) {
    console.error('Close dashboard error:', err);
    res.status(500).json({ success: false, message: 'Failed to close dashboard' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// ACCOUNTING ENDPOINTS
// ─────────────────────────────────────────────────────────────────────────────

router.get('/accounting/transactions', authenticateSuperadmin, async (req, res) => {
  try {
    const limit = Math.min(Math.max(parseInt(req.query.limit) || 50, 1), 1000);
    const offset = Math.max(parseInt(req.query.offset) || 0, 0);

    // Query successful payments from Payments (Mongo)
    const payments = await Payment.find({ status: 'SUCCESS' })
      .sort({ paidAt: -1 })
      .skip(offset)
      .limit(limit)
      .lean()
      .exec();

    const results = [];

    for (const p of payments) {
      // Find booking linked to this payment (if any)
      const booking = await Booking.findOne({ paymentId: p._id }).lean().exec();

      // Try to fetch package info from Supabase (if booking exists and packageId present)
      let packageInfo = null;
      let percentage = 0;
      if (booking && booking.packageId) {
        try {
          const { data: pkg, error: pkgErr } = await supabase.from('packages').select('*').eq('id', String(booking.packageId)).maybeSingle();
          if (!pkgErr && pkg) packageInfo = pkg;
        } catch (err) { /* ignore */ }
      }

      if (packageInfo) {
        percentage = Number(packageInfo.profit_percentage || packageInfo.agent_percentage || packageInfo.commission_percent || packageInfo.percentage || 0) || 0;
      }

      const profit = (Number(p.amountKes) || 0) * (percentage / 100);

      // Fetch agent and client names from Supabase when possible
      let agentName = null; let agentEmail = null; let clientName = null; let clientEmail = null;
      try {
        if (booking && booking.packageId && packageInfo && packageInfo.created_by) {
          const { data: agentProfile } = await supabase.from('profiles').select('first_name,last_name,email').eq('id', packageInfo.created_by).maybeSingle();
          if (agentProfile) {
            agentName = `${agentProfile.first_name || ''} ${agentProfile.last_name || ''}`.trim() || agentProfile.email;
            agentEmail = agentProfile.email;
          }
        }
        if (booking && booking.userId) {
          const { data: clientProfile } = await supabase.from('profiles').select('first_name,last_name,email').eq('id', String(booking.userId)).maybeSingle();
          if (clientProfile) {
            clientName = `${clientProfile.first_name || ''} ${clientProfile.last_name || ''}`.trim() || clientProfile.email;
            clientEmail = clientProfile.email;
          }
        }
      } catch (err) { /* ignore profile lookup failures */ }

      results.push({
        id: String(p._id),
        packageId: booking?.packageId || p.packageId || null,
        packageName: packageInfo?.name || p.packageName || null,
        clientId: booking?.userId || p.userId || null,
        clientName: clientName || p.clientName || null,
        clientEmail: clientEmail || p.clientEmail || null,
        agentName: agentName || p.agentName || null,
        agentEmail: agentEmail || p.agentEmail || null,
        amount: p.amountKes,
        percentage,
        profit,
        paidAt: p.paidAt || p.createdAt || p.updatedAt || null,
        disbursed: !!p.disbursed,
      });
    }

    res.json({ success: true, data: results });
  } catch (err) {
    console.error('Accounting transactions error:', err);
    res.status(500).json({ success: false, message: 'Failed to fetch transactions' });
  }
});

router.post('/accounting/transactions/:id/disburse', authenticateSuperadmin, async (req, res) => {
  try {
    const { id } = req.params;
    if (!id) return res.status(422).json({ success: false, message: 'Missing transaction id' });

    const payment = await Payment.findById(id).exec();
    if (!payment) return res.status(404).json({ success: false, message: 'Transaction not found' });
    if (payment.disbursed) return res.status(409).json({ success: false, message: 'Already disbursed' });
    if (payment.status !== 'SUCCESS') return res.status(422).json({ success: false, message: 'Payment not successful' });

    payment.disbursed = true;
    payment.disbursedAt = new Date();
    payment.disbursedBy = String(req.superadmin.id);
    await payment.save();

    await logAuditAction(req.superadmin.id, 'DISBURSE_TRANSACTION', 'transaction', id, `Disbursed by superadmin ${req.superadmin.id}`, 'success', '', req);

    res.json({ success: true, message: 'Marked as disbursed' });
  } catch (err) {
    console.error('Disburse error:', err);
    res.status(500).json({ success: false, message: 'Failed to disburse transaction' });
  }
});

router.get('/accounting/transactions/:id/receipt', authenticateSuperadmin, async (req, res) => {
  try {
    const { id } = req.params;
    if (!id) return res.status(422).json({ success: false, message: 'Missing transaction id' });

    const payment = await Payment.findById(id).lean().exec();
    if (!payment) return res.status(404).json({ success: false, message: 'Transaction not found' });

    // Minimal receipt PDF
    const doc = new PDFDocument({ size: 'A4', margin: 50 });
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="receipt-${id}.pdf"`);

    doc.info.Title = `Receipt - ${id}`;

    doc.fontSize(20).text('Umrah Market - Receipt', { align: 'center' });
    doc.moveDown();

    doc.fontSize(12).text(`Receipt ID: ${id}`);
    doc.text(`Amount: KES ${Number(payment.amountKes).toLocaleString()}`);
    doc.text(`Status: ${payment.status}`);
    doc.text(`Paid At: ${payment.paidAt ? new Date(payment.paidAt).toISOString() : ''}`);
    doc.moveDown();

    doc.text('Thank you for using Umrah Market.', { align: 'left' });
    doc.end();

    // Pipe PDF to response
    doc.pipe(res);

    // Mark receipt as generated (async)
    Payment.findByIdAndUpdate(id, { receiptGenerated: true }).then(() => {}).catch(() => {});
  } catch (err) {
    console.error('Receipt error:', err);
    res.status(500).json({ success: false, message: 'Failed to generate receipt' });
  }
});


// Email receipt endpoint
router.post('/accounting/transactions/:id/email', authenticateSuperadmin, async (req, res) => {
  try {
    const { id } = req.params;
    if (!id) return res.status(422).json({ success: false, message: 'Missing transaction id' });

    const payment = await Payment.findById(id).lean().exec();
    if (!payment) return res.status(404).json({ success: false, message: 'Transaction not found' });

    const recipient = req.body.email || payment.payerEmail || null;
    if (!recipient) return res.status(422).json({ success: false, message: 'No recipient email available' });

    // Require SMTP config
    if (!process.env.SMTP_HOST || !process.env.SMTP_USER || !process.env.SMTP_PASS) {
      return res.status(501).json({ success: false, message: 'Email service not configured on server' });
    }

    // Generate PDF in memory
    const doc = new PDFDocument({ size: 'A4', margin: 50 });
    const chunks = [];
    doc.on('data', (c) => chunks.push(c));
    doc.on('end', async () => {
      const pdfBuffer = Buffer.concat(chunks);

      // Send email using nodemailer
      try {
        const nodemailer = await import('nodemailer');
        const transporter = nodemailer.createTransport({
          host: process.env.SMTP_HOST,
          port: Number(process.env.SMTP_PORT || 587),
          secure: String(process.env.SMTP_SECURE || 'false') === 'true',
          auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
        });

        await transporter.sendMail({
          from: process.env.SMTP_FROM || process.env.SMTP_USER,
          to: recipient,
          subject: `Receipt for transaction ${id}`,
          text: `Please find attached the receipt for transaction ${id}.`,
          attachments: [{ filename: `receipt-${id}.pdf`, content: pdfBuffer }],
        });

        // mark as receiptGenerated
        await Payment.findByIdAndUpdate(id, { receiptGenerated: true }).exec();
        await logAuditAction(req.superadmin.id, 'EMAIL_RECEIPT', 'transaction', id, `Emailed receipt to ${recipient}`, 'success', '', req);
        return res.json({ success: true, message: 'Email sent' });
      } catch (mailErr) {
        console.error('Mail send failed:', mailErr);
        return res.status(500).json({ success: false, message: 'Failed to send email' });
      }
    });

    // Build simple receipt
    doc.fontSize(18).text('Umrah Market Receipt', { align: 'center' });
    doc.moveDown();
    doc.fontSize(12).text(`Receipt ID: ${id}`);
    doc.text(`Amount: KES ${Number(payment.amountKes).toLocaleString()}`);
    doc.text(`Status: ${payment.status}`);
    doc.text(`Paid At: ${payment.paidAt ? new Date(payment.paidAt).toISOString() : ''}`);
    doc.end();
  } catch (err) {
    console.error('Email receipt error:', err);
    res.status(500).json({ success: false, message: 'Failed to email receipt' });
  }
});


// ─────────────────────────────────────────────────────────────────────────────
// DATA EXPORT
// ─────────────────────────────────────────────────────────────────────────────

const csvCell = (v) => {
  if (v == null) return '';
  const s = String(v);
  return s.includes(',') || s.includes('"') || s.includes('\n')
    ? `"${s.replace(/"/g, '""')}"`
    : s;
};

const toCsv = (rows, columns) => {
  const header = columns.join(',');
  const body   = rows.map(row => columns.map(col => csvCell(row[col])).join(',')).join('\n');
  return `${header}\n${body}`;
};

const EXPORT_QUERIES = {
  agents: {
    table:   'profiles',
    filters: [['role', 'agent']],
    columns: ['id', 'first_name', 'last_name', 'email', 'phone', 'status', 'created_at'],
  },
  clients: {
    table:   'profiles',
    filters: [['role', 'client']],
    columns: ['id', 'first_name', 'last_name', 'email', 'phone', 'status', 'created_at'],
  },
  bookings: {
    table:   'bookings',
    filters: [],
    columns: ['id', 'package_id', 'user_id', 'status', 'total_price', 'created_at'],
  },
  packages: {
    table:   'packages',
    filters: [],
    columns: ['id', 'name', 'type', 'price', 'agent_id', 'created_at'],
  },
};

router.get('/export/:dataType', authenticateSuperadmin, async (req, res) => {
  try {
    const { dataType } = req.params;

    if (!EXPORT_QUERIES[dataType]) {
      return res.status(422).json({ success: false, message: 'Invalid export type' });
    }

    const { table, filters, columns } = EXPORT_QUERIES[dataType];
    let query = supabase.from(table).select(columns.join(', ')).order('created_at', { ascending: false });

    for (const [col, val] of filters) {
      query = query.eq(col, val);
    }

    const { data: rows, error } = await query;
    if (error) throw error;

    const csv = toCsv(rows || [], columns);

    await logAuditAction(req.superadmin.id, AUDIT_ACTIONS.EXPORT_DATA, 'export', dataType, `Exported ${dataType}`, 'success', '', req);

    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="export-${dataType}-${Date.now()}.csv"`);
    res.send(csv);
  } catch (err) {
    console.error('Export error:', err);
    res.status(500).json({ success: false, message: 'Export failed' });
  }
});

export default router;