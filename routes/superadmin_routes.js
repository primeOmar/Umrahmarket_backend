import express from 'express';
import jwt from 'jsonwebtoken';
import { S3Client, ListObjectsV2Command, GetObjectCommand, DeleteObjectCommand } from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import { supabaseAdmin as supabase } from '../config/supabase.js';
import {
  hashPassword, verifyPassword, generateToken, hashToken,
  loginRateLimiter, validateEmail, sanitizeInput, AUDIT_ACTIONS,
} from '../utils/securityUtils.js';

import PDFDocument from 'pdfkit';
import accountingRouter from './accounting.routes.js';
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
        // Agents who explicitly asked for review float to the top, so a
        // backlog doesn't bury someone who's actively waiting.
        .order('review_requested_at', { ascending: false, nullsFirst: false })
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
        reviewRequestedAt: doc.review_requested_at,
        // Per-document verification — each one is checked independently.
        items: {
          incorporation: { status: doc.incorporation_status, notes: doc.incorporation_notes, reviewedAt: doc.incorporation_reviewed_at },
          tourism:       { status: doc.tourism_status,       notes: doc.tourism_notes,       reviewedAt: doc.tourism_reviewed_at },
          krapin:        { status: doc.krapin_status,        notes: doc.krapin_notes,        reviewedAt: doc.krapin_reviewed_at },
          director_id:   { status: doc.director_id_status,   notes: doc.director_id_notes,   reviewedAt: doc.director_id_reviewed_at },
          office_photo:  { status: doc.office_photo_status,  notes: doc.office_photo_notes,   reviewedAt: doc.office_photo_reviewed_at },
        },
      };
    });

    res.json({ success: true, data: normalized });
  } catch (err) {
    console.error('Documents error:', err);
    res.status(500).json({ success: false, message: err.message || 'Failed to fetch documents' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// PER-DOCUMENT VERIFICATION
// ─────────────────────────────────────────────────────────────────────────────
// Maps the public doc key (used in the API and frontend) to its DB columns.
// office_photo is intentionally NOT in REQUIRED_DOC_KEYS — some agencies are
// home-based and we don't want to block an otherwise-genuine agent over a
// photo of an office that doesn't exist. It can still be reviewed/rejected
// individually; it just doesn't gate overall approval.
const DOC_FIELD_MAP = {
  incorporation: { urlCol: 'incorporation_doc', statusCol: 'incorporation_status', notesCol: 'incorporation_notes', reviewedAtCol: 'incorporation_reviewed_at' },
  tourism:       { urlCol: 'tourism_doc',       statusCol: 'tourism_status',       notesCol: 'tourism_notes',       reviewedAtCol: 'tourism_reviewed_at' },
  krapin:        { urlCol: 'krapin_doc',        statusCol: 'krapin_status',        notesCol: 'krapin_notes',        reviewedAtCol: 'krapin_reviewed_at' },
  director_id:   { urlCol: 'director_id_doc',   statusCol: 'director_id_status',   notesCol: 'director_id_notes',   reviewedAtCol: 'director_id_reviewed_at' },
  office_photo:  { urlCol: 'office_photo',      statusCol: 'office_photo_status',  notesCol: 'office_photo_notes',  reviewedAtCol: 'office_photo_reviewed_at' },
};
// REQUIRED_DOC_KEYS — documents an agent must have approved to be fully
// verified. director_id was briefly excluded here because, at the time,
// no uploaded frontend file showed an upload form for it — but
// DocumentsTab.jsx (the agent's actual document upload UI) confirms a real
// "Director / Manager ID" upload card exists. Restored to required.
//
// office_photo remains optional — some agencies are home-based.
const REQUIRED_DOC_KEYS = ['incorporation', 'tourism', 'krapin', 'director_id'];

// Recomputes the bundle-level `status` from the five per-document statuses,
// then mirrors it onto `profiles.approved` / `profiles.verification_status`
// — every existing query in this codebase (agents list, package-creation
// gate, client-facing agent display) reads from `profiles`, so this is the
// single place that keeps them truthful after any per-document change.
//
//   - 'approved'  → every REQUIRED doc is 'approved' (office_photo optional)
//   - 'rejected'  → any REQUIRED doc is 'rejected' (a single rejection blocks
//                   the agent immediately; they must fix it, not just wait)
//   - 'pending'   → otherwise (still missing approvals, nothing rejected yet)
const recomputeOverallStatus = async (docRow, superadminId) => {
  const requiredStatuses = REQUIRED_DOC_KEYS.map(key => docRow[DOC_FIELD_MAP[key].statusCol]);

  let overall;
  if (requiredStatuses.includes('rejected')) overall = 'rejected';
  else if (requiredStatuses.every(s => s === 'approved')) overall = 'approved';
  else overall = 'pending';

  const { error: bundleError } = await supabase
    .from('agent_documents')
    .update({ status: overall, updated_at: new Date().toISOString() })
    .eq('id', docRow.id);
  if (bundleError) throw bundleError;

  const { error: profileError } = await supabase
    .from('profiles')
    .update({
      approved: overall === 'approved',
      verification_status: overall,
      updated_at: new Date().toISOString(),
    })
    .eq('id', docRow.user_id);
  if (profileError) throw profileError;

  return overall;
};

// POST /documents/:docId/verify-item
// Approves or rejects ONE document type within a bundle. The agent only
// becomes "genuine" (able to post packages) once every required document
// independently reaches 'approved' — see recomputeOverallStatus above.
router.post('/documents/:docId/verify-item', authenticateSuperadmin, async (req, res) => {
  const { docId } = req.params;
  const { docType, status, notes } = req.body;
  const allowedStatuses = ['approved', 'rejected'];
  const safeStatus = sanitizeInput((status || '').toString()).toLowerCase();
  const safeDocType = sanitizeInput((docType || '').toString()).toLowerCase();
  const auditAction = safeStatus === 'approved' ? AUDIT_ACTIONS.VERIFY_DOCUMENT : AUDIT_ACTIONS.REJECT_DOCUMENT;
  const auditResourceId = docId || 'unknown';

  if (!docId || typeof docId !== 'string' || !docId.trim()) {
    await logAuditAction(req.superadmin.id, auditAction, 'document', auditResourceId, 'Invalid document id', 'failed', 'Missing or invalid document id', req);
    return res.status(422).json({ success: false, message: 'Invalid document id' });
  }
  if (!DOC_FIELD_MAP[safeDocType]) {
    await logAuditAction(req.superadmin.id, auditAction, 'document', auditResourceId, 'Invalid document type', 'failed', `Invalid docType: ${docType}`, req);
    return res.status(422).json({ success: false, message: `Invalid document type. Allowed: ${Object.keys(DOC_FIELD_MAP).join(', ')}` });
  }
  if (!allowedStatuses.includes(safeStatus)) {
    await logAuditAction(req.superadmin.id, auditAction, 'document', auditResourceId, 'Invalid status', 'failed', `Invalid status: ${status}`, req);
    return res.status(422).json({ success: false, message: 'Invalid status' });
  }

  const fields = DOC_FIELD_MAP[safeDocType];

  try {
    // Fetch the current row first — we need every per-document status
    // column to recompute the overall bundle status after this update,
    // and .update().select() only reliably returns the columns we set.
    const { data: existing, error: fetchError } = await supabase
      .from('agent_documents')
      .select('*')
      .eq('id', docId)
      .single();

    if (fetchError || !existing) {
      await logAuditAction(req.superadmin.id, auditAction, 'document', auditResourceId, 'Document not found', 'failed', fetchError?.message || 'No matching row', req);
      return res.status(404).json({ success: false, message: 'Document not found' });
    }

    let uploaded = Boolean(existing[fields.urlCol]);
    if (!uploaded) {
      const r2Urls = await getAgentDocumentUrls(existing.user_id);
      if (safeDocType === 'office_photo') {
        uploaded = Array.isArray(r2Urls.office_photo) && r2Urls.office_photo.length > 0;
      } else if (r2Urls[safeDocType]) {
        uploaded = Boolean(r2Urls[safeDocType].publicUrl || r2Urls[safeDocType].path);
      }
    }

    if (!uploaded) {
      await logAuditAction(req.superadmin.id, auditAction, 'document', auditResourceId, `No ${safeDocType} file uploaded`, 'failed', 'Cannot verify a document that was not uploaded', req);
      return res.status(422).json({ success: false, message: `Agent has not uploaded a ${safeDocType.replace('_', ' ')} document yet` });
    }

    const itemUpdate = {
      [fields.statusCol]:     safeStatus,
      [fields.notesCol]:      sanitizeInput(notes || ''),
      [fields.reviewedAtCol]: new Date().toISOString(),
      // Clear any pending review request for this bundle — the admin is
      // actively reviewing right now, so the "waiting for review" flag
      // is stale the moment any item gets a decision.
      review_requested_at: null,
    };

    const { error: updateError } = await supabase
      .from('agent_documents')
      .update(itemUpdate)
      .eq('id', docId);

    if (updateError) {
      await logAuditAction(req.superadmin.id, auditAction, 'document', auditResourceId, `${safeDocType} update failed`, 'failed', updateError.message, req);
      throw updateError;
    }

    // Re-fetch the full row rather than relying on .update().select('*') —
    // the update return can have RLS-truncated columns if any column-level
    // policy restricts the service role, which causes recomputeOverallStatus
    // to see null statuses and compute 'pending' even when all docs are approved.
    const { data: freshRow, error: freshErr } = await supabase
      .from('agent_documents')
      .select('*')
      .eq('id', docId)
      .single();

    if (freshErr || !freshRow) {
      await logAuditAction(req.superadmin.id, auditAction, 'document', auditResourceId, `${safeDocType} re-fetch failed`, 'failed', freshErr?.message || 'Row disappeared after update', req);
      throw freshErr ?? new Error('Row disappeared after update');
    }

    const overall = await recomputeOverallStatus(freshRow, req.superadmin.id);

    await logAuditAction(
      req.superadmin.id, auditAction, 'document', auditResourceId,
      `${safeDocType} → ${safeStatus}${notes ? ` (${notes})` : ''}; overall bundle now ${overall}`,
      'success', '', req,
    );

    return res.json({
      success: true,
      message: `${safeDocType.replace('_', ' ')} marked ${safeStatus}`,
      data: { docType: safeDocType, status: safeStatus, overallStatus: overall },
    });
  } catch (err) {
    console.error('Per-document verify error:', err);
    await logAuditAction(req.superadmin.id, auditAction, 'document', auditResourceId, `${safeDocType} verification failed`, 'failed', err.message || 'Unknown error', req);
    return res.status(500).json({ success: false, message: err?.message || 'Failed to verify document' });
  }
});

// POST /documents/:docId/verify
// LEGACY / CONVENIENCE: approves or rejects every uploaded document in the
// bundle at once, rather than item-by-item. Kept for bulk actions, but the
// dashboard's primary flow is now verify-item above.
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
    // Fetch first so we only stamp a per-document status column for
    // documents the agent actually uploaded (an unset doc stays 'pending',
    // it doesn't get force-approved just because the bundle action was 'approved').
    const { data: existing, error: fetchError } = await supabase
      .from('agent_documents')
      .select('*')
      .eq('id', docId)
      .single();

    if (fetchError || !existing) {
      await logAuditAction(req.superadmin.id, auditAction, 'document', auditResourceId, 'Document not found', 'failed', fetchError?.message || 'No matching row', req);
      return res.status(404).json({ success: false, message: 'Document not found' });
    }

    const nowIso = new Date().toISOString();
    const updatePayload = {
      status: safeStatus,
      review_notes: sanitizeInput(notes || ''),
      reviewed_by: req.superadmin.id,
      reviewed_at: nowIso,
      review_requested_at: null,
    };
    // Stamp every uploaded document's individual status to match the bulk
    // decision, so verify-item and verify never disagree on the same row.
    for (const key of Object.keys(DOC_FIELD_MAP)) {
      const { urlCol, statusCol, reviewedAtCol } = DOC_FIELD_MAP[key];
      if (existing[urlCol]) {
        updatePayload[statusCol] = safeStatus;
        updatePayload[reviewedAtCol] = nowIso;
      }
    }

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
    const limit  = Math.min(Number(req.query.limit  ?? 200), 1000);
    const offset = Number(req.query.offset ?? 0);
    const status = req.query.status ?? 'all';
    const from   = req.query.from;
    const to     = req.query.to;
    const DEFAULT_PROFIT_PERCENTAGE = Number(process.env.PLATFORM_PROFIT_PERCENTAGE ?? 10);

    // NOTE: payments.user_id → auth.users(id), NOT public.profiles.
    // PostgREST cannot resolve a direct join from payments to profiles.
    // Fetch client profiles in a separate query using the collected user_ids.
    let query = supabase
      .from('payments')
      .select(`
        id, user_id, package_id, amount_kes, status, phone, mpesa_ref,
        paid_at, created_at, disbursed, disbursed_at, disbursed_by, receipt_generated,
        package:packages(id, name, price, profit_percentage, created_by,
          agent:profiles!packages_created_by_fkey(id, first_name, last_name, email, agent_number))
      `)
      .eq('status', 'SUCCESS')
      .order('paid_at', { ascending: false })
      .range(offset, offset + limit - 1);

    if (status === 'pending')   query = query.eq('disbursed', false);
    if (status === 'disbursed') query = query.eq('disbursed', true);
    if (from) query = query.gte('paid_at', new Date(from).toISOString());
    if (to)   query = query.lte('paid_at', new Date(to + 'T23:59:59').toISOString());

    const { data: payments, error } = await query;
    if (error) throw error;

    // Fetch client profiles separately (no direct FK from payments → profiles)
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
      const amount     = Number(p.amount_kes ?? 0);
      const pct        = Number(p.package?.profit_percentage ?? DEFAULT_PROFIT_PERCENTAGE);
      const profit     = Math.round((amount * pct) / 100 * 100) / 100;
      const agentShare = Math.round((amount - profit) * 100) / 100;
      const agent      = p.package?.agent;
      const client     = clientMap.get(p.user_id) ?? null;
      return {
        id:               p.id,
        packageId:        p.package_id,
        packageName:      p.package?.name ?? '\u2014',
        clientId:         p.user_id,
        clientName:       client ? `${client.first_name} ${client.last_name}`.trim() : null,
        clientEmail:      client?.email ?? null,
        agentId:          agent?.id ?? null,
        agentName:        agent  ? `${agent.first_name} ${agent.last_name}`.trim()  : null,
        agentEmail:       agent?.email ?? null,
        agentNumber:      agent?.agent_number ?? null,
        amount, percentage: pct, profit, agentShare,
        mpesaRef:         p.mpesa_ref ?? null,
        paidAt:           p.paid_at,
        disbursed:        !!p.disbursed,
        disbursedAt:      p.disbursed_at ?? null,
        disbursedBy:      p.disbursed_by ?? null,
        receiptGenerated: !!p.receipt_generated,
        createdAt:        p.created_at,
      };
    });

    res.json({ success: true, data: results, total: results.length });
  } catch (err) {
    console.error('[accounting] Transactions error:', err);
    res.status(500).json({ success: false, message: 'Failed to fetch transactions' });
  }
});

router.post('/accounting/transactions/:id/disburse', authenticateSuperadmin, async (req, res) => {
  const { id } = req.params;
  if (!id) return res.status(422).json({ success: false, message: 'Invalid transaction id' });
  try {
    const { data: payment, error: fetchErr } = await supabase
      .from('payments')
      .select('id, status, disbursed, amount_kes, package:packages(name, profit_percentage)')
      .eq('id', id)
      .single();
    if (fetchErr || !payment) return res.status(404).json({ success: false, message: 'Transaction not found' });
    if (payment.status !== 'SUCCESS') return res.status(422).json({ success: false, message: 'Payment is not successful' });
    if (payment.disbursed) return res.status(409).json({ success: false, message: 'Already disbursed' });

    const { error: updateErr } = await supabase
      .from('payments')
      .update({ disbursed: true, disbursed_at: new Date().toISOString(), disbursed_by: String(req.superadmin.id) })
      .eq('id', id).eq('disbursed', false);
    if (updateErr) throw updateErr;

    const DEFAULT_PROFIT_PERCENTAGE = Number(process.env.PLATFORM_PROFIT_PERCENTAGE ?? 10);
    const amount     = Number(payment.amount_kes ?? 0);
    const pct        = Number(payment.package?.profit_percentage ?? DEFAULT_PROFIT_PERCENTAGE);
    const agentShare = amount - (amount * pct) / 100;

    await logAuditAction(req.superadmin.id, 'DISBURSE_TRANSACTION', 'transaction', id,
      `Disbursed KES ${agentShare.toLocaleString()} to agent`, 'success', '', req);
    res.json({ success: true, message: 'Transaction marked as disbursed', data: { id, disbursedAt: new Date().toISOString(), agentShare } });
  } catch (err) {
    console.error('[accounting] Disburse error:', err);
    res.status(500).json({ success: false, message: 'Failed to mark as disbursed' });
  }
});

router.get('/accounting/transactions/:id/receipt', authenticateSuperadmin, async (req, res) => {
  const { id } = req.params;
  const inline  = req.query.inline === '1';
  if (!id) return res.status(422).json({ success: false, message: 'Missing transaction id' });
  try {
    const { data: payment, error: fetchErr } = await supabase
      .from('payments')
      .select(`
        id, amount_kes, status, paid_at, disbursed, disbursed_at, mpesa_ref,
        package:packages(id, name, profit_percentage,
          agent:profiles!packages_created_by_fkey(first_name, last_name, email, agent_number)),
        client:profiles(first_name, last_name, email)
      `)
      .eq('id', id).single();
    if (fetchErr || !payment) return res.status(404).json({ success: false, message: 'Transaction not found' });

    const DEFAULT_PROFIT_PERCENTAGE = Number(process.env.PLATFORM_PROFIT_PERCENTAGE ?? 10);
    const amount     = Number(payment.amount_kes ?? 0);
    const pct        = Number(payment.package?.profit_percentage ?? DEFAULT_PROFIT_PERCENTAGE);
    const profit     = Math.round((amount * pct) / 100 * 100) / 100;
    const agentShare = amount - profit;
    const agentProfile  = payment.package?.agent;
    const clientProfile = payment.client;
    const agentName     = agentProfile  ? `${agentProfile.first_name} ${agentProfile.last_name}`.trim()  : '\u2014';
    const clientName    = clientProfile ? `${clientProfile.first_name} ${clientProfile.last_name}`.trim() : '\u2014';

    const doc = new PDFDocument({ size: 'A4', margin: 60, bufferPages: true });
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `${inline ? 'inline' : 'attachment'}; filename="receipt-${id}.pdf"`);
    doc.pipe(res);

    doc.rect(0, 0, doc.page.width, 100).fill('#0F172A');
    doc.fill('#FFFFFF').fontSize(22).font('Helvetica-Bold').text('UMRAH MARKET', 60, 30);
    doc.fontSize(9).font('Helvetica').fill('#94A3B8').text('Official Agent Disbursement Receipt', 60, 58);
    doc.fill('#FFFFFF').fontSize(9)
      .text(`Receipt #${id.slice(0,8).toUpperCase()}`, doc.page.width - 180, 35, { width: 120, align: 'right' })
      .text(new Date().toLocaleDateString('en-KE', { day: '2-digit', month: 'long', year: 'numeric' }), doc.page.width - 180, 52, { width: 120, align: 'right' });

    const bannerColor = payment.disbursed ? '#DCFCE7' : '#FEF3C7';
    const bannerText  = payment.disbursed
      ? `Funds Disbursed on ${payment.disbursed_at ? new Date(payment.disbursed_at).toLocaleDateString('en-KE') : '\u2014'}`
      : 'Disbursement Pending - Agent Has NOT Yet Received Funds';
    doc.rect(60, 115, doc.page.width - 120, 32).fill(bannerColor);
    doc.fontSize(9).font('Helvetica-Bold').fill(payment.disbursed ? '#166534' : '#92400E')
      .text(bannerText, 72, 124, { width: doc.page.width - 144 });

    const col1 = 60, col2 = doc.page.width / 2 + 20;
    let y = 168;
    const field = (label, value, x, yPos) => {
      doc.fontSize(8).font('Helvetica').fill('#64748B').text(label, x, yPos);
      doc.fontSize(9).font('Helvetica-Bold').fill('#0F172A').text(String(value ?? '\u2014'), x, yPos + 13, { width: 185 });
      return yPos + 32;
    };
    doc.fontSize(7).font('Helvetica-Bold').fill('#64748B').text('CLIENT DETAILS', col1, y, { characterSpacing: 0.8 });
    doc.moveTo(col1, y + 12).lineTo(col1 + 180, y + 12).stroke('#E2E8F0');
    let y1 = y + 18;
    y1 = field('Full Name', clientName, col1, y1);
    y1 = field('Email', clientProfile?.email ?? '\u2014', col1, y1);
    y1 = field('Package', payment.package?.name ?? '\u2014', col1, y1);

    doc.fontSize(7).font('Helvetica-Bold').fill('#64748B').text('AGENT DETAILS', col2, y, { characterSpacing: 0.8 });
    doc.moveTo(col2, y + 12).lineTo(col2 + 180, y + 12).stroke('#E2E8F0');
    let y2 = y + 18;
    y2 = field('Full Name', agentName, col2, y2);
    y2 = field('Email', agentProfile?.email ?? '\u2014', col2, y2);
    y2 = field('Agent No.', agentProfile?.agent_number ?? '\u2014', col2, y2);

    const tableTop = Math.max(y1, y2) + 20;
    doc.rect(col1, tableTop, doc.page.width - 120, 22).fill('#F8FAFC');
    doc.fontSize(8).font('Helvetica-Bold').fill('#475569').text('FINANCIAL BREAKDOWN', col1 + 8, tableTop + 7);
    const rows = [
      { label: 'Package Revenue (Client Paid)', value: `KES ${amount.toLocaleString('en-KE', { minimumFractionDigits: 2 })}`,     bold: false },
      { label: `Platform Fee (${pct}%)`,         value: `KES ${profit.toLocaleString('en-KE',  { minimumFractionDigits: 2 })}`,     bold: false },
      { label: 'Agent Disbursement',             value: `KES ${agentShare.toLocaleString('en-KE', { minimumFractionDigits: 2 })}`, bold: true  },
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
      .text(`Payment Date: ${payment.paid_at ? new Date(payment.paid_at).toLocaleString('en-KE') : '\u2014'}`, col1, ry)
      .text(`M-Pesa Ref: ${payment.mpesa_ref ?? '\u2014'}`, col1, ry + 14)
      .text(`Transaction ID: ${id}`, col1, ry + 28);

    const footerY = doc.page.height - 70;
    doc.moveTo(60, footerY).lineTo(doc.page.width - 60, footerY).stroke('#E2E8F0');
    doc.fontSize(7.5).font('Helvetica').fill('#94A3B8')
      .text('This receipt is system-generated by Umrah Market and does not require a signature.', 60, footerY + 8, { align: 'center', width: doc.page.width - 120 })
      .text(`Generated by Superadmin on ${new Date().toLocaleString('en-KE')}`, 60, footerY + 22, { align: 'center', width: doc.page.width - 120 });
    doc.end();

    supabase.from('payments').update({ receipt_generated: true }).eq('id', id).then(() => {}).catch(() => {});
    await logAuditAction(req.superadmin.id, 'GENERATE_RECEIPT', 'transaction', id, `Receipt ${inline ? 'previewed' : 'downloaded'}`, 'success', '', req);
  } catch (err) {
    console.error('[accounting] Receipt error:', err);
    if (!res.headersSent) res.status(500).json({ success: false, message: 'Failed to generate receipt' });
  }
});

router.post('/accounting/transactions/:id/email', authenticateSuperadmin, async (req, res) => {
  const { id } = req.params;
  if (!id) return res.status(422).json({ success: false, message: 'Missing transaction id' });
  if (!process.env.SMTP_HOST || !process.env.SMTP_USER || !process.env.SMTP_PASS)
    return res.status(501).json({ success: false, message: 'Email service not configured on this server' });
  try {
    const { data: payment, error: fetchErr } = await supabase
      .from('payments')
      .select(`
        id, amount_kes, status, paid_at, disbursed, mpesa_ref,
        package:packages(name, profit_percentage,
          agent:profiles!packages_created_by_fkey(first_name, last_name, email)),
        client:profiles(first_name, last_name, email)
      `)
      .eq('id', id).single();
    if (fetchErr || !payment) return res.status(404).json({ success: false, message: 'Transaction not found' });

    const recipient = (req.body.email || payment.package?.agent?.email || payment.client?.email || '').trim();
    if (!recipient || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(recipient))
      return res.status(422).json({ success: false, message: 'No valid recipient email provided' });

    const DEFAULT_PROFIT_PERCENTAGE = Number(process.env.PLATFORM_PROFIT_PERCENTAGE ?? 10);
    const pdfBuffer = await new Promise((resolve, reject) => {
      const doc = new PDFDocument({ size: 'A4', margin: 60 });
      const chunks = [];
      doc.on('data', c => chunks.push(c));
      doc.on('end',  () => resolve(Buffer.concat(chunks)));
      doc.on('error', reject);
      const amount     = Number(payment.amount_kes ?? 0);
      const pct        = Number(payment.package?.profit_percentage ?? DEFAULT_PROFIT_PERCENTAGE);
      const profit     = (amount * pct) / 100;
      const agentShare = amount - profit;
      const clientName = payment.client       ? `${payment.client.first_name} ${payment.client.last_name}`.trim()               : '\u2014';
      const agentName  = payment.package?.agent ? `${payment.package.agent.first_name} ${payment.package.agent.last_name}`.trim() : '\u2014';
      doc.rect(0, 0, doc.page.width, 100).fill('#0F172A');
      doc.fill('#FFFFFF').fontSize(22).font('Helvetica-Bold').text('UMRAH MARKET', 60, 30);
      doc.fontSize(9).font('Helvetica').fill('#94A3B8').text('Agent Disbursement Receipt', 60, 58);
      doc.fill('#000000').fontSize(11).font('Helvetica').moveDown(6);
      doc.text(`Receipt ID:   ${id.slice(0,8).toUpperCase()}`, 60, 120);
      doc.text(`Package:      ${payment.package?.name ?? '\u2014'}`, 60, 140);
      doc.text(`Client:       ${clientName}`, 60, 160);
      doc.text(`Agent:        ${agentName}`, 60, 180);
      doc.text(`Payment Date: ${payment.paid_at ? new Date(payment.paid_at).toLocaleDateString('en-KE') : '\u2014'}`, 60, 200);
      doc.moveTo(60, 230).lineTo(535, 230).stroke('#E2E8F0');
      doc.text(`Revenue:           KES ${amount.toLocaleString('en-KE', { minimumFractionDigits: 2 })}`, 60, 245);
      doc.text(`Platform Fee(${pct}%): KES ${profit.toLocaleString('en-KE',  { minimumFractionDigits: 2 })}`, 60, 265);
      doc.font('Helvetica-Bold').text(`Agent Disbursement: KES ${agentShare.toLocaleString('en-KE', { minimumFractionDigits: 2 })}`, 60, 285);
      doc.font('Helvetica').fontSize(9).fill('#64748B')
        .text(payment.disbursed ? 'Funds have been disbursed to this agent.' : 'Disbursement is still pending.', 60, 320);
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
      subject: `Umrah Market - Receipt for Transaction ${id.slice(0,8).toUpperCase()}`,
      text: `Dear ${recipient},\n\nPlease find attached your receipt for transaction ${id.slice(0,8).toUpperCase()}.\n\nThank you for partnering with Umrah Market.`,
      attachments: [{ filename: `receipt-${id.slice(0,8)}.pdf`, content: pdfBuffer }],
    });

    await supabase.from('payments').update({ receipt_generated: true }).eq('id', id);
    await logAuditAction(req.superadmin.id, 'EMAIL_RECEIPT', 'transaction', id, `Emailed to ${recipient}`, 'success', '', req);
    res.json({ success: true, message: `Receipt emailed to ${recipient}` });
  } catch (err) {
    console.error('[accounting] Email receipt error:', err);
    res.status(500).json({ success: false, message: 'Failed to send receipt email' });
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

router.use('/accounting', accountingRouter);
export default router;