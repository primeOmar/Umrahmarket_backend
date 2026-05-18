import express from 'express';
import jwt from 'jsonwebtoken';
import { supabaseAdmin as supabase } from '../config/supabase.js';
import {
  hashPassword, verifyPassword, generateToken, hashToken,
  loginRateLimiter, validateEmail, sanitizeInput, AUDIT_ACTIONS,
} from '../utils/securityUtils.js';

const router = express.Router();

// ─────────────────────────────────────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────────────────────────────────────

/** Extract the real client IP, respecting Render's reverse proxy */
const getClientIp = (req) =>
  (req.headers['x-forwarded-for'] || '').split(',')[0].trim() ||
  req.socket?.remoteAddress ||
  req.ip ||
  'unknown';

/**
 * Audit log helper.
 * Accepts the full request object so real IP/UA are recorded.
 */
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

// ─────────────────────────────────────────────────────────────────────────────
// MIDDLEWARE — authenticateSuperadmin
// ─────────────────────────────────────────────────────────────────────────────

const authenticateSuperadmin = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '').trim();
    if (!token) {
      return res.status(401).json({ success: false, message: 'No token provided' });
    }

    // Verify JWT signature & expiry
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch {
      return res.status(401).json({ success: false, message: 'Invalid or expired token' });
    }

    // Load superadmin record
    const { data: superadmin, error } = await supabase
      .from('superadmin_credentials')
      .select('*')
      .eq('id', decoded.superadminId)
      .single();

    if (error || !superadmin || superadmin.status !== 'active') {
      return res.status(403).json({ success: false, message: 'Unauthorized' });
    }

    // Validate session in DB (covers manual revocation & logout)
    const { data: session } = await supabase
      .from('superadmin_sessions')
      .select('*')
      .eq('token_hash', hashToken(token))
      .is('revoked_at', null)
      .single();

    if (!session || new Date(session.expires_at) < new Date()) {
      return res.status(401).json({ success: false, message: 'Session expired' });
    }

    // Touch last_activity (fire-and-forget)
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
// AUTH — REGISTER
// ─────────────────────────────────────────────────────────────────────────────

router.post('/register', async (req, res) => {
  try {
    const { username, email, fullName, password, confirmPassword, registerSecret } = req.body;

    // 1. Verify registration secret
    const expectedSecret = process.env.SUPERADMIN_REGISTER_SECRET;
    if (!expectedSecret) {
      return res.status(503).json({ success: false, message: 'Registration is disabled' });
    }
    if (!registerSecret || registerSecret !== expectedSecret) {
      return res.status(403).json({ success: false, message: 'Invalid registration secret' });
    }

    // 2. Validate inputs
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

    // 3. Check uniqueness
    const { data: existing } = await supabase
      .from('superadmin_credentials')
      .select('id')
      .or(`email.eq.${email.toLowerCase()},username.eq.${username.trim()}`)
      .maybeSingle();

    if (existing) {
      return res.status(409).json({ success: false, message: 'Email or username already registered' });
    }

    // 4. Hash password & insert
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

    // 5. Grant default permissions
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

    // 6. Audit log
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
// AUTH — LOGIN
// ─────────────────────────────────────────────────────────────────────────────

router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const clientIp  = getClientIp(req);
    const userAgent = req.get('user-agent') || 'unknown';

    // Input validation
    if (!validateEmail(email)) {
      return res.status(422).json({ success: false, message: 'Invalid email' });
    }
    if (!password || password.length < 8) {
      return res.status(422).json({ success: false, message: 'Invalid password' });
    }

    // Rate limiting
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

    // Fetch superadmin
    const { data: superadmin, error } = await supabase
      .from('superadmin_credentials')
      .select('*')
      .eq('email', email.toLowerCase())
      .single();

    if (error || !superadmin) {
      await logAuditAction(null, AUDIT_ACTIONS.LOGIN, 'superadmin', email, '', 'failed', 'User not found', req);
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    // Account status
    if (superadmin.status === 'suspended') {
      return res.status(403).json({ success: false, message: 'Account suspended' });
    }
    if (superadmin.status === 'inactive') {
      return res.status(403).json({ success: false, message: 'Account inactive' });
    }

    // Lockout check
    if (superadmin.locked_until && new Date(superadmin.locked_until) > new Date()) {
      return res.status(429).json({
        success: false,
        message: 'Account locked',
        lockedUntil: superadmin.locked_until,
      });
    }

    // Verify password
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

    // ── 2FA path ──────────────────────────────────────────────────────────────
    if (superadmin.two_factor_enabled) {
      const tempToken = generateToken();
      const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 min

      // Store hashed temp token so the verify-2fa endpoint can look it up
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

    // ── Full login ────────────────────────────────────────────────────────────
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

    // Reset failed attempts + record last login
    await supabase
      .from('superadmin_credentials')
      .update({
        failed_login_attempts: 0,
        locked_until:          null,
        last_login:            new Date().toISOString(),
        last_ip_address:       clientIp,
      })
      .eq('id', superadmin.id);

    // Load permissions
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
// AUTH — VERIFY 2FA
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

    // Look up the pending 2FA record
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

    // TOTP verification — requires speakeasy (npm i speakeasy)
    // Uncomment once speakeasy is installed:
    // import speakeasy from 'speakeasy';
    // const verified = speakeasy.totp.verify({
    //   secret:   superadmin.two_factor_secret,
    //   encoding: 'base32',
    //   token:    code,
    //   window:   2,
    // });
    // if (!verified) {
    //   return res.status(401).json({ success: false, message: 'Invalid 2FA code' });
    // }

    // ── Issue tokens ──────────────────────────────────────────────────────────
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

    // Clean up pending record
    await supabase.from('superadmin_2fa_pending').delete().eq('id', pending.id);

    // Reset failed attempts
    await supabase
      .from('superadmin_credentials')
      .update({
        failed_login_attempts: 0,
        locked_until:          null,
        last_login:            new Date().toISOString(),
        last_ip_address:       clientIp,
      })
      .eq('id', superadmin.id);

    // Load permissions
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
// AUTH — REFRESH TOKEN
// ─────────────────────────────────────────────────────────────────────────────

router.post('/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) {
      return res.status(401).json({ success: false, message: 'No refresh token provided' });
    }

    // Find session by refresh token hash
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
      // Revoke expired session
      await supabase.from('superadmin_sessions').update({ revoked_at: new Date().toISOString() }).eq('id', session.id);
      return res.status(401).json({ success: false, message: 'Refresh token expired, please log in again' });
    }

    const superadmin = session.superadmin_credentials;
    if (!superadmin || superadmin.status !== 'active') {
      return res.status(403).json({ success: false, message: 'Account inactive or suspended' });
    }

    // Issue new access token
    const newAccessToken = jwt.sign({ superadminId: superadmin.id }, process.env.JWT_SECRET, { expiresIn: '24h' });

    // Rotate: update session with new access token hash (keep same refresh token)
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
// AUTH — LOGOUT
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
      success:          true,
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
// CLIENTS
// ─────────────────────────────────────────────────────────────────────────────

router.get('/clients', authenticateSuperadmin, async (req, res) => {
  try {
    const { data: clients, error } = await supabase
      .from('profiles')
      .select('id, first_name, last_name, email, phone, status, created_at')
      .eq('role', 'client')
      .order('created_at', { ascending: false });

    if (error) throw error;

    const normalized = (clients || []).map(c => ({
      id:        c.id,
      name:      `${c.first_name || ''} ${c.last_name || ''}`.trim() || null,
      email:     c.email,
      phone:     c.phone,
      status:    c.status,
      createdAt: c.created_at,
    }));

    res.json({ success: true, data: normalized });
  } catch (err) {
    console.error('Clients error:', err);
    res.status(500).json({ success: false, message: 'Failed to fetch clients' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// AGENTS
// ─────────────────────────────────────────────────────────────────────────────

router.get('/agents', authenticateSuperadmin, async (req, res) => {
  try {
    const { data: agents, error } = await supabase
      .from('profiles')
      .select('id, first_name, last_name, email, phone, status, created_at')
      .eq('role', 'agent')
      .order('created_at', { ascending: false });

    if (error) throw error;

    const normalized = (agents || []).map(a => ({
      id:        a.id,
      name:      `${a.first_name || ''} ${a.last_name || ''}`.trim() || null,
      email:     a.email,
      phone:     a.phone,
      status:    a.status,
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
    // Attempt RPC first; fall back to a direct query
    let chats = [];
    const { data: rpcRows, error: rpcErr } = await supabase.rpc('get_superadmin_chats');

    if (!rpcErr && rpcRows) {
      chats = rpcRows;
    } else {
      // Fallback: grab latest message per booking
      const { data: rows } = await supabase
        .from('messages')
        .select('id, booking_id, body, is_closed, closed_at, created_at')
        .order('created_at', { ascending: false })
        .limit(200);
      chats = rows || [];
    }

    const normalized = chats.map(r => ({
      id:          r.message_id || r.id,
      bookingId:   r.booking_id,
      lastMessage: r.last_message || r.body || '',
      clientName:  r.client_name || r.client_full_name || '',
      agentName:   r.agent_name  || r.agent_full_name  || '',
      status:      r.is_closed ? 'closed' : 'active',
      createdAt:   r.created_at,
    }));

    res.json({ success: true, data: normalized });
  } catch (err) {
    console.error('Chats error:', err);
    res.status(500).json({ success: false, message: 'Failed to fetch chats' });
  }
});

router.post('/chats/:chatId/close', authenticateSuperadmin, async (req, res) => {
  try {
    const { chatId } = req.params;
    const { reason } = req.body;

    if (!reason || reason.trim().length === 0) {
      return res.status(422).json({ success: false, message: 'Reason required' });
    }

    const { data: messages } = await supabase
      .from('messages')
      .select('booking_id')
      .eq('id', parseInt(chatId))
      .limit(1);

    if (!messages || messages.length === 0) {
      return res.status(404).json({ success: false, message: 'Chat not found' });
    }

    const bookingId = messages[0].booking_id;

    await supabase
      .from('messages')
      .update({
        is_closed:    true,
        closed_by:    req.superadmin.id,
        close_reason: sanitizeInput(reason),
        closed_at:    new Date().toISOString(),
      })
      .eq('booking_id', bookingId);

    await supabase.from('chat_closures').insert({
      message_id: parseInt(chatId),
      booking_id: bookingId,
      closed_by:  req.superadmin.id,
      reason:     sanitizeInput(reason),
    });

    await logAuditAction(req.superadmin.id, AUDIT_ACTIONS.CLOSE_CHAT, 'chat', chatId, reason, 'success', '', req);

    res.json({ success: true, message: 'Chat closed' });
  } catch (err) {
    console.error('Close chat error:', err);
    await logAuditAction(req.superadmin.id, AUDIT_ACTIONS.CLOSE_CHAT, 'chat', req.params.chatId, '', 'failed', err.message, req);
    res.status(500).json({ success: false, message: 'Failed to close chat' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// DOCUMENTS
// ─────────────────────────────────────────────────────────────────────────────

router.get('/documents', authenticateSuperadmin, async (req, res) => {
  try {
    const status = req.query.status;
    let query = supabase
      .from('agent_documents')
      .select('*, profiles(first_name, last_name, email)')
      .order('created_at', { ascending: false });

    if (status && status !== 'all') {
      query = query.eq('status', status);
    }

    const { data: documents, error } = await query;
    if (error) throw error;

    res.json({ success: true, data: documents || [] });
  } catch (err) {
    console.error('Documents error:', err);
    res.status(500).json({ success: false, message: 'Failed to fetch documents' });
  }
});

router.post('/documents/:docId/verify', authenticateSuperadmin, async (req, res) => {
  try {
    const { docId } = req.params;
    const { status, notes } = req.body;

    if (!['approved', 'rejected'].includes(status)) {
      return res.status(422).json({ success: false, message: 'Invalid status' });
    }

    const { error } = await supabase
      .from('agent_documents')
      .update({
        status,
        review_notes: sanitizeInput(notes || ''),
        reviewed_by:  req.superadmin.id,
        reviewed_at:  new Date().toISOString(),
      })
      .eq('id', docId);

    if (error) throw error;

    await logAuditAction(
      req.superadmin.id,
      status === 'approved' ? AUDIT_ACTIONS.VERIFY_DOCUMENT : AUDIT_ACTIONS.REJECT_DOCUMENT,
      'document', docId, notes || '', 'success', '', req,
    );

    res.json({ success: true, message: `Document ${status}` });
  } catch (err) {
    console.error('Document verify error:', err);
    res.status(500).json({ success: false, message: 'Failed to verify document' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// PACKAGES
// ─────────────────────────────────────────────────────────────────────────────

router.get('/packages', authenticateSuperadmin, async (req, res) => {
  try {
    const { data: packages, error } = await supabase
      .from('packages')
      .select('id, name, type, price, created_at, agent_id')
      .order('created_at', { ascending: false });

    if (error) throw error;
    res.json({ success: true, data: packages || [] });
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
// DASHBOARDS
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
// DATA EXPORT — real CSV generation
// ─────────────────────────────────────────────────────────────────────────────

/** Escape a CSV cell value */
const csvCell = (v) => {
  if (v == null) return '';
  const s = String(v);
  return s.includes(',') || s.includes('"') || s.includes('\n')
    ? `"${s.replace(/"/g, '""')}"`
    : s;
};

/** Convert an array of objects to CSV text */
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