/**
 * SUPERADMIN BACKEND IMPLEMENTATION EXAMPLE
 * Node.js/Express
 * This is a reference implementation - adapt to your framework
 */

import express from 'express';
import jwt from 'jsonwebtoken';
import { supabaseAdmin as supabase } from '../config/supabase.js';
import {
  hashPassword, verifyPassword, generateToken, hashToken,
  loginRateLimiter, validateEmail, sanitizeInput, AUDIT_ACTIONS
} from '../utils/securityUtils.js';

const router = express.Router();

// ==================== MIDDLEWARE ====================

/**
 * Superadmin Authentication Middleware
 */
const authenticateSuperadmin = async (req, res, next) => {
  try {
    // DEV MODE: Bypass auth for testing (REMOVE IN PRODUCTION)
    if (process.env.NODE_ENV === 'development' && req.headers['x-dev-bypass'] === 'true') {
      console.warn('⚠️  DEV MODE: Auth bypassed. Remove in production!');
      req.superadmin = { id: 'dev-admin-123', username: 'dev-admin', email: 'dev@test.com' };
      req.session = { id: 'dev-session-123' };
      return next();
    }

    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) {
      return res.status(401).json({ success: false, message: 'No token provided' });
    }

    // Verify JWT
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Load superadmin from database
    const { data: superadmin, error } = await supabase
      .from('superadmin_credentials')
      .select('*')
      .eq('id', decoded.superadminId)
      .single();

    if (error || !superadmin || superadmin.status !== 'active') {
      return res.status(403).json({ success: false, message: 'Unauthorized' });
    }

    // Check session validity
    const { data: session } = await supabase
      .from('superadmin_sessions')
      .select('*')
      .eq('token_hash', hashToken(token))
      .eq('revoked_at', null)
      .single();

    if (!session || new Date(session.expires_at) < new Date()) {
      return res.status(401).json({ success: false, message: 'Session expired' });
    }

    // Update last activity
    await supabase
      .from('superadmin_sessions')
      .update({ last_activity: new Date().toISOString() })
      .eq('id', session.id);

    req.superadmin = superadmin;
    req.session = session;
    next();
  } catch (err) {
    console.error('Auth error:', err);
    res.status(401).json({ success: false, message: 'Authentication failed' });
  }
};

/**
 * Audit Logging Helper
 */
const logAuditAction = async (superadminId, action, resourceType, resourceId, reason = '', status = 'success', error = '') => {
  try {
    await supabase.from('superadmin_audit_logs').insert({
      superadmin_id: superadminId,
      action,
      resource_type: resourceType,
      resource_id: resourceId,
      reason,
      status,
      error_message: error,
      ip_address: 'get_from_request',
      user_agent: 'get_from_request',
    });
  } catch (err) {
    console.error('Failed to log audit action:', err);
  }
};

// ==================== AUTHENTICATION ENDPOINTS ====================
router.post('/register', async (req, res) => {
  try {
    const { username, email, fullName, password, confirmPassword, registerSecret } = req.body;
 
    // ── 1. Verify registration secret ──────────────────────────────────────
    const expectedSecret = process.env.SUPERADMIN_REGISTER_SECRET;
    if (!expectedSecret) {
      return res.status(503).json({ success: false, message: 'Registration is disabled' });
    }
    if (!registerSecret || registerSecret !== expectedSecret) {
      return res.status(403).json({ success: false, message: 'Invalid registration secret' });
    }
 
    // ── 2. Validate inputs ─────────────────────────────────────────────────
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
    // Basic strength check
    const strongPassword = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{8,}$/.test(password);
    if (!strongPassword) {
      return res.status(422).json({
        success: false,
        message: 'Password must contain uppercase, lowercase, number and special character',
      });
    }
 
    // ── 3. Check uniqueness ────────────────────────────────────────────────
    const { data: existing } = await supabase
      .from('superadmin_credentials')
      .select('id')
      .or(`email.eq.${email.toLowerCase()},username.eq.${username.trim()}`)
      .maybeSingle();
 
    if (existing) {
      return res.status(409).json({ success: false, message: 'Email or username already registered' });
    }
 
    // ── 4. Hash password & insert ──────────────────────────────────────────
    const passwordHash = hashPassword(password);
 
    const { data: newAdmin, error } = await supabase
      .from('superadmin_credentials')
      .insert({
        username:   sanitizeInput(username.trim()),
        email:      email.trim().toLowerCase(),
        full_name:  sanitizeInput(fullName?.trim() || ''),
        password_hash: passwordHash,
        status:     'active',
        two_factor_enabled: false,
      })
      .select('id, username, email, full_name')
      .single();
 
    if (error) throw error;
 
    // ── 5. Grant all default permissions ──────────────────────────────────
    const defaultPermissions = [
      'view_agents', 'manage_agents',
      'view_clients', 'manage_clients',
      'view_chats', 'close_chats',
      'view_documents', 'verify_documents',
      'view_packages', 'delete_packages',
      'view_audit_logs', 'export_data',
    ];
    await supabase.from('superadmin_permissions').insert(
      defaultPermissions.map(key => ({ superadmin_id: newAdmin.id, permission_key: key }))
    );
 
    // ── 6. Audit log ───────────────────────────────────────────────────────
    await logAuditAction(newAdmin.id, 'REGISTER', 'superadmin', newAdmin.id, 'Initial registration', 'success');
 
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
/**
 * POST /api/superadmin/login
 */
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Input validation
    if (!validateEmail(email)) {
      return res.status(422).json({ success: false, message: 'Invalid email' });
    }
    if (!password || password.length < 8) {
      return res.status(422).json({ success: false, message: 'Invalid password' });
    }

    // Rate limiting
    if (loginRateLimiter.isLimited(email)) {
      await logAuditAction(null, AUDIT_ACTIONS.LOGIN, 'superadmin', email, '', 'failed', 'Rate limit exceeded');
      
      // Check if account is locked
      const { data: creds } = await supabase
        .from('superadmin_credentials')
        .select('locked_until')
        .eq('email', email)
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
      await logAuditAction(null, AUDIT_ACTIONS.LOGIN, 'superadmin', email, '', 'failed', 'Invalid credentials');
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    // Check account status
    if (superadmin.status === 'suspended') {
      return res.status(403).json({ success: false, message: 'Account suspended' });
    }

    if (superadmin.status === 'inactive') {
      return res.status(403).json({ success: false, message: 'Account inactive' });
    }

    // Check lockout
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
      // Increment failed attempts
      const newFailedAttempts = (superadmin.failed_login_attempts || 0) + 1;
      
      if (newFailedAttempts >= 5) {
        // Lock account for 15 minutes
        const lockedUntil = new Date(Date.now() + 15 * 60 * 1000);
        await supabase
          .from('superadmin_credentials')
          .update({ failed_login_attempts: newFailedAttempts, locked_until: lockedUntil })
          .eq('id', superadmin.id);
      } else {
        await supabase
          .from('superadmin_credentials')
          .update({ failed_login_attempts: newFailedAttempts })
          .eq('id', superadmin.id);
      }

      await logAuditAction(superadmin.id, AUDIT_ACTIONS.LOGIN, 'superadmin', superadmin.id, '', 'failed', 'Invalid password');
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    // Check 2FA
    if (superadmin.two_factor_enabled) {
      // Generate temporary session token for 2FA
      const tempToken = generateToken();
      return res.json({
        success: true,
        requires2FA: true,
        sessionToken: tempToken,
      });
    }

    // Generate session
    const accessToken = jwt.sign(
      { superadminId: superadmin.id },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );
    const refreshToken = generateToken();
    const sessionExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000);

    await supabase.from('superadmin_sessions').insert({
      superadmin_id: superadmin.id,
      token_hash: hashToken(accessToken),
      ip_address: 'get_from_request',
      user_agent: 'get_from_request',
      expires_at: sessionExpiry,
    });

    // Reset failed attempts
    await supabase
      .from('superadmin_credentials')
      .update({
        failed_login_attempts: 0,
        locked_until: null,
        last_login: new Date().toISOString(),
        last_ip_address: 'get_from_request',
      })
      .eq('id', superadmin.id);

    // Load permissions
    const { data: permissions } = await supabase
      .from('superadmin_permissions')
      .select('permission_key')
      .eq('superadmin_id', superadmin.id);

    await logAuditAction(superadmin.id, AUDIT_ACTIONS.LOGIN, 'superadmin', superadmin.id, 'Successful login', 'success');

    res.json({
      success: true,
      token: accessToken,
      refreshToken,
      requires2FA: false,
      user: {
        id: superadmin.id,
        username: superadmin.username,
        email: superadmin.email,
        fullName: superadmin.full_name,
        permissions: permissions.map(p => p.permission_key),
      },
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ success: false, message: 'Login failed' });
  }
});

/**
 * POST /api/superadmin/verify-2fa
 */
router.post('/verify-2fa', async (req, res) => {
  try {
    const { sessionToken, code } = req.body;

    if (!code || code.length !== 6) {
      return res.status(422).json({ success: false, message: 'Invalid code format' });
    }

    // TODO: Implement TOTP verification with speakeasy or similar
    // const verified = speakeasy.totp.verify({
    //   secret: superadmin.two_factor_secret,
    //   encoding: 'base32',
    //   token: code,
    //   window: 2,
    // });

    // For now, just return success
    const accessToken = jwt.sign(
      { superadminId: 'verified_id' },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      success: true,
      token: accessToken,
      refreshToken: generateToken(),
      user: { /* user data */ },
    });
  } catch (err) {
    console.error('2FA error:', err);
    res.status(500).json({ success: false, message: '2FA verification failed' });
  }
});

/**
 * POST /api/superadmin/logout
 */
router.post('/logout', authenticateSuperadmin, async (req, res) => {
  try {
    await supabase
      .from('superadmin_sessions')
      .update({ revoked_at: new Date().toISOString() })
      .eq('id', req.session.id);

    await logAuditAction(req.superadmin.id, AUDIT_ACTIONS.LOGOUT, 'superadmin', req.superadmin.id, 'Logout', 'success');

    res.json({ success: true, message: 'Logged out' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Logout failed' });
  }
});

// ==================== STATISTICS ENDPOINTS ====================

/**
 * GET /api/superadmin/stats
 */
router.get('/stats', authenticateSuperadmin, async (req, res) => {
  try {
    // Query all counts from database
    const [agents, clients, chats, docs] = await Promise.all([
      supabase.from('profiles').select('id', { count: 'exact', head: true }).eq('user_type', 'agent'),
      supabase.from('profiles').select('id', { count: 'exact', head: true }).eq('user_type', 'client'),
      supabase.from('messages').select('id', { count: 'exact', head: true }).is('closed_at', null),
      supabase.from('agent_documents').select('id', { count: 'exact', head: true }).eq('status', 'pending'),
    ]);

    res.json({
      totalAgents: agents.count || 0,
      totalClients: clients.count || 0,
      activeChats: chats.count || 0,
      pendingDocuments: docs.count || 0,
      agentsTrend: 5,
      clientsTrend: 12,
      chatsTrend: -3,
      docsTrend: 8,
    });
  } catch (err) {
    console.error('Stats error:', err);
    res.status(500).json({ success: false, message: 'Failed to fetch stats' });
  }
});

/**
 * GET /api/superadmin/audit-logs
 */
router.get('/audit-logs', authenticateSuperadmin, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 50, 500);
    const offset = parseInt(req.query.offset) || 0;

    const { data: logs, error, count } = await supabase
      .from('superadmin_audit_logs')
      .select('*, superadmin_credentials(username)', { count: 'exact' })
      .order('created_at', { ascending: false })
      .range(offset, offset + limit - 1);

    // Return an array directly (frontend expects an array) and normalize keys to camelCase
    const normalized = (logs || []).map(log => ({
      id: log.id,
      action: log.action,
      resourceType: log.resource_type,
      resourceId: log.resource_id,
      reason: log.reason,
      status: log.status,
      errorMessage: log.error_message,
      createdAt: log.created_at,
      superadminUsername: log.superadmin_credentials?.username,
    }));

    res.json(normalized);
  } catch (err) {
    console.error('Audit logs error:', err);
    res.status(500).json({ success: false, message: 'Failed to fetch audit logs' });
  }
});

/**
 * GET /api/superadmin/clients
 */
router.get('/clients', authenticateSuperadmin, async (req, res) => {
  try {
    const { data: clients } = await supabase
      .from('profiles')
      .select('id, first_name, last_name, email, phone, status, created_at')
      .eq('user_type', 'client');

    const normalized = (clients || []).map(c => ({
      id: c.id,
      name: `${c.first_name || ''} ${c.last_name || ''}`.trim() || undefined,
      email: c.email,
      phone: c.phone,
      status: c.status,
      createdAt: c.created_at,
    }));

    res.json(normalized);
  } catch (err) {
    console.error('Clients error:', err);
    res.status(500).json({ success: false, message: 'Failed to fetch clients' });
  }
});

/**
 * GET /api/superadmin/chats
 * Returns list of recent/chat threads (one per booking) with basic meta
 */
router.get('/chats', authenticateSuperadmin, async (req, res) => {
  try {
    // Fetch latest message per booking where not closed
    const { data: rows } = await supabase.rpc('get_superadmin_chats');
    // If rpc not available, fallback to simple query
    let chats = rows || [];

    // Normalize
    const normalized = (chats || []).map(r => ({
      id: r.message_id || r.id,
      bookingId: r.booking_id,
      lastMessage: r.last_message || r.body || '',
      clientName: r.client_name || r.client_full_name || '',
      agentName: r.agent_name || r.agent_full_name || '',
      status: r.is_closed ? 'closed' : 'active',
      createdAt: r.created_at || r.created_at,
    }));

    res.json(normalized);
  } catch (err) {
    console.error('Chats error:', err);
    res.status(500).json({ success: false, message: 'Failed to fetch chats' });
  }
});

// ==================== AGENTS ENDPOINTS ====================

/**
 * GET /api/superadmin/agents
 */
router.get('/agents', authenticateSuperadmin, async (req, res) => {
  try {
    const { data: agents, error } = await supabase
      .from('profiles')
      .select('id, first_name, last_name, email, phone, status, created_at')
      .eq('user_type', 'agent');

    res.json(agents);
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to fetch agents' });
  }
});

// ==================== CHATS ENDPOINTS ====================

/**
 * POST /api/superadmin/chats/:chatId/close
 */
router.post('/chats/:chatId/close', authenticateSuperadmin, async (req, res) => {
  try {
    const { chatId } = req.params;
    const { reason } = req.body;

    if (!reason || reason.trim().length === 0) {
      return res.status(422).json({ success: false, message: 'Reason required' });
    }

    // Get chat/booking info
    const { data: messages } = await supabase
      .from('messages')
      .select('booking_id')
      .eq('id', parseInt(chatId))
      .limit(1);

    if (!messages || messages.length === 0) {
      return res.status(404).json({ success: false, message: 'Chat not found' });
    }

    const bookingId = messages[0].booking_id;

    // Update all messages in chat
    await supabase
      .from('messages')
      .update({
        is_closed: true,
        closed_by: req.superadmin.id,
        close_reason: sanitizeInput(reason),
        closed_at: new Date().toISOString(),
      })
      .eq('booking_id', bookingId);

    // Log closure
    await supabase.from('chat_closures').insert({
      message_id: parseInt(chatId),
      booking_id: bookingId,
      closed_by: req.superadmin.id,
      reason: sanitizeInput(reason),
    });

    // Audit log
    await logAuditAction(
      req.superadmin.id,
      AUDIT_ACTIONS.CLOSE_CHAT,
      'chat',
      chatId,
      reason,
      'success'
    );

    // TODO: Send notification to client and agent

    res.json({ success: true, message: 'Chat closed' });
  } catch (err) {
    console.error('Close chat error:', err);
    await logAuditAction(
      req.superadmin.id,
      AUDIT_ACTIONS.CLOSE_CHAT,
      'chat',
      req.params.chatId,
      '',
      'failed',
      err.message
    );
    res.status(500).json({ success: false, message: 'Failed to close chat' });
  }
});

// ==================== DOCUMENTS ENDPOINTS ====================

/**
 * GET /api/superadmin/documents
 */
router.get('/documents', authenticateSuperadmin, async (req, res) => {
  try {
    const status = req.query.status;
    let query = supabase.from('agent_documents').select('*, profiles(first_name, last_name, email)');
    
    if (status && status !== 'all') {
      query = query.eq('status', status);
    }

    const { data: documents } = await query;

    res.json(documents);
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to fetch documents' });
  }
});

/**
 * POST /api/superadmin/documents/:docId/verify
 */
router.post('/documents/:docId/verify', authenticateSuperadmin, async (req, res) => {
  try {
    const { docId } = req.params;
    const { status, notes } = req.body;

    if (!['approved', 'rejected'].includes(status)) {
      return res.status(422).json({ success: false, message: 'Invalid status' });
    }

    // Update document
    const { error } = await supabase
      .from('agent_documents')
      .update({
        status,
        review_notes: sanitizeInput(notes || ''),
        reviewed_by: req.superadmin.id,
        reviewed_at: new Date().toISOString(),
      })
      .eq('id', docId);

    if (error) throw error;

    await logAuditAction(
      req.superadmin.id,
      status === 'approved' ? AUDIT_ACTIONS.VERIFY_DOCUMENT : AUDIT_ACTIONS.REJECT_DOCUMENT,
      'document',
      docId,
      notes || '',
      'success'
    );

    res.json({ success: true, message: `Document ${status}` });
  } catch (err) {
    console.error('Document verify error:', err);
    res.status(500).json({ success: false, message: 'Failed to verify document' });
  }
});

// ==================== PACKAGES ENDPOINTS ====================

/**
 * GET /api/superadmin/packages
 */
router.get('/packages', authenticateSuperadmin, async (req, res) => {
  try {
    const { data: packages } = await supabase
      .from('packages')
      .select('id, name, type, price, created_at, agent_id')
      .order('created_at', { ascending: false });

    res.json(packages);
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to fetch packages' });
  }
});

/**
 * DELETE /api/superadmin/packages/:packageId
 */
router.delete('/packages/:packageId', authenticateSuperadmin, async (req, res) => {
  try {
    const { packageId } = req.params;
    const { reason } = req.body;

    // Check for active bookings
    const { data: bookings } = await supabase
      .from('bookings')
      .select('id')
      .eq('package_id', packageId)
      .neq('status', 'cancelled');

    if (bookings && bookings.length > 0) {
      return res.status(422).json({
        success: false,
        message: `Cannot delete package with ${bookings.length} active bookings`,
      });
    }

    // Soft delete
    await supabase
      .from('packages')
      .delete()
      .eq('id', packageId);

    await logAuditAction(
      req.superadmin.id,
      AUDIT_ACTIONS.DELETE_PACKAGE,
      'package',
      packageId,
      reason || '',
      'success'
    );

    res.json({ success: true, message: 'Package deleted' });
  } catch (err) {
    console.error('Delete package error:', err);
    res.status(500).json({ success: false, message: 'Failed to delete package' });
  }
});

// ==================== DASHBOARDS ENDPOINTS ====================

/**
 * POST /api/superadmin/dashboards/close
 */
router.post('/dashboards/close', authenticateSuperadmin, async (req, res) => {
  try {
    const { userId, type, reason } = req.body;

    if (!['agent', 'client'].includes(type)) {
      return res.status(422).json({ success: false, message: 'Invalid dashboard type' });
    }

    await supabase.from('dashboard_closures').insert({
      user_id: userId,
      dashboard_type: type,
      closed_by: req.superadmin.id,
      reason: sanitizeInput(reason),
      closed_at: new Date().toISOString(),
    });

    await logAuditAction(
      req.superadmin.id,
      AUDIT_ACTIONS.CLOSE_DASHBOARD,
      'dashboard',
      userId,
      reason,
      'success'
    );

    res.json({ success: true, message: 'Dashboard closed' });
  } catch (err) {
    console.error('Close dashboard error:', err);
    res.status(500).json({ success: false, message: 'Failed to close dashboard' });
  }
});

// ==================== DATA EXPORT ENDPOINTS ====================

/**
 * GET /api/superadmin/export/:dataType
 */
router.get('/export/:dataType', authenticateSuperadmin, async (req, res) => {
  try {
    const { dataType } = req.params;
    const validTypes = ['agents', 'clients', 'bookings', 'packages'];

    if (!validTypes.includes(dataType)) {
      return res.status(422).json({ success: false, message: 'Invalid export type' });
    }

    // TODO: Generate CSV based on dataType
    // Include all relevant data
    // Set proper headers for download

    await logAuditAction(
      req.superadmin.id,
      AUDIT_ACTIONS.EXPORT_DATA,
      'export',
      dataType,
      `Exported ${dataType}`,
      'success'
    );

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="export-${dataType}-${Date.now()}.csv"`);
    res.send('id,name,email\n'); // TODO: Replace with actual CSV data
  } catch (err) {
    console.error('Export error:', err);
    res.status(500).json({ success: false, message: 'Export failed' });
  }
});

export default router;
