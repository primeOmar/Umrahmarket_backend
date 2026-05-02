import jwt from 'jsonwebtoken';
import config from '../config/security.config.js';
import logger from '../config/logger.js';
import { supabaseAdmin } from '../config/supabase.js';
/**
 * Authentication Middleware & Token Generation
 * Handles JWT token generation, validation, and verification
 */

// ─────────────────────────────────────────────
// ACCESS TOKEN GENERATION
// ─────────────────────────────────────────────
export const generateAccessToken = (userId, userType, email) => {
  try {
    const token = jwt.sign(
      {
        userId,
        userType,
        email,
        tokenType: 'access',
      },
      config.jwt.accessTokenSecret,
      {
        expiresIn: config.jwt.accessTokenExpiry,
        issuer: config.jwt.issuer,
        audience: config.jwt.audience,
      }
    );

    return token;
  } catch (error) {
    logger.error('Error generating access token', {
      error: error.message,
      userId,
    });
    throw new Error('Failed to generate access token');
  }
};

// ─────────────────────────────────────────────
// REFRESH TOKEN GENERATION
// ─────────────────────────────────────────────
export const generateRefreshToken = (userId, userType, email) => {
  try {
    const token = jwt.sign(
      {
        userId,
        userType,
        email,
        tokenType: 'refresh',
      },
      config.jwt.refreshTokenSecret,
      {
        expiresIn: config.jwt.refreshTokenExpiry,
        issuer: config.jwt.issuer,
        audience: config.jwt.audience,
      }
    );

    return token;
  } catch (error) {
    logger.error('Error generating refresh token', {
      error: error.message,
      userId,
    });
    throw new Error('Failed to generate refresh token');
  }
};

// ─────────────────────────────────────────────
// HELPER - Build normalised req.user object
// Single source of truth so verifyToken, extractUser,
// and requireUserType all agree on field names.
// ─────────────────────────────────────────────
const buildUserObject = (profile, decoded) => ({
  id:          profile.id,
  firstName:   profile.first_name,
  lastName:    profile.last_name,
  // role comes from DB (authoritative); userType kept in sync so
  // requireUserType(["agent"]) and req.user.role both work.
  role:        profile.role,
  userType:    profile.role,          // ← FIX: was missing; caused agent→client switch
  agentName:   profile.company_name,
  agentNumber: profile.agent_number,
  approved:    profile.approved,
  email:       decoded.email,
});

// ─────────────────────────────────────────────
// TOKEN VERIFICATION - Access Token
// ─────────────────────────────────────────────
export const verifyToken = async (req, res, next) => {
  try {
    const token = req.cookies.access_token || req.headers.authorization?.split(' ')[1];

    if (!token) {
      return res.status(401).json({ success: false, error: 'Access token required' });
    }

    const decoded = jwt.verify(token, config.jwt.accessTokenSecret, {
      audience: config.jwt.audience,
      issuer:   config.jwt.issuer,
    });

    const { data: profile, error } = await supabaseAdmin
      .from('profiles')
      .select('id, first_name, last_name, role, company_name, agent_number, approved')
      .eq('id', decoded.userId)
      .single();

    if (error || !profile) {
      return res.status(401).json({ success: false, error: 'User not found' });
    }

    req.user   = buildUserObject(profile, decoded);
    req.userId = profile.id;

    next();

  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ success: false, error: 'Access token expired', code: 'TOKEN_EXPIRED' });
    }
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ success: false, error: `Invalid token: ${error.message}` });
    }
    if (error.name === 'NotBeforeError') {
      return res.status(401).json({ success: false, error: 'Token not yet valid' });
    }
    return res.status(401).json({ success: false, error: 'Invalid access token' });
  }
};

// ─────────────────────────────────────────────
// TOKEN VERIFICATION - Refresh Token
// ─────────────────────────────────────────────
export const verifyRefreshToken = (token) => {
  try {
    const decoded = jwt.verify(token, config.jwt.refreshTokenSecret, {
      issuer: config.jwt.issuer,
      audience: config.jwt.audience,
    });

    if (decoded.tokenType !== 'refresh') {
      throw new Error('Invalid token type');
    }

    return decoded;
  } catch (error) {
    logger.warn('Refresh token verification failed', { error: error.message });
    return null;
  }
};

// ─────────────────────────────────────────────
// MIDDLEWARE - Verify Access Token (alias)
// ─────────────────────────────────────────────
export const requireAuth = verifyToken;

// ─────────────────────────────────────────────
// MIDDLEWARE - Verify User Type/Role
// Accepts role strings: "agent", "client", "admin", etc.
// ─────────────────────────────────────────────
export const requireUserType = (allowedTypes) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ success: false, error: 'User not authenticated' });
    }

    // Check both userType and role so callers using either field are covered
    const userRole = req.user.userType || req.user.role;

    if (!allowedTypes.includes(userRole)) {
      logger.warn('Unauthorized role access attempt', {
        userId:   req.user.id,
        userRole,
        required: allowedTypes,
        path:     req.path,
      });
      return res.status(403).json({
        success: false,
        error: 'Insufficient permissions for this operation',
      });
    }

    next();
  };
};

// ─────────────────────────────────────────────
// MIDDLEWARE - Extract User Info (optional auth)
// Sets req.user if a valid token is present; never blocks.
// ─────────────────────────────────────────────
export const extractUser = async (req, res, next) => {
  const token =
    req.cookies?.access_token ||
    req.headers.authorization?.split(' ')[1];

  if (!token) return next();

  try {
    const decoded = jwt.verify(token, config.jwt.accessTokenSecret, {
      audience: config.jwt.audience,
      issuer:   config.jwt.issuer,
    });

    if (supabaseAdmin) {
      const { data: profile } = await supabaseAdmin
        .from('profiles')
        .select('id, first_name, last_name, role, company_name, agent_number, approved')
        .eq('id', decoded.userId)
        .single();

      if (profile) {
        req.user   = buildUserObject(profile, decoded); // ← FIX: was also missing userType
        req.userId = profile.id;
      }
    }
  } catch {
    // Invalid/expired token — silently ignore for optional-auth routes
  }

  next();
};

// ─────────────────────────────────────────────
// Default Export
// ─────────────────────────────────────────────
export default {
  generateAccessToken,
  generateRefreshToken,
  verifyToken,
  verifyRefreshToken,
  requireAuth,
  requireUserType,
  extractUser,
};