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
// TOKEN VERIFICATION - Access Token
// ─────────────────────────────────────────────

export const verifyToken = async (req, res, next) => {
  try {
    // ─── DEBUG 1: Log all cookies received ───────────────────────────────────
    console.log('[verifyToken] All cookies:', req.cookies);
    console.log('[verifyToken] Authorization header:', req.headers.authorization);

    const token = req.cookies.access_token || req.headers.authorization?.split(' ')[1];

    // ─── DEBUG 2: Token presence check ───────────────────────────────────────
    console.log('[verifyToken] Cookie token present:', !!req.cookies.access_token);
    console.log('[verifyToken] Header token present:', !!req.headers.authorization);
    console.log('[verifyToken] Token resolved:', token ? `${token.substring(0, 50)}...` : 'NONE');

    if (!token) {
      console.log('[verifyToken] ❌ No token found in cookies or headers');
      return res.status(401).json({ success: false, error: 'Access token required' });
    }

    // ─── DEBUG 3: Config values ───────────────────────────────────────────────
    console.log('[verifyToken] Secret (first 10 chars):', config.jwt.accessTokenSecret?.substring(0, 10) ?? 'UNDEFINED');
    console.log('[verifyToken] Audience:', config.jwt.audience ?? 'UNDEFINED');
    console.log('[verifyToken] Issuer:', config.jwt.issuer ?? 'UNDEFINED');

    // ─── DEBUG 4: Decode token WITHOUT verifying to inspect its payload ───────
    const rawDecoded = jwt.decode(token);
    console.log('[verifyToken] Token payload (unverified):', rawDecoded);
    console.log('[verifyToken] Token aud claim:', rawDecoded?.aud);
    console.log('[verifyToken] Token iss claim:', rawDecoded?.iss);
    console.log('[verifyToken] Token exp:', rawDecoded?.exp ? new Date(rawDecoded.exp * 1000).toISOString() : 'NONE');
    console.log('[verifyToken] Token expired?:', rawDecoded?.exp ? Date.now() > rawDecoded.exp * 1000 : 'NO EXP');

    // ─── Actual verification ──────────────────────────────────────────────────
    const decoded = jwt.verify(token, config.jwt.accessTokenSecret, {
      audience: config.jwt.audience,
      issuer:   config.jwt.issuer,
    });

    console.log('[verifyToken] ✅ Token verified successfully. userId:', decoded.userId);

    // ─── DB lookup ────────────────────────────────────────────────────────────
    const { data: profile, error } = await supabaseAdmin
      .from('profiles')
      .select('id, first_name, last_name, role, company_name, agent_number, approved')
      .eq('id', decoded.userId)
      .single();

    console.log('[verifyToken] Profile fetch error:', error ?? 'NONE');
    console.log('[verifyToken] Profile found:', profile ? `id=${profile.id}, role=${profile.role}` : 'NOT FOUND');

    if (error || !profile) {
      console.log('[verifyToken] ❌ User not found in DB for userId:', decoded.userId);
      return res.status(401).json({ success: false, error: 'User not found' });
    }

    req.user = {
      id:          profile.id,
      firstName:   profile.first_name,
      lastName:    profile.last_name,
      role:        profile.role,
      agentName:   profile.company_name,
      agentNumber: profile.agent_number,
      approved:    profile.approved,
    };

    req.userId = profile.id;

    console.log('[verifyToken] ✅ req.user set:', req.user);
    next();

  } catch (error) {
    // ─── DEBUG 5: Exact error that caused failure ─────────────────────────────
    console.log('[verifyToken] ❌ JWT verification threw an error:');
    console.log('[verifyToken] error.name:', error.name);
    console.log('[verifyToken] error.message:', error.message);

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

    // Ensure it's a refresh token
    if (decoded.tokenType !== 'refresh') {
      throw new Error('Invalid token type');
    }

    return decoded;
  } catch (error) {
    logger.warn('Refresh token verification failed', {
      error: error.message,
    });
    return null;
  }
};

// ─────────────────────────────────────────────
// MIDDLEWARE - Verify Access Token
// ─────────────────────────────────────────────
export const requireAuth = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      success: false,
      error: 'Missing or invalid authorization header',
    });
  }

  const token = authHeader.substring(7); // Remove "Bearer " prefix

  const decoded = verifyToken(token);
  if (!decoded) {
    return res.status(401).json({
      success: false,
      error: 'Invalid or expired access token',
    });
  }

  req.user = decoded;
  next();
};

// ─────────────────────────────────────────────
// MIDDLEWARE - Verify User Type
// ─────────────────────────────────────────────
export const requireUserType = (allowedTypes) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        error: 'User not authenticated',
      });
    }

    if (!allowedTypes.includes(req.user.userType)) {
      logger.warn('Unauthorized user type access attempt', {
        userId: req.user.userId,
        userType: req.user.userType,
        path: req.path,
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
// MIDDLEWARE - Extract User Info from Token
// ─────────────────────────────────────────────
export const extractUser = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.substring(7);
    const decoded = verifyToken(token);

    if (decoded) {
      req.user = decoded;
    }
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