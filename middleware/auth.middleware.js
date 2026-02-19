import jwt from 'jsonwebtoken';
import config from '../config/security.config.js';
import logger from '../config/logger.js';

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
export const verifyToken = (token) => {
  try {
    const decoded = jwt.verify(token, config.jwt.accessTokenSecret, {
      issuer: config.jwt.issuer,
      audience: config.jwt.audience,
    });

    // Ensure it's an access token
    if (decoded.tokenType !== 'access') {
      throw new Error('Invalid token type');
    }

    return decoded;
  } catch (error) {
    logger.warn('Access token verification failed', {
      error: error.message,
    });
    return null;
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