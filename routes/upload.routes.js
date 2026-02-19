import express from 'express';
import bcrypt from 'bcryptjs';
import { supabase, supabaseAdmin } from '../config/supabase.js';
import config from '../config/security.config.js';
import logger, { 
  logAuthAttempt, 
  logSecurityEvent,
  logSuspiciousActivity,
  logAccountLockout 
} from '../config/logger.js';
import {
  validateClientRegistration,
  validateAgentRegistration,
  validateLogin,
  validateEmail,
  validatePasswordReset,
} from '../middleware/validation.middleware.js';
import { authRateLimiter } from '../middleware/security.middleware.js';
import {
  generateAccessToken,
  generateRefreshToken,
  verifyRefreshToken,
  verifyToken,
} from '../middleware/auth.middleware.js';

const router = express.Router();

/**
 * Authentication Routes
 * Secure endpoints for user registration, login, and session management
 */

// ===========================================
// Account Lockout Tracking
// ===========================================
const loginAttempts = new Map(); // In production, use Redis

const checkAccountLockout = async (email) => {
  const attempts = loginAttempts.get(email) || { count: 0, lockedUntil: null };
  
  // Check if account is locked
  if (attempts.lockedUntil && Date.now() < attempts.lockedUntil) {
    const remainingTime = Math.ceil((attempts.lockedUntil - Date.now()) / 60000);
    return {
      locked: true,
      remainingMinutes: remainingTime,
    };
  }
  
  // Reset if lockout expired
  if (attempts.lockedUntil && Date.now() >= attempts.lockedUntil) {
    loginAttempts.delete(email);
    return { locked: false };
  }
  
  return { locked: false };
};

const recordFailedLogin = (email, ip) => {
  const attempts = loginAttempts.get(email) || { count: 0, lockedUntil: null };
  attempts.count += 1;
  
  if (attempts.count >= config.security.maxLoginAttempts) {
    attempts.lockedUntil = Date.now() + config.security.lockoutDuration;
    logAccountLockout(email, ip, 'Exceeded maximum login attempts');
  }
  
  loginAttempts.set(email, attempts);
};

const resetLoginAttempts = (email) => {
  loginAttempts.delete(email);
};

// ===========================================
// 1. CLIENT REGISTRATION
// ===========================================
router.post(
  '/register/client',
  authRateLimiter,
  validateClientRegistration,
  async (req, res) => {
    try {
      const { email, password, firstName, lastName, phone } = req.body;
      
      // Check if user already exists
      const { data: existingUser } = await supabase
        .from('profiles')
        .select('id')
        .eq('email', email)
        .single();
      
      if (existingUser) {
        return res.status(409).json({
          success: false,
          error: 'An account with this email already exists',
        });
      }
      
      // Create user in Supabase Auth
      const { data: authData, error: authError } = await supabase.auth.signUp({
        email,
        password,
        options: {
          data: {
            firstName,
            lastName,
            phone,
            role: 'client',
            approved: true, // Clients are auto-approved
            createdAt: new Date().toISOString(),
          },
          emailRedirectTo: `${config.cors.allowedOrigins[0]}/verify-email`,
        },
      });
      
      if (authError) {
        logger.error('Client registration failed', {
          error: authError.message,
          email,
          ip: req.ip,
        });
        
        return res.status(400).json({
          success: false,
          error: authError.message,
        });
      }
      
      // Create profile in database
      if (supabaseAdmin) {
        const { error: profileError } = await supabaseAdmin
          .from('profiles')
          .insert({
            id: authData.user.id,
            email,
            first_name: firstName,
            last_name: lastName,
            phone,
            role: 'client',
            approved: true,
            created_at: new Date().toISOString(),
          });
        
        if (profileError) {
          logger.error('Failed to create profile', {
            error: profileError.message,
            userId: authData.user.id,
          });
        }
      }
      
      logAuthAttempt(true, authData.user.id, req.ip, req.get('user-agent'), {
        type: 'registration',
        role: 'client',
      });
      
      logSecurityEvent('New client registered', {
        userId: authData.user.id,
        email,
        ip: req.ip,
      });
      
      res.status(201).json({
        success: true,
        message: 'Registration successful. Please check your email to verify your account.',
        data: {
          user: {
            id: authData.user.id,
            email: authData.user.email,
            role: 'client',
          },
        },
      });
    } catch (error) {
      logger.error('Client registration error', {
        error: error.message,
        stack: error.stack,
        ip: req.ip,
      });
      
      res.status(500).json({
        success: false,
        error: 'Registration failed. Please try again later.',
      });
    }
  }
);

// ===========================================
// 2. AGENT REGISTRATION
// ===========================================
router.post(
  '/register/agent',
  authRateLimiter,
  validateAgentRegistration,
  async (req, res) => {
    try {
      const { 
        email, 
        password, 
        firstName, 
        lastName, 
        phone, 
        companyName, 
        licenseNumber 
      } = req.body;
      
      // Check if user already exists
      const { data: existingUser } = await supabase
        .from('profiles')
        .select('id')
        .eq('email', email)
        .single();
      
      if (existingUser) {
        return res.status(409).json({
          success: false,
          error: 'An account with this email already exists',
        });
      }
      
      // Create user in Supabase Auth
      const { data: authData, error: authError } = await supabase.auth.signUp({
        email,
        password,
        options: {
          data: {
            firstName,
            lastName,
            phone,
            companyName,
            licenseNumber,
            role: 'agent',
            approved: false, // Agents need manual approval
            createdAt: new Date().toISOString(),
          },
          emailRedirectTo: `${config.cors.allowedOrigins[0]}/verify-email`,
        },
      });
      
      if (authError) {
        logger.error('Agent registration failed', {
          error: authError.message,
          email,
          ip: req.ip,
        });
        
        return res.status(400).json({
          success: false,
          error: authError.message,
        });
      }
      
      // Create profile in database
      if (supabaseAdmin) {
        const { error: profileError } = await supabaseAdmin
          .from('profiles')
          .insert({
            id: authData.user.id,
            email,
            first_name: firstName,
            last_name: lastName,
            phone,
            company_name: companyName,
            license_number: licenseNumber,
            role: 'agent',
            approved: false,
            created_at: new Date().toISOString(),
          });
        
        if (profileError) {
          logger.error('Failed to create agent profile', {
            error: profileError.message,
            userId: authData.user.id,
          });
        }
      }
      
      logAuthAttempt(true, authData.user.id, req.ip, req.get('user-agent'), {
        type: 'registration',
        role: 'agent',
      });
      
      logSecurityEvent('New agent registered - pending approval', {
        userId: authData.user.id,
        email,
        companyName,
        ip: req.ip,
      });
      
      // TODO: Send notification to admin for approval
      
      res.status(201).json({
        success: true,
        message: 'Registration successful. Your account is pending approval. You will receive an email once approved.',
        data: {
          user: {
            id: authData.user.id,
            email: authData.user.email,
            role: 'agent',
            approved: false,
          },
        },
      });
    } catch (error) {
      logger.error('Agent registration error', {
        error: error.message,
        stack: error.stack,
        ip: req.ip,
      });
      
      res.status(500).json({
        success: false,
        error: 'Registration failed. Please try again later.',
      });
    }
  }
);

// ===========================================
// 3. LOGIN
// ===========================================
router.post(
  '/login',
  authRateLimiter,
  validateLogin,
  async (req, res) => {
    try {
      const { email, password } = req.body;
      
      // Check account lockout
      const lockoutStatus = await checkAccountLockout(email);
      if (lockoutStatus.locked) {
        return res.status(423).json({
          success: false,
          error: `Account locked due to too many failed attempts. Try again in ${lockoutStatus.remainingMinutes} minutes.`,
          code: 'ACCOUNT_LOCKED',
        });
      }
      
      // Authenticate with Supabase
      const { data, error } = await supabase.auth.signInWithPassword({
        email,
        password,
      });
      
      if (error) {
        recordFailedLogin(email, req.ip);
        
        logAuthAttempt(false, null, req.ip, req.get('user-agent'), {
          type: 'login',
          email,
          error: error.message,
        });
        
        // Generic error message for security
        return res.status(401).json({
          success: false,
          error: 'Invalid email or password',
        });
      }
      
      // Reset login attempts on successful login
      resetLoginAttempts(email);
      
      // Generate custom JWT tokens
      const accessToken = generateAccessToken(
        data.user.id,
        data.user.user_metadata.role
      );
      const refreshToken = generateRefreshToken(data.user.id);
      
      // Set cookies
      res.cookie('access_token', accessToken, {
        httpOnly: config.cookie.httpOnly,
        secure: config.cookie.secure,
        sameSite: config.cookie.sameSite,
        maxAge: 15 * 60 * 1000, // 15 minutes
      });
      
      res.cookie('refresh_token', refreshToken, {
        httpOnly: true,
        secure: config.cookie.secure,
        sameSite: config.cookie.sameSite,
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
        path: '/api/auth/refresh',
      });
      
      logAuthAttempt(true, data.user.id, req.ip, req.get('user-agent'), {
        type: 'login',
        role: data.user.user_metadata.role,
      });
      
      res.json({
        success: true,
        message: 'Login successful',
        data: {
          user: {
            id: data.user.id,
            email: data.user.email,
            role: data.user.user_metadata.role,
            firstName: data.user.user_metadata.firstName,
            lastName: data.user.user_metadata.lastName,
            approved: data.user.user_metadata.approved,
          },
          accessToken,
          refreshToken,
        },
      });
    } catch (error) {
      logger.error('Login error', {
        error: error.message,
        stack: error.stack,
        ip: req.ip,
      });
      
      res.status(500).json({
        success: false,
        error: 'Login failed. Please try again later.',
      });
    }
  }
);

// ===========================================
// 4. GOOGLE OAUTH LOGIN
// ===========================================
router.post('/google', authRateLimiter, async (req, res) => {
  try {
    const { idToken } = req.body;
    
    if (!idToken) {
      return res.status(400).json({
        success: false,
        error: 'ID token is required',
      });
    }
    
    // Sign in with Google
    const { data, error } = await supabase.auth.signInWithIdToken({
      provider: 'google',
      token: idToken,
    });
    
    if (error) {
      logger.error('Google login failed', {
        error: error.message,
        ip: req.ip,
      });
      
      return res.status(400).json({
        success: false,
        error: error.message,
      });
    }
    
    // Generate custom tokens
    const accessToken = generateAccessToken(
      data.user.id,
      data.user.user_metadata.role || 'client'
    );
    const refreshToken = generateRefreshToken(data.user.id);
    
    logAuthAttempt(true, data.user.id, req.ip, req.get('user-agent'), {
      type: 'google-login',
    });
    
    res.json({
      success: true,
      message: 'Google login successful',
      data: {
        user: {
          id: data.user.id,
          email: data.user.email,
          role: data.user.user_metadata.role || 'client',
        },
        accessToken,
        refreshToken,
      },
    });
  } catch (error) {
    logger.error('Google login error', {
      error: error.message,
      ip: req.ip,
    });
    
    res.status(500).json({
      success: false,
      error: 'Google login failed',
    });
  }
});

// ===========================================
// 5. REFRESH TOKEN
// ===========================================
router.post('/refresh', async (req, res) => {
  try {
    const refreshToken = req.cookies.refresh_token || req.body.refreshToken;
    
    if (!refreshToken) {
      return res.status(401).json({
        success: false,
        error: 'Refresh token is required',
      });
    }
    
    // Verify refresh token
    const decoded = verifyRefreshToken(refreshToken);
    
    if (!decoded) {
      return res.status(401).json({
        success: false,
        error: 'Invalid refresh token',
      });
    }
    
    // Generate new access token
    const accessToken = generateAccessToken(decoded.userId, decoded.role);
    
    res.json({
      success: true,
      data: {
        accessToken,
      },
    });
  } catch (error) {
    logger.error('Token refresh error', {
      error: error.message,
      ip: req.ip,
    });
    
    res.status(500).json({
      success: false,
      error: 'Token refresh failed',
    });
  }
});

// ===========================================
// 6. LOGOUT
// ===========================================
router.post('/logout', verifyToken, async (req, res) => {
  try {
    // Sign out from Supabase
    await supabase.auth.signOut();
    
    // Clear cookies
    res.clearCookie('access_token');
    res.clearCookie('refresh_token');
    
    logSecurityEvent('User logged out', {
      userId: req.userId,
      ip: req.ip,
    });
    
    res.json({
      success: true,
      message: 'Logout successful',
    });
  } catch (error) {
    logger.error('Logout error', {
      error: error.message,
      userId: req.userId,
    });
    
    res.status(500).json({
      success: false,
      error: 'Logout failed',
    });
  }
});

// ===========================================
// 7. PASSWORD RESET REQUEST
// ===========================================
router.post(
  '/password-reset/request',
  authRateLimiter,
  validateEmail,
  async (req, res) => {
    try {
      const { email } = req.body;
      
      // Send password reset email
      const { error } = await supabase.auth.resetPasswordForEmail(email, {
        redirectTo: `${config.cors.allowedOrigins[0]}/reset-password`,
      });
      
      if (error) {
        logger.error('Password reset request failed', {
          error: error.message,
          email,
        });
      }
      
      // Always return success to prevent email enumeration
      res.json({
        success: true,
        message: 'If an account exists with this email, a password reset link has been sent.',
      });
    } catch (error) {
      logger.error('Password reset request error', {
        error: error.message,
        ip: req.ip,
      });
      
      res.status(500).json({
        success: false,
        error: 'Failed to process password reset request',
      });
    }
  }
);

// ===========================================
// 8. PASSWORD RESET CONFIRM
// ===========================================
router.post(
  '/password-reset/confirm',
  authRateLimiter,
  validatePasswordReset,
  async (req, res) => {
    try {
      const { token, password } = req.body;
      
      // Update password
      const { error } = await supabase.auth.updateUser({
        password,
      });
      
      if (error) {
        return res.status(400).json({
          success: false,
          error: error.message,
        });
      }
      
      logSecurityEvent('Password reset completed', {
        ip: req.ip,
      });
      
      res.json({
        success: true,
        message: 'Password has been reset successfully',
      });
    } catch (error) {
      logger.error('Password reset error', {
        error: error.message,
        ip: req.ip,
      });
      
      res.status(500).json({
        success: false,
        error: 'Password reset failed',
      });
    }
  }
);

// ===========================================
// 9. VERIFY EMAIL
// ===========================================
router.post('/verify-email', async (req, res) => {
  try {
    const { token } = req.body;
    
    // Verify email with token
    const { error } = await supabase.auth.verifyOtp({
      token_hash: token,
      type: 'email',
    });
    
    if (error) {
      return res.status(400).json({
        success: false,
        error: error.message,
      });
    }
    
    res.json({
      success: true,
      message: 'Email verified successfully',
    });
  } catch (error) {
    logger.error('Email verification error', {
      error: error.message,
      ip: req.ip,
    });
    
    res.status(500).json({
      success: false,
      error: 'Email verification failed',
    });
  }
});

// ===========================================
// 10. GET CURRENT USER
// ===========================================
router.get('/me', verifyToken, async (req, res) => {
  try {
    res.json({
      success: true,
      data: {
        user: req.user,
      },
    });
  } catch (error) {
    logger.error('Get user error', {
      error: error.message,
      userId: req.userId,
    });
    
    res.status(500).json({
      success: false,
      error: 'Failed to fetch user data',
    });
  }
});

export default router;