import { body, param, query, validationResult } from 'express-validator';
import validator from 'validator';
import config from '../config/security.config.js';
import logger, { logSuspiciousActivity } from '../config/logger.js';

/**
 * Input Validation Middleware
 * Prevents injection attacks and ensures data integrity
 */

// ===========================================
// Validation Error Handler
// ===========================================
export const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  
  if (!errors.isEmpty()) {
    const errorMessages = errors.array().map(err => ({
      field: err.path,
      message: err.msg,
    }));
    
    logger.warn('Validation failed', {
      errors: errorMessages,
      ip: req.ip,
      path: req.path,
    });
    
    return res.status(400).json({
      success: false,
      error: 'Validation failed',
      details: errorMessages,
    });
  }
  
  next();
};

// ===========================================
// Password Strength Validator
// ===========================================
const passwordStrengthValidator = (value) => {
  const { password } = config.security;
  
  if (value.length < password.minLength) {
    throw new Error(`Password must be at least ${password.minLength} characters long`);
  }
  
  if (password.requireUppercase && !/[A-Z]/.test(value)) {
    throw new Error('Password must contain at least one uppercase letter');
  }
  
  if (password.requireLowercase && !/[a-z]/.test(value)) {
    throw new Error('Password must contain at least one lowercase letter');
  }
  
  if (password.requireNumbers && !/\d/.test(value)) {
    throw new Error('Password must contain at least one number');
  }
  
  if (password.requireSpecialChars && !/[!@#$%^&*(),.?":{}|<>]/.test(value)) {
    throw new Error('Password must contain at least one special character');
  }
  
  // Check for common passwords
  const commonPasswords = [
    'password', '123456', '12345678', 'qwerty', 'abc123',
    'password123', '111111', '123123', 'admin', 'letmein'
  ];
  
  if (commonPasswords.includes(value.toLowerCase())) {
    throw new Error('This password is too common. Please choose a stronger password');
  }
  
  return true;
};

// ===========================================
// Email Sanitizer
// ===========================================
const sanitizeEmail = (email) => {
  return validator.normalizeEmail(email, {
    gmail_remove_dots: false,
    gmail_remove_subaddress: false,
  });
};

// ===========================================
// Validation Rules
// ===========================================

/**
 * Client Registration Validation
 */
export const validateClientRegistration = [
  body('firstName')
    .trim()
    .notEmpty().withMessage('First name is required')
    .isLength({ min: 2, max: 50 }).withMessage('First name must be between 2 and 50 characters')
    .matches(/^[a-zA-Z\s'-]+$/).withMessage('First name can only contain letters, spaces, hyphens, and apostrophes')
    .escape(),
  
  body('lastName')
    .trim()
    .notEmpty().withMessage('Last name is required')
    .isLength({ min: 2, max: 50 }).withMessage('Last name must be between 2 and 50 characters')
    .matches(/^[a-zA-Z\s'-]+$/).withMessage('Last name can only contain letters, spaces, hyphens, and apostrophes')
    .escape(),
  
  body('email')
    .trim()
    .notEmpty().withMessage('Email is required')
    .isEmail().withMessage('Please provide a valid email address')
    .normalizeEmail()
    .customSanitizer(sanitizeEmail)
    .isLength({ max: 100 }).withMessage('Email is too long'),
  
  body('password')
    .notEmpty().withMessage('Password is required')
    .custom(passwordStrengthValidator),
  
  body('phone')
    .optional()
    .trim()
    .isMobilePhone('any', { strictMode: false }).withMessage('Please provide a valid phone number')
    .isLength({ max: 20 }).withMessage('Phone number is too long'),
  
  handleValidationErrors,
];

/**
 * Agent Registration Validation
 */
export const validateAgentRegistration = [
  body('firstName')
    .trim()
    .notEmpty().withMessage('First name is required')
    .isLength({ min: 2, max: 50 }).withMessage('First name must be between 2 and 50 characters')
    .matches(/^[a-zA-Z\s'-]+$/).withMessage('First name contains invalid characters')
    .escape(),
  
  body('lastName')
    .trim()
    .notEmpty().withMessage('Last name is required')
    .isLength({ min: 2, max: 50 }).withMessage('Last name must be between 2 and 50 characters')
    .matches(/^[a-zA-Z\s'-]+$/).withMessage('Last name contains invalid characters')
    .escape(),
  
  body('email')
    .trim()
    .notEmpty().withMessage('Email is required')
    .isEmail().withMessage('Please provide a valid email address')
    .normalizeEmail()
    .customSanitizer(sanitizeEmail),
  
  body('password')
    .notEmpty().withMessage('Password is required')
    .custom(passwordStrengthValidator),
  
  body('phone')
    .trim()
    .notEmpty().withMessage('Phone number is required')
    .isMobilePhone('any', { strictMode: false }).withMessage('Please provide a valid phone number'),
  
  body('companyName')
    .trim()
    .notEmpty().withMessage('Company name is required')
    .isLength({ min: 2, max: 100 }).withMessage('Company name must be between 2 and 100 characters')
    .escape(),
  
  body('licenseNumber')
    .optional()
    .trim()
    .isLength({ max: 50 }).withMessage('License number is too long')
    .escape(),
  
  handleValidationErrors,
];

/**
 * Login Validation
 */
export const validateLogin = [
  body('email')
    .trim()
    .notEmpty().withMessage('Email is required')
    .isEmail().withMessage('Please provide a valid email address')
    .normalizeEmail()
    .customSanitizer(sanitizeEmail),
  
  body('password')
    .notEmpty().withMessage('Password is required'),
  
  handleValidationErrors,
];

/**
 * Email Validation (for password reset, etc.)
 */
export const validateEmail = [
  body('email')
    .trim()
    .notEmpty().withMessage('Email is required')
    .isEmail().withMessage('Please provide a valid email address')
    .normalizeEmail()
    .customSanitizer(sanitizeEmail),
  
  handleValidationErrors,
];

/**
 * Password Reset Validation
 */
export const validatePasswordReset = [
  body('token')
    .trim()
    .notEmpty().withMessage('Reset token is required')
    .isLength({ min: 20, max: 500 }).withMessage('Invalid reset token'),
  
  body('password')
    .notEmpty().withMessage('Password is required')
    .custom(passwordStrengthValidator),
  
  body('confirmPassword')
    .notEmpty().withMessage('Password confirmation is required')
    .custom((value, { req }) => {
      if (value !== req.body.password) {
        throw new Error('Passwords do not match');
      }
      return true;
    }),
  
  handleValidationErrors,
];

/**
 * User ID Parameter Validation
 */
export const validateUserId = [
  param('userId')
    .trim()
    .notEmpty().withMessage('User ID is required')
    .isUUID().withMessage('Invalid user ID format'),
  
  handleValidationErrors,
];

/**
 * Profile Update Validation
 */
export const validateProfileUpdate = [
  body('firstName')
    .optional()
    .trim()
    .isLength({ min: 2, max: 50 }).withMessage('First name must be between 2 and 50 characters')
    .matches(/^[a-zA-Z\s'-]+$/).withMessage('First name contains invalid characters')
    .escape(),
  
  body('lastName')
    .optional()
    .trim()
    .isLength({ min: 2, max: 50 }).withMessage('Last name must be between 2 and 50 characters')
    .matches(/^[a-zA-Z\s'-]+$/).withMessage('Last name contains invalid characters')
    .escape(),
  
  body('phone')
    .optional()
    .trim()
    .isMobilePhone('any', { strictMode: false }).withMessage('Please provide a valid phone number'),
  
  body('companyName')
    .optional()
    .trim()
    .isLength({ min: 2, max: 100 }).withMessage('Company name must be between 2 and 100 characters')
    .escape(),
  
  handleValidationErrors,
];

/**
 * Query Pagination Validation
 */
export const validatePagination = [
  query('page')
    .optional()
    .isInt({ min: 1 }).withMessage('Page must be a positive integer')
    .toInt(),
  
  query('limit')
    .optional()
    .isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100')
    .toInt(),
  
  handleValidationErrors,
];

// ===========================================
// XSS Prevention Middleware
// ===========================================
export const sanitizeInput = (req, res, next) => {
  // Recursively sanitize all string inputs
  const sanitizeObject = (obj) => {
    if (typeof obj === 'string') {
      return validator.escape(obj);
    }
    
    if (Array.isArray(obj)) {
      return obj.map(sanitizeObject);
    }
    
    if (obj !== null && typeof obj === 'object') {
      const sanitized = {};
      for (const key in obj) {
        sanitized[key] = sanitizeObject(obj[key]);
      }
      return sanitized;
    }
    
    return obj;
  };
  
  // Sanitize body, query, and params
  if (req.body) {
    req.body = sanitizeObject(req.body);
  }
  
  if (req.query) {
    req.query = sanitizeObject(req.query);
  }
  
  if (req.params) {
    req.params = sanitizeObject(req.params);
  }
  
  next();
};

// ===========================================
// Dangerous Pattern Detection
// ===========================================
const dangerousPatterns = [
  /<script[^>]*>.*?<\/script>/gi,
  /javascript:/gi,
  /on\w+\s*=/gi, // Event handlers like onclick=
  /eval\(/gi,
  /expression\(/gi,
  /vbscript:/gi,
  /import\s+/gi,
  /require\s*\(/gi,
];

export const detectDangerousPatterns = (req, res, next) => {
  const checkValue = (value) => {
    if (typeof value === 'string') {
      for (const pattern of dangerousPatterns) {
        if (pattern.test(value)) {
          return true;
        }
      }
    }
    return false;
  };
  
  const checkObject = (obj) => {
    if (typeof obj === 'string') {
      return checkValue(obj);
    }
    
    if (Array.isArray(obj)) {
      return obj.some(checkObject);
    }
    
    if (obj !== null && typeof obj === 'object') {
      return Object.values(obj).some(checkObject);
    }
    
    return false;
  };
  
  // Check all inputs
  if (checkObject(req.body) || checkObject(req.query) || checkObject(req.params)) {
    logSuspiciousActivity('Dangerous pattern detected in request', {
      ip: req.ip,
      path: req.path,
      userAgent: req.get('user-agent'),
    });
    
    return res.status(400).json({
      success: false,
      error: 'Invalid input detected',
    });
  }
  
  next();
};

// ===========================================
// Export all validators
// ===========================================
export default {
  validateClientRegistration,
  validateAgentRegistration,
  validateLogin,
  validateEmail,
  validatePasswordReset,
  validateUserId,
  validateProfileUpdate,
  validatePagination,
  sanitizeInput,
  detectDangerousPatterns,
  handleValidationErrors,
};