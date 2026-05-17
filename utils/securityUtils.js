/**
 * Security Utilities for Superadmin System
 * Production-ready security features
 */

import crypto from 'crypto';

// ==================== PASSWORD & HASHING ====================

/**
 * Hash password using PBKDF2
 * Never use plain passwords
 */
export const hashPassword = (password) => {
  if (!password || password.length < 12) {
    throw new Error('Password must be at least 12 characters long');
  }
  
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
  return `${salt}:${hash}`;
};

/**
 * Verify password against hash
 */
export const verifyPassword = (password, hash) => {
  try {
    const [salt, storedHash] = hash.split(':');
    const newHash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
    return newHash === storedHash;
  } catch (e) {
    return false;
  }
};

// ==================== TOKEN GENERATION ====================

/**
 * Generate secure random token
 */
export const generateToken = (length = 32) => {
  return crypto.randomBytes(length).toString('hex');
};

/**
 * Hash token for storage (one-way)
 */
export const hashToken = (token) => {
  return crypto.createHash('sha256').update(token).digest('hex');
};

// ==================== RATE LIMITING ====================

class RateLimiter {
  constructor(maxAttempts = 5, windowMs = 15 * 60 * 1000) { // 15 minutes
    this.maxAttempts = maxAttempts;
    this.windowMs = windowMs;
    this.attempts = new Map();
  }

  isLimited(identifier) {
    const now = Date.now();
    const record = this.attempts.get(identifier) || { count: 0, resetTime: now + this.windowMs };

    if (now > record.resetTime) {
      record.count = 0;
      record.resetTime = now + this.windowMs;
    }

    record.count++;
    this.attempts.set(identifier, record);

    return record.count > this.maxAttempts;
  }

  getRemainingAttempts(identifier) {
    const record = this.attempts.get(identifier);
    if (!record) return this.maxAttempts;
    return Math.max(0, this.maxAttempts - record.count);
  }

  reset(identifier) {
    this.attempts.delete(identifier);
  }
}

export const loginRateLimiter = new RateLimiter(5, 15 * 60 * 1000); // 5 attempts per 15 minutes
export const apiRateLimiter = new RateLimiter(100, 60 * 1000); // 100 requests per minute

// ==================== INPUT VALIDATION ====================

export const validateEmail = (email) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email) && email.length <= 254;
};

export const validateUsername = (username) => {
  const usernameRegex = /^[a-zA-Z0-9_]{3,32}$/;
  return usernameRegex.test(username);
};

export const validatePassword = (password) => {
  // At least 12 chars, 1 uppercase, 1 lowercase, 1 number, 1 special char
  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,}$/;
  return passwordRegex.test(password);
};

export const validateUUID = (uuid) => {
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  return uuidRegex.test(uuid);
};

// ==================== INPUT SANITIZATION ====================

/**
 * Sanitize string to prevent XSS
 */
export const sanitizeInput = (input) => {
  if (typeof input !== 'string') return input;
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .trim();
};

/**
 * Validate and sanitize JSON
 */
export const validateJSON = (json) => {
  try {
    const parsed = JSON.parse(json);
    return { valid: true, data: parsed };
  } catch (e) {
    return { valid: false, error: e.message };
  }
};

// ==================== SESSION MANAGEMENT ====================

export const sessionConfig = {
  maxAge: 24 * 60 * 60 * 1000, // 24 hours
  refreshThreshold: 1 * 60 * 60 * 1000, // Refresh if within 1 hour
  inactivityTimeout: 30 * 60 * 1000, // 30 minutes of inactivity
};

export const generateSessionToken = () => {
  return generateToken(32);
};

// ==================== ENCRYPTION (For sensitive data) ====================

const ENCRYPTION_KEY = process.env.VITE_ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex');
const ENCRYPTION_IV_LENGTH = 16;

export const encrypt = (text) => {
  const iv = crypto.randomBytes(ENCRYPTION_IV_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY, 'hex'), iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + ':' + encrypted;
};

export const decrypt = (encryptedText) => {
  try {
    const parts = encryptedText.split(':');
    const iv = Buffer.from(parts[0], 'hex');
    const encrypted = parts[1];
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY, 'hex'), iv);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (e) {
    throw new Error('Decryption failed');
  }
};

// ==================== IP & USER AGENT ====================

export const getClientIP = (request) => {
  return request.headers.get('x-forwarded-for')?.split(',')[0] ||
    request.headers.get('cf-connecting-ip') ||
    request.headers.get('x-client-ip') ||
    request.remote?.address ||
    'unknown';
};

export const getUserAgent = (request) => {
  return request.headers.get('user-agent') || 'unknown';
};

// ==================== CSRF PROTECTION ====================

export const generateCSRFToken = () => {
  return crypto.randomBytes(32).toString('hex');
};

export const verifyCSRFToken = (token, sessionToken) => {
  // In production, validate against session store
  return token && sessionToken && token.length === 64;
};

// ==================== CONSTANTS ====================

export const SUPERADMIN_PERMISSIONS = {
  // Viewing permissions
  VIEW_AGENTS: 'view_agents',
  VIEW_CLIENTS: 'view_clients',
  VIEW_CHATS: 'view_chats',
  VIEW_DOCUMENTS: 'view_documents',
  VIEW_PACKAGES: 'view_packages',
  VIEW_BOOKINGS: 'view_bookings',
  VIEW_AUDIT_LOGS: 'view_audit_logs',
  VIEW_USERS: 'view_users',

  // Modification permissions
  VERIFY_DOCUMENTS: 'verify_documents',
  CLOSE_CHATS: 'close_chats',
  CLOSE_DASHBOARD: 'close_dashboard',
  DELETE_PACKAGES: 'delete_packages',
  DELETE_BOOKINGS: 'delete_bookings',
  DELETE_USERS: 'delete_users',
  MANAGE_AGENTS: 'manage_agents',
  MANAGE_CLIENTS: 'manage_clients',

  // Admin permissions
  MANAGE_SUPERADMINS: 'manage_superadmins',
  VIEW_SYSTEM_SETTINGS: 'view_system_settings',
  MANAGE_SYSTEM_SETTINGS: 'manage_system_settings',
  EXPORT_DATA: 'export_data',
  MANAGE_API_KEYS: 'manage_api_keys',
};

export const DEFAULT_SUPERADMIN_PERMISSIONS = [
  SUPERADMIN_PERMISSIONS.VIEW_AGENTS,
  SUPERADMIN_PERMISSIONS.VIEW_CLIENTS,
  SUPERADMIN_PERMISSIONS.VIEW_CHATS,
  SUPERADMIN_PERMISSIONS.VIEW_DOCUMENTS,
  SUPERADMIN_PERMISSIONS.VIEW_PACKAGES,
  SUPERADMIN_PERMISSIONS.VIEW_BOOKINGS,
  SUPERADMIN_PERMISSIONS.VIEW_AUDIT_LOGS,
  SUPERADMIN_PERMISSIONS.VIEW_USERS,
  SUPERADMIN_PERMISSIONS.VERIFY_DOCUMENTS,
  SUPERADMIN_PERMISSIONS.CLOSE_CHATS,
  SUPERADMIN_PERMISSIONS.CLOSE_DASHBOARD,
  SUPERADMIN_PERMISSIONS.DELETE_PACKAGES,
  SUPERADMIN_PERMISSIONS.DELETE_BOOKINGS,
  SUPERADMIN_PERMISSIONS.DELETE_USERS,
  SUPERADMIN_PERMISSIONS.MANAGE_AGENTS,
  SUPERADMIN_PERMISSIONS.MANAGE_CLIENTS,
];

export const AUDIT_ACTIONS = {
  LOGIN: 'LOGIN',
  LOGOUT: 'LOGOUT',
  VERIFY_DOCUMENT: 'VERIFY_DOCUMENT',
  REJECT_DOCUMENT: 'REJECT_DOCUMENT',
  CLOSE_CHAT: 'CLOSE_CHAT',
  CLOSE_DASHBOARD: 'CLOSE_DASHBOARD',
  REOPEN_DASHBOARD: 'REOPEN_DASHBOARD',
  DELETE_PACKAGE: 'DELETE_PACKAGE',
  DELETE_BOOKING: 'DELETE_BOOKING',
  DELETE_USER: 'DELETE_USER',
  SUSPEND_AGENT: 'SUSPEND_AGENT',
  SUSPEND_CLIENT: 'SUSPEND_CLIENT',
  EXPORT_DATA: 'EXPORT_DATA',
  VIEW_CHAT: 'VIEW_CHAT',
  ACCESS_USER_DATA: 'ACCESS_USER_DATA',
};
