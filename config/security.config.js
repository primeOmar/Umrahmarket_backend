import dotenv from 'dotenv';
dotenv.config();

/**
 * Security Configuration
 * All security-related settings centralized here
 */

const config = {
  // Environment
  env: process.env.NODE_ENV || 'development',
  port: parseInt(process.env.PORT) || 5000,
  
  // Supabase
  supabase: {
    url: process.env.SUPABASE_URL,
    anonKey: process.env.SUPABASE_ANON_KEY,
    serviceRoleKey: process.env.SUPABASE_SERVICE_ROLE_KEY,
  },
  
  // JWT
  jwt: {
    accessTokenSecret: process.env.JWT_SECRET,
    refreshTokenSecret: process.env.JWT_REFRESH_SECRET,
    accessTokenExpiry: process.env.JWT_EXPIRES_IN || '15m',
    refreshTokenExpiry: process.env.JWT_REFRESH_EXPIRES_IN || '7d',
    secret: process.env.JWT_SECRET, // Keep for backward compatibility
    expiresIn: process.env.JWT_EXPIRES_IN || '15m',
    refreshSecret: process.env.JWT_REFRESH_SECRET,
    refreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d',
    issuer: 'secure-auth-backend',
    audience: 'web-app',
  },
  
  // Cookie
  cookie: {
    secret: process.env.COOKIE_SECRET,
    domain: process.env.COOKIE_DOMAIN || 'localhost',
    secure: process.env.COOKIE_SECURE === 'true',
    httpOnly: process.env.COOKIE_HTTPONLY !== 'false',
    sameSite: process.env.COOKIE_SAMESITE || 'strict',
  },
  
  // CORS
  cors: {
    allowedOrigins: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],['https://umrahmarket-backend.onrender.com'],
    credentials: true,
  },
  
  // Rate Limiting
 rateLimiting: {
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 60 * 60 * 1000,
  maxRequests: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100,
  loginWindowMs: parseInt(process.env.LOGIN_RATE_LIMIT_WINDOW_MS) || 60 * 60 * 1000,
  loginMaxAttempts: parseInt(process.env.LOGIN_RATE_LIMIT_MAX_ATTEMPTS) || (process.env.NODE_ENV === 'development' ? 100 : 20),
},
  
  // File Upload
  fileUpload: {
    maxFileSize: parseInt(process.env.MAX_FILE_SIZE) || 5 * 1024 * 1024, // 5MB
    allowedTypes: process.env.ALLOWED_FILE_TYPES?.split(',') || [
      'image/jpeg',
      'image/png',
      'image/jpg',
      'application/pdf'
    ],
    uploadDir: process.env.UPLOAD_DIR || './uploads',
  },
  
  // Security Settings
  security: {
    maxLoginAttempts: parseInt(process.env.MAX_LOGIN_ATTEMPTS) || 5,
    lockoutDuration: parseInt(process.env.LOCKOUT_DURATION_MS) || 30 * 60 * 1000, // 30 minutes
    sessionTimeout: parseInt(process.env.SESSION_TIMEOUT_MS) || 60 * 60 * 1000, // 1 hour
    enable2FA: process.env.ENABLE_2FA === 'true',
    
    password: {
      minLength: parseInt(process.env.MIN_PASSWORD_LENGTH) || 8,
      requireUppercase: process.env.REQUIRE_UPPERCASE !== 'false',
      requireLowercase: process.env.REQUIRE_LOWERCASE !== 'false',
      requireNumbers: process.env.REQUIRE_NUMBERS !== 'false',
      requireSpecialChars: process.env.REQUIRE_SPECIAL_CHARS !== 'false',
    },
  },
  
  // Google OAuth
  google: {
    clientId: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackUrl: process.env.GOOGLE_CALLBACK_URL,
  },
  
  // Email
  email: {
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT) || 587,
    secure: process.env.SMTP_SECURE === 'true',
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
  
  // Logging
  logging: {
    level: process.env.LOG_LEVEL || 'info',
    filePath: process.env.LOG_FILE_PATH || './logs',
    enableRequestLogging: process.env.ENABLE_REQUEST_LOGGING !== 'false',
    enableErrorLogging: process.env.ENABLE_ERROR_LOGGING !== 'false',
  },
  
  // Admin
  admin: {
    email: process.env.ADMIN_EMAIL,
    alertEmail: process.env.ADMIN_ALERT_EMAIL,
  },
  
  // Production Settings
  production: {
    forceHttps: process.env.FORCE_HTTPS === 'true',
    trustProxy: process.env.TRUST_PROXY === 'true',
    enableHelmet: process.env.ENABLE_HELMET !== 'false',
    enableCompression: process.env.ENABLE_COMPRESSION !== 'false',
  },
};

// Validation function to ensure critical configs are set
export const validateConfig = () => {
  const required = [
    'SUPABASE_URL',
    'SUPABASE_ANON_KEY',
    'JWT_SECRET',
    'COOKIE_SECRET',
  ];
  
  const missing = required.filter(key => !process.env[key]);
  
  if (missing.length > 0) {
    throw new Error(
      `Missing required environment variables: ${missing.join(', ')}\n` +
      'Please check your .env file and ensure all required variables are set.'
    );
  }
  
  // Validate JWT secret length
  if (process.env.JWT_SECRET && process.env.JWT_SECRET.length < 32) {
    throw new Error('JWT_SECRET must be at least 32 characters long for security');
  }
  
  // Validate Supabase URL format
  if (config.supabase.url && !config.supabase.url.includes('supabase.co')) {
    console.warn('Warning: SUPABASE_URL format looks incorrect');
  }
  
  return true;
};

export default config;
