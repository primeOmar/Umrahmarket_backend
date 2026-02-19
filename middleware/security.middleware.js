import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import slowDown from 'express-slow-down';
import mongoSanitize from 'express-mongo-sanitize';
import hpp from 'hpp';
import cookieParser from 'cookie-parser';
import compression from 'compression';
import config from '../config/security.config.js';
import logger, { logRateLimitExceeded, logSuspiciousActivity } from '../config/logger.js';

/**
 * Security Middleware Collection
 * Implements multiple layers of protection following OWASP Top 10 & industry standards.
 *
 * Layer Order (applied in server.js):
 *  1.  securityHeaders     – Custom hardening headers
 *  2.  httpsEnforce        – Force HTTPS in production
 *  3.  helmet              – Comprehensive HTTP security headers
 *  4.  cors                – Cross-Origin Resource Sharing
 *  5.  compression         – Gzip/Brotli response compression
 *  6.  requestLogger       – Structured access logging
 *  7.  cookieParser        – Signed cookie support
 *  8.  requestSizeLimit    – Reject oversized payloads
 *  9.  generalRateLimit    – Global request throttle
 *  10. speedLimit          – Progressive slowdown for abusive clients
 *  11. sanitize            – NoSQL / MongoDB injection prevention
 *  12. hpp                 – HTTP Parameter Pollution prevention
 *  13. ipFilter            – IP blocklist enforcement
 *
 * Per-route rate limiters (imported directly by route files):
 *  - authRateLimiter       – Strict limit on /api/auth endpoints
 *  - uploadRateLimiter     – Hourly upload quota enforcement
 */

// ─────────────────────────────────────────────
// 1. HELMET – Security Headers (OWASP A05)
// ─────────────────────────────────────────────
export const helmetMiddleware = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:   ["'self'"],
      scriptSrc:    ["'self'"],
      styleSrc:     ["'self'", "'unsafe-inline'"],
      imgSrc:       ["'self'", 'data:', 'https:'],
      fontSrc:      ["'self'"],
      connectSrc:   ["'self'", config.supabase.url].filter(Boolean),
      objectSrc:    ["'none'"],
      mediaSrc:     ["'self'"],
      frameSrc:     ["'none'"],
      baseUri:      ["'self'"],
      formAction:   ["'self'"],
      frameAncestors: ["'none'"],
      upgradeInsecureRequests: [],
    },
  },
  hsts: {
    maxAge: 31536000, // 1 year
    includeSubDomains: true,
    preload: true,
  },
  frameguard:      { action: 'deny' },
  noSniff:         true,
  referrerPolicy:  { policy: 'strict-origin-when-cross-origin' },
  crossOriginEmbedderPolicy: false,                              // would block cross-origin resources
  crossOriginOpenerPolicy:   { policy: 'same-origin-allow-popups' }, // 'same-origin' kills cross-origin windows
  crossOriginResourcePolicy: { policy: 'cross-origin' },         // 'same-origin' strips CORS responses
  originAgentCluster: true,
  dnsPrefetchControl: { allow: false },
  ieNoOpen: true,
  permittedCrossDomainPolicies: { permittedPolicies: 'none' },
  // xssFilter is deprecated in modern browsers — Helmet still adds it for legacy support
  xssFilter: true,
});

// ─────────────────────────────────────────────
// 2. CORS – Cross-Origin Resource Sharing
// ─────────────────────────────────────────────
export const corsMiddleware = cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (native mobile apps, Postman, server-to-server)
    if (!origin) return callback(null, true);

    if (config.cors.allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      logger.warn('CORS blocked request', { origin });
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials:    config.cors.credentials,
  methods:        ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'X-Requested-With',
    'X-CSRF-Token',
  ],
  exposedHeaders: ['X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset'],
  maxAge: 86400, // 24 hours – browsers cache pre-flight results
});

// ─────────────────────────────────────────────
// 3. RATE LIMITING – General (OWASP A04)
// ─────────────────────────────────────────────
export const generalRateLimiter = rateLimit({
  windowMs:       config.rateLimiting.windowMs,
  max:            config.rateLimiting.maxRequests,
  standardHeaders: true,  // Return rate limit info in RateLimit-* headers (RFC 6585)
  legacyHeaders:  false,  // Disable X-RateLimit-* legacy headers
  handler: (req, res) => {
    logRateLimitExceeded(req.ip, req.originalUrl, req.get('user-agent'));
    res.status(429).json({
      success:    false,
      error:      'Too many requests. Please try again later.',
      retryAfter: Math.ceil(config.rateLimiting.windowMs / 1000),
    });
  },
  skip: (req) => req.path === '/health', // Health checks are never rate-limited
});

// ─────────────────────────────────────────────
// 4. RATE LIMITING – Authentication Routes
//    Exported individually so auth.routes.js can import directly.
// ─────────────────────────────────────────────
export const authRateLimiter = rateLimit({
  windowMs:               config.rateLimiting.loginWindowMs,
  max:                    config.rateLimiting.loginMaxAttempts,
  skipSuccessfulRequests: true, // Only count failed attempts toward the limit
  standardHeaders:        true,
  legacyHeaders:          false,
  handler: (req, res) => {
    logRateLimitExceeded(req.ip, req.originalUrl, req.get('user-agent'));
    logSuspiciousActivity('Excessive login attempts', {
      ip:        req.ip,
      userAgent: req.get('user-agent'),
      email:     req.body?.email,
    });
    res.status(429).json({
      success:    false,
      error:      'Too many login attempts. Please try again in 15 minutes.',
      retryAfter: Math.ceil(config.rateLimiting.loginWindowMs / 1000),
    });
  },
});

// ─────────────────────────────────────────────
// 5. RATE LIMITING – File Upload Routes
// ─────────────────────────────────────────────
export const uploadRateLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour window
  max:      10,              // 10 uploads per IP per hour
  standardHeaders: true,
  legacyHeaders:   false,
  handler: (req, res) => {
    logRateLimitExceeded(req.ip, req.originalUrl, req.get('user-agent'));
    res.status(429).json({
      success: false,
      error:   'Upload limit exceeded. Please try again later.',
    });
  },
});

// ─────────────────────────────────────────────
// 6. SPEED LIMITER – Progressive Slowdown
//    Complements rate-limiting: slows repeated abusers
//    before hard-blocking them (better UX for edge cases).
// ─────────────────────────────────────────────
export const speedLimiter = slowDown({
  windowMs:    15 * 60 * 1000, // 15-minute sliding window
  delayAfter:  50,             // First 50 req/window at full speed
  delayMs:     (used) => (used - 50) * 500, // +500 ms per extra request
  maxDelayMs:  5000,           // Cap at 5 s delay
});

// ─────────────────────────────────────────────
// 7. SANITIZATION – NoSQL Injection Prevention (OWASP A03)
// ─────────────────────────────────────────────
export const sanitizeMiddleware = mongoSanitize({
  replaceWith: '_',
  onSanitize: ({ req, key }) => {
    logger.warn('Request sanitized – potential NoSQL injection attempt', {
      ip:   req.ip,
      key,
      path: req.path,
    });
  },
});

// ─────────────────────────────────────────────
// 8. HPP – HTTP Parameter Pollution Prevention
// ─────────────────────────────────────────────
export const hppMiddleware = hpp({
  // Allow these params to be repeated (e.g. ?page=1&page=2 is valid for some APIs)
  whitelist: ['page', 'limit', 'sort', 'fields'],
});

// ─────────────────────────────────────────────
// 9. COOKIE PARSER – Signed Cookie Support
// ─────────────────────────────────────────────
export const cookieParserMiddleware = cookieParser(config.cookie.secret);

// ─────────────────────────────────────────────
// 10. COMPRESSION – Gzip/Brotli Response Compression
// ─────────────────────────────────────────────
export const compressionMiddleware = compression({
  filter: (req, res) => {
    // Opt-out header for clients that don't support compression
    if (req.headers['x-no-compression']) return false;
    return compression.filter(req, res);
  },
  level: 6, // Balanced compression (0 = none, 9 = max CPU cost)
});

// ─────────────────────────────────────────────
// 11. REQUEST SIZE LIMITER – Prevent Large Payload Attacks (OWASP A06)
// ─────────────────────────────────────────────
export const requestSizeLimiter = (req, res, next) => {
  const maxSize = 10 * 1024 * 1024; // 10 MB

  const contentLength = parseInt(req.headers['content-length'], 10);
  if (!isNaN(contentLength) && contentLength > maxSize) {
    logger.warn('Request payload too large', {
      ip:   req.ip,
      size: contentLength,
      path: req.path,
    });
    return res.status(413).json({
      success: false,
      error:   'Request entity too large. Maximum allowed size is 10 MB.',
    });
  }

  next();
};

// ─────────────────────────────────────────────
// 12. HTTPS ENFORCER – Redirect HTTP → HTTPS (OWASP A02)
// ─────────────────────────────────────────────
export const httpsEnforcer = (req, res, next) => {
  if (config.env === 'production' && config.production.forceHttps) {
    // Check proto forwarded by load-balancer / reverse proxy
    const proto = req.headers['x-forwarded-proto'] || req.protocol;
    if (proto !== 'https') {
      return res.redirect(301, `https://${req.headers.host}${req.url}`);
    }
  }
  next();
};

// ─────────────────────────────────────────────
// 13. IP FILTER – Blocklist Enforcement
//     In production, populate blacklistedIPs from Redis or a DB.
// ─────────────────────────────────────────────
const blacklistedIPs = new Set(
  (process.env.BLOCKED_IPS || '').split(',').filter(Boolean)
);

export const ipFilter = (req, res, next) => {
  // Prefer X-Forwarded-For (set by trusted proxy) over socket address
  const clientIP =
    (req.headers['x-forwarded-for'] || '').split(',')[0].trim() ||
    req.ip ||
    req.socket?.remoteAddress;

  if (clientIP && blacklistedIPs.has(clientIP)) {
    logSuspiciousActivity('Blocklisted IP access attempt', {
      ip:   clientIP,
      path: req.path,
    });
    return res.status(403).json({
      success: false,
      error:   'Access denied.',
    });
  }

  next();
};

// ─────────────────────────────────────────────
// 14. SECURITY HEADERS – Custom Hardening Layer
//     Applied before Helmet to guarantee presence even if Helmet is disabled.
// ─────────────────────────────────────────────
export const securityHeaders = (req, res, next) => {
  // Strip fingerprinting headers
  res.removeHeader('X-Powered-By');
  res.removeHeader('Server');

  // Layered defence-in-depth headers
  res.setHeader('X-Content-Type-Options',     'nosniff');
  res.setHeader('X-Frame-Options',            'DENY');
  res.setHeader('X-XSS-Protection',           '1; mode=block');
  res.setHeader(
    'Strict-Transport-Security',
    'max-age=31536000; includeSubDomains; preload'
  );
  res.setHeader(
    'Permissions-Policy',
    'geolocation=(), microphone=(), camera=(), payment=(), usb=(), interest-cohort=()'
  );
  res.setHeader('X-DNS-Prefetch-Control', 'off');
  res.setHeader('X-Download-Options',     'noopen');
  res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');

  next();
};

// ─────────────────────────────────────────────
// 15. REQUEST LOGGER – Structured Access Logging
// ─────────────────────────────────────────────
export const requestLogger = (req, res, next) => {
  if (!config.logging.enableRequestLogging) return next();

  const start = Date.now();

  res.on('finish', () => {
    const duration = Date.now() - start;

    // Log at 'warn' level for 4xx/5xx to make errors more visible
    const level = res.statusCode >= 400 ? 'warn' : 'info';

    logger[level]('HTTP request', {
      method:     req.method,
      path:       req.path,
      statusCode: res.statusCode,
      duration:   `${duration}ms`,
      ip:         req.ip,
      userAgent:  req.get('user-agent'),
      referrer:   req.get('referer') || '-',
    });
  });

  next();
};

// ─────────────────────────────────────────────
// Default export – single object consumed by server.js
// ─────────────────────────────────────────────
export default {
  helmet:           helmetMiddleware,
  cors:             corsMiddleware,
  generalRateLimit: generalRateLimiter,
  authRateLimit:    authRateLimiter,
  uploadRateLimit:  uploadRateLimiter,
  speedLimit:       speedLimiter,
  sanitize:         sanitizeMiddleware,
  hpp:              hppMiddleware,
  cookieParser:     cookieParserMiddleware,
  compression:      compressionMiddleware,
  requestSizeLimit: requestSizeLimiter,
  httpsEnforce:     httpsEnforcer,
  ipFilter,
  securityHeaders,
  requestLogger,
};