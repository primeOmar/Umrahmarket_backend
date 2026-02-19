import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import config, { validateConfig } from './config/security.config.js';
import logger from './config/logger.js';
import { verifySupabaseConnection } from './config/supabase.js';
import securityMiddleware from './middleware/security.middleware.js';
import { handleValidationErrors } from './middleware/validation.middleware.js';
import authRoutes from './routes/auth.routes.js';
import uploadRoutes from './routes/upload.routes.js';
import documentRoutes from './routes/document.routes.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/**
 * SECURE EXPRESS SERVER
 * World-class authentication backend with comprehensive security
 */

// ===========================================
// VALIDATE CONFIGURATION
// ===========================================
try {
  validateConfig();
  logger.info('Configuration validated successfully');
} catch (error) {
  logger.error('Configuration validation failed', { error: error.message });
  process.exit(1);
}

// ===========================================
// INITIALIZE EXPRESS APP
// ===========================================
const app = express();

// ===========================================
// TRUST PROXY (for accurate IP detection behind load balancers)
// ===========================================
if (config.production.trustProxy) {
  app.set('trust proxy', 1);
}

// ===========================================
// MIDDLEWARE - ORDER MATTERS!
// ===========================================

// 1. CORS — must be first so the OPTIONS preflight gets
//    Access-Control-Allow-* headers before anything else
//    can reject or redirect the request.
app.use(securityMiddleware.cors);
app.options('*', securityMiddleware.cors); // explicit preflight short-circuit

// 2. Security Headers
app.use(securityMiddleware.securityHeaders);

// 3. HTTPS Enforcement
app.use(securityMiddleware.httpsEnforce);

// 4. Helmet (Security Headers)
if (config.production.enableHelmet) {
  app.use(securityMiddleware.helmet);
}

// 5. Compression
if (config.production.enableCompression) {
  app.use(securityMiddleware.compression);
}

// 6. Request Logger
app.use(securityMiddleware.requestLogger);

// 7. Body Parsers with size limits
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// 8. Validation Error Handler
app.use(handleValidationErrors);

// 9. Cookie Parser
app.use(securityMiddleware.cookieParser);

// 9. Request Size Limiter
app.use(securityMiddleware.requestSizeLimit);

// 10. General Rate Limiter
app.use(securityMiddleware.generalRateLimit);

// 11. Speed Limiter — skip for file uploads (legitimately slow, timeout otherwise)
app.use((req, res, next) => {
  if (req.path.startsWith('/upload')) return next();
  return securityMiddleware.speedLimit(req, res, next);
});

// 12. NoSQL Injection Prevention
app.use(securityMiddleware.sanitize);

// 13. HTTP Parameter Pollution Prevention
app.use(securityMiddleware.hpp);

// 14. IP Filter (Blacklist)
app.use(securityMiddleware.ipFilter);

// ===========================================
// HEALTH CHECK ENDPOINT
// ===========================================
app.get('/health', (req, res) => {
  res.status(200).json({
    success: true,
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: config.env,
  });
});

// ===========================================
// API ROUTES
// ===========================================
app.use('/api/auth',      authRoutes);
app.use('/api/upload',    uploadRoutes);
app.use('/api/documents', documentRoutes); // Agent document uploads


// ===========================================
// ROOT ENDPOINT
// ===========================================
app.get('/', (req, res) => {
  res.json({
    success: true,
    message: 'Secure Authentication API',
    version: '1.0.0',
    documentation: '/api/docs',
    endpoints: {
      auth: '/api/auth',
      upload: '/api/upload',
      health: '/health',
    },
  });
});

// ===========================================
// 404 HANDLER
// ===========================================
app.use((req, res) => {
  logger.warn('404 Not Found', {
    method: req.method,
    path: req.path,
    ip: req.ip,
  });
  
  res.status(404).json({
    success: false,
    error: 'Endpoint not found',
    requestedPath: req.path,
  });
});

// ===========================================
// GLOBAL ERROR HANDLER
// ===========================================
app.use((err, req, res, next) => {
  // Log error
  logger.error('Unhandled error', {
    error: err.message,
    stack: err.stack,
    path: req.path,
    method: req.method,
    ip: req.ip,
  });
  
  // Don't leak error details in production
  const errorMessage = config.env === 'production'
    ? 'An unexpected error occurred'
    : err.message;
  
  res.status(err.status || 500).json({
    success: false,
    error: errorMessage,
    ...(config.env !== 'production' && { stack: err.stack }),
  });
});

// ===========================================
// GRACEFUL SHUTDOWN
// ===========================================
const gracefulShutdown = (signal) => {
  logger.info(`Received ${signal}, shutting down gracefully...`);
  
  server.close(() => {
    logger.info('Server closed');
    process.exit(0);
  });
  
  // Force shutdown after 30 seconds
  setTimeout(() => {
    logger.error('Forced shutdown after timeout');
    process.exit(1);
  }, 30000);
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// ===========================================
// UNHANDLED REJECTIONS & EXCEPTIONS
// ===========================================
process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection', {
    reason: reason instanceof Error ? reason.message : reason,
    stack: reason instanceof Error ? reason.stack : undefined,
  });
});

process.on('uncaughtException', (error) => {
  logger.error('Uncaught Exception', {
    error: error.message,
    stack: error.stack,
  });
  
  // Exit process in production for safety
  if (config.env === 'production') {
    process.exit(1);
  }
});

// ===========================================
// START SERVER
// ===========================================
const server = app.listen(config.port, async () => {
  logger.info('🚀 Server starting...', {
    port: config.port,
    environment: config.env,
    nodeVersion: process.version,
  });
  
  // Verify Supabase connection
  const supabaseConnected = await verifySupabaseConnection();
  if (!supabaseConnected) {
    logger.warn('Supabase connection could not be verified. Some features may not work.');
  }
  
  logger.info('✅ Server is ready', {
    port: config.port,
    environment: config.env,
    supabase: supabaseConnected ? 'connected' : 'not verified',
  });
  
  // Display security features enabled
  logger.info('🔒 Security features enabled:', {
    helmet: config.production.enableHelmet,
    cors: true,
    rateLimit: true,
    inputValidation: true,
    fileUploadValidation: true,
    jwtAuth: true,
    accountLockout: true,
    https: config.production.forceHttps,
  });
});

export default app;