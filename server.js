import express from 'express';
import cors from 'cors';
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
// TRUST PROXY (CRITICAL FOR RENDER)
// ===========================================
app.set('trust proxy', 1);

// ===========================================
// CORS - MUST BE FIRST MIDDLEWARE
// ===========================================
const allowedOrigins = [
  'http://localhost:5173',
  'http://localhost:3000',
  'https://umrahmarket.vercel.app',
  ...(process.env.ALLOWED_ORIGINS?.split(',').map(o => o.trim()) || [])
].filter(Boolean);

console.log('🌐 CORS enabled for origins:', allowedOrigins);

app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (mobile apps, Postman, curl)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      console.warn('❌ CORS blocked:', origin);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  exposedHeaders: ['X-RateLimit-Limit', 'X-RateLimit-Remaining'],
  maxAge: 86400 // 24 hours
}));

// Handle preflight for all routes
app.options('*', cors());

// ===========================================
// OTHER MIDDLEWARE
// ===========================================

// Security Headers (after CORS)
app.use(securityMiddleware.securityHeaders);

// HTTPS Enforcement (but not in dev)
if (config.env === 'production') {
  app.use(securityMiddleware.httpsEnforce);
}

// Helmet (but with CORS-friendly settings)
if (config.production.enableHelmet) {
  app.use(securityMiddleware.helmet);
}

// Compression
if (config.production.enableCompression) {
  app.use(securityMiddleware.compression);
}

// Request Logger
app.use(securityMiddleware.requestLogger);

// Body Parsers
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Validation Error Handler
app.use(handleValidationErrors);

// Cookie Parser
app.use(securityMiddleware.cookieParser);

// Request Size Limiter
app.use(securityMiddleware.requestSizeLimit);

// General Rate Limiter
app.use(securityMiddleware.generalRateLimit);

// Speed Limiter (skip for uploads)
app.use((req, res, next) => {
  if (req.path.startsWith('/upload') || req.path.startsWith('/api/upload') || req.path.startsWith('/api/documents')) {
    return next();
  }
  return securityMiddleware.speedLimit(req, res, next);
});

// NoSQL Injection Prevention
app.use(securityMiddleware.sanitize);

// HTTP Parameter Pollution Prevention
app.use(securityMiddleware.hpp);

// IP Filter
app.use(securityMiddleware.ipFilter);

// ===========================================
// HEALTH & DEBUG ENDPOINTS
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

app.get('/cors-test', (req, res) => {
  res.json({
    success: true,
    message: 'CORS is working!',
    origin: req.headers.origin,
    allowedOrigins: allowedOrigins,
    env: config.env
  });
});

// ===========================================
// API ROUTES
// ===========================================
app.use('/api/auth', authRoutes);
app.use('/api/upload', uploadRoutes);
app.use('/api/documents', documentRoutes);

// ===========================================
// ROOT ENDPOINT
// ===========================================
app.get('/', (req, res) => {
  res.json({
    success: true,
    message: 'Umrah Market API',
    version: '1.0.0',
    endpoints: {
      auth: '/api/auth',
      upload: '/api/upload',
      documents: '/api/documents',
      health: '/health',
      corsTest: '/cors-test'
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
  logger.error('Unhandled error', {
    error: err.message,
    stack: err.stack,
    path: req.path,
    method: req.method,
    ip: req.ip,
  });
  
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
  
  if (config.env === 'production') {
    process.exit(1);
  }
});

// ===========================================
// START SERVER
// ===========================================
const PORT = process.env.PORT || config.port || 10000;
const server = app.listen(PORT, '0.0.0.0', async () => {
  logger.info('🚀 Server starting...', {
    port: PORT,
    environment: config.env,
    nodeVersion: process.version,
  });
  
  console.log('\n🌐 CORS Configuration:');
  console.log('   Allowed origins:', allowedOrigins);
  console.log('   Credentials:', true);
  
  const supabaseConnected = await verifySupabaseConnection();
  if (!supabaseConnected) {
    logger.warn('⚠️  Supabase connection could not be verified');
  }
  
  logger.info('✅ Server is ready', {
    port: PORT,
    environment: config.env,
    supabase: supabaseConnected ? 'connected' : 'not verified',
  });
  
  logger.info('🔒 Security features enabled:', {
    helmet: config.production.enableHelmet,
    cors: true,
    rateLimit: true,
    https: config.env === 'production' && config.production.forceHttps,
  });
});

export default app;
