import winston from 'winston';
import DailyRotateFile from 'winston-daily-rotate-file';
import config from './security.config.js';
import path from 'path';

/**
 * Security-focused logging system
 * Tracks authentication events, errors, and suspicious activities
 */

// Custom format to sanitize sensitive data
const sanitizeFormat = winston.format((info) => {
  // Remove sensitive fields from logs
  const sensitiveFields = ['password', 'token', 'refreshToken', 'jwt', 'secret', 'apiKey'];
  
  if (info.metadata) {
    sensitiveFields.forEach(field => {
      if (info.metadata[field]) {
        info.metadata[field] = '[REDACTED]';
      }
    });
  }
  
  return info;
});

// Create logs directory if it doesn't exist
const logDir = config.logging.filePath;

// Define log format
const logFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.errors({ stack: true }),
  sanitizeFormat(),
  winston.format.metadata(),
  winston.format.json()
);

// Console format for development
const consoleFormat = winston.format.combine(
  winston.format.colorize(),
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.printf(({ timestamp, level, message, ...metadata }) => {
    let msg = `${timestamp} [${level}]: ${message}`;
    if (Object.keys(metadata).length > 0) {
      msg += ` ${JSON.stringify(metadata)}`;
    }
    return msg;
  })
);

// Transport for all logs
const allLogsTransport = new DailyRotateFile({
  filename: path.join(logDir, 'application-%DATE%.log'),
  datePattern: 'YYYY-MM-DD',
  maxSize: '20m',
  maxFiles: '14d',
  format: logFormat,
});

// Transport for error logs only
const errorLogsTransport = new DailyRotateFile({
  filename: path.join(logDir, 'error-%DATE%.log'),
  datePattern: 'YYYY-MM-DD',
  level: 'error',
  maxSize: '20m',
  maxFiles: '30d',
  format: logFormat,
});

// Transport for security events
const securityLogsTransport = new DailyRotateFile({
  filename: path.join(logDir, 'security-%DATE%.log'),
  datePattern: 'YYYY-MM-DD',
  maxSize: '20m',
  maxFiles: '90d', // Keep security logs longer
  format: logFormat,
});

// Transport for audit trail
const auditLogsTransport = new DailyRotateFile({
  filename: path.join(logDir, 'audit-%DATE%.log'),
  datePattern: 'YYYY-MM-DD',
  maxSize: '20m',
  maxFiles: '365d', // Keep audit logs for 1 year
  format: logFormat,
});

// Create the logger
const logger = winston.createLogger({
  level: config.logging.level,
  format: logFormat,
  transports: [
    allLogsTransport,
    errorLogsTransport,
  ],
  exceptionHandlers: [
    new DailyRotateFile({
      filename: path.join(logDir, 'exceptions-%DATE%.log'),
      datePattern: 'YYYY-MM-DD',
      maxSize: '20m',
      maxFiles: '30d',
    }),
  ],
  rejectionHandlers: [
    new DailyRotateFile({
      filename: path.join(logDir, 'rejections-%DATE%.log'),
      datePattern: 'YYYY-MM-DD',
      maxSize: '20m',
      maxFiles: '30d',
    }),
  ],
});

// Add console transport in development
if (config.env !== 'production') {
  logger.add(new winston.transports.Console({
    format: consoleFormat,
  }));
}

// Security-specific logger
export const securityLogger = winston.createLogger({
  level: 'info',
  format: logFormat,
  transports: [securityLogsTransport],
});

// Audit-specific logger
export const auditLogger = winston.createLogger({
  level: 'info',
  format: logFormat,
  transports: [auditLogsTransport],
});

// Helper functions for structured logging
export const logSecurityEvent = (event, details = {}) => {
  securityLogger.info(event, {
    timestamp: new Date().toISOString(),
    event,
    ...details,
  });
};

export const logAuthAttempt = (success, userId, ip, userAgent, details = {}) => {
  auditLogger.info('Authentication Attempt', {
    timestamp: new Date().toISOString(),
    success,
    userId,
    ip,
    userAgent,
    ...details,
  });
};

export const logFileUpload = (userId, filename, fileType, fileSize, success, ip) => {
  auditLogger.info('File Upload', {
    timestamp: new Date().toISOString(),
    userId,
    filename,
    fileType,
    fileSize,
    success,
    ip,
  });
};

export const logSuspiciousActivity = (type, details = {}) => {
  securityLogger.warn('Suspicious Activity Detected', {
    timestamp: new Date().toISOString(),
    type,
    severity: 'high',
    ...details,
  });
};

export const logRateLimitExceeded = (ip, endpoint, userAgent) => {
  securityLogger.warn('Rate Limit Exceeded', {
    timestamp: new Date().toISOString(),
    ip,
    endpoint,
    userAgent,
  });
};

export const logAccountLockout = (userId, ip, reason) => {
  securityLogger.warn('Account Locked', {
    timestamp: new Date().toISOString(),
    userId,
    ip,
    reason,
  });
};

export default logger;