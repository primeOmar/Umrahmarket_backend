import multer from 'multer';
import { fileTypeFromBuffer } from 'file-type';
import path from 'path';
import crypto from 'crypto';
import fs from 'fs/promises';
import config from '../config/security.config.js';
import logger, { logFileUpload, logSuspiciousActivity } from '../config/logger.js';

/**
 * Secure File Upload Middleware
 * Implements comprehensive file validation and security checks
 */

// ===========================================
// File Upload Configuration
// ===========================================

// Ensure upload directory exists
const ensureUploadDir = async () => {
  try {
    await fs.access(config.fileUpload.uploadDir);
  } catch {
    await fs.mkdir(config.fileUpload.uploadDir, { recursive: true });
    logger.info('Created upload directory', { path: config.fileUpload.uploadDir });
  }
};

ensureUploadDir();

// ===========================================
// Storage Configuration
// ===========================================
const storage = multer.diskStorage({
  destination: async (req, file, cb) => {
    try {
      // Create user-specific folder
      const userFolder = path.join(
        config.fileUpload.uploadDir,
        req.userId || 'anonymous'
      );
      
      await fs.mkdir(userFolder, { recursive: true });
      cb(null, userFolder);
    } catch (error) {
      logger.error('Failed to create upload directory', { error: error.message });
      cb(error);
    }
  },
  
  filename: (req, file, cb) => {
    // Generate secure filename
    const uniqueSuffix = crypto.randomBytes(16).toString('hex');
    const timestamp = Date.now();
    const ext = path.extname(file.originalname);
    const safeName = `${timestamp}-${uniqueSuffix}${ext}`;
    
    cb(null, safeName);
  },
});

// ===========================================
// File Filter - MIME Type Validation
// ===========================================
const fileFilter = (req, file, cb) => {
  // Check MIME type from header
  const allowedMimes = config.fileUpload.allowedTypes;
  
  if (!allowedMimes.includes(file.mimetype)) {
    logger.warn('File upload rejected - invalid MIME type', {
      mimetype: file.mimetype,
      originalname: file.originalname,
      userId: req.userId,
      ip: req.ip,
    });
    
    return cb(
      new Error(`Invalid file type. Allowed types: ${allowedMimes.join(', ')}`),
      false
    );
  }
  
  // Check file extension
  const ext = path.extname(file.originalname).toLowerCase();
  const allowedExtensions = ['.jpg', '.jpeg', '.png', '.pdf'];
  
  if (!allowedExtensions.includes(ext)) {
    logger.warn('File upload rejected - invalid extension', {
      extension: ext,
      originalname: file.originalname,
      userId: req.userId,
      ip: req.ip,
    });
    
    return cb(new Error('Invalid file extension'), false);
  }
  
  cb(null, true);
};

// ===========================================
// Multer Configuration
// ===========================================
const upload = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: config.fileUpload.maxFileSize, // 5MB
    files: 5, // Max 5 files per request
    fields: 20, // Max 20 non-file fields
    parts: 25, // Max 25 parts (files + fields)
  },
});

// ===========================================
// Deep File Validation Middleware
// ===========================================
export const validateFileContent = async (req, res, next) => {
  try {
    if (!req.files && !req.file) {
      return next();
    }
    
    const files = req.files 
      ? (Array.isArray(req.files) ? req.files : Object.values(req.files).flat())
      : [req.file];
    
    for (const file of files) {
      if (!file) continue;
      
      // Read file buffer for deep inspection
      const buffer = await fs.readFile(file.path);
      
      // Verify actual file type from content
      const fileType = await fileTypeFromBuffer(buffer);
      
      if (!fileType) {
        await fs.unlink(file.path);
        logSuspiciousActivity('File upload - unable to determine file type', {
          originalname: file.originalname,
          mimetype: file.mimetype,
          userId: req.userId,
          ip: req.ip,
        });
        
        return res.status(400).json({
          success: false,
          error: 'Unable to verify file type. File may be corrupted.',
        });
      }
      
      // Verify MIME type matches claimed type
      if (fileType.mime !== file.mimetype) {
        await fs.unlink(file.path);
        logSuspiciousActivity('MIME type mismatch detected', {
          claimed: file.mimetype,
          actual: fileType.mime,
          userId: req.userId,
          ip: req.ip,
        });
        
        return res.status(400).json({
          success: false,
          error: 'File type mismatch detected. Possible file manipulation.',
        });
      }
      
      // Additional security checks
      await performSecurityChecks(buffer, file);
      
      // Log successful upload
      logFileUpload(
        req.userId,
        file.filename,
        file.mimetype,
        file.size,
        true,
        req.ip
      );
    }
    
    next();
  } catch (error) {
    logger.error('File validation failed', {
      error: error.message,
      userId: req.userId,
    });
    
    // Clean up uploaded files on error
    if (req.files || req.file) {
      const files = req.files 
        ? (Array.isArray(req.files) ? req.files : Object.values(req.files).flat())
        : [req.file];
      
      for (const file of files) {
        if (file && file.path) {
          try {
            await fs.unlink(file.path);
          } catch (unlinkError) {
            logger.error('Failed to clean up file', {
              file: file.path,
              error: unlinkError.message,
            });
          }
        }
      }
    }
    
    return res.status(500).json({
      success: false,
      error: 'File validation failed',
    });
  }
};

// ===========================================
// Security Checks
// ===========================================
const performSecurityChecks = async (buffer, file) => {
  // Check for executable content in PDF
  if (file.mimetype === 'application/pdf') {
    const pdfString = buffer.toString('utf8');
    
    // Check for JavaScript in PDF
    if (pdfString.includes('/JavaScript') || pdfString.includes('/JS')) {
      throw new Error('PDF contains potentially malicious JavaScript');
    }
    
    // Check for embedded files
    if (pdfString.includes('/EmbeddedFile')) {
      logger.warn('PDF contains embedded files', {
        filename: file.filename,
      });
    }
  }
  
  // Check for PHP code in images (web shell attempts)
  if (file.mimetype.startsWith('image/')) {
    const imageString = buffer.toString('utf8');
    
    if (imageString.includes('<?php') || imageString.includes('<?=')) {
      throw new Error('Image contains executable code');
    }
  }
  
  // Check file size again (redundant check)
  if (buffer.length > config.fileUpload.maxFileSize) {
    throw new Error('File size exceeds limit');
  }
  
  // Check for null bytes (path traversal attempt)
  if (buffer.includes(0x00)) {
    throw new Error('File contains null bytes');
  }
};

// ===========================================
// Sanitize Filename
// ===========================================
export const sanitizeFilename = (filename) => {
  // Remove path traversal attempts
  let safe = filename.replace(/\.\.\//g, '');
  safe = safe.replace(/\.\./g, '');
  
  // Remove special characters except dots and hyphens
  safe = safe.replace(/[^a-zA-Z0-9._-]/g, '_');
  
  // Limit length
  if (safe.length > 255) {
    const ext = path.extname(safe);
    const name = path.basename(safe, ext);
    safe = name.substring(0, 255 - ext.length) + ext;
  }
  
  return safe;
};

// ===========================================
// File Size Validator
// ===========================================
export const validateFileSize = (req, res, next) => {
  if (!req.files && !req.file) {
    return next();
  }
  
  const files = req.files 
    ? (Array.isArray(req.files) ? req.files : Object.values(req.files).flat())
    : [req.file];
  
  for (const file of files) {
    if (file && file.size > config.fileUpload.maxFileSize) {
      return res.status(400).json({
        success: false,
        error: `File ${file.originalname} exceeds maximum size of ${config.fileUpload.maxFileSize / 1024 / 1024}MB`,
      });
    }
  }
  
  next();
};

// ===========================================
// Virus Scanning (Optional - requires ClamAV)
// ===========================================
// Uncomment and configure if you have ClamAV installed
/*
import NodeClam from 'clamscan';

const ClamScan = await new NodeClam().init({
  clamdscan: {
    host: 'localhost',
    port: 3310,
  },
});

export const scanForViruses = async (req, res, next) => {
  try {
    if (!req.files && !req.file) {
      return next();
    }
    
    const files = req.files 
      ? (Array.isArray(req.files) ? req.files : Object.values(req.files).flat())
      : [req.file];
    
    for (const file of files) {
      if (!file) continue;
      
      const { isInfected, viruses } = await ClamScan.isInfected(file.path);
      
      if (isInfected) {
        await fs.unlink(file.path);
        
        logSuspiciousActivity('Virus detected in upload', {
          filename: file.filename,
          viruses,
          userId: req.userId,
          ip: req.ip,
        });
        
        return res.status(400).json({
          success: false,
          error: 'File rejected: malware detected',
        });
      }
    }
    
    next();
  } catch (error) {
    logger.error('Virus scan failed', { error: error.message });
    next(); // Continue even if scan fails (or fail closed in production)
  }
};
*/

// ===========================================
// Export Multer Upload Handlers
// ===========================================

// Single file upload
export const uploadSingle = (fieldName) => upload.single(fieldName);

// Multiple files upload (same field)
export const uploadMultiple = (fieldName, maxCount = 5) => 
  upload.array(fieldName, maxCount);

// Multiple files upload (different fields)
export const uploadFields = (fields) => upload.fields(fields);

// Any files
export const uploadAny = () => upload.any();

// ===========================================
// Error Handler for Multer
// ===========================================
export const handleUploadError = (err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    logger.warn('Multer error', {
      error: err.message,
      code: err.code,
      field: err.field,
      userId: req.userId,
      ip: req.ip,
    });
    
    let errorMessage = 'File upload failed';
    
    switch (err.code) {
      case 'LIMIT_FILE_SIZE':
        errorMessage = `File too large. Maximum size is ${config.fileUpload.maxFileSize / 1024 / 1024}MB`;
        break;
      case 'LIMIT_FILE_COUNT':
        errorMessage = 'Too many files uploaded';
        break;
      case 'LIMIT_UNEXPECTED_FILE':
        errorMessage = 'Unexpected file field';
        break;
      case 'LIMIT_FIELD_COUNT':
        errorMessage = 'Too many fields';
        break;
      case 'LIMIT_FIELD_KEY':
        errorMessage = 'Field name too long';
        break;
      case 'LIMIT_FIELD_VALUE':
        errorMessage = 'Field value too long';
        break;
      case 'LIMIT_PART_COUNT':
        errorMessage = 'Too many parts';
        break;
      default:
        errorMessage = err.message;
    }
    
    return res.status(400).json({
      success: false,
      error: errorMessage,
    });
  }
  
  if (err) {
    logger.error('File upload error', {
      error: err.message,
      userId: req.userId,
      ip: req.ip,
    });
    
    return res.status(400).json({
      success: false,
      error: err.message || 'File upload failed',
    });
  }
  
  next();
};

// ===========================================
// Clean Up Old Files (Scheduled Task)
// ===========================================
export const cleanUpOldFiles = async (daysOld = 30) => {
  try {
    const uploadDir = config.fileUpload.uploadDir;
    const cutoffDate = Date.now() - (daysOld * 24 * 60 * 60 * 1000);
    
    const cleanDirectory = async (dir) => {
      const entries = await fs.readdir(dir, { withFileTypes: true });
      
      for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);
        
        if (entry.isDirectory()) {
          await cleanDirectory(fullPath);
          
          // Remove empty directories
          const isEmpty = (await fs.readdir(fullPath)).length === 0;
          if (isEmpty) {
            await fs.rmdir(fullPath);
          }
        } else {
          const stats = await fs.stat(fullPath);
          
          if (stats.mtimeMs < cutoffDate) {
            await fs.unlink(fullPath);
            logger.info('Deleted old file', {
              file: fullPath,
              age: Math.floor((Date.now() - stats.mtimeMs) / (24 * 60 * 60 * 1000)),
            });
          }
        }
      }
    };
    
    await cleanDirectory(uploadDir);
    logger.info('Old files cleanup completed');
  } catch (error) {
    logger.error('Failed to clean up old files', { error: error.message });
  }
};

export default {
  uploadSingle,
  uploadMultiple,
  uploadFields,
  uploadAny,
  validateFileContent,
  validateFileSize,
  handleUploadError,
  sanitizeFilename,
  cleanUpOldFiles,
};