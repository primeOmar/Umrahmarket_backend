import logger from '../../config/logger.js';

/**
 * validatePackage middleware
 * Runs AFTER parseFormData (multer) so req.body is populated.
 * Rejects the request early — before any R2 upload — if required fields
 * are missing or obviously invalid.
 */

const ALLOWED_TYPES     = ['umrah', 'hajj'];
const ALLOWED_LOCATIONS = ['makkah', 'madinah', 'jeddah'];

export const validatePackage = (req, res, next) => {
  const errors = [];
  const b = req.body;

  // ── Required text fields ───────────────────────────────────────────────────
  if (!b.name || String(b.name).trim().length < 3) {
    errors.push('Package name is required (min 3 characters).');
  }

  if (!ALLOWED_TYPES.includes(b.type)) {
    errors.push(`Package type must be one of: ${ALLOWED_TYPES.join(', ')}.`);
  }

  if (!ALLOWED_LOCATIONS.includes(b.location)) {
    errors.push(`Location must be one of: ${ALLOWED_LOCATIONS.join(', ')}.`);
  }

  // ── Required numeric fields ────────────────────────────────────────────────
  const price = parseFloat(b.price);
  if (isNaN(price) || price <= 0) {
    errors.push('A valid price greater than 0 is required.');
  }

  const duration = parseInt(b.duration, 10);
  if (isNaN(duration) || duration < 1) {
    errors.push('Duration must be at least 1 day.');
  }

  // ── Optional but validated if present ─────────────────────────────────────
  if (b.discount !== undefined && b.discount !== '') {
    const discount = parseFloat(b.discount);
    if (isNaN(discount) || discount < 0 || discount > 100) {
      errors.push('Discount must be between 0 and 100.');
    }
  }

  if (b.available_from && !/^\d{4}-\d{2}-\d{2}$/.test(b.available_from)) {
    errors.push('available_from must be in YYYY-MM-DD format.');
  }

  if (b.available_to && !/^\d{4}-\d{2}-\d{2}$/.test(b.available_to)) {
    errors.push('available_to must be in YYYY-MM-DD format.');
  }

  if (
    b.available_from && b.available_to &&
    new Date(b.available_to) < new Date(b.available_from)
  ) {
    errors.push('available_to must be on or after available_from.');
  }

  // ── Hotel date consistency ─────────────────────────────────────────────────
  for (const city of ['makkah', 'madinah']) {
    const ci = b[`${city}_check_in_date`];
    const co = b[`${city}_check_out_date`];
    if (ci && !/^\d{4}-\d{2}-\d{2}$/.test(ci)) {
      errors.push(`${city} check-in date must be YYYY-MM-DD.`);
    }
    if (co && !/^\d{4}-\d{2}-\d{2}$/.test(co)) {
      errors.push(`${city} check-out date must be YYYY-MM-DD.`);
    }
    if (ci && co && new Date(co) < new Date(ci)) {
      errors.push(`${city} check-out must be on or after check-in.`);
    }
  }

  // ── Return errors if any ───────────────────────────────────────────────────
  if (errors.length > 0) {
    logger.warn('Package validation failed', {
      errors,
      userId: req.userId,
      ip:     req.ip,
    });
    return res.status(400).json({
      success: false,
      error:   'Validation failed',
      details: errors,
    });
  }

  next();
};