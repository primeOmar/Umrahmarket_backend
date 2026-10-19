import express from 'express';
import { supabaseAdmin } from '../config/supabase.js';
import { requireAuth } from '../middleware/auth.middleware.js';
import logger from '../config/logger.js';

const router = express.Router();

// Accepts +254712345678, 254712345678, 0712345678, 712345678 (Kenyan mobile).
function toKenyaE164(raw) {
  const d = String(raw ?? '').replace(/\D/g, '');
  let national = null;
  if (d.length === 12 && d.startsWith('254')) national = d.slice(3);
  else if (d.length === 10 && d.startsWith('0')) national = d.slice(1);
  else if (d.length === 9) national = d;
  if (!national || !/^[17]\d{8}$/.test(national)) return null;
  return `+254${national}`;
}

// POST /api/profiles/whatsapp-number { whatsappNumber }
router.post('/whatsapp-number', requireAuth, async (req, res) => {
  const e164 = toKenyaE164(req.body?.whatsappNumber);
  if (!e164) {
    return res.status(400).json({
      success: false,
      message: 'Enter a valid Kenyan mobile number (e.g. 0712 345 678).',
    });
  }

  try {
    const { data, error } = await supabaseAdmin
      .from('profiles')
      .update({ phone: e164 })
      .eq('id', req.user.id)
      .select('id')
      .maybeSingle();

    if (error) throw error;
    if (!data) {
      return res.status(404).json({ success: false, message: 'Profile not found.' });
    }

    return res.json({
      success: true,
      user: { ...req.user, phone: e164 },
    });
  } catch (err) {
    logger.error('Save WhatsApp number failed', { userId: req.user?.id, error: err.message });
    return res.status(500).json({ success: false, message: 'Could not save your number. Please try again.' });
  }
});

export default router;
