/**
 * Agent self-service profile — lets a logged-in agent edit the content
 * that shows up on their PUBLIC profile (agents.routes.js / AgentDetailPage):
 * logo, bio, years of experience, specialties, website.
 *
 * Auth + scoping follow the same pattern as agent_documents.routes.js:
 * requireAuth, and every query is scoped to req.user.id — an agent can only
 * ever read/write their own row, never another agent's.
 *
 * NOTE: matches agent_documents.routes.js's auth pattern — requireAuth from
 * ../middleware/auth.middleware.js sets req.user (with req.user.id) after
 * verifying the Bearer access token against the profiles table.
 * */
import express from 'express';
import multer from 'multer';
import { supabaseAdmin as supabase } from '../config/supabase.js';
import { requireAuth } from '../middleware/auth.middleware.js';

const router = express.Router();

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
  fileFilter: (req, file, cb) => {
    if (!/^image\/(png|jpe?g|webp|svg\+xml)$/.test(file.mimetype)) {
      return cb(new Error('Logo must be a PNG, JPG, WEBP, or SVG image'));
    }
    cb(null, true);
  },
});

// Whitelist of fields an agent is allowed to self-edit. Deliberately
// excludes verification_status, approved, agent_number, role, etc. — those
// stay admin-controlled (see SuperAdminDashboard).
const EDITABLE_FIELDS = {
  companyName: 'company_name',
  bio: 'bio',
  yearsExperience: 'years_experience',
  specialties: 'specialties',
  websiteUrl: 'website_url',
  officeMapsUrl: 'office_maps_url',
  logoUrl: 'logo_url',
};

function toRow(body) {
  const row = {};
  for (const [key, column] of Object.entries(EDITABLE_FIELDS)) {
    if (body[key] === undefined) continue;

    if (key === 'yearsExperience') {
      const n = Number(body[key]);
      if (!Number.isFinite(n) || n < 0 || n > 100) {
        throw new Error('yearsExperience must be a number between 0 and 100');
      }
      row[column] = Math.round(n);
    } else if (key === 'specialties') {
      if (!Array.isArray(body[key])) throw new Error('specialties must be an array of strings');
      row[column] = body[key].map((s) => String(s).trim()).filter(Boolean).slice(0, 20);
    } else if (key === 'bio') {
      const bio = String(body[key] ?? '').trim();
      if (bio.length > 2000) throw new Error('bio must be 2000 characters or fewer');
      row[column] = bio;
    } else {
      row[column] = body[key] === null ? null : String(body[key]).trim();
    }
  }
  return row;
}

// ── GET /api/agents/me/profile ─────────────────────────────────────────────
// Full editable profile for the logged-in agent (superset of what the
// public GET /api/agents/:id returns).
router.get('/me/profile', requireAuth, async (req, res) => {
  try {
    const { data: agent, error } = await supabase
      .from('profiles')
      .select('id, first_name, last_name, company_name, verification_status, approved, agent_number, office_maps_url, bio, logo_url, years_experience, specialties, website_url, created_at')
      .eq('id', req.user.id)
      .eq('role', 'agent')
      .maybeSingle();

    if (error) throw error;
    if (!agent) return res.status(404).json({ success: false, message: 'Agent profile not found' });

    res.json({
      success: true,
      profile: {
        id: agent.id,
        businessName: agent.company_name,
        firstName: agent.first_name,
        lastName: agent.last_name,
        verificationStatus: agent.verification_status,
        approved: agent.approved,
        agentNumber: agent.agent_number,
        officeMapsUrl: agent.office_maps_url,
        bio: agent.bio,
        logoUrl: agent.logo_url,
        yearsExperience: agent.years_experience,
        specialties: agent.specialties || [],
        websiteUrl: agent.website_url,
        memberSince: agent.created_at ? new Date(agent.created_at).getFullYear() : null,
      },
    });
  } catch (err) {
    console.error('[agent-profile] get error:', err);
    res.status(500).json({ success: false, message: 'Failed to load profile' });
  }
});

// ── PUT /api/agents/me/profile ─────────────────────────────────────────────
// Update the editable profile fields. Body is a partial object — only keys
// present in EDITABLE_FIELDS are written.
router.put('/me/profile', requireAuth, async (req, res) => {
  try {
    let row;
    try {
      row = toRow(req.body || {});
    } catch (validationErr) {
      return res.status(400).json({ success: false, message: validationErr.message });
    }

    if (Object.keys(row).length === 0) {
      return res.status(400).json({ success: false, message: 'No editable fields provided' });
    }

    const { data: updated, error } = await supabase
      .from('profiles')
      .update(row)
      .eq('id', req.user.id)
      .eq('role', 'agent')
      .select('id, company_name, bio, logo_url, years_experience, specialties, website_url, office_maps_url')
      .maybeSingle();

    if (error) throw error;
    if (!updated) return res.status(404).json({ success: false, message: 'Agent profile not found' });

    res.json({
      success: true,
      profile: {
        businessName: updated.company_name,
        bio: updated.bio,
        logoUrl: updated.logo_url,
        yearsExperience: updated.years_experience,
        specialties: updated.specialties || [],
        websiteUrl: updated.website_url,
        officeMapsUrl: updated.office_maps_url,
      },
    });
  } catch (err) {
    console.error('[agent-profile] update error:', err);
    res.status(500).json({ success: false, message: 'Failed to update profile' });
  }
});

// ── POST /api/agents/me/logo ────────────────────────────────────────────────
// Uploads a logo image to the `agent-logos` storage bucket and saves its
// public URL onto the agent's profile row.
router.post('/me/logo', requireAuth, upload.single('logo'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ success: false, message: 'No logo file provided' });

    const ext = (req.file.originalname.split('.').pop() || 'png').toLowerCase();
    const path = `${req.user.id}/logo-${Date.now()}.${ext}`;

    const { error: uploadErr } = await supabase.storage
      .from('agent-logos')
      .upload(path, req.file.buffer, {
        contentType: req.file.mimetype,
        upsert: true,
      });

    if (uploadErr) throw uploadErr;

    const { data: publicUrlData } = supabase.storage.from('agent-logos').getPublicUrl(path);
    const logoUrl = publicUrlData?.publicUrl;

    const { error: updateErr } = await supabase
      .from('profiles')
      .update({ logo_url: logoUrl })
      .eq('id', req.user.id)
      .eq('role', 'agent');

    if (updateErr) throw updateErr;

    res.json({ success: true, logoUrl });
  } catch (err) {
    console.error('[agent-profile] logo upload error:', err);
    res.status(500).json({ success: false, message: 'Failed to upload logo' });
  }
});

export default router;