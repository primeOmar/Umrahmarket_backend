import express from 'express';
import multer from 'multer';
import { supabase } from '../config/supabase.js';
import { requireAuth } from '../middleware/auth.middleware.js';

const router = express.Router();

const BUCKET      = 'agent-documents';
const ALLOWED_KEYS = ['incorporation', 'tourism', 'krapin'];
const MAX_SIZE    = 5 * 1024 * 1024; // 5 MB

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_SIZE },
  fileFilter: (_req, file, cb) => {
    const ALLOWED_MIME = ['image/jpeg', 'image/png', 'image/webp', 'application/pdf'];
    if (!ALLOWED_MIME.includes(file.mimetype)) {
      return cb(new Error(`Invalid type: ${file.mimetype}. Only JPEG, PNG, WebP, PDF allowed.`), false);
    }
    cb(null, true);
  },
});

// ─── GET /api/documents ───────────────────────────────────────────────────────
// Returns the current upload status for each document type for the authed agent.
router.get('/', requireAuth, async (req, res) => {
  try {
    const agentId = req.userId; // set by requireAuth

    const result = {};

    for (const key of ALLOWED_KEYS) {
      // List files under agentId/key_* prefix
      const { data: files, error } = await supabase.storage
        .from(BUCKET)
        .list(agentId, { search: `${key}_` });

      if (error) {
        result[key] = { status: 'none' };
        continue;
      }

      if (!files || files.length === 0) {
        result[key] = { status: 'none' };
        continue;
      }

      // Most recent file
      const latest = files
        .filter(f => f.name.startsWith(`${key}_`))
        .sort((a, b) => new Date(b.created_at) - new Date(a.created_at))[0];

      if (!latest) { result[key] = { status: 'none' }; continue; }

      const path = `${agentId}/${latest.name}`;

      // Generate a short-lived signed URL (60 min) for the View button
      const { data: urlData } = await supabase.storage
        .from(BUCKET)
        .createSignedUrl(path, 3600);

      result[key] = {
        status:     'uploaded',   // admin verification status can be enriched later via DB
        path,
        publicUrl:  urlData?.signedUrl ?? null,
        uploadedAt: latest.created_at,
      };
    }

    return res.json({ success: true, data: result });

  } catch (error) {
    console.error('GET /api/documents error:', error);
    return res.status(500).json({ success: false, error: 'Failed to fetch documents.' });
  }
});

// ─── POST /api/documents ──────────────────────────────────────────────────────
// Uploads one or more documents.  Only fields matching ALLOWED_KEYS are accepted.
router.post('/', requireAuth, upload.fields(
  ALLOWED_KEYS.map(k => ({ name: k, maxCount: 1 }))
), async (req, res) => {
  try {
    const agentId = req.userId;
    const files   = req.files;

    if (!files || Object.keys(files).length === 0) {
      return res.status(400).json({ success: false, error: 'No files provided.' });
    }

    // Reject any unexpected field names
    const unknownKeys = Object.keys(files).filter(k => !ALLOWED_KEYS.includes(k));
    if (unknownKeys.length > 0) {
      return res.status(400).json({
        success: false,
        error:   `Unexpected file field(s): ${unknownKeys.join(', ')}.`,
      });
    }

    const uploadResults = {};

    for (const key of ALLOWED_KEYS) {
      if (!files[key]) continue;

      const file     = files[key][0];
      const fileName = `${agentId}/${key}_${Date.now()}_${file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_')}`;

      const { data, error } = await supabase.storage
        .from(BUCKET)
        .upload(fileName, file.buffer, {
          contentType: file.mimetype,
          upsert:      true,
        });

      if (error) throw new Error(`Supabase upload failed for ${key}: ${error.message}`);

      uploadResults[key] = data.path;
    }

    return res.json({
      success: true,
      message: 'Documents uploaded successfully.',
      data:    uploadResults,
    });

  } catch (error) {
    console.error('POST /api/documents error:', error);
    return res.status(500).json({ success: false, error: 'Upload failed: ' + error.message });
  }
});

export default router;