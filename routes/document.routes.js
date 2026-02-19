import express from 'express';
import multer from 'multer';
import { supabase } from '../config/supabase.js';
import { requireAuth } from '../middleware/auth.middleware.js';

const router = express.Router();

// Configure multer to store files in memory temporarily
const upload = multer({ 
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 } // 5MB limit
});

// POST /api/documents
router.post('/', requireAuth, upload.fields([
  { name: 'incorporation', maxCount: 1 },
  { name: 'tourism',       maxCount: 1 },
  { name: 'krapin',        maxCount: 1 },
]), async (req, res) => {
  try {
    const { agentId } = req.body;
    const files = req.files;

    if (!files || Object.keys(files).length === 0) {
      return res.status(400).json({ success: false, error: 'No files provided' });
    }

    const uploadResults = {};

    // Helper to upload to Supabase bucket 'agent-documents'
    for (const key in files) {
      const file = files[key][0];
      const fileName = `${agentId}/${key}_${Date.now()}_${file.originalname}`;

      const { data, error } = await supabase.storage
        .from('agent-documents')
        .upload(fileName, file.buffer, {
          contentType: file.mimetype,
          upsert: true
        });

      if (error) throw error;
      uploadResults[key] = data.path;
    }

    res.json({
      success: true,
      message: 'Documents uploaded successfully',
      data: uploadResults
    });

  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({ success: false, error: 'Upload failed: ' + error.message });
  }
});

export default router;