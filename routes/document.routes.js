import express from 'express';
import { S3Client, ListObjectsV2Command, GetObjectCommand } from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import { requireAuth } from '../middleware/auth.middleware.js';
import { parseDocumentData, uploadDocumentsToR2 } from '../middleware/uploads/Uploadtocloudflare.js';
import { supabaseAdmin } from '../config/supabase.js';

const router = express.Router();

const DOCUMENT_KEYS = ['incorporation', 'tourism', 'krapin', 'director_id', 'office_photo'];

// ─── R2 client (read operations — presigned URLs) ─────────────────────────────
const R2 = new S3Client({
  region: 'auto',
  endpoint: `https://${process.env.CLOUDFLARE_ACCOUNT_ID}.r2.cloudflarestorage.com`,
  credentials: {
    accessKeyId:     process.env.CLOUDFLARE_R2_ACCESS_KEY_ID,
    secretAccessKey: process.env.CLOUDFLARE_R2_SECRET_ACCESS_KEY,
  },
});

const BUCKET = process.env.CLOUDFLARE_R2_BUCKET_NAME;

// ─── GET /api/documents ────────────────────────────────────────────────────────
// Returns upload status + presigned view URL (1 hr) for each document type.
router.get('/', requireAuth, async (req, res) => {
  try {
    const agentId = req.userId;
    const result  = {};

    // Fetch saved Maps URL from profile
    const { data: profile } = await supabaseAdmin
      .from('profiles')
      .select('office_maps_url')
      .eq('id', agentId)
      .single();
    const savedMapsUrl = profile?.office_maps_url || null;

    for (const docKey of DOCUMENT_KEYS) {
      const prefix = `documents/${agentId}/${docKey}/`;

      const { Contents } = await R2.send(new ListObjectsV2Command({
        Bucket: BUCKET,
        Prefix: prefix,
      }));

      if (!Contents || Contents.length === 0) {
        result[docKey] = {
          status: 'none',
          ...(docKey === 'office_photo' && savedMapsUrl ? { mapsUrl: savedMapsUrl } : {}),
          ...(docKey === 'office_photo' ? { photos: [] } : {}),
        };
        continue;
      }

      // Sort newest-first
      const sorted = Contents.sort(
        (a, b) => new Date(b.LastModified) - new Date(a.LastModified)
      );

      if (docKey === 'office_photo') {
        // Return ALL office photos as an array
        const photos = await Promise.all(
          sorted.map(async (obj) => {
            const signedUrl = await getSignedUrl(
              R2,
              new GetObjectCommand({ Bucket: BUCKET, Key: obj.Key }),
              { expiresIn: 3600 }
            );
            return { path: obj.Key, publicUrl: signedUrl, uploadedAt: obj.LastModified };
          })
        );

        result[docKey] = {
          status:     'uploaded',
          photos,
          // Convenience: most recent photo as top-level publicUrl for backward compat
          path:       photos[0].path,
          publicUrl:  photos[0].publicUrl,
          uploadedAt: photos[0].uploadedAt,
          ...(savedMapsUrl ? { mapsUrl: savedMapsUrl } : {}),
        };
      } else {
        // Most recently uploaded file for this doc type
        const latest = sorted[0];

        // Generate presigned URL valid for 1 hour
        const signedUrl = await getSignedUrl(
          R2,
          new GetObjectCommand({ Bucket: BUCKET, Key: latest.Key }),
          { expiresIn: 3600 }
        );

        result[docKey] = {
          status:     'uploaded',
          path:       latest.Key,
          publicUrl:  signedUrl,
          uploadedAt: latest.LastModified,
        };
      }
    }

    return res.json({ success: true, data: result });

  } catch (error) {
    console.error('GET /api/documents error:', error);
    return res.status(500).json({ success: false, error: 'Failed to fetch documents.' });
  }
});

router.get('/debug/status', async (req, res) => {
  try {
    console.log('[DEBUG] Checking agent_documents table...');

    // Check table existence
    const { data: tableInfo, error: tableError } = await supabaseAdmin
      .from('agent_documents')
      .select('*')
      .limit(0);

    if (tableError) {
      return res.json({
        success: false,
        table: 'not found',
        error: tableError.message,
      });
    }

    // Check record count
    const { count, error: countError } = await supabaseAdmin
      .from('agent_documents')
      .select('*', { count: 'exact', head: true });

    // Check RLS status
    const { data: rlsCheck, error: rlsError } = await supabaseAdmin
      .rpc('pg_class', {}, { count: 'exact' })
      .catch(() => ({ data: null, error: 'RLS check unavailable' }));

    // Try a test insert
    const testId = `test-${Date.now()}`;
    const testUserId = 'test-user-id';
    const { data: testData, error: testError } = await supabaseAdmin
      .from('agent_documents')
      .insert({
        user_id: testUserId,
        status: 'pending',
      })
      .select('id,user_id')
      .single()
      .catch(err => ({ data: null, error: err.message }));

    // Clean up test record if insert succeeded
    if (testData) {
      await supabaseAdmin
        .from('agent_documents')
        .delete()
        .eq('user_id', testUserId)
        .catch(() => {});
    }

    res.json({
      success: true,
      status: 'ok',
      table: 'agent_documents exists',
      recordCount: count || 0,
      testInsert: {
        success: !!testData,
        error: testError || null,
      },
    });
  } catch (error) {
    console.error('[DEBUG] Error:', error);
    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
});

// ─── POST /api/documents ──────────────────────────────────────────────────────
// Accepts: incorporation | tourism | krapin  (multipart/form-data)
// Middleware chain: requireAuth → parseDocumentData → uploadDocumentsToR2 → handler
router.post('/',
  requireAuth,
  parseDocumentData,
  uploadDocumentsToR2,
  async (req, res) => {
    const uploaded = req.documentUrls ?? {};

    if (Object.keys(uploaded).length === 0) {
      return res.status(400).json({ success: false, error: 'No files provided.' });
    }

    try {
      const userId = req.userId;
      console.log(`[POST /api/documents] Starting upload for user: ${userId}`);
      console.log(`[POST /api/documents] Uploaded files:`, Object.keys(uploaded));

      const documentPayload = {
        user_id:        userId,
        incorporation_doc: uploaded.incorporation || null,
        tourism_doc:       uploaded.tourism || null,
        krapin_doc:        uploaded.krapin || null,
        director_id_doc:   uploaded.director_id || null,
        office_photo:      Array.isArray(uploaded.office_photo) ? uploaded.office_photo : (uploaded.office_photo ? [uploaded.office_photo] : null),
        status:            'pending',
        submitted_at:      new Date().toISOString(),
      };

      console.log(`[POST /api/documents] Payload:`, JSON.stringify(documentPayload, null, 2));

      // Check if record exists
      const { data: existing, error: selectError } = await supabaseAdmin
        .from('agent_documents')
        .select('id')
        .eq('user_id', userId)
        .maybeSingle();

      if (selectError) {
        console.error(`[POST /api/documents] SELECT error:`, selectError);
        throw new Error(`Database select failed: ${selectError.message}`);
      }

      console.log(`[POST /api/documents] Existing record:`, existing ? 'Found' : 'Not found');

      let savedDoc;

      if (existing) {
        console.log(`[POST /api/documents] Updating existing record (id: ${existing.id})`);
        const { data, error } = await supabaseAdmin
          .from('agent_documents')
          .update({
            incorporation_doc: uploaded.incorporation || null,
            tourism_doc:       uploaded.tourism || null,
            krapin_doc:        uploaded.krapin || null,
            director_id_doc:   uploaded.director_id || null,
            office_photo:      Array.isArray(uploaded.office_photo) ? uploaded.office_photo : (uploaded.office_photo ? [uploaded.office_photo] : null),
            status:            'pending',
            submitted_at:      new Date().toISOString(),
            updated_at:        new Date().toISOString(),
          })
          .eq('user_id', userId)
          .select('id,user_id,status,submitted_at')
          .single();

        if (error) {
          console.error(`[POST /api/documents] UPDATE error:`, error);
          throw new Error(`Database update failed: ${error.message}`);
        }
        console.log(`[POST /api/documents] Update successful:`, data);
        savedDoc = data;
      } else {
        console.log(`[POST /api/documents] Inserting new record`);
        const { data, error } = await supabaseAdmin
          .from('agent_documents')
          .insert(documentPayload)
          .select('id,user_id,status,submitted_at')
          .single();

        if (error) {
          console.error(`[POST /api/documents] INSERT error:`, error);
          throw new Error(`Database insert failed: ${error.message}`);
        }
        console.log(`[POST /api/documents] Insert successful:`, data);
        savedDoc = data;
      }

      console.log(`[POST /api/documents] Completed successfully`);
      return res.json({
        success: true,
        message: 'Documents uploaded successfully.',
        data: {
          uploaded,
          document: savedDoc,
        },
      });
    } catch (error) {
      console.error('[POST /api/documents] Fatal error:', error);
      return res.status(500).json({ success: false, error: error.message || 'Failed to save documents.' });
    }
  }
);

// ─── PATCH /api/documents/office-location ─────────────────────────────────────
// Saves agent's Google Maps URL to profiles table

router.patch('/office-location', requireAuth, async (req, res) => {
  try {
    const { mapsUrl } = req.body;
    if (!mapsUrl) return res.status(400).json({ success: false, error: 'mapsUrl is required.' });

    // Basic validation
    const isGoogleMaps =
      mapsUrl.includes('google.com/maps') ||
      mapsUrl.includes('maps.app.goo.gl') ||
      mapsUrl.includes('goo.gl/maps');
    if (!isGoogleMaps) {
      return res.status(400).json({ success: false, error: 'Please provide a valid Google Maps URL.' });
    }

    const { error } = await supabaseAdmin
      .from('profiles')
      .update({ office_maps_url: mapsUrl, updated_at: new Date().toISOString() })
      .eq('id', req.userId);

    if (error) throw error;

    return res.json({ success: true, message: 'Office location saved.' });
  } catch (error) {
    console.error('PATCH /api/documents/office-location error:', error);
    return res.status(500).json({ success: false, error: 'Failed to save office location.' });
  }
});

export default router;