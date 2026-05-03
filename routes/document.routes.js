import express from 'express';
import { S3Client, ListObjectsV2Command, GetObjectCommand } from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import { requireAuth } from '../middleware/auth.middleware.js';
import { parseDocumentData, uploadDocumentsToR2 } from '../middleware/Uploadtocloudflare.js';

const router = express.Router();

const DOCUMENT_KEYS = ['incorporation', 'tourism', 'krapin'];

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

    for (const docKey of DOCUMENT_KEYS) {
      const prefix = `documents/${agentId}/${docKey}/`;

      const { Contents } = await R2.send(new ListObjectsV2Command({
        Bucket: BUCKET,
        Prefix: prefix,
      }));

      if (!Contents || Contents.length === 0) {
        result[docKey] = { status: 'none' };
        continue;
      }

      // Most recently uploaded file for this doc type
      const latest = Contents.sort(
        (a, b) => new Date(b.LastModified) - new Date(a.LastModified)
      )[0];

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

    return res.json({ success: true, data: result });

  } catch (error) {
    console.error('GET /api/documents error:', error);
    return res.status(500).json({ success: false, error: 'Failed to fetch documents.' });
  }
});

// ─── POST /api/documents ──────────────────────────────────────────────────────
// Accepts: incorporation | tourism | krapin  (multipart/form-data)
// Middleware chain: requireAuth → parseDocumentData → uploadDocumentsToR2 → handler
router.post('/',
  requireAuth,
  parseDocumentData,
  uploadDocumentsToR2,
  (req, res) => {
    const uploaded = req.documentUrls ?? {};

    if (Object.keys(uploaded).length === 0) {
      return res.status(400).json({ success: false, error: 'No files provided.' });
    }

    return res.json({
      success: true,
      message: 'Documents uploaded successfully.',
      data:    uploaded,
    });
  }
);

export default router;