import express from 'express';
import crypto from 'crypto';
import multer from 'multer';
import path from 'path';
import { fileTypeFromBuffer } from 'file-type';
import { S3Client, PutObjectCommand, DeleteObjectCommand } from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import { supabaseAdmin as supabase } from '../config/supabase.js';
import logger, { logFileUpload, logSuspiciousActivity } from '../config/logger.js';
// Circular import by design — mirrors how accounting.routes.js pulls
// authenticateSuperadmin back out of superadmin_routes.js. Safe because it's
// a function declaration (hoisted) and only invoked per-request, never at
// module-eval time.
import { authenticateSuperadmin } from './superadmin_routes.js';

const router = express.Router();

// ─────────────────────────────────────────────────────────────────────────────
// R2 client (same credentials/bucket as superadmin_routes.js, separate
// client instance to keep this module independently importable)
// ─────────────────────────────────────────────────────────────────────────────
const R2 = new S3Client({
  region: 'auto',
  endpoint: `https://${process.env.CLOUDFLARE_ACCOUNT_ID}.r2.cloudflarestorage.com`,
  credentials: {
    accessKeyId:     process.env.CLOUDFLARE_R2_ACCESS_KEY_ID,
    secretAccessKey: process.env.CLOUDFLARE_R2_SECRET_ACCESS_KEY,
  },
});

const R2_BUCKET      = process.env.CLOUDFLARE_R2_BUCKET_NAME;
const R2_PUBLIC_URL  = process.env.CLOUDFLARE_R2_PUBLIC_URL || '';
const UPLOAD_URL_TTL = 300; // 5 min — plenty for a browser to start a direct PUT

const publicUrlFor = (key) => (R2_PUBLIC_URL ? `${R2_PUBLIC_URL}/${key}` : null);

// Keep this list tight — it's the whitelist for what the presign endpoint
// will hand out a write URL for. (Video only now — images go through the
// backend-proxy route below, matching the packages/documents convention.)
const ALLOWED_CONTENT_TYPES = {
  video: ['video/mp4', 'video/webm', 'video/quicktime'],
};
const MAX_BYTES = { video: 500 * 1024 * 1024 }; // 500MB

// ─────────────────────────────────────────────────────────────────────────────
// Image upload — backend proxy (browser → this server → R2), same pattern
// as uploadImagesToR2 in Uploadtocloudflare.js. Chosen over a presigned URL
// for images specifically because it reuses your existing CORS setup (the
// browser only ever talks to your own API origin, never R2 directly) and
// images are small enough that Render's request limits are a non-issue.
// Video keeps the presigned direct-to-R2 path below — 500MB files should
// not round-trip through the backend.
// ─────────────────────────────────────────────────────────────────────────────
const IMAGE_MIMES = ['image/jpeg', 'image/png', 'image/webp', 'image/gif'];
const IMAGE_MAX_SIZE = 10 * 1024 * 1024; // 10MB

const imageUpload = multer({
  storage: multer.memoryStorage(),
  fileFilter: (_req, file, cb) => {
    if (!IMAGE_MIMES.includes(file.mimetype)) {
      return cb(new Error(`Invalid file type: ${file.mimetype}. Allowed: jpeg, png, webp, gif`), false);
    }
    cb(null, true);
  },
  limits: { fileSize: IMAGE_MAX_SIZE, files: 1 },
});

router.post('/upload-image', authenticateSuperadmin, imageUpload.single('image'), async (req, res) => {
  try {
    const file = req.file;
    if (!file) return res.status(422).json({ success: false, message: 'No image file provided' });
    if (!R2_BUCKET) return res.status(500).json({ success: false, message: 'R2 bucket not configured' });

    const buffer = file.buffer;

    // Deep MIME check — don't trust the client-declared content-type
    const detected = await fileTypeFromBuffer(buffer);
    if (!detected || !IMAGE_MIMES.includes(detected.mime)) {
      logSuspiciousActivity('Blog image upload rejected — MIME mismatch', {
        claimed: file.mimetype, detected: detected?.mime ?? 'unknown',
        userId: req.superadmin?.id, ip: req.ip,
      });
      return res.status(400).json({ success: false, message: 'File type verification failed. Only JPEG, PNG, WebP, and GIF allowed.' });
    }

    // Quick code-injection scan (same approach as packages/documents flow)
    const headerStr = buffer.slice(0, 1024).toString('latin1');
    if (headerStr.includes('<?php') || headerStr.includes('<?=') || headerStr.includes('<script')) {
      logSuspiciousActivity('Blog image upload rejected — executable code detected', { userId: req.superadmin?.id, ip: req.ip });
      return res.status(400).json({ success: false, message: 'File contains executable code and was rejected.' });
    }

    const uid = crypto.randomBytes(16).toString('hex');
    const ext = path.extname(file.originalname).toLowerCase() || `.${detected.ext}`;
    const key = `blog/images/${Date.now()}-${uid}${ext}`;

    await R2.send(new PutObjectCommand({ Bucket: R2_BUCKET, Key: key, Body: buffer, ContentType: detected.mime }));

    logFileUpload(req.superadmin?.id, key, detected.mime, buffer.length, true, req.ip);

    return res.json({ success: true, data: { publicUrl: publicUrlFor(key), key } });
  } catch (err) {
    if (err instanceof multer.MulterError) {
      const msgs = {
        LIMIT_FILE_SIZE: `File too large. Max ${IMAGE_MAX_SIZE / 1024 / 1024}MB.`,
      };
      return res.status(400).json({ success: false, message: msgs[err.code] || err.message });
    }
    logger.error('Blog image upload failed', { error: err.message });
    return res.status(500).json({ success: false, message: 'Image upload failed. Please try again.' });
  }
});

const slugify = (str = '') =>
  str
    .toString()
    .trim()
    .toLowerCase()
    .replace(/[^\w\s-]/g, '')
    .replace(/[\s_-]+/g, '-')
    .replace(/^-+|-+$/g, '');

const ensureUniqueSlug = async (base, excludeId = null) => {
  let slug = base || 'post';
  let n = 1;
  // Small table, a loop here is fine — avoids a bespoke uniqueness RPC.
  while (true) {
    let query = supabase.from('blog_posts').select('id').eq('slug', slug).limit(1);
    if (excludeId) query = query.neq('id', excludeId);
    const { data } = await query;
    if (!data || data.length === 0) return slug;
    n += 1;
    slug = `${base}-${n}`;
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// POST /superadmin/blog/upload-url
// Body: { fileName, contentType, mediaType: 'video' }
// Video only — returns a presigned PUT URL so the browser uploads straight
// to R2, since routing a large video file through Render isn't practical.
// Requires the R2 bucket's CORS policy to allow your frontend origin(s).
// ─────────────────────────────────────────────────────────────────────────────
router.post('/upload-url', authenticateSuperadmin, async (req, res) => {
  try {
    const { fileName, contentType, mediaType } = req.body || {};

    if (!fileName || !contentType || !mediaType) {
      return res.status(422).json({ success: false, message: 'fileName, contentType and mediaType are required' });
    }
    if (mediaType !== 'video') {
      return res.status(422).json({ success: false, message: 'This endpoint is for video uploads only — use /upload-image for images.' });
    }
    if (!ALLOWED_CONTENT_TYPES[mediaType].includes(contentType)) {
      return res.status(422).json({ success: false, message: `Unsupported content type for ${mediaType}: ${contentType}` });
    }
    if (!R2_BUCKET) {
      return res.status(500).json({ success: false, message: 'R2 bucket not configured' });
    }

    const safeName = fileName.replace(/[^\w.\-]/g, '_');
    const key = `blog/${mediaType}s/${Date.now()}-${crypto.randomUUID()}-${safeName}`;

    const uploadUrl = await getSignedUrl(
      R2,
      new PutObjectCommand({ Bucket: R2_BUCKET, Key: key, ContentType: contentType }),
      { expiresIn: UPLOAD_URL_TTL }
    );

    return res.json({
      success: true,
      data: {
        uploadUrl,
        key,
        publicUrl: publicUrlFor(key),
        maxBytes: MAX_BYTES[mediaType],
        expiresIn: UPLOAD_URL_TTL,
      },
    });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Failed to create upload URL' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /superadmin/blog
// List posts for the admin table. Lightweight — omits `content`.
// Query: ?status=draft|published&category=News&search=foo
// ─────────────────────────────────────────────────────────────────────────────
router.get('/', authenticateSuperadmin, async (req, res) => {
  try {
    const { status, category, search } = req.query;

    let query = supabase
      .from('blog_posts')
      .select(`
        id, slug, title, excerpt, cover_image_url, cover_video_url,
        author_name, author_avatar_url, category, tags, status,
        view_count, published_at, created_at, updated_at
      `)
      .order('created_at', { ascending: false });

    if (status && status !== 'all')     query = query.eq('status', status);
    if (category && category !== 'all') query = query.eq('category', category);
    if (search)                         query = query.ilike('title', `%${search}%`);

    const { data, error } = await query;
    if (error) throw error;

    return res.json({ success: true, data: data || [] });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Failed to fetch blog posts' });
  }
});

// GET /superadmin/blog/:id — full post, including content, for the editor
router.get('/:id', authenticateSuperadmin, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('blog_posts')
      .select('*')
      .eq('id', req.params.id)
      .single();

    if (error || !data) return res.status(404).json({ success: false, message: 'Post not found' });

    return res.json({ success: true, data });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Failed to fetch post' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /superadmin/blog — create (draft or published)
// ─────────────────────────────────────────────────────────────────────────────
router.post('/', authenticateSuperadmin, async (req, res) => {
  try {
    const {
      title, excerpt, content, slug: rawSlug,
      cover_image_url, cover_image_key, cover_video_url, cover_video_key,
      category, tags, status, meta_title, meta_description,
      author_name, author_avatar_url,
    } = req.body || {};

    if (!title || !content) {
      return res.status(422).json({ success: false, message: 'title and content are required' });
    }

    const safeStatus = status === 'published' ? 'published' : 'draft';
    const slug = await ensureUniqueSlug(slugify(rawSlug || title));

    const { data, error } = await supabase
      .from('blog_posts')
      .insert({
        title,
        slug,
        excerpt:            excerpt || null,
        content,
        cover_image_url:    cover_image_url || null,
        cover_image_key:    cover_image_key || null,
        cover_video_url:    cover_video_url || null,
        cover_video_key:    cover_video_key || null,
        category:           category || 'News',
        tags:                Array.isArray(tags) ? tags : [],
        status:              safeStatus,
        meta_title:          meta_title || title,
        meta_description:    meta_description || excerpt || null,
        author_id:           req.superadmin?.id || null,
        author_name:         author_name || req.superadmin?.name || 'UmrahMarket Team',
        author_avatar_url:   author_avatar_url || null,
        published_at:        safeStatus === 'published' ? new Date().toISOString() : null,
      })
      .select()
      .single();

    if (error) throw error;

    await logAuditActionSafe(req.superadmin?.id, 'CREATE_BLOG_POST', 'blog_post', data.id, `Created "${title}"`, req);

    return res.status(201).json({ success: true, data });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Failed to create blog post' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// PUT /superadmin/blog/:id — update (also handles publish/unpublish via status)
// ─────────────────────────────────────────────────────────────────────────────
router.put('/:id', authenticateSuperadmin, async (req, res) => {
  try {
    const { id } = req.params;

    const { data: existing, error: fetchErr } = await supabase
      .from('blog_posts')
      .select('id, slug, status, published_at, cover_image_key, cover_video_key')
      .eq('id', id)
      .single();

    if (fetchErr || !existing) return res.status(404).json({ success: false, message: 'Post not found' });

    const {
      title, excerpt, content, slug: rawSlug,
      cover_image_url, cover_image_key, cover_video_url, cover_video_key,
      category, tags, status, meta_title, meta_description,
      author_name, author_avatar_url,
    } = req.body || {};

    const update = {};
    if (title !== undefined)             update.title = title;
    if (excerpt !== undefined)           update.excerpt = excerpt;
    if (content !== undefined)           update.content = content;
    if (category !== undefined)          update.category = category;
    if (tags !== undefined)              update.tags = Array.isArray(tags) ? tags : [];
    if (meta_title !== undefined)        update.meta_title = meta_title;
    if (meta_description !== undefined)  update.meta_description = meta_description;
    if (author_name !== undefined)       update.author_name = author_name;
    if (author_avatar_url !== undefined) update.author_avatar_url = author_avatar_url;

    // Re-slug only if the title changed and no explicit slug override was sent
    if (rawSlug !== undefined) {
      update.slug = await ensureUniqueSlug(slugify(rawSlug), id);
    } else if (title !== undefined) {
      update.slug = await ensureUniqueSlug(slugify(title), id);
    }

    // Media — old objects are deleted from R2 below if replaced
    const oldImageKey = existing.cover_image_key;
    const oldVideoKey = existing.cover_video_key;
    if (cover_image_url !== undefined) { update.cover_image_url = cover_image_url; update.cover_image_key = cover_image_key || null; }
    if (cover_video_url !== undefined) { update.cover_video_url = cover_video_url; update.cover_video_key = cover_video_key || null; }

    // Publish/unpublish transitions
    if (status !== undefined && status !== existing.status) {
      update.status = status;
      if (status === 'published' && !existing.published_at) {
        update.published_at = new Date().toISOString();
      }
      if (status === 'draft') {
        update.published_at = null;
      }
    }

    const { data, error } = await supabase
      .from('blog_posts')
      .update(update)
      .eq('id', id)
      .select()
      .single();

    if (error) throw error;

    // Best-effort cleanup of replaced media — never block the response on this
    if (cover_image_url !== undefined && oldImageKey && oldImageKey !== update.cover_image_key) {
      R2.send(new DeleteObjectCommand({ Bucket: R2_BUCKET, Key: oldImageKey })).catch(() => {});
    }
    if (cover_video_url !== undefined && oldVideoKey && oldVideoKey !== update.cover_video_key) {
      R2.send(new DeleteObjectCommand({ Bucket: R2_BUCKET, Key: oldVideoKey })).catch(() => {});
    }

    await logAuditActionSafe(req.superadmin?.id, 'UPDATE_BLOG_POST', 'blog_post', id, `Updated "${data.title}"`, req);

    return res.json({ success: true, data });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Failed to update blog post' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// DELETE /superadmin/blog/:id
// ─────────────────────────────────────────────────────────────────────────────
router.delete('/:id', authenticateSuperadmin, async (req, res) => {
  try {
    const { id } = req.params;

    const { data: existing, error: fetchErr } = await supabase
      .from('blog_posts')
      .select('id, title, cover_image_key, cover_video_key')
      .eq('id', id)
      .single();

    if (fetchErr || !existing) return res.status(404).json({ success: false, message: 'Post not found' });

    const { error } = await supabase.from('blog_posts').delete().eq('id', id);
    if (error) throw error;

    // Best-effort R2 cleanup
    const cleanupKeys = [existing.cover_image_key, existing.cover_video_key].filter(Boolean);
    await Promise.all(
      cleanupKeys.map((key) =>
        R2.send(new DeleteObjectCommand({ Bucket: R2_BUCKET, Key: key })).catch(() => {})
      )
    );

    await logAuditActionSafe(req.superadmin?.id, 'DELETE_BLOG_POST', 'blog_post', id, `Deleted "${existing.title}"`, req);

    return res.json({ success: true, message: 'Post deleted' });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Failed to delete blog post' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// Local audit helper — mirrors logAuditAction in superadmin_routes.js.
// Kept separate (rather than importing that one too) since it isn't exported
// there. Writes to the same superadmin_audit_logs table.
// ─────────────────────────────────────────────────────────────────────────────
const logAuditActionSafe = async (superadminId, action, resourceType, resourceId, reason, req) => {
  try {
    await supabase.from('superadmin_audit_logs').insert({
      superadmin_id: superadminId || null,
      action,
      resource_type: resourceType,
      resource_id:   String(resourceId),
      reason:        reason || '',
      status:        'success',
      error_message: '',
      ip_address:    req?.headers?.['x-forwarded-for']?.split(',')[0]?.trim() || req?.socket?.remoteAddress || 'unknown',
      user_agent:    req?.get?.('user-agent') || 'unknown',
    });
  } catch {
    // audit logging must never break the request
  }
};

export default router;