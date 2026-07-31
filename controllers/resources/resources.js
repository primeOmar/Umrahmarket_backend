import supabase from '../../config/supabase.js';
import { deleteResourceFromR2 } from './r2ResourceUpload.js';

export const handleDatabaseError = (res, error) => {
  
  return res.status(500).json({ success: false, message: 'An internal server error occurred.' });
};

function sanitizeText(value = '', maxLen = 120) {
  return String(value)
    .replace(/\0/g, '')
    .replace(/<[^>]*>/g, '')
    .replace(/&(?:#x?[\da-f]+|[a-z]+);/gi, '')
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '')
    .replace(/[ \t]+/g, ' ')
    .trimStart()
    .slice(0, maxLen);
}

// ─────────────────────────────────────────────────────────────────────────────
// createResource   POST /api/superadmin/resources
// Expects: multipart/form-data { title, description, file }
// req.resourceFile is set by uploadResourceToR2 middleware (url, key, mimeType,
// size, isImage, isPdf) and must run before this controller.
// ─────────────────────────────────────────────────────────────────────────────
export const createResource = async (req, res) => {
  const userId = req.user?.id ?? req.userId ?? null;

  const title       = sanitizeText(req.body.title, 150);
  const description = sanitizeText(req.body.description, 1000);

  if (!title) {
    return res.status(400).json({ success: false, message: 'Title is required.' });
  }

  const resourceFile = req.resourceFile;
  if (!resourceFile) {
    return res.status(400).json({ success: false, message: 'No file was uploaded.' });
  }

  const currentTime = new Date().toISOString();

  const newResource = {
    title,
    description: description || null,
    file_url:    resourceFile.url,
    file_key:    resourceFile.key,
    file_type:   resourceFile.isPdf ? 'pdf' : 'image',
    mime_type:   resourceFile.mimeType,
    file_size:   resourceFile.size,
    created_by:  userId,
    created_at:  currentTime,
    updated_at:  currentTime,
  };

  try {
    const { data, error } = await supabase
      .from('resources')
      .insert([newResource])
      .select('id, title, description, file_url, file_type, mime_type, file_size, created_by, created_at')
      .single();

    if (error) {
      
      // Roll back the uploaded file so we don't leave orphans in R2
      await deleteResourceFromR2(resourceFile.url);
      throw error;
    }

    return res.status(201).json({
      success:  true,
      message:  `Resource "${title}" has been uploaded successfully.`,
      resource: data,
    });

  } catch (error) {
    return handleDatabaseError(res, error);
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// getResources   GET /api/superadmin/resources
// Supports optional ?search= (matches title) and pagination via ?page & ?limit
// ─────────────────────────────────────────────────────────────────────────────
export const getResources = async (req, res) => {
  const page  = Math.max(parseInt(req.query.page, 10)  || 1, 1);
  const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 20, 1), 100);
  const from  = (page - 1) * limit;
  const to    = from + limit - 1;
  const search = sanitizeText(req.query.search, 150);

  try {
    let query = supabase
      .from('resources')
      .select('id, title, description, file_url, file_type, mime_type, file_size, created_by, created_at', { count: 'exact' })
      .order('created_at', { ascending: false })
      .range(from, to);

    if (search) {
      query = query.ilike('title', `%${search}%`);
    }

    const { data, error, count } = await query;
    if (error) throw error;

    return res.status(200).json({
      success:      true,
      resources:    data ?? [],
      totalRecords: count ?? 0,
      page,
      limit,
    });

  } catch (error) {
    return handleDatabaseError(res, error);
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// deleteResource   DELETE /api/superadmin/resources/:id
// Removes the DB row and best-effort cleans up the R2 object.
// ─────────────────────────────────────────────────────────────────────────────
export const deleteResource = async (req, res) => {
  const { id } = req.params;

  if (!id) {
    return res.status(400).json({ success: false, message: 'Resource id is required.' });
  }

  try {
    const { data: existing, error: fetchError } = await supabase
      .from('resources')
      .select('id, file_url')
      .eq('id', id)
      .single();

    if (fetchError || !existing) {
      return res.status(404).json({ success: false, message: 'Resource not found.' });
    }

    const { error: deleteError } = await supabase
      .from('resources')
      .delete()
      .eq('id', id);

    if (deleteError) throw deleteError;

    // Best-effort R2 cleanup — non-fatal if it fails, DB record is already gone
    await deleteResourceFromR2(existing.file_url);

    return res.status(200).json({ success: true, message: 'Resource deleted successfully.' });

  } catch (error) {
    return handleDatabaseError(res, error);
  }
};