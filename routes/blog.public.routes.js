import express from 'express';
import { supabaseAdmin as supabase } from '../config/supabase.js';

const router = express.Router();

// ─────────────────────────────────────────────────────────────────────────────
// GET /blog — published posts only, for the public /blog index.
// Query: ?category=News&limit=20&offset=0
// ─────────────────────────────────────────────────────────────────────────────
router.get('/', async (req, res) => {
  try {
    const { category, limit = 20, offset = 0 } = req.query;

    let query = supabase
      .from('blog_posts')
      .select(`
        id, slug, title, excerpt, cover_image_url, cover_video_url,
        author_name, author_avatar_url, category, tags,
        view_count, published_at
      `)
      .eq('status', 'published')
      .order('published_at', { ascending: false })
      .range(Number(offset), Number(offset) + Number(limit) - 1);

    if (category && category !== 'all') query = query.eq('category', category);

    const { data, error } = await query;
    if (error) throw error;

    return res.json({ success: true, data: data || [] });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Failed to fetch posts' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /blog/:slug — single published post, for /blog/:slug.
// Best-effort view_count increment — never blocks or fails the response.
// ─────────────────────────────────────────────────────────────────────────────
router.get('/:slug', async (req, res) => {
  try {
    const { slug } = req.params;

    const { data, error } = await supabase
      .from('blog_posts')
      .select('*')
      .eq('slug', slug)
      .eq('status', 'published')
      .single();

    if (error || !data) return res.status(404).json({ success: false, message: 'Post not found' });

    supabase
      .from('blog_posts')
      .update({ view_count: (data.view_count || 0) + 1 })
      .eq('id', data.id)
      .then(() => {})
      .catch(() => {});

    // Related posts — same category, most recent, excluding this one
    const { data: related } = await supabase
      .from('blog_posts')
      .select('id, slug, title, excerpt, cover_image_url, published_at')
      .eq('status', 'published')
      .eq('category', data.category)
      .neq('id', data.id)
      .order('published_at', { ascending: false })
      .limit(3);

    return res.json({ success: true, data: { ...data, related: related || [] } });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Failed to fetch post' });
  }
});

export default router;