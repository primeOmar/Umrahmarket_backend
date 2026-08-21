
import { Router } from 'express';
import { createClient } from '@supabase/supabase-js';
import { LANDING_PAGES } from '../src/seo/landingPagesConfig.js';

const router = Router();

const SITE_ORIGIN = 'https://www.umrahmarket.net';

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY,
);

const FIXED_ROUTES = [
  { path: '/', changefreq: 'daily', priority: '1.0' },
  { path: '/agents', changefreq: 'daily', priority: '0.9' },
  { path: '/guidance', changefreq: 'monthly', priority: '0.7' },
  { path: '/experiences', changefreq: 'monthly', priority: '0.6' },
  { path: '/verified', changefreq: 'monthly', priority: '0.6' },
];

let cache = { xml: null, expiresAt: 0 };
const CACHE_TTL_MS = 15 * 60 * 1000;

function slugify(name) {
  return String(name || 'package')
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/(^-|-$)/g, '');
}

function urlEntry(loc, changefreq, priority, lastmod) {
  return `  <url>
    <loc>${loc}</loc>
${lastmod ? `    <lastmod>${lastmod}</lastmod>\n` : ''}    <changefreq>${changefreq}</changefreq>
    <priority>${priority}</priority>
  </url>`;
}

async function buildSitemapXml() {
  const entries = [];

  // 1. Fixed static routes
  for (const r of FIXED_ROUTES) {
    entries.push(urlEntry(`${SITE_ORIGIN}${r.path}`, r.changefreq, r.priority));
  }

  // 2. Programmatic landing pages — read live from landingPagesConfig.js
  for (const entry of LANDING_PAGES) {
    entries.push(urlEntry(`${SITE_ORIGIN}${entry.path}`, 'weekly', '0.8'));
  }

  // 3. Live active packages
  const { data: packages, error: pkgError } = await supabase
    .from('packages')
    .select('id, name, status, updated_at')
    .eq('status', 'Active'); // exact casing as stored in the DB

  if (pkgError) {
    console.error('[sitemap] failed to fetch packages:', pkgError.message);
  } else {
    for (const pkg of packages || []) {
      const slug = slugify(pkg.name);
      const lastmod = pkg.updated_at ? new Date(pkg.updated_at).toISOString().slice(0, 10) : null;
      entries.push(
        urlEntry(`${SITE_ORIGIN}/umra-package/${slug}/${pkg.id}`, 'weekly', '0.8', lastmod),
      );
    }
  }

  // 4. Verified agents — "profiles" table rows with role='agent', not a
  //    separate agents table.
  const { data: agents, error: agentError } = await supabase
    .from('profiles')
    .select('id, updated_at, role, approved, verification_status')
    .eq('role', 'agent')
    .eq('approved', true)
    .eq('verification_status', 'approved');

  if (agentError) {
    console.error('[sitemap] failed to fetch agent profiles:', agentError.message);
  } else {
    for (const agent of agents || []) {
      const lastmod = agent.updated_at ? new Date(agent.updated_at).toISOString().slice(0, 10) : null;
      entries.push(urlEntry(`${SITE_ORIGIN}/agents/${agent.id}`, 'weekly', '0.7', lastmod));
    }
  }

  return `<?xml version="1.0" encoding="UTF-8"?>
<!--
  Dynamic sitemap for umrahmarket.net, served from the Render Express
  backend. Built live on each request (cached ${CACHE_TTL_MS / 60000} min)
  from fixed routes, landingPagesConfig.js, active Supabase packages, and
  verified agent profiles (profiles table, role='agent').
  Do not reintroduce a committed static sitemap.xml — that's what caused
  the 7 landing pages to silently disappear from the live sitemap before.
  Only one sitemap source (this route OR api/sitemap.js on Vercel) should
  be wired up at a time — check vercel.json's /sitemap.xml rewrite target
  before deploying this.
-->
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${entries.join('\n')}
</urlset>
`;
}

router.get('/sitemap.xml', async (req, res) => {
  try {
    const now = Date.now();
    if (!cache.xml || cache.expiresAt < now) {
      cache.xml = await buildSitemapXml();
      cache.expiresAt = now + CACHE_TTL_MS;
    }
    res.set('Content-Type', 'application/xml; charset=utf-8');
    res.send(cache.xml);
  } catch (err) {
    console.error('[sitemap] fatal error building sitemap:', err);
    res.status(500).send('Error generating sitemap');
  }
});

export default router;