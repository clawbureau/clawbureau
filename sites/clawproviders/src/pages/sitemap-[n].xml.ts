import type { APIRoute, GetStaticPaths } from 'astro';
import { generatePageMatrix } from '../lib/data/loaders';

const SITE_URL = 'https://clawproviders.com';
const URLS_PER_SITEMAP = 50000;

export const getStaticPaths: GetStaticPaths = async () => {
  const pages = generatePageMatrix();
  const totalPages = pages.length;
  const sitemapCount = Math.ceil(totalPages / URLS_PER_SITEMAP);

  // Only generate chunked sitemaps if we need more than one
  if (sitemapCount <= 1) {
    return [];
  }

  return Array.from({ length: sitemapCount }, (_, i) => ({
    params: { n: String(i + 1) },
  }));
};

export const GET: APIRoute = async ({ params }) => {
  const n = parseInt(params.n || '1', 10);
  const pages = generatePageMatrix();

  const start = (n - 1) * URLS_PER_SITEMAP;
  const end = start + URLS_PER_SITEMAP;
  const chunk = pages.slice(start, end);

  const urls = chunk
    .map(
      (page) => `  <url>
    <loc>${SITE_URL}${page.slug}</loc>
    <changefreq>${getChangeFreq(page.type)}</changefreq>
    <priority>${page.priority.toFixed(1)}</priority>
  </url>`
    )
    .join('\n');

  const sitemap = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${urls}
</urlset>`;

  return new Response(sitemap, {
    headers: {
      'Content-Type': 'application/xml',
      'Cache-Control': 'public, max-age=3600',
    },
  });
};

function getChangeFreq(type: string): string {
  switch (type) {
    case 'hub':
      return 'weekly';
    case 'provider':
    case 'channel':
    case 'deployment':
      return 'weekly';
    default:
      return 'monthly';
  }
}
