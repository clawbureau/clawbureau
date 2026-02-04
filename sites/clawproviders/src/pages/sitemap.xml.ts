import type { APIRoute } from 'astro';
import { generatePageMatrix } from '../lib/data/loaders';

const SITE_URL = 'https://clawproviders.com';
const URLS_PER_SITEMAP = 50000;

export const GET: APIRoute = async () => {
  const pages = generatePageMatrix();
  const totalPages = pages.length;
  const sitemapCount = Math.ceil(totalPages / URLS_PER_SITEMAP);

  // If we have fewer than 50K URLs, just create a simple sitemap
  if (sitemapCount === 1) {
    const urls = pages
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
  }

  // Otherwise, create a sitemap index
  const sitemaps = Array.from({ length: sitemapCount }, (_, i) => i + 1)
    .map(
      (n) => `  <sitemap>
    <loc>${SITE_URL}/sitemap-${n}.xml</loc>
  </sitemap>`
    )
    .join('\n');

  const sitemapIndex = `<?xml version="1.0" encoding="UTF-8"?>
<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${sitemaps}
</sitemapindex>`;

  return new Response(sitemapIndex, {
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
