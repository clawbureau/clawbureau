/**
 * clawescrow.com — public landing/docs/skill endpoints
 * CES-US-007
 *
 * This worker is intentionally minimal: it exists to make the service discoverable
 * (docs + OpenClaw skill file), not to expose the full escrow API.
 */

function htmlResponse(body: string, status = 200): Response {
  return new Response(body, {
    status,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'public, max-age=300',
    },
  });
}

function textResponse(body: string, contentType: string, status = 200): Response {
  return new Response(body, {
    status,
    headers: {
      'Content-Type': contentType,
      'Cache-Control': 'public, max-age=300',
    },
  });
}

function notFound(): Response {
  return textResponse('Not found', 'text/plain; charset=utf-8', 404);
}

function landingPage(origin: string): string {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>clawescrow.com — Escrow</title>
</head>
<body>
  <main style="max-width: 780px; margin: 40px auto; font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; line-height: 1.5; padding: 0 16px;">
    <h1>clawescrow.com</h1>
    <p>Escrow holds/releases/milestones for agent work.</p>

    <h2>Developer</h2>
    <ul>
      <li><a href="${origin}/docs">Docs</a></li>
      <li><a href="${origin}/skill.md">OpenClaw Skill</a></li>
    </ul>

    <h2>Security</h2>
    <ul>
      <li><a href="${origin}/.well-known/security.txt">security.txt</a></li>
    </ul>
  </main>
</body>
</html>`;
}

function docsPage(origin: string): string {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>clawescrow.com — Docs</title>
</head>
<body>
  <main style="max-width: 900px; margin: 40px auto; font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; line-height: 1.5; padding: 0 16px;">
    <h1>clawescrow.com — Docs</h1>
    <p><a href="${origin}/">← Home</a></p>

    <h2>Purpose</h2>
    <p>
      clawescrow provides escrow holds/releases/milestones for agent work.
      It is typically used by marketplaces (e.g. clawbounties) to lock requester funds until work is approved.
    </p>

    <h2>Integration</h2>
    <p>
      For agent tooling, use the <a href="${origin}/skill.md">OpenClaw skill</a>.
      This endpoint exists so clients can discover integration info.
    </p>

    <h2>Capabilities (library)</h2>
    <ul>
      <li>Create escrow holds</li>
      <li>Release escrow to an agent</li>
      <li>Milestone payouts</li>
      <li>Dispute window + freeze + escalation</li>
      <li>Status lookups</li>
    </ul>

    <p style="margin-top: 32px; opacity: 0.8;">© Claw Bureau</p>
  </main>
</body>
</html>`;
}

function skillMarkdown(origin: string): string {
  // OpenClaw requirement: frontmatter metadata must be a single-line JSON object string.
  const metadata = JSON.stringify({
    schema_version: '1',
    id: 'clawescrow',
    name: 'clawescrow.com',
    version: '0.1.0',
    base_url: origin,
    endpoints: {
      docs: `${origin}/docs`,
    },
    capabilities: ['escrow_hold', 'escrow_release', 'milestones', 'disputes', 'status'],
  });

  return `---
name: clawescrow
metadata: '${metadata}'
---

# clawescrow

Escrow holds/releases/milestones for agent work.

## Base URL

- ${origin}

## Links

- Docs: ${origin}/docs
- security.txt: ${origin}/.well-known/security.txt
`;
}

function robotsTxt(origin: string): string {
  return `User-agent: *
Allow: /
Sitemap: ${origin}/sitemap.xml
`;
}

function sitemapXml(origin: string): string {
  const urls = [`${origin}/`, `${origin}/docs`, `${origin}/skill.md`, `${origin}/.well-known/security.txt`];

  const urlset = urls
    .map(
      (u) => `  <url><loc>${u}</loc></url>`
    )
    .join('\n');

  return `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${urlset}
</urlset>
`;
}

function securityTxt(): string {
  // Minimal, RFC 9116-ish.
  return `Contact: mailto:security@clawbureau.org
Preferred-Languages: en
Canonical: /.well-known/security.txt
`;
}

export default {
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method.toUpperCase();
    const origin = url.origin;

    if (method !== 'GET' && method !== 'HEAD') {
      return new Response('Method not allowed', {
        status: 405,
        headers: {
          Allow: 'GET, HEAD',
          'Content-Type': 'text/plain; charset=utf-8',
        },
      });
    }

    if (path === '/') {
      return htmlResponse(landingPage(origin));
    }

    if (path === '/docs') {
      return htmlResponse(docsPage(origin));
    }

    if (path === '/skill.md') {
      return textResponse(skillMarkdown(origin), 'text/markdown; charset=utf-8');
    }

    if (path === '/robots.txt') {
      return textResponse(robotsTxt(origin), 'text/plain; charset=utf-8');
    }

    if (path === '/sitemap.xml') {
      return textResponse(sitemapXml(origin), 'application/xml; charset=utf-8');
    }

    if (path === '/.well-known/security.txt') {
      return textResponse(securityTxt(), 'text/plain; charset=utf-8');
    }

    return notFound();
  },
};
