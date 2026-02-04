import type { APIRoute } from 'astro';
import { getProviders, getChannels, getDeployments, getPageCount } from '../lib/data/loaders';

export const GET: APIRoute = async () => {
  const providers = getProviders();
  const channels = getChannels();
  const deployments = getDeployments();
  const pageCount = getPageCount();

  const content = `# ClawProviders.com
> Complete setup guides for OpenClaw AI assistants

This site contains ${pageCount}+ integration guides for OpenClaw, the open-source AI assistant gateway.

## Site Structure

- **/providers/** - AI model provider setup guides (${providers.length} providers)
- **/channels/** - Messaging channel integration guides (${channels.length} channels)
- **/deploy/** - Deployment method guides (${deployments.length} methods)
- **/compare/** - Side-by-side comparisons

## AI Providers

${providers.map((p) => `### ${p.name}
- Slug: ${p.slug}
- Models: ${p.models.map((m) => m.name).join(', ')}
- Default: ${p.defaultModel}
- Auth: ${p.authMethods.map((a) => a.type).join(', ')}
- Guide: /providers/${p.slug}/`).join('\n\n')}

## Messaging Channels

${channels.map((c) => `### ${c.name}
- Slug: ${c.slug}
- DMs: ${c.capabilities.dms ? 'Yes' : 'No'}
- Groups: ${c.capabilities.groups ? 'Yes' : 'No'}
- Media: ${c.capabilities.media ? 'Yes' : 'No'}
- Guide: /channels/${c.slug}/`).join('\n\n')}

## Deployment Methods

${deployments.map((d) => `### ${d.name}
- Slug: ${d.slug}
- Difficulty: ${d.difficulty}
- Platform: ${d.platform}
- Guide: /deploy/${d.slug}/`).join('\n\n')}

## Combinatorial Pages

This site generates pages for every combination of:
- Provider + Channel: /providers/{provider}/{channel}/
- Channel + Provider: /channels/{channel}/{provider}/
- Deploy + Provider: /deploy/{method}/{provider}/
- Provider vs Provider: /compare/providers/{a}-vs-{b}/
- Channel vs Channel: /compare/channels/{a}-vs-{b}/

## API

No API is provided. This is a static site. All content is available via standard HTTP requests.

## Contact

For OpenClaw support, visit: https://github.com/openclaw/openclaw
`;

  return new Response(content, {
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      'Cache-Control': 'public, max-age=86400',
    },
  });
};
