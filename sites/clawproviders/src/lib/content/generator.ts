import type {
  Provider,
  Channel,
  Deployment,
  PageType,
  SEOMeta,
  FAQ,
  Breadcrumb,
  TitleTemplate,
  DescriptionTemplate,
  FAQTemplate,
} from '../data/types';

// ============================================================================
// Title Templates with Variations
// ============================================================================

const titleTemplates: TitleTemplate[] = [
  // Provider pages
  { id: 'provider-1', pattern: 'Setup {provider} with OpenClaw', pageTypes: ['provider'] },
  { id: 'provider-2', pattern: '{provider} Integration Guide for OpenClaw', pageTypes: ['provider'] },
  { id: 'provider-3', pattern: 'How to Use {provider} with OpenClaw AI', pageTypes: ['provider'] },
  { id: 'provider-4', pattern: 'Connect {provider} to OpenClaw', pageTypes: ['provider'] },

  // Channel pages
  { id: 'channel-1', pattern: 'Setup {channel} with OpenClaw', pageTypes: ['channel'] },
  { id: 'channel-2', pattern: '{channel} Bot Guide for OpenClaw', pageTypes: ['channel'] },
  { id: 'channel-3', pattern: 'How to Build a {channel} AI Assistant', pageTypes: ['channel'] },
  { id: 'channel-4', pattern: 'Connect OpenClaw to {channel}', pageTypes: ['channel'] },

  // Provider + Channel pages
  { id: 'provider-channel-1', pattern: 'Setup {provider} on {channel} with OpenClaw', pageTypes: ['provider-channel'] },
  { id: 'provider-channel-2', pattern: '{provider} + {channel} Integration Guide', pageTypes: ['provider-channel'] },
  { id: 'provider-channel-3', pattern: 'Build a {channel} Bot with {provider}', pageTypes: ['provider-channel'] },
  { id: 'provider-channel-4', pattern: 'Connect {provider} AI to {channel}', pageTypes: ['provider-channel'] },

  // Deployment pages
  { id: 'deploy-1', pattern: '{deployment} Deployment Guide for OpenClaw', pageTypes: ['deployment'] },
  { id: 'deploy-2', pattern: 'How to Deploy OpenClaw on {deployment}', pageTypes: ['deployment'] },
  { id: 'deploy-3', pattern: 'OpenClaw {deployment} Setup Guide', pageTypes: ['deployment'] },

  // Deploy + Provider pages
  { id: 'deploy-provider-1', pattern: 'Deploy {provider} on {deployment} with OpenClaw', pageTypes: ['deploy-provider'] },
  { id: 'deploy-provider-2', pattern: '{deployment} Setup for {provider} AI', pageTypes: ['deploy-provider'] },

  // Comparison pages
  { id: 'compare-provider-1', pattern: '{provider1} vs {provider2} for AI Assistants', pageTypes: ['provider-comparison'] },
  { id: 'compare-provider-2', pattern: 'Compare {provider1} and {provider2} with OpenClaw', pageTypes: ['provider-comparison'] },
  { id: 'compare-channel-1', pattern: '{channel1} vs {channel2} for AI Bots', pageTypes: ['channel-comparison'] },
];

// ============================================================================
// Description Templates
// ============================================================================

const descriptionTemplates: DescriptionTemplate[] = [
  {
    id: 'provider-1',
    pattern: 'Learn how to configure {provider} with OpenClaw. Step-by-step guide covering authentication, model selection, and best practices for {provider} AI integration.',
    pageTypes: ['provider'],
  },
  {
    id: 'provider-2',
    pattern: 'Complete guide to setting up {provider} with your OpenClaw AI assistant. Includes configuration examples, auth methods, and troubleshooting tips.',
    pageTypes: ['provider'],
  },
  {
    id: 'channel-1',
    pattern: 'Setup your AI assistant on {channel} with OpenClaw. Complete guide covering authentication, access control, and message handling for {channel} bots.',
    pageTypes: ['channel'],
  },
  {
    id: 'channel-2',
    pattern: 'Build a {channel} AI bot with OpenClaw. Step-by-step integration guide with configuration examples and best practices.',
    pageTypes: ['channel'],
  },
  {
    id: 'provider-channel-1',
    pattern: 'Create a {channel} AI assistant powered by {provider}. Complete setup guide with configuration, authentication, and deployment instructions.',
    pageTypes: ['provider-channel'],
  },
  {
    id: 'deployment-1',
    pattern: 'Deploy OpenClaw using {deployment}. Complete guide covering installation, configuration, service management, and security best practices.',
    pageTypes: ['deployment'],
  },
  {
    id: 'compare-provider-1',
    pattern: 'Compare {provider1} vs {provider2} for AI assistants. Detailed comparison of features, pricing, models, and best use cases.',
    pageTypes: ['provider-comparison'],
  },
];

// ============================================================================
// FAQ Templates
// ============================================================================

const faqTemplates: FAQTemplate[] = [
  // Provider FAQs
  {
    id: 'provider-cost',
    question: 'How much does {provider} cost with OpenClaw?',
    answerPattern: '{provider} pricing depends on your usage. {provider} charges based on tokens processed. OpenClaw itself is free and open source. You only pay for the AI provider API costs.',
    pageTypes: ['provider'],
    category: 'pricing',
  },
  {
    id: 'provider-auth',
    question: 'How do I authenticate {provider} with OpenClaw?',
    answerPattern: '{provider} supports {authMethods}. The most common method is using an API key which you can get from the {provider} console.',
    pageTypes: ['provider'],
    category: 'setup',
  },
  {
    id: 'provider-models',
    question: 'Which {provider} models work with OpenClaw?',
    answerPattern: 'OpenClaw supports all {provider} models including {modelList}. You can configure your preferred model in openclaw.json or use model aliases for convenience.',
    pageTypes: ['provider'],
    category: 'features',
  },
  {
    id: 'provider-fallback',
    question: 'Can I use {provider} as a fallback provider?',
    answerPattern: 'Yes, OpenClaw supports automatic failover. You can configure {provider} as a fallback in the model configuration. If your primary provider fails, OpenClaw will automatically switch to {provider}.',
    pageTypes: ['provider'],
    category: 'features',
  },

  // Channel FAQs
  {
    id: 'channel-setup',
    question: 'How do I set up {channel} with OpenClaw?',
    answerPattern: 'To set up {channel}: {setupStepsSummary}. Full configuration options are available in the openclaw.json file.',
    pageTypes: ['channel'],
    category: 'setup',
  },
  {
    id: 'channel-access',
    question: 'How do I control who can message my {channel} bot?',
    answerPattern: '{channel} supports {dmPolicies} for DM access control and {groupPolicies} for groups. Use allowlists for maximum security or pairing mode for easy onboarding.',
    pageTypes: ['channel'],
    category: 'security',
  },
  {
    id: 'channel-media',
    question: 'Does {channel} support media messages?',
    answerPattern: '{channel} supports media including {mediaTypes}. Maximum media size is configurable via mediaMaxMb setting (default: {mediaMaxMb}MB).',
    pageTypes: ['channel'],
    category: 'features',
  },
  {
    id: 'channel-groups',
    question: 'Can I use OpenClaw in {channel} groups?',
    answerPattern: '{channel} supports group chats with configurable access policies. {groupFeatures}',
    pageTypes: ['channel'],
    category: 'features',
  },

  // Provider + Channel FAQs
  {
    id: 'pc-setup',
    question: 'How do I set up {provider} with {channel}?',
    answerPattern: 'Configure {provider} as your AI provider and enable {channel} as a channel in openclaw.json. The gateway routes {channel} messages to {provider} for processing automatically.',
    pageTypes: ['provider-channel'],
    category: 'setup',
  },
  {
    id: 'pc-best',
    question: 'Is {provider} a good choice for {channel} bots?',
    answerPattern: '{provider} works great with {channel}. {providerStrengths} make it well-suited for {channelUseCases}.',
    pageTypes: ['provider-channel'],
    category: 'comparison',
  },

  // Deployment FAQs
  {
    id: 'deploy-requirements',
    question: 'What are the requirements for {deployment}?',
    answerPattern: '{deployment} requires: {requirements}. The setup typically takes {setupTime} for first-time users.',
    pageTypes: ['deployment'],
    category: 'requirements',
  },
  {
    id: 'deploy-state',
    question: 'Where is state stored with {deployment}?',
    answerPattern: 'State is stored in {stateDirectory}. This includes configuration, credentials, session history, and workspace files. Always back up this directory.',
    pageTypes: ['deployment'],
    category: 'architecture',
  },
];

// ============================================================================
// Content Generation Functions
// ============================================================================

/**
 * Select a title template based on page type and a hash for variation
 */
export function generateTitle(
  pageType: PageType,
  entities: {
    provider?: Provider;
    channel?: Channel;
    deployment?: Deployment;
    provider1?: Provider;
    provider2?: Provider;
    channel1?: Channel;
    channel2?: Channel;
  }
): string {
  const templates = titleTemplates.filter((t) => t.pageTypes.includes(pageType));
  if (templates.length === 0) {
    return 'OpenClaw Setup Guide';
  }

  // Use entity names to create a hash for consistent variation selection
  const hashInput = Object.values(entities)
    .filter(Boolean)
    .map((e) => (e as { id: string }).id)
    .join('-');
  const hash = simpleHash(hashInput);
  const template = templates[hash % templates.length];

  return interpolateTemplate(template.pattern, entities);
}

/**
 * Generate meta description
 */
export function generateDescription(
  pageType: PageType,
  entities: {
    provider?: Provider;
    channel?: Channel;
    deployment?: Deployment;
    provider1?: Provider;
    provider2?: Provider;
  }
): string {
  const templates = descriptionTemplates.filter((t) => t.pageTypes.includes(pageType));
  if (templates.length === 0) {
    return 'Complete guide for setting up OpenClaw AI assistant.';
  }

  const hashInput = Object.values(entities)
    .filter(Boolean)
    .map((e) => (e as { id: string }).id)
    .join('-');
  const hash = simpleHash(hashInput);
  const template = templates[hash % templates.length];

  return interpolateTemplate(template.pattern, entities);
}

/**
 * Generate FAQs for a page
 */
export function generateFAQs(
  pageType: PageType,
  entities: {
    provider?: Provider;
    channel?: Channel;
    deployment?: Deployment;
  }
): FAQ[] {
  const templates = faqTemplates.filter((t) => t.pageTypes.includes(pageType));

  return templates.slice(0, 5).map((template) => ({
    question: interpolateFAQTemplate(template.question, entities),
    answer: interpolateFAQTemplate(template.answerPattern, entities),
  }));
}

/**
 * Generate breadcrumbs for a page
 */
export function generateBreadcrumbs(
  pageType: PageType,
  entities: {
    provider?: Provider;
    channel?: Channel;
    deployment?: Deployment;
  }
): Breadcrumb[] {
  const crumbs: Breadcrumb[] = [{ name: 'Home', url: '/' }];

  switch (pageType) {
    case 'provider':
      crumbs.push({ name: 'Providers', url: '/providers/' });
      if (entities.provider) {
        crumbs.push({
          name: entities.provider.name,
          url: `/providers/${entities.provider.slug}/`,
        });
      }
      break;

    case 'channel':
      crumbs.push({ name: 'Channels', url: '/channels/' });
      if (entities.channel) {
        crumbs.push({
          name: entities.channel.name,
          url: `/channels/${entities.channel.slug}/`,
        });
      }
      break;

    case 'provider-channel':
      crumbs.push({ name: 'Providers', url: '/providers/' });
      if (entities.provider) {
        crumbs.push({
          name: entities.provider.name,
          url: `/providers/${entities.provider.slug}/`,
        });
      }
      if (entities.channel) {
        crumbs.push({
          name: entities.channel.name,
          url: `/providers/${entities.provider?.slug}/${entities.channel.slug}/`,
        });
      }
      break;

    case 'deployment':
      crumbs.push({ name: 'Deploy', url: '/deploy/' });
      if (entities.deployment) {
        crumbs.push({
          name: entities.deployment.name,
          url: `/deploy/${entities.deployment.slug}/`,
        });
      }
      break;

    default:
      break;
  }

  return crumbs;
}

/**
 * Generate full SEO meta object
 */
export function generateSEOMeta(
  pageType: PageType,
  slug: string,
  entities: {
    provider?: Provider;
    channel?: Channel;
    deployment?: Deployment;
    provider1?: Provider;
    provider2?: Provider;
  }
): SEOMeta {
  const title = generateTitle(pageType, entities);
  const description = generateDescription(pageType, entities);
  const canonical = `https://clawproviders.com${slug}`;

  const keywords: string[] = [];
  if (entities.provider) keywords.push(entities.provider.name, 'AI provider', entities.provider.id);
  if (entities.channel) keywords.push(entities.channel.name, 'chat bot', entities.channel.id);
  if (entities.deployment) keywords.push(entities.deployment.name, 'deployment');
  keywords.push('OpenClaw', 'AI assistant', 'setup guide');

  return {
    title,
    description,
    canonical,
    ogTitle: title,
    ogDescription: description,
    keywords,
    robots: 'index, follow',
    twitterCard: 'summary_large_image',
  };
}

/**
 * Generate related pages for internal linking
 */
export function generateRelatedPages(
  pageType: PageType,
  entities: {
    provider?: Provider;
    channel?: Channel;
    deployment?: Deployment;
  },
  allProviders: Provider[],
  allChannels: Channel[],
  allDeployments: Deployment[]
): string[] {
  const related: string[] = [];

  // Add provider-channel combinations
  if (entities.provider) {
    allChannels.slice(0, 3).forEach((ch) => {
      related.push(`/providers/${entities.provider!.slug}/${ch.slug}/`);
    });
  }

  if (entities.channel) {
    allProviders.slice(0, 3).forEach((pr) => {
      related.push(`/channels/${entities.channel!.slug}/${pr.slug}/`);
    });
  }

  // Add deployment pages
  if (!entities.deployment) {
    allDeployments.slice(0, 2).forEach((dep) => {
      related.push(`/deploy/${dep.slug}/`);
    });
  }

  return related.slice(0, 6);
}

// ============================================================================
// Helper Functions
// ============================================================================

function simpleHash(str: string): number {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = (hash << 5) - hash + char;
    hash = hash & hash;
  }
  return Math.abs(hash);
}

function interpolateTemplate(
  template: string,
  entities: {
    provider?: Provider;
    channel?: Channel;
    deployment?: Deployment;
    provider1?: Provider;
    provider2?: Provider;
    channel1?: Channel;
    channel2?: Channel;
  }
): string {
  let result = template;

  if (entities.provider) {
    result = result.replace(/{provider}/g, entities.provider.name);
  }
  if (entities.channel) {
    result = result.replace(/{channel}/g, entities.channel.name);
  }
  if (entities.deployment) {
    result = result.replace(/{deployment}/g, entities.deployment.name);
  }
  if (entities.provider1) {
    result = result.replace(/{provider1}/g, entities.provider1.name);
  }
  if (entities.provider2) {
    result = result.replace(/{provider2}/g, entities.provider2.name);
  }
  if (entities.channel1) {
    result = result.replace(/{channel1}/g, entities.channel1.name);
  }
  if (entities.channel2) {
    result = result.replace(/{channel2}/g, entities.channel2.name);
  }

  return result;
}

function interpolateFAQTemplate(
  template: string,
  entities: {
    provider?: Provider;
    channel?: Channel;
    deployment?: Deployment;
  }
): string {
  let result = template;

  if (entities.provider) {
    const p = entities.provider;
    result = result.replace(/{provider}/g, p.name);
    result = result.replace(/{authMethods}/g, p.authMethods.map((a) => a.type).join(', '));
    result = result.replace(/{modelList}/g, p.models.slice(0, 3).map((m) => m.name).join(', '));
    result = result.replace(/{providerStrengths}/g, p.pros.slice(0, 2).join(' and '));
  }

  if (entities.channel) {
    const c = entities.channel;
    result = result.replace(/{channel}/g, c.name);
    result = result.replace(/{setupStepsSummary}/g, c.setupSteps.slice(0, 3).join('. '));
    result = result.replace(/{dmPolicies}/g, c.dmPolicies.join(', '));
    result = result.replace(/{groupPolicies}/g, c.groupPolicies.join(', '));
    result = result.replace(/{mediaMaxMb}/g, String(c.textChunkLimit / 1000));
    result = result.replace(/{mediaTypes}/g, c.capabilities.media ? 'images, audio, video, documents' : 'text only');
    result = result.replace(/{groupFeatures}/g, c.capabilities.groups ? 'Groups and DMs are supported.' : 'DMs only.');
    result = result.replace(/{channelUseCases}/g, c.useCases.slice(0, 2).join(' and '));
  }

  if (entities.deployment) {
    const d = entities.deployment;
    result = result.replace(/{deployment}/g, d.name);
    result = result.replace(/{requirements}/g, d.requirements.filter((r) => r.required).map((r) => r.name).join(', '));
    result = result.replace(/{stateDirectory}/g, d.stateDirectory);
    result = result.replace(/{setupTime}/g, '15-30 minutes');
  }

  return result;
}
