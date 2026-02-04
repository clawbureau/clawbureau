import type { Provider, Channel, Deployment } from './types';
import providersData from '../../data/extracted/providers.json';
import channelsData from '../../data/extracted/channels.json';
import deploymentsData from '../../data/extracted/deployments.json';

// ============================================================================
// Data Loaders
// ============================================================================

export function getProviders(): Provider[] {
  return providersData.providers as Provider[];
}

export function getProvider(slug: string): Provider | undefined {
  return getProviders().find((p) => p.slug === slug);
}

export function getChannels(): Channel[] {
  return channelsData.channels as Channel[];
}

export function getChannel(slug: string): Channel | undefined {
  return getChannels().find((c) => c.slug === slug);
}

export function getDeployments(): Deployment[] {
  return deploymentsData.deployments as Deployment[];
}

export function getDeployment(slug: string): Deployment | undefined {
  return getDeployments().find((d) => d.slug === slug);
}

// ============================================================================
// Combination Generators
// ============================================================================

export interface ProviderChannelCombo {
  provider: Provider;
  channel: Channel;
}

export function getProviderChannelCombos(): ProviderChannelCombo[] {
  const providers = getProviders();
  const channels = getChannels();
  const combos: ProviderChannelCombo[] = [];

  for (const provider of providers) {
    for (const channel of channels) {
      combos.push({ provider, channel });
    }
  }

  return combos;
}

export interface DeploymentProviderCombo {
  deployment: Deployment;
  provider: Provider;
}

export function getDeploymentProviderCombos(): DeploymentProviderCombo[] {
  const deployments = getDeployments();
  const providers = getProviders();
  const combos: DeploymentProviderCombo[] = [];

  for (const deployment of deployments) {
    for (const provider of providers) {
      combos.push({ deployment, provider });
    }
  }

  return combos;
}

export interface DeploymentChannelCombo {
  deployment: Deployment;
  channel: Channel;
}

export function getDeploymentChannelCombos(): DeploymentChannelCombo[] {
  const deployments = getDeployments();
  const channels = getChannels();
  const combos: DeploymentChannelCombo[] = [];

  for (const deployment of deployments) {
    for (const channel of channels) {
      combos.push({ deployment, channel });
    }
  }

  return combos;
}

export interface ProviderComparison {
  a: Provider;
  b: Provider;
}

export function getProviderComparisons(): ProviderComparison[] {
  const providers = getProviders();
  const comparisons: ProviderComparison[] = [];

  for (let i = 0; i < providers.length; i++) {
    for (let j = i + 1; j < providers.length; j++) {
      comparisons.push({ a: providers[i], b: providers[j] });
    }
  }

  return comparisons;
}

export interface ChannelComparison {
  a: Channel;
  b: Channel;
}

export function getChannelComparisons(): ChannelComparison[] {
  const channels = getChannels();
  const comparisons: ChannelComparison[] = [];

  for (let i = 0; i < channels.length; i++) {
    for (let j = i + 1; j < channels.length; j++) {
      comparisons.push({ a: channels[i], b: channels[j] });
    }
  }

  return comparisons;
}

// ============================================================================
// Page Matrix Generation
// ============================================================================

export interface PageEntry {
  slug: string;
  type: string;
  priority: number;
}

export function generatePageMatrix(): PageEntry[] {
  const pages: PageEntry[] = [];

  // Hub pages
  pages.push({ slug: '/', type: 'hub', priority: 1.0 });
  pages.push({ slug: '/providers/', type: 'hub', priority: 0.9 });
  pages.push({ slug: '/channels/', type: 'hub', priority: 0.9 });
  pages.push({ slug: '/deploy/', type: 'hub', priority: 0.9 });
  pages.push({ slug: '/compare/', type: 'hub', priority: 0.8 });
  pages.push({ slug: '/simple-claw/', type: 'hub', priority: 0.9 });
  pages.push({ slug: '/use-cases/', type: 'hub', priority: 0.8 });
  pages.push({ slug: '/setup-guide/', type: 'hub', priority: 0.8 });

  // Provider pages
  for (const provider of getProviders()) {
    pages.push({
      slug: `/providers/${provider.slug}/`,
      type: 'provider',
      priority: 0.8,
    });
  }

  // Channel pages
  for (const channel of getChannels()) {
    pages.push({
      slug: `/channels/${channel.slug}/`,
      type: 'channel',
      priority: 0.8,
    });
  }

  // Deployment pages
  for (const deployment of getDeployments()) {
    pages.push({
      slug: `/deploy/${deployment.slug}/`,
      type: 'deployment',
      priority: 0.8,
    });
  }

  // Provider + Channel combinations
  for (const { provider, channel } of getProviderChannelCombos()) {
    pages.push({
      slug: `/providers/${provider.slug}/${channel.slug}/`,
      type: 'provider-channel',
      priority: 0.7,
    });
  }

  // Channel + Provider (reverse routing)
  for (const { provider, channel } of getProviderChannelCombos()) {
    pages.push({
      slug: `/channels/${channel.slug}/${provider.slug}/`,
      type: 'channel-provider',
      priority: 0.7,
    });
  }

  // Deployment + Provider combinations
  for (const { deployment, provider } of getDeploymentProviderCombos()) {
    pages.push({
      slug: `/deploy/${deployment.slug}/${provider.slug}/`,
      type: 'deploy-provider',
      priority: 0.6,
    });
  }

  // Provider comparisons
  for (const { a, b } of getProviderComparisons()) {
    pages.push({
      slug: `/compare/providers/${a.slug}-vs-${b.slug}/`,
      type: 'provider-comparison',
      priority: 0.6,
    });
  }

  // Channel comparisons
  for (const { a, b } of getChannelComparisons()) {
    pages.push({
      slug: `/compare/channels/${a.slug}-vs-${b.slug}/`,
      type: 'channel-comparison',
      priority: 0.6,
    });
  }

  return pages;
}

export function getPageCount(): number {
  return generatePageMatrix().length;
}
