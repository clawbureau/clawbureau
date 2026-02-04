// Core data types for ClawProviders programmatic SEO

// ============================================================================
// Provider Types
// ============================================================================

export interface ProviderModel {
  id: string;
  name: string;
  description: string;
  contextWindow: number;
  inputPrice?: number;  // per 1M tokens
  outputPrice?: number; // per 1M tokens
  supportsImages: boolean;
  supportsTools: boolean;
}

export interface ProviderAuthMethod {
  type: 'api_key' | 'oauth' | 'token' | 'none';
  envVar?: string;
  description: string;
  setupSteps: string[];
}

export interface Provider {
  id: string;
  name: string;
  slug: string;
  description: string;
  shortDescription: string;
  website: string;
  docsUrl: string;
  logo?: string;
  models: ProviderModel[];
  authMethods: ProviderAuthMethod[];
  defaultModel: string;
  configExample: string;
  features: string[];
  pros: string[];
  cons: string[];
  useCases: string[];
}

// ============================================================================
// Channel Types
// ============================================================================

export interface ChannelCapability {
  dms: boolean;
  groups: boolean;
  threads?: boolean;
  topics?: boolean;
  media: boolean;
  voice: boolean;
  reactions: boolean;
  nativeCommands: boolean;
}

export interface ChannelConfig {
  key: string;
  type: 'string' | 'boolean' | 'number' | 'array';
  required: boolean;
  description: string;
  default?: string | boolean | number;
  envVar?: string;
}

export interface Channel {
  id: string;
  name: string;
  slug: string;
  description: string;
  shortDescription: string;
  website?: string;
  logo?: string;
  protocolLibrary: string;
  capabilities: ChannelCapability;
  configOptions: ChannelConfig[];
  configExample: string;
  setupSteps: string[];
  dmPolicies: ('allowlist' | 'pairing' | 'open')[];
  groupPolicies: ('allowlist' | 'open')[];
  textChunkLimit: number;
  features: string[];
  pros: string[];
  cons: string[];
  useCases: string[];
}

// ============================================================================
// Deployment Types
// ============================================================================

export interface DeploymentRequirement {
  name: string;
  description: string;
  required: boolean;
}

export interface DeploymentStep {
  order: number;
  title: string;
  description: string;
  command?: string;
  note?: string;
}

export interface Deployment {
  id: string;
  name: string;
  slug: string;
  description: string;
  shortDescription: string;
  type: 'local' | 'vps' | 'cloud' | 'container';
  platform?: string;
  requirements: DeploymentRequirement[];
  steps: DeploymentStep[];
  configExample: string;
  serviceManagement: string[];
  stateDirectory: string;
  bindingModes: string[];
  authModes: string[];
  pros: string[];
  cons: string[];
  useCases: string[];
}

// ============================================================================
// Skill Types
// ============================================================================

export interface SkillDependency {
  name: string;
  type: 'npm' | 'binary' | 'system';
}

export interface Skill {
  id: string;
  name: string;
  slug: string;
  description: string;
  shortDescription: string;
  whenToUse: string;
  instructions: string;
  dependencies?: SkillDependency[];
  envVars?: Record<string, string>;
  category: string;
}

// ============================================================================
// SEO Types
// ============================================================================

export interface SEOMeta {
  title: string;
  description: string;
  canonical: string;
  ogTitle?: string;
  ogDescription?: string;
  ogImage?: string;
  twitterCard?: 'summary' | 'summary_large_image';
  robots?: string;
  keywords?: string[];
}

export interface Breadcrumb {
  name: string;
  url: string;
}

export interface FAQ {
  question: string;
  answer: string;
}

// ============================================================================
// Schema.org Types
// ============================================================================

export interface SchemaOrgArticle {
  '@context': 'https://schema.org';
  '@type': 'Article' | 'HowTo' | 'TechArticle';
  headline: string;
  description: string;
  author: {
    '@type': 'Organization';
    name: string;
    url: string;
  };
  publisher: {
    '@type': 'Organization';
    name: string;
    logo: {
      '@type': 'ImageObject';
      url: string;
    };
  };
  datePublished: string;
  dateModified: string;
  mainEntityOfPage: {
    '@type': 'WebPage';
    '@id': string;
  };
}

export interface SchemaOrgHowTo {
  '@context': 'https://schema.org';
  '@type': 'HowTo';
  name: string;
  description: string;
  step: {
    '@type': 'HowToStep';
    position: number;
    name: string;
    text: string;
  }[];
  totalTime?: string;
  estimatedCost?: {
    '@type': 'MonetaryAmount';
    currency: string;
    value: string;
  };
}

export interface SchemaOrgFAQ {
  '@context': 'https://schema.org';
  '@type': 'FAQPage';
  mainEntity: {
    '@type': 'Question';
    name: string;
    acceptedAnswer: {
      '@type': 'Answer';
      text: string;
    };
  }[];
}

export interface SchemaOrgBreadcrumb {
  '@context': 'https://schema.org';
  '@type': 'BreadcrumbList';
  itemListElement: {
    '@type': 'ListItem';
    position: number;
    name: string;
    item: string;
  }[];
}

// ============================================================================
// Page Types
// ============================================================================

export type PageType =
  | 'hub'
  | 'provider'
  | 'channel'
  | 'deployment'
  | 'skill'
  | 'provider-channel'
  | 'channel-provider'
  | 'deploy-provider'
  | 'deploy-channel'
  | 'provider-comparison'
  | 'channel-comparison'
  | 'provider-channel-deploy';

export interface PageData {
  type: PageType;
  slug: string;
  title: string;
  description: string;
  breadcrumbs: Breadcrumb[];
  seo: SEOMeta;
  faqs: FAQ[];
  relatedPages: string[];
  provider?: Provider;
  channel?: Channel;
  deployment?: Deployment;
  skill?: Skill;
  providers?: Provider[];
  channels?: Channel[];
}

// ============================================================================
// Content Generation Types
// ============================================================================

export interface TitleTemplate {
  id: string;
  pattern: string;
  pageTypes: PageType[];
}

export interface DescriptionTemplate {
  id: string;
  pattern: string;
  pageTypes: PageType[];
}

export interface FAQTemplate {
  id: string;
  question: string;
  answerPattern: string;
  pageTypes: PageType[];
  category: string;
}

// ============================================================================
// Sitemap Types
// ============================================================================

export interface SitemapEntry {
  loc: string;
  lastmod: string;
  changefreq: 'always' | 'hourly' | 'daily' | 'weekly' | 'monthly' | 'yearly' | 'never';
  priority: number;
}

export interface SitemapIndex {
  sitemaps: {
    loc: string;
    lastmod: string;
  }[];
}

// ============================================================================
// Page Matrix Types
// ============================================================================

export interface PageMatrixEntry {
  slug: string;
  type: PageType;
  providerId?: string;
  channelId?: string;
  deploymentId?: string;
  skillId?: string;
  comparisonIds?: string[];
}

export interface PageMatrix {
  version: string;
  generatedAt: string;
  totalPages: number;
  entries: PageMatrixEntry[];
}
