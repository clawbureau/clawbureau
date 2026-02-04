/**
 * Content Validation Script
 *
 * Checks for:
 * - Duplicate or highly similar content
 * - Missing required fields
 * - SEO issues (title length, description length)
 *
 * Run with: npx tsx scripts/validate-content.ts
 */

import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

interface Provider {
  id: string;
  slug: string;
  name: string;
  description: string;
  shortDescription: string;
  models: Array<{ name: string }>;
  authMethods: Array<{ type: string }>;
  features: string[];
}

interface Channel {
  id: string;
  slug: string;
  name: string;
  description: string;
  shortDescription: string;
  features: string[];
}

interface Deployment {
  id: string;
  slug: string;
  name: string;
  description: string;
  shortDescription: string;
}

// Load data
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const dataDir = join(__dirname, '../src/data/extracted');
const providers: Provider[] = JSON.parse(
  readFileSync(join(dataDir, 'providers.json'), 'utf-8')
).providers;
const channels: Channel[] = JSON.parse(
  readFileSync(join(dataDir, 'channels.json'), 'utf-8')
).channels;
const deployments: Deployment[] = JSON.parse(
  readFileSync(join(dataDir, 'deployments.json'), 'utf-8')
).deployments;

let errors = 0;
let warnings = 0;

function error(msg: string) {
  console.error(`ERROR: ${msg}`);
  errors++;
}

function warn(msg: string) {
  console.warn(`WARN: ${msg}`);
  warnings++;
}

function info(msg: string) {
  console.log(`INFO: ${msg}`);
}

// ============================================================================
// Validation: Required Fields
// ============================================================================

info('Checking required fields...');

for (const provider of providers) {
  if (!provider.id) error(`Provider missing id: ${JSON.stringify(provider)}`);
  if (!provider.slug) error(`Provider missing slug: ${provider.name || 'unknown'}`);
  if (!provider.name) error(`Provider missing name: ${provider.slug || 'unknown'}`);
  if (!provider.description) error(`Provider ${provider.slug} missing description`);
  if (!provider.shortDescription) error(`Provider ${provider.slug} missing shortDescription`);
  if (!provider.models?.length) error(`Provider ${provider.slug} has no models`);
  if (!provider.authMethods?.length) error(`Provider ${provider.slug} has no auth methods`);
}

for (const channel of channels) {
  if (!channel.id) error(`Channel missing id: ${JSON.stringify(channel)}`);
  if (!channel.slug) error(`Channel missing slug: ${channel.name || 'unknown'}`);
  if (!channel.name) error(`Channel missing name: ${channel.slug || 'unknown'}`);
  if (!channel.description) error(`Channel ${channel.slug} missing description`);
  if (!channel.shortDescription) error(`Channel ${channel.slug} missing shortDescription`);
}

for (const deployment of deployments) {
  if (!deployment.id) error(`Deployment missing id: ${JSON.stringify(deployment)}`);
  if (!deployment.slug) error(`Deployment missing slug: ${deployment.name || 'unknown'}`);
  if (!deployment.name) error(`Deployment missing name: ${deployment.slug || 'unknown'}`);
  if (!deployment.description) error(`Deployment ${deployment.slug} missing description`);
}

// ============================================================================
// Validation: SEO Best Practices
// ============================================================================

info('Checking SEO best practices...');

for (const provider of providers) {
  if (provider.shortDescription && provider.shortDescription.length > 160) {
    warn(`Provider ${provider.slug} shortDescription too long (${provider.shortDescription.length} chars, max 160)`);
  }
  if (provider.shortDescription && provider.shortDescription.length < 50) {
    warn(`Provider ${provider.slug} shortDescription too short (${provider.shortDescription.length} chars, min 50)`);
  }
}

for (const channel of channels) {
  if (channel.shortDescription && channel.shortDescription.length > 160) {
    warn(`Channel ${channel.slug} shortDescription too long (${channel.shortDescription.length} chars, max 160)`);
  }
  if (channel.shortDescription && channel.shortDescription.length < 50) {
    warn(`Channel ${channel.slug} shortDescription too short (${channel.shortDescription.length} chars, min 50)`);
  }
}

// ============================================================================
// Validation: Unique Slugs
// ============================================================================

info('Checking for unique slugs...');

const providerSlugs = new Set<string>();
for (const provider of providers) {
  if (providerSlugs.has(provider.slug)) {
    error(`Duplicate provider slug: ${provider.slug}`);
  }
  providerSlugs.add(provider.slug);
}

const channelSlugs = new Set<string>();
for (const channel of channels) {
  if (channelSlugs.has(channel.slug)) {
    error(`Duplicate channel slug: ${channel.slug}`);
  }
  channelSlugs.add(channel.slug);
}

const deploymentSlugs = new Set<string>();
for (const deployment of deployments) {
  if (deploymentSlugs.has(deployment.slug)) {
    error(`Duplicate deployment slug: ${deployment.slug}`);
  }
  deploymentSlugs.add(deployment.slug);
}

// ============================================================================
// Validation: Content Similarity
// ============================================================================

info('Checking for content similarity...');

function similarity(a: string, b: string): number {
  const setA = new Set(a.toLowerCase().split(/\s+/));
  const setB = new Set(b.toLowerCase().split(/\s+/));
  const intersection = new Set([...setA].filter((x) => setB.has(x)));
  const union = new Set([...setA, ...setB]);
  return intersection.size / union.size;
}

// Check provider descriptions
for (let i = 0; i < providers.length; i++) {
  for (let j = i + 1; j < providers.length; j++) {
    const sim = similarity(providers[i].description, providers[j].description);
    if (sim > 0.85) {
      warn(
        `High similarity (${(sim * 100).toFixed(0)}%) between providers: ${providers[i].slug} and ${providers[j].slug}`
      );
    }
  }
}

// Check channel descriptions
for (let i = 0; i < channels.length; i++) {
  for (let j = i + 1; j < channels.length; j++) {
    const sim = similarity(channels[i].description, channels[j].description);
    if (sim > 0.85) {
      warn(
        `High similarity (${(sim * 100).toFixed(0)}%) between channels: ${channels[i].slug} and ${channels[j].slug}`
      );
    }
  }
}

// ============================================================================
// Summary
// ============================================================================

console.log('\n========================================');
console.log('Validation Summary');
console.log('========================================');
console.log(`Providers: ${providers.length}`);
console.log(`Channels: ${channels.length}`);
console.log(`Deployments: ${deployments.length}`);
console.log(`Errors: ${errors}`);
console.log(`Warnings: ${warnings}`);
console.log('========================================');

if (errors > 0) {
  console.log('\n❌ Validation FAILED');
  process.exit(1);
} else if (warnings > 0) {
  console.log('\n⚠️  Validation passed with warnings');
  process.exit(0);
} else {
  console.log('\n✅ Validation PASSED');
  process.exit(0);
}
