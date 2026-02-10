import { describe, expect, it } from 'vitest';

import {
  buildProviderUrl,
  buildFalOpenrouterUrl,
  buildFalOpenrouterAuthHeader,
  isFalOpenrouterModel,
} from '../src/providers';

describe('providers', () => {
  it('builds OpenAI chat completions URL by default', () => {
    expect(buildProviderUrl('openai', 'gpt-5.2')).toBe('https://api.openai.com/v1/chat/completions');
  });

  it('builds OpenAI responses URL when requested', () => {
    expect(buildProviderUrl('openai', 'gpt-5.2', { openaiApi: 'responses' })).toBe(
      'https://api.openai.com/v1/responses'
    );
  });

  it('requires model for Google Gemini URL building', () => {
    expect(() => buildProviderUrl('google')).toThrow(/Model is required/);
  });

  it('builds Google Gemini OpenAI-compat chat completions URL', () => {
    expect(buildProviderUrl('google', 'gemini-3-flash-preview')).toBe(
      'https://generativelanguage.googleapis.com/v1beta/openai/chat/completions'
    );
  });

  it('builds Google Gemini OpenAI-compat responses URL when requested', () => {
    expect(buildProviderUrl('google', 'gemini-3-flash-preview', { openaiApi: 'responses' })).toBe(
      'https://generativelanguage.googleapis.com/v1beta/openai/responses'
    );
  });

  it('detects fal OpenRouter model prefix', () => {
    expect(isFalOpenrouterModel('openrouter/openai/gpt-4o-mini')).toBe(true);
    expect(isFalOpenrouterModel('OpenRouter/anthropic/claude-3.5-sonnet')).toBe(true);
    expect(isFalOpenrouterModel('gpt-4o-mini')).toBe(false);
    expect(isFalOpenrouterModel(undefined)).toBe(false);
  });

  it('builds fal OpenRouter chat completions URL by default', () => {
    expect(buildFalOpenrouterUrl()).toBe('https://fal.run/openrouter/router/openai/v1/chat/completions');
  });

  it('builds fal OpenRouter responses URL when requested', () => {
    expect(buildFalOpenrouterUrl({ openaiApi: 'responses' })).toBe('https://fal.run/openrouter/router/openai/v1/responses');
  });

  it('builds fal OpenRouter Authorization: Key header (strips optional Key prefix)', () => {
    expect(buildFalOpenrouterAuthHeader('fal_abc').Authorization).toBe('Key fal_abc');
    expect(buildFalOpenrouterAuthHeader('Key fal_abc').Authorization).toBe('Key fal_abc');
  });
});
