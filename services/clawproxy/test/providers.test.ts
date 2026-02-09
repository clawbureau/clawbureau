import { describe, expect, it } from 'vitest';

import { buildProviderUrl } from '../src/providers';

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
});
