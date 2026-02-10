import test from 'node:test';
import assert from 'node:assert/strict';

import { createClawproxyProvider } from '../dist/provider.js';

test('routes openrouter/* models via /v1/proxy/openai', async () => {
  const originalFetch = globalThis.fetch;

  /** @type {string | null} */
  let calledUrl = null;

  globalThis.fetch = async (url, init) => {
    calledUrl = String(url);

    // Respond in OpenAI chat-completions shape so the provider can extract text.
    const body = JSON.stringify({
      choices: [{ message: { content: 'OK' } }],
    });

    return new Response(body, {
      status: 200,
      headers: { 'content-type': 'application/json; charset=utf-8' },
    });
  };

  try {
    const provider = createClawproxyProvider(
      { baseUrl: 'https://clawproxy.test', defaultProvider: 'anthropic' },
      {
        logger: {
          debug() {},
          info() {},
          warn() {},
          error() {},
        },
      },
    );

    const events = [];
    for await (const ev of provider.stream(
      'openrouter/openai/gpt-4o-mini',
      [{ role: 'user', content: 'hi' }],
      { auth: { Authorization: 'Key fak_test' } },
    )) {
      events.push(ev);
    }

    assert.equal(calledUrl, 'https://clawproxy.test/v1/proxy/openai');
    assert(events.some((e) => e.type === 'text' && e.text === 'OK'));
  } finally {
    globalThis.fetch = originalFetch;
  }
});
