import { describe, expect, it } from 'vitest';
import { inspectPage } from '../src/pages/inspect.js';

describe('inspect page', () => {
  it('renders GitHub sign-in affordance and decrypt UX copy', () => {
    const html = inspectPage({
      auth: { authenticated: false },
      authStatus: null,
    });

    expect(html).toContain('Sign in with GitHub');
    expect(html).toContain('Public verification layer is always visible');
    expect(html).toContain('Decrypt Plaintext');
  });
});
