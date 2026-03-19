import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    exclude: [
      '**/node_modules/**',
      // These use node:test (not vitest) and have dedicated CI workflows
      '**/test/cross-platform.test.ts',
      '**/test/wrap-reseal.test.ts',
    ],
  },
});
