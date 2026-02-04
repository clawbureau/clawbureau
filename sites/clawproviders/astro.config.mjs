// @ts-check
import { defineConfig } from 'astro/config';

// https://astro.build/config
export default defineConfig({
  output: 'static',
  site: 'https://clawproviders.com',
  trailingSlash: 'always',
  build: {
    format: 'directory',
  },
  vite: {
    build: {
      minify: true,
    },
  },
});
