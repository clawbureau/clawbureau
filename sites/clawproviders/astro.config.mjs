// @ts-check
import { defineConfig } from 'astro/config';
import cloudflare from '@astrojs/cloudflare';

// https://astro.build/config
export default defineConfig({
  output: 'static',
  site: 'https://clawproviders.com',
  build: {
    format: 'directory',
  },
  vite: {
    build: {
      minify: true,
    },
  },
});
