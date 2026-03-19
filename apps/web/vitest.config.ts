import path from 'node:path';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  esbuild: {
    jsx: 'automatic',
    target: 'es2022',
  },
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  test: {
    environment: 'jsdom',
    environmentOptions: {
      jsdom: {
        url: 'http://localhost:3000/',
      },
    },
    exclude: ['node_modules', 'dist', '.next', '.turbo'],
    globals: true,
    include: ['test/**/*.test.tsx'],
  },
});
