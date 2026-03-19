import path from 'node:path';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  esbuild: {
    target: 'node20',
  },
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  test: {
    environment: 'node',
    exclude: ['node_modules', 'dist', '.serverless', '.turbo'],
    globals: true,
    include: ['src/**/*.test.ts'],
  },
});
