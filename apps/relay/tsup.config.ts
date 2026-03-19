import { defineConfig } from 'tsup';

export default defineConfig({
  bundle: true,
  clean: true,
  dts: true,
  entry: ['src/index.ts', 'src/server.ts', 'src/handlers/api.ts'],
  format: ['esm', 'cjs'],
  outDir: 'dist',
  sourcemap: true,
  splitting: true,
  target: 'node20',
});
