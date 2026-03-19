import { defineConfig } from 'tsup';

export default defineConfig({
  bundle: true,
  clean: true,
  dts: true,
  entry: ['src/index.ts', 'src/client/index.ts', 'src/errors/index.ts', 'src/service/index.ts'],
  format: ['esm', 'cjs'],
  outDir: 'dist',
  sourcemap: true,
  splitting: true,
  target: 'node20',
});
