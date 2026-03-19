import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    cli: 'src/cli.ts'
  },
  format: ['cjs'],
  platform: 'node',
  target: 'node20',
  clean: true,
  sourcemap: true,
  dts: false,
  banner: {
    js: '#!/usr/bin/env node'
  },
  outExtension() {
    return { js: '.cjs' };
  },
  noExternal: [
    '@worldlibertyfinancial/agent-config',
    '@worldlibertyfinancial/agent-rpc',
    'commander',
    'viem'
  ]
});
