import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

const modulePath = new URL('../src/lib/cli-version.ts', import.meta.url);

test('resolveCliVersion follows symlinked CLI entrypoints back to the package root', async () => {
  const cliVersion = await import(`${modulePath.href}?case=${Date.now()}-symlinked-entrypoint`);
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-cli-version-module-'));
  const packageRoot = path.join(root, 'package');
  const distDir = path.join(packageRoot, 'dist');
  const binDir = path.join(root, 'bin');
  const symlinkPath = path.join(binDir, 'agentpay');

  try {
    fs.mkdirSync(distDir, { recursive: true });
    fs.mkdirSync(binDir, { recursive: true });
    fs.writeFileSync(path.join(packageRoot, 'package.json'), JSON.stringify({ version: '9.8.7' }));
    fs.writeFileSync(path.join(distDir, 'cli.cjs'), '#!/usr/bin/env node\n');
    fs.symlinkSync(path.join('..', 'package', 'dist', 'cli.cjs'), symlinkPath);

    assert.equal(cliVersion.resolveCliVersion({ cwd: root, scriptPath: symlinkPath }), '9.8.7');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('resolveCliVersion falls back to unknown when no package metadata can be found', async () => {
  const cliVersion = await import(`${modulePath.href}?case=${Date.now()}-missing-package-json`);
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-cli-version-module-missing-'));

  try {
    assert.equal(
      cliVersion.resolveCliVersion({ cwd: root, scriptPath: path.join(root, 'bin', 'agentpay') }),
      'unknown',
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
