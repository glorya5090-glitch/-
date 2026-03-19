import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import test from 'node:test';

const scriptPath = path.join(process.cwd(), 'scripts', 'run-installer-smoke.sh');

test('installer smoke helper exposes a stable help entrypoint', () => {
  const result = spawnSync('bash', [scriptPath, '--help'], {
    cwd: process.cwd(),
    encoding: 'utf8',
  });

  assert.equal(result.status, 0, result.stderr || result.stdout);
  assert.match(result.stdout, /Run a GitHub-friendly macOS smoke test/u);
  assert.match(result.stdout, /--work-dir/u);
  assert.match(result.stdout, /--bundle-archive/u);
  assert.match(result.stdout, /--keep-work-dir/u);
});
