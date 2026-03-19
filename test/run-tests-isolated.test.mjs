import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { constants as osConstants } from 'node:os';
import test from 'node:test';

const repoRoot = new URL('..', import.meta.url).pathname;
const scriptPath = new URL('../scripts/run-tests-isolated.mjs', import.meta.url).pathname;

function signalExitCode(signal) {
  const signalNumber = osConstants.signals[signal];
  return typeof signalNumber === 'number' ? 128 + signalNumber : 128;
}

test('run-tests-isolated preserves child signal exit codes', () => {
  const signal = 'SIGKILL';
  const result = spawnSync(
    process.execPath,
    [
      scriptPath,
      '--',
      process.execPath,
      '--input-type=module',
      '-e',
      `process.kill(process.pid, '${signal}')`,
    ],
    {
      cwd: repoRoot,
      encoding: 'utf8',
    },
  );

  assert.equal(result.status, signalExitCode(signal));
});
