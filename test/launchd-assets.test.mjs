import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

const modulePath = new URL('../src/lib/launchd-assets.ts', import.meta.url);

test('resolveLaunchDaemonHelperScriptPath falls back to the configured rustBinDir path when no helper exists', async () => {
  const launchdAssets = await import(`${modulePath.href}?case=${Date.now()}-fallback`);
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-launchd-assets-'));

  try {
    const rustBinDir = path.join(tempRoot, 'bin');
    fs.mkdirSync(rustBinDir, { recursive: true, mode: 0o700 });

    const resolved = launchdAssets.resolveLaunchDaemonHelperScriptPath('missing-helper.sh', {
      rustBinDir,
    });

    assert.equal(resolved, path.join(rustBinDir, 'missing-helper.sh'));
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});

test('resolveLaunchDaemonHelperScriptPath returns the checked-in launchd helper when it exists', async () => {
  const launchdAssets = await import(`${modulePath.href}?case=${Date.now()}-checked-in-helper`);
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-launchd-assets-default-'));
  const originalAgentPayHome = process.env.AGENTPAY_HOME;

  process.env.AGENTPAY_HOME = path.join(tempRoot, 'home');

  try {
    const resolved = launchdAssets.resolveLaunchDaemonHelperScriptPath(
      launchdAssets.LAUNCHD_INSTALL_SCRIPT_NAME,
    );

    assert.equal(
      resolved,
      path.resolve(process.cwd(), 'scripts/launchd', launchdAssets.LAUNCHD_INSTALL_SCRIPT_NAME),
    );
  } finally {
    if (originalAgentPayHome === undefined) {
      delete process.env.AGENTPAY_HOME;
    } else {
      process.env.AGENTPAY_HOME = originalAgentPayHome;
    }
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});
