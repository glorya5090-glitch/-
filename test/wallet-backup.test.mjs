import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

const walletBackupModulePath = new URL('../src/lib/wallet-backup.ts', import.meta.url);
const walletBackupAdminModulePath = new URL('../src/lib/wallet-backup-admin.ts', import.meta.url);

const TEST_PRIVATE_KEY = '11'.repeat(32);
const TEST_VAULT_KEY_ID = '00000000-0000-0000-0000-000000000001';

function tempPath(prefix, suffix = '') {
  return path.join(
    os.tmpdir(),
    `${prefix}-${process.pid}-${Date.now()}-${Math.random().toString(16).slice(2)}${suffix}`,
  );
}

test('wallet backup encrypts and decrypts software wallet material', async () => {
  const walletBackup = await import(walletBackupModulePath.href + `?case=${Date.now()}-roundtrip`);

  const backup = walletBackup.createEncryptedWalletBackup({
    privateKeyHex: TEST_PRIVATE_KEY,
    sourceVaultKeyId: TEST_VAULT_KEY_ID,
    password: 'backup-secret',
  });
  const decrypted = walletBackup.decryptWalletBackup(backup, 'backup-secret');

  assert.equal(decrypted.privateKeyHex, TEST_PRIVATE_KEY);
  assert.equal(decrypted.sourceVaultKeyId, TEST_VAULT_KEY_ID);
  assert.match(decrypted.address, /^0x[0-9a-fA-F]{40}$/u);
  assert.match(decrypted.vaultPublicKey, /^0x[0-9a-fA-F]+$/u);
});

test('wallet backup rejects an incorrect password', async () => {
  const walletBackup = await import(
    walletBackupModulePath.href + `?case=${Date.now()}-wrong-password`
  );

  const backup = walletBackup.createEncryptedWalletBackup({
    privateKeyHex: TEST_PRIVATE_KEY,
    password: 'backup-secret',
  });

  assert.throws(
    () => walletBackup.decryptWalletBackup(backup, 'wrong-password'),
    /wallet backup password is incorrect or the backup file is corrupted/,
  );
});

test('wallet backup file verify round-trips encrypted metadata', async () => {
  const walletBackup = await import(
    walletBackupModulePath.href + `?case=${Date.now()}-verify-file`
  );

  const outputPath = tempPath('agentpay-wallet-backup', '.json');
  try {
    const backup = walletBackup.createEncryptedWalletBackup({
      privateKeyHex: TEST_PRIVATE_KEY,
      sourceVaultKeyId: TEST_VAULT_KEY_ID,
      password: 'backup-secret',
    });
    walletBackup.writeEncryptedWalletBackupFile(outputPath, backup);

    const verified = walletBackup.verifyWalletBackupFile(outputPath, 'backup-secret');
    assert.equal(verified.sourcePath, path.resolve(outputPath));
    assert.equal(verified.sourceVaultKeyId, TEST_VAULT_KEY_ID);
    assert.match(verified.address, /^0x[0-9a-fA-F]{40}$/u);
  } finally {
    fs.rmSync(outputPath, { force: true });
  }
});

test('defaultWalletBackupOutputPath uses the dedicated agentpay-backups directory', async () => {
  const walletBackup = await import(
    walletBackupModulePath.href + `?case=${Date.now()}-default-output-path`
  );

  const outputPath = walletBackup.defaultWalletBackupOutputPath(
    '0x1234567890abcdef1234567890abcdef12345678',
  );
  assert.match(outputPath, /agentpay-backups/u);
  assert.match(outputPath, /agentpay-wallet-backup-1234567890ab\.json$/u);
});

test('temporary wallet import key files are written under AGENTPAY_HOME and cleaned up', async () => {
  const walletBackup = await import(
    walletBackupModulePath.href + `?case=${Date.now()}-temporary-import-file`
  );
  const agentpayHome = tempPath('agentpay-home');
  const originalAgentPayHome = process.env.AGENTPAY_HOME;

  process.env.AGENTPAY_HOME = agentpayHome;
  try {
    const writtenPath = walletBackup.writeTemporaryWalletImportKeyFile(TEST_PRIVATE_KEY);
    assert.equal(path.dirname(writtenPath), path.resolve(agentpayHome));
    assert.equal(fs.readFileSync(writtenPath, 'utf8').trim(), TEST_PRIVATE_KEY);

    assert.deepEqual(walletBackup.cleanupTemporaryWalletImportKeyFile(writtenPath), {
      path: path.resolve(writtenPath),
      action: 'deleted',
    });
    assert.equal(fs.existsSync(writtenPath), false);
  } finally {
    if (originalAgentPayHome === undefined) {
      delete process.env.AGENTPAY_HOME;
    } else {
      process.env.AGENTPAY_HOME = originalAgentPayHome;
    }
    fs.rmSync(agentpayHome, { recursive: true, force: true });
  }
});

test('temporary wallet import key cleanup reports failures without throwing', async () => {
  const walletBackup = await import(
    walletBackupModulePath.href + `?case=${Date.now()}-temporary-import-file-cleanup-failure`
  );
  const agentpayHome = tempPath('agentpay-home');
  const originalAgentPayHome = process.env.AGENTPAY_HOME;

  process.env.AGENTPAY_HOME = agentpayHome;
  try {
    const writtenPath = walletBackup.writeTemporaryWalletImportKeyFile(TEST_PRIVATE_KEY);
    const originalRmSync = fs.rmSync;
    fs.rmSync = (targetPath, ...args) => {
      if (path.resolve(String(targetPath)) === path.resolve(writtenPath)) {
        throw new Error('delete failed');
      }
      return originalRmSync.call(fs, targetPath, ...args);
    };

    try {
      const result = walletBackup.cleanupTemporaryWalletImportKeyFile(writtenPath);
      assert.equal(result.path, path.resolve(writtenPath));
      assert.equal(result.action, 'failed');
      assert.match(result.error ?? '', /delete failed/u);
    } finally {
      fs.rmSync = originalRmSync;
    }

    assert.equal(fs.existsSync(writtenPath), true);
  } finally {
    if (originalAgentPayHome === undefined) {
      delete process.env.AGENTPAY_HOME;
    } else {
      process.env.AGENTPAY_HOME = originalAgentPayHome;
    }
    fs.rmSync(agentpayHome, { recursive: true, force: true });
  }
});

test('exportEncryptedWalletBackup pulls the private key from rust admin JSON and writes an encrypted backup', async () => {
  const walletBackup = await import(
    walletBackupModulePath.href + `?case=${Date.now()}-export-admin-verify`
  );
  const walletBackupAdmin = await import(
    walletBackupAdminModulePath.href + `?case=${Date.now()}-export-admin`
  );

  const outputPath = tempPath('agentpay-wallet-export', '.json');
  try {
    const exported = await walletBackupAdmin.exportEncryptedWalletBackup(
      {
        daemonSocket: '/Library/AgentPay/run/daemon.sock',
        vaultPassword: 'vault-secret',
        backupPassword: 'backup-secret',
        outputPath,
      },
      {
        readConfig: () => ({ wallet: { vaultKeyId: TEST_VAULT_KEY_ID } }),
        resolveWalletProfile: () => ({ vaultKeyId: TEST_VAULT_KEY_ID }),
        runRustBinaryJson: async (_binary, args, _config, options) => {
          const nonce = args.indexOf('--vault-key-id');
          assert.ok(nonce >= 0);
          assert.equal(args[nonce + 1], TEST_VAULT_KEY_ID);
          assert.equal(options?.stdin, 'vault-secret\n');
          return {
            vault_key_id: TEST_VAULT_KEY_ID,
            vault_private_key: TEST_PRIVATE_KEY,
          };
        },
      },
    );

    assert.equal(exported.outputPath, path.resolve(outputPath));
    const verified = walletBackup.verifyWalletBackupFile(outputPath, 'backup-secret');
    assert.equal(verified.address, exported.address);
    assert.equal(verified.sourceVaultKeyId, TEST_VAULT_KEY_ID);
  } finally {
    fs.rmSync(outputPath, { force: true });
  }
});
