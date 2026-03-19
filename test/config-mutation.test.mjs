import assert from 'node:assert/strict';
import test from 'node:test';

const modulePath = new URL('../src/lib/config-mutation.ts', import.meta.url);

async function loadModule(caseSuffix) {
  return await import(`${modulePath.href}?case=${caseSuffix}-${Date.now()}`);
}

test('assertWritableConfigKey accepts the supported control-plane keys', async () => {
  const configMutation = await loadModule('supported');

  assert.equal(configMutation.assertWritableConfigKey('rpcUrl'), 'rpcUrl');
  assert.equal(configMutation.assertWritableConfigKey('daemonSocket'), 'daemonSocket');
  assert.equal(configMutation.assertWritableConfigKey('agentKeyId'), 'agentKeyId');
});

test('assertWritableConfigKey rejects legacy plaintext agent auth storage', async () => {
  const configMutation = await loadModule('agent-auth-token');

  assert.throws(
    () => configMutation.assertWritableConfigKey('agentAuthToken'),
    /agentAuthToken must be stored with `agentpay config agent-auth set --agent-key-id <uuid> --agent-auth-token-stdin`/,
  );
});

test('resolveConfigMutationCommandLabel renders the root-guarded config command label', async () => {
  const configMutation = await loadModule('command-label');

  assert.equal(
    configMutation.resolveConfigMutationCommandLabel('set', 'rpcUrl'),
    'agentpay config set rpcUrl',
  );
  assert.equal(
    configMutation.resolveConfigMutationCommandLabel('unset', 'daemonSocket'),
    'agentpay config unset daemonSocket',
  );
});

test('resolveConfigMutationCommandLabel fails closed for unsupported config keys', async () => {
  const configMutation = await loadModule('unsupported');

  assert.throws(
    () => configMutation.resolveConfigMutationCommandLabel('set', 'wallet'),
    /Unsupported config key: wallet/,
  );
});
