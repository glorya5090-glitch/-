import assert from 'node:assert/strict';
import test from 'node:test';

const modulePath = new URL('../src/lib/agent-auth.ts', import.meta.url);
const TEST_AGENT_KEY_ID = '00000000-0000-0000-0000-000000000001';

test('resolveAgentAuthToken rejects conflicting argv and stdin sources', async () => {
  const auth = await import(`${modulePath.href}?case=${Date.now()}-1`);

  await assert.rejects(
    () =>
      auth.resolveAgentAuthToken({
        cliToken: 'argv-token',
        cliTokenStdin: true,
        readFromStdin: async () => 'stdin-token',
      }),
    /conflicts with --agent-auth-token-stdin/,
  );
});

test('resolveAgentAuthToken reads and returns stdin tokens', async () => {
  const auth = await import(`${modulePath.href}?case=${Date.now()}-2`);

  const resolved = await auth.resolveAgentAuthToken({
    cliTokenStdin: true,
    readFromStdin: async (label) => {
      assert.equal(label, 'agentAuthToken');
      return 'stdin-token';
    },
  });

  assert.deepEqual(resolved, { token: 'stdin-token', source: 'stdin' });
});

test('resolveAgentAuthToken rejects argv fallback unless explicitly allowed', async () => {
  const auth = await import(`${modulePath.href}?case=${Date.now()}-argv-reject`);

  await assert.rejects(
    () =>
      auth.resolveAgentAuthToken({
        agentKeyId: TEST_AGENT_KEY_ID,
        cliToken: 'argv-token',
        readFromStdin: async () => 'stdin-token',
      }),
    /--agent-auth-token is disabled by default/,
  );
});

test('resolveAgentAuthToken includes the placeholder migration hint when agentKeyId is absent', async () => {
  const auth = await import(`${modulePath.href}?case=${Date.now()}-argv-reject-no-agent-id`);

  await assert.rejects(
    () =>
      auth.resolveAgentAuthToken({
        cliToken: 'argv-token',
        readFromStdin: async () => 'stdin-token',
      }),
    /set --agent-key-id <uuid> --agent-auth-token-stdin/,
  );
});

test('resolveAgentAuthToken allows argv fallback when explicitly enabled', async () => {
  const auth = await import(`${modulePath.href}?case=${Date.now()}-argv-allow`);

  const resolved = await auth.resolveAgentAuthToken({
    agentKeyId: TEST_AGENT_KEY_ID,
    cliToken: 'argv-token',
    allowLegacySource: true,
    readFromStdin: async () => 'stdin-token',
  });

  assert.deepEqual(resolved, { token: 'argv-token', source: 'argv' });
});

test('resolveAgentAuthToken prefers keychain over legacy config/env sources', async () => {
  const auth = await import(`${modulePath.href}?case=${Date.now()}-3`);

  const resolved = await auth.resolveAgentAuthToken({
    agentKeyId: TEST_AGENT_KEY_ID,
    keychainToken: 'keychain-token',
    configToken: 'config-token',
    envToken: 'env-token',
    readFromStdin: async () => {
      throw new Error('stdin should not be used');
    },
  });

  assert.deepEqual(resolved, { token: 'keychain-token', source: 'keychain' });
});

test('resolveAgentAuthToken rejects config fallback unless explicitly allowed', async () => {
  const auth = await import(`${modulePath.href}?case=${Date.now()}-4`);

  await assert.rejects(
    () =>
      auth.resolveAgentAuthToken({
        agentKeyId: TEST_AGENT_KEY_ID,
        configToken: 'config-token',
        readFromStdin: async () => 'stdin-token',
      }),
    /config\.json is disabled by default/,
  );
});

test('resolveAgentAuthToken allows config fallback when explicitly enabled', async () => {
  const auth = await import(`${modulePath.href}?case=${Date.now()}-5`);

  const resolved = await auth.resolveAgentAuthToken({
    agentKeyId: TEST_AGENT_KEY_ID,
    configToken: 'config-token',
    allowLegacySource: true,
    readFromStdin: async () => 'stdin-token',
  });

  assert.deepEqual(resolved, { token: 'config-token', source: 'config' });
});

test('resolveAgentAuthToken rejects env fallback unless explicitly allowed', async () => {
  const auth = await import(`${modulePath.href}?case=${Date.now()}-6`);

  await assert.rejects(
    () =>
      auth.resolveAgentAuthToken({
        agentKeyId: TEST_AGENT_KEY_ID,
        envToken: 'env-token',
        readFromStdin: async () => 'stdin-token',
      }),
    /AGENTPAY_AGENT_AUTH_TOKEN is disabled by default/,
  );
});

test('resolveAgentAuthToken allows env fallback when explicitly enabled', async () => {
  const auth = await import(`${modulePath.href}?case=${Date.now()}-env-allow`);

  const resolved = await auth.resolveAgentAuthToken({
    agentKeyId: TEST_AGENT_KEY_ID,
    envToken: 'env-token',
    allowLegacySource: true,
    readFromStdin: async () => 'stdin-token',
  });

  assert.deepEqual(resolved, { token: 'env-token', source: 'env' });
});

test('resolveAgentAuthToken rejects malformed keychain tokens instead of silently falling back', async () => {
  const auth = await import(`${modulePath.href}?case=${Date.now()}-7`);

  await assert.rejects(
    () =>
      auth.resolveAgentAuthToken({
        agentKeyId: TEST_AGENT_KEY_ID,
        keychainToken: '   \n',
        configToken: 'config-token',
        allowLegacySource: true,
        readFromStdin: async () => 'stdin-token',
      }),
    /agentAuthToken is required/,
  );
});

test('resolveAgentAuthToken rejects oversized legacy env tokens when fallback is enabled', async () => {
  const auth = await import(`${modulePath.href}?case=${Date.now()}-8`);

  await assert.rejects(
    () =>
      auth.resolveAgentAuthToken({
        agentKeyId: TEST_AGENT_KEY_ID,
        envToken: 'a'.repeat(16 * 1024 + 1),
        allowLegacySource: true,
        readFromStdin: async () => 'stdin-token',
      }),
    /agentAuthToken must not exceed 16384 bytes/,
  );
});

test('resolveAgentAuthToken requires a token when no source is available', async () => {
  const auth = await import(`${modulePath.href}?case=${Date.now()}-required`);

  await assert.rejects(
    () =>
      auth.resolveAgentAuthToken({
        readFromStdin: async () => 'stdin-token',
      }),
    /agentAuthToken is required/,
  );
});
