import assert from 'node:assert/strict';
import test from 'node:test';

const modulePath = new URL('../apps/web/src/lib/config.ts', import.meta.url);

async function loadConfig(caseSuffix) {
  return await import(`${modulePath.href}?case=${caseSuffix}-${Date.now()}`);
}

test('assertSafeRelayBaseUrl allows loopback http and trims trailing slash', async () => {
  const config = await loadConfig('loopback');
  assert.equal(config.assertSafeRelayBaseUrl('http://127.0.0.1:8787/'), 'http://127.0.0.1:8787');
});

test('assertSafeRelayBaseUrl rejects non-loopback http relay URLs', async () => {
  const config = await loadConfig('remote-http');
  assert.throws(
    () => config.assertSafeRelayBaseUrl('http://relay.example'),
    /must use https unless it targets localhost or a loopback address/,
  );
});

test('assertSafeRelayBaseUrl rejects embedded credentials', async () => {
  const config = await loadConfig('credentials');
  assert.throws(
    () => config.assertSafeRelayBaseUrl('https://user:pass@relay.example'),
    /must not include embedded credentials/,
  );
});
