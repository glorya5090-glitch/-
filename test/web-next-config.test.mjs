import assert from 'node:assert/strict';
import test from 'node:test';

const modulePath = new URL('../apps/web/next.config.ts', import.meta.url);

async function loadConfig(caseSuffix) {
  return await import(`${modulePath.href}?case=${caseSuffix}-${Date.now()}`);
}

test('next config serves hardened approval-console security headers', async () => {
  const configModule = await loadConfig('headers');
  const headers = await configModule.default.headers();

  assert.equal(headers.length, 3);
  assert.equal(headers[0].source, '/approvals/:path*');
  assert.equal(headers[1].source, '/daemons/:path*');
  assert.equal(headers[2].source, '/:path*');
  assert.equal(
    configModule.approvalConsoleNoStoreHeaders.some(
      (header) => header.key === 'Cache-Control' && header.value === 'private, no-store, max-age=0',
    ),
    true,
  );
  assert.equal(
    configModule.approvalConsoleNoStoreHeaders.some(
      (header) => header.key === 'Pragma' && header.value === 'no-cache',
    ),
    true,
  );
  assert.equal(
    configModule.approvalConsoleSecurityHeaders.some(
      (header) =>
        header.key === 'Content-Security-Policy' && header.value.includes("frame-ancestors 'none'"),
    ),
    true,
  );
  assert.equal(
    configModule.approvalConsoleSecurityHeaders.some(
      (header) => header.key === 'Referrer-Policy' && header.value === 'no-referrer',
    ),
    true,
  );
  assert.equal(
    configModule.approvalConsoleSecurityHeaders.some(
      (header) => header.key === 'X-Frame-Options' && header.value === 'DENY',
    ),
    true,
  );
});
