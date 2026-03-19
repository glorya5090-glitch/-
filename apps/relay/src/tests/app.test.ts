import { createHash } from 'node:crypto';
import { CacheError, cacheErrorCodes } from '@worldlibertyfinancial/agent-cache/errors';
import type { RelayCacheService } from '@worldlibertyfinancial/agent-cache/service';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const daemonId = '11'.repeat(32);
const daemonPublicKey = '22'.repeat(32);
const ethereumAddress = '0x3333333333333333333333333333333333333333';
const daemonToken = 'relay-daemon-token-1234567890abcd';
const approvalRequestId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';

const approvalRecord = {
  agentKeyId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
  amountWei: '1000000000000000000',
  approvalRequestId,
  chainId: 1,
  daemonId,
  destination: ethereumAddress,
  metadata: {
    approvalCapabilityToken: 'dd'.repeat(32),
    approvalCapabilityHash: createHash('sha256').update('dd'.repeat(32)).digest('hex'),
  },
  requestedAt: new Date().toISOString(),
  status: 'pending',
  transactionType: 'transfer_native',
  updatedAt: new Date().toISOString(),
};

const publicApprovalUpdatePayload = {
  approvalCapability: 'dd'.repeat(32),
  daemonId,
  envelope: {
    algorithm: 'x25519-xchacha20poly1305-v1',
    ciphertext: 'aa'.repeat(64),
    ephemeralPublicKey: 'bb'.repeat(32),
    nonce: 'cc'.repeat(24),
  },
};

const registerPayload = {
  daemon: {
    daemonId,
    daemonPublicKey,
    ethereumAddress,
    lastSeenAt: new Date().toISOString(),
    registeredAt: new Date().toISOString(),
    relayUrl: 'https://relay.example',
    signerBackend: 'software',
    status: 'active',
    updatedAt: new Date().toISOString(),
    version: '0.1.0',
  },
  policies: [],
  agentKeys: [],
  approvalRequests: [],
};

async function loadCreateApp() {
  process.env.RELAY_ADMIN_TOKEN = 'relay-admin-token-1234567890abcd';
  process.env.RELAY_BASE_URL = 'https://relay.example';
  process.env.RELAY_DAEMON_TOKEN = daemonToken;
  vi.resetModules();
  const module = await import('@/app');
  return module.createApp;
}

const daemonAuthHeaders = (headers: Record<string, string> = {}) => ({
  'content-type': 'application/json',
  'x-relay-daemon-token': daemonToken,
  ...headers,
});

const expectSensitiveNoStoreHeaders = (response: Response) => {
  expect(response.headers.get('cache-control')).toBe('private, no-store, max-age=0');
  expect(response.headers.get('pragma')).toBe('no-cache');
  expect(response.headers.get('expires')).toBe('0');
};

describe('relay app', () => {
  beforeEach(() => {
    process.env.RELAY_ADMIN_TOKEN = 'relay-admin-token-1234567890abcd';
    process.env.RELAY_BASE_URL = 'https://relay.example';
    process.env.RELAY_DAEMON_TOKEN = daemonToken;
  });

  it('serves healthz', async () => {
    const createApp = await loadCreateApp();
    const app = createApp({ ping: vi.fn() } as unknown as RelayCacheService);
    const response = await app.request('http://relay.test/healthz');

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ ok: true, service: 'agentpay-relay' });
  });

  it('returns ready when cache responds', async () => {
    const createApp = await loadCreateApp();
    const app = createApp({
      ping: vi.fn().mockResolvedValue('PONG'),
    } as unknown as RelayCacheService);
    const response = await app.request('http://relay.test/readyz');

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ cache: 'ready', ok: true });
  });

  it('rejects daemon registration over the REST daemon API without daemon auth', async () => {
    const createApp = await loadCreateApp();
    const syncDaemonRegistration = vi.fn();
    const app = createApp({
      ping: vi.fn(),
      syncDaemonRegistration,
    } as unknown as RelayCacheService);

    const response = await app.request('http://relay.test/v1/daemon/register', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
      },
      body: JSON.stringify(registerPayload),
    });

    expect(response.status).toBe(401);
    expect(syncDaemonRegistration).not.toHaveBeenCalled();
    await expect(response.json()).resolves.toEqual({ error: 'Daemon token is required' });
  });

  it('rejects daemon registration over the REST daemon API with the wrong daemon auth token', async () => {
    const createApp = await loadCreateApp();
    const syncDaemonRegistration = vi.fn();
    const app = createApp({
      ping: vi.fn(),
      syncDaemonRegistration,
    } as unknown as RelayCacheService);

    const response = await app.request('http://relay.test/v1/daemon/register', {
      method: 'POST',
      headers: daemonAuthHeaders({
        'x-relay-daemon-token': 'wrong-daemon-token-1234567890abcd',
      }),
      body: JSON.stringify(registerPayload),
    });

    expect(response.status).toBe(401);
    expect(syncDaemonRegistration).not.toHaveBeenCalled();
    await expect(response.json()).resolves.toEqual({ error: 'Daemon token is required' });
  });

  it('registers daemon snapshots over the REST daemon API with daemon auth', async () => {
    const createApp = await loadCreateApp();
    const syncDaemonRegistration = vi.fn().mockResolvedValue({
      agentKeyCount: 0,
      approvalRequestCount: 0,
      policyCount: 0,
    });
    const app = createApp({
      ping: vi.fn(),
      syncDaemonRegistration,
    } as unknown as RelayCacheService);

    const response = await app.request('http://relay.test/v1/daemon/register', {
      method: 'POST',
      headers: daemonAuthHeaders(),
      body: JSON.stringify(registerPayload),
    });

    expect(response.status).toBe(200);
    expect(syncDaemonRegistration).toHaveBeenCalledTimes(1);
    await expect(response.json()).resolves.toMatchObject({ daemonId });
  });

  it('rejects polling encrypted updates over the REST daemon API without daemon auth', async () => {
    const createApp = await loadCreateApp();
    const claimEncryptedUpdates = vi.fn();
    const app = createApp({
      claimEncryptedUpdates,
      ping: vi.fn(),
    } as unknown as RelayCacheService);

    const response = await app.request('http://relay.test/v1/daemon/poll-updates', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
      },
      body: JSON.stringify({ daemonId, leaseSeconds: 30, limit: 5 }),
    });

    expect(response.status).toBe(401);
    expect(claimEncryptedUpdates).not.toHaveBeenCalled();
    await expect(response.json()).resolves.toEqual({ error: 'Daemon token is required' });
  });

  it('polls encrypted updates over the REST daemon API with daemon auth', async () => {
    const createApp = await loadCreateApp();
    const claimEncryptedUpdates = vi.fn().mockResolvedValue([
      {
        claimToken: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
        createdAt: new Date().toISOString(),
        daemonId,
        payload: {
          algorithm: 'x25519-xchacha20poly1305-v1',
          ciphertextBase64: 'deadbeef',
          encapsulatedKeyBase64: 'beadfeed',
          nonceBase64: 'abcd',
          schemaVersion: 1,
        },
        status: 'inflight',
        type: 'manual_approval_decision',
        updateId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
        updatedAt: new Date().toISOString(),
      },
    ]);
    const app = createApp({
      claimEncryptedUpdates,
      ping: vi.fn(),
    } as unknown as RelayCacheService);

    const response = await app.request('http://relay.test/v1/daemon/poll-updates', {
      method: 'POST',
      headers: daemonAuthHeaders(),
      body: JSON.stringify({ daemonId, leaseSeconds: 30, limit: 5 }),
    });

    expect(response.status).toBe(200);
    expect(claimEncryptedUpdates).toHaveBeenCalledWith({ daemonId, leaseSeconds: 30, limit: 5 });
    await expect(response.json()).resolves.toMatchObject({
      items: [
        expect.objectContaining({
          daemonId,
          type: 'manual_approval_decision',
        }),
      ],
    });
  });

  it('rejects daemon feedback over the REST daemon API without daemon auth', async () => {
    const createApp = await loadCreateApp();
    const submitUpdateFeedback = vi.fn();
    const app = createApp({
      ping: vi.fn(),
      submitUpdateFeedback,
    } as unknown as RelayCacheService);

    const response = await app.request('http://relay.test/v1/daemon/submit-feedback', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        claimToken: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
        daemonId,
        updateId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
        status: 'applied',
      }),
    });

    expect(response.status).toBe(401);
    expect(submitUpdateFeedback).not.toHaveBeenCalled();
    await expect(response.json()).resolves.toEqual({ error: 'Daemon token is required' });
  });

  it('submits daemon feedback over the REST daemon API with daemon auth', async () => {
    const createApp = await loadCreateApp();
    const submitUpdateFeedback = vi.fn().mockResolvedValue({
      status: 'completed',
      updateId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
      updatedAt: new Date().toISOString(),
    });
    const app = createApp({
      ping: vi.fn(),
      submitUpdateFeedback,
    } as unknown as RelayCacheService);

    const response = await app.request('http://relay.test/v1/daemon/submit-feedback', {
      method: 'POST',
      headers: daemonAuthHeaders(),
      body: JSON.stringify({
        claimToken: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
        daemonId,
        updateId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
        status: 'applied',
      }),
    });

    expect(response.status).toBe(200);
    expect(submitUpdateFeedback).toHaveBeenCalledWith({
      claimToken: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      daemonId,
      status: 'applied',
      updateId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
    });
    await expect(response.json()).resolves.toMatchObject({
      status: 'completed',
      updateId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
    });
  });

  it('accepts a public approval update only for the matching pending approval', async () => {
    const createApp = await loadCreateApp();
    const getApprovalRequest = vi.fn().mockResolvedValue(approvalRecord);
    const hasActiveApprovalUpdate = vi.fn().mockResolvedValue(false);
    const createEncryptedUpdate = vi.fn().mockResolvedValue({
      daemonId,
      status: 'pending',
      updateId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
    });
    const clearApprovalCapabilityFailures = vi.fn().mockResolvedValue(undefined);
    const consumeApprovalCapability = vi.fn().mockResolvedValue(true);
    const app = createApp({
      clearApprovalCapabilityFailures,
      consumeApprovalCapability,
      createEncryptedUpdate,
      getApprovalRequest,
      hasActiveApprovalUpdate,
      ping: vi.fn(),
      releaseApprovalCapabilityConsumption: vi.fn(),
    } as unknown as RelayCacheService);

    const response = await app.request(
      `http://relay.test/v1/approvals/${approvalRequestId}/updates`,
      {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
        },
        body: JSON.stringify(publicApprovalUpdatePayload),
      },
    );

    expect(response.status).toBe(200);
    expectSensitiveNoStoreHeaders(response);
    expect(clearApprovalCapabilityFailures).toHaveBeenCalledWith(approvalRequestId);
    expect(getApprovalRequest).toHaveBeenCalledWith(approvalRequestId);
    expect(hasActiveApprovalUpdate).toHaveBeenCalledWith(daemonId, approvalRequestId);
    expect(consumeApprovalCapability).toHaveBeenCalledWith(
      approvalRequestId,
      approvalRecord.metadata.approvalCapabilityHash,
    );
    expect(createEncryptedUpdate).toHaveBeenCalledWith({
      daemonId,
      metadata: {
        source: 'approval_console',
      },
      payload: {
        algorithm: 'x25519-xchacha20poly1305-v1',
        ciphertextBase64: publicApprovalUpdatePayload.envelope.ciphertext,
        encapsulatedKeyBase64: publicApprovalUpdatePayload.envelope.ephemeralPublicKey,
        nonceBase64: publicApprovalUpdatePayload.envelope.nonce,
        schemaVersion: 1,
      },
      targetApprovalRequestId: approvalRequestId,
      type: 'manual_approval_decision',
    });
    await expect(response.json()).resolves.toMatchObject({
      approvalId: approvalRequestId,
      daemonId,
      status: 'pending',
    });
  });

  it('reissues a secure approval link only for admin-authenticated callers', async () => {
    const createApp = await loadCreateApp();
    const rotatedCapability = 'ee'.repeat(32);
    const rotateApprovalCapability = vi.fn().mockResolvedValue({
      ...approvalRecord,
      metadata: {
        approvalCapabilityHash: createHash('sha256').update(rotatedCapability).digest('hex'),
        approvalCapabilityToken: rotatedCapability,
      },
    });
    const app = createApp({
      ping: vi.fn(),
      rotateApprovalCapability,
    } as unknown as RelayCacheService);

    const response = await app.request(
      `http://relay.test/v1/admin/approvals/${approvalRequestId}/secure-link`,
      {
        method: 'POST',
        headers: {
          authorization: 'Bearer relay-admin-token-1234567890abcd',
        },
      },
    );

    expect(response.status).toBe(200);
    expectSensitiveNoStoreHeaders(response);
    expect(rotateApprovalCapability).toHaveBeenCalledWith(approvalRequestId);
    await expect(response.json()).resolves.toEqual({
      approvalCapability: rotatedCapability,
      approvalId: approvalRequestId,
      approvalUrl: `https://relay.example/approvals/${approvalRequestId}?daemonId=${daemonId}&approvalCapability=${rotatedCapability}`,
      daemonId,
    });
  });

  it('rejects secure-link reissue without admin auth', async () => {
    const createApp = await loadCreateApp();
    const app = createApp({
      ping: vi.fn(),
    } as unknown as RelayCacheService);

    const response = await app.request(
      `http://relay.test/v1/admin/approvals/${approvalRequestId}/secure-link`,
      {
        method: 'POST',
      },
    );

    expect(response.status).toBe(401);
    expectSensitiveNoStoreHeaders(response);
    await expect(response.json()).resolves.toEqual({
      error: 'Admin token is required',
    });
  });

  it('returns not found for secure-link reissue on unknown approvals', async () => {
    const createApp = await loadCreateApp();
    const rotateApprovalCapability = vi.fn().mockRejectedValue(
      new CacheError({
        code: cacheErrorCodes.notFound,
        message: `Unknown approval '${approvalRequestId}'`,
        operation: 'rotateApprovalCapability',
      }),
    );
    const app = createApp({
      ping: vi.fn(),
      rotateApprovalCapability,
    } as unknown as RelayCacheService);

    const response = await app.request(
      `http://relay.test/v1/admin/approvals/${approvalRequestId}/secure-link`,
      {
        method: 'POST',
        headers: {
          authorization: 'Bearer relay-admin-token-1234567890abcd',
        },
      },
    );

    expect(response.status).toBe(404);
    await expect(response.json()).resolves.toEqual({
      error: `Unknown approval '${approvalRequestId}'`,
    });
  });

  it('rejects secure-link reissue for non-pending approvals', async () => {
    const createApp = await loadCreateApp();
    const rotateApprovalCapability = vi.fn().mockRejectedValue(
      new CacheError({
        code: cacheErrorCodes.invalidPayload,
        message: `Approval '${approvalRequestId}' is 'completed' and cannot accept a new secure approval link`,
        operation: 'rotateApprovalCapability',
      }),
    );
    const app = createApp({
      ping: vi.fn(),
      rotateApprovalCapability,
    } as unknown as RelayCacheService);

    const response = await app.request(
      `http://relay.test/v1/admin/approvals/${approvalRequestId}/secure-link`,
      {
        method: 'POST',
        headers: {
          authorization: 'Bearer relay-admin-token-1234567890abcd',
        },
      },
    );

    expect(response.status).toBe(409);
    await expect(response.json()).resolves.toEqual({
      error: `Approval '${approvalRequestId}' is 'completed' and cannot accept a new secure approval link`,
    });
  });

  it('rejects public approval updates for unknown approvals', async () => {
    const createApp = await loadCreateApp();
    const getApprovalRequest = vi.fn().mockResolvedValue(null);
    const createEncryptedUpdate = vi.fn();
    const app = createApp({
      createEncryptedUpdate,
      getApprovalRequest,
      hasActiveApprovalUpdate: vi.fn(),
      ping: vi.fn(),
    } as unknown as RelayCacheService);

    const response = await app.request(
      `http://relay.test/v1/approvals/${approvalRequestId}/updates`,
      {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
        },
        body: JSON.stringify(publicApprovalUpdatePayload),
      },
    );

    expect(response.status).toBe(404);
    expect(createEncryptedUpdate).not.toHaveBeenCalled();
    await expect(response.json()).resolves.toMatchObject({
      error: `Unknown approval '${approvalRequestId}'`,
    });
  });

  it('rejects public approval updates when daemon ownership does not match', async () => {
    const createApp = await loadCreateApp();
    const createEncryptedUpdate = vi.fn();
    const app = createApp({
      createEncryptedUpdate,
      getApprovalRequest: vi.fn().mockResolvedValue({
        ...approvalRecord,
        daemonId: '44'.repeat(32),
      }),
      hasActiveApprovalUpdate: vi.fn(),
      ping: vi.fn(),
    } as unknown as RelayCacheService);

    const response = await app.request(
      `http://relay.test/v1/approvals/${approvalRequestId}/updates`,
      {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
        },
        body: JSON.stringify(publicApprovalUpdatePayload),
      },
    );

    expect(response.status).toBe(409);
    expect(createEncryptedUpdate).not.toHaveBeenCalled();
  });

  it('rejects public approval updates once the approval is not pending', async () => {
    const createApp = await loadCreateApp();
    const createEncryptedUpdate = vi.fn();
    const app = createApp({
      createEncryptedUpdate,
      getApprovalRequest: vi.fn().mockResolvedValue({
        ...approvalRecord,
        status: 'approved',
      }),
      hasActiveApprovalUpdate: vi.fn(),
      ping: vi.fn(),
    } as unknown as RelayCacheService);

    const response = await app.request(
      `http://relay.test/v1/approvals/${approvalRequestId}/updates`,
      {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
        },
        body: JSON.stringify(publicApprovalUpdatePayload),
      },
    );

    expect(response.status).toBe(409);
    expect(createEncryptedUpdate).not.toHaveBeenCalled();
    await expect(response.json()).resolves.toMatchObject({
      error: `Approval '${approvalRequestId}' is 'approved' and cannot accept new updates`,
    });
  });

  it('rejects duplicate public approval updates while one is already queued', async () => {
    const createApp = await loadCreateApp();
    const createEncryptedUpdate = vi.fn();
    const app = createApp({
      clearApprovalCapabilityFailures: vi.fn().mockResolvedValue(undefined),
      consumeApprovalCapability: vi.fn(),
      createEncryptedUpdate,
      getApprovalRequest: vi.fn().mockResolvedValue(approvalRecord),
      hasActiveApprovalUpdate: vi.fn().mockResolvedValue(true),
      ping: vi.fn(),
    } as unknown as RelayCacheService);

    const response = await app.request(
      `http://relay.test/v1/approvals/${approvalRequestId}/updates`,
      {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
        },
        body: JSON.stringify(publicApprovalUpdatePayload),
      },
    );

    expect(response.status).toBe(409);
    expect(createEncryptedUpdate).not.toHaveBeenCalled();
    await expect(response.json()).resolves.toMatchObject({
      error: `Approval '${approvalRequestId}' already has a queued operator update`,
    });
  });

  it('rejects public approval updates with an invalid approval capability', async () => {
    const createApp = await loadCreateApp();
    const createEncryptedUpdate = vi.fn();
    const recordApprovalCapabilityFailure = vi.fn().mockResolvedValue({
      attempts: 1,
      blocked: false,
      blockedUntil: null,
    });
    const app = createApp({
      createEncryptedUpdate,
      getApprovalRequest: vi.fn().mockResolvedValue(approvalRecord),
      hasActiveApprovalUpdate: vi.fn(),
      ping: vi.fn(),
      recordApprovalCapabilityFailure,
    } as unknown as RelayCacheService);

    const response = await app.request(
      `http://relay.test/v1/approvals/${approvalRequestId}/updates`,
      {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          ...publicApprovalUpdatePayload,
          approvalCapability: 'ee'.repeat(32),
        }),
      },
    );

    expect(response.status).toBe(401);
    expect(recordApprovalCapabilityFailure).toHaveBeenCalledWith(approvalRequestId);
    expect(createEncryptedUpdate).not.toHaveBeenCalled();
    await expect(response.json()).resolves.toMatchObject({
      error: `Approval '${approvalRequestId}' requires a valid secure approval link`,
    });
  });

  it('rate limits repeated invalid approval capability attempts', async () => {
    const createApp = await loadCreateApp();
    const createEncryptedUpdate = vi.fn();
    const recordApprovalCapabilityFailure = vi.fn().mockResolvedValue({
      attempts: 5,
      blocked: true,
      blockedUntil: new Date(Date.now() + 60_000).toISOString(),
    });
    const app = createApp({
      createEncryptedUpdate,
      getApprovalRequest: vi.fn().mockResolvedValue(approvalRecord),
      hasActiveApprovalUpdate: vi.fn(),
      ping: vi.fn(),
      recordApprovalCapabilityFailure,
    } as unknown as RelayCacheService);

    const response = await app.request(
      `http://relay.test/v1/approvals/${approvalRequestId}/updates`,
      {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          ...publicApprovalUpdatePayload,
          approvalCapability: 'ee'.repeat(32),
        }),
      },
    );

    expect(response.status).toBe(429);
    expect(createEncryptedUpdate).not.toHaveBeenCalled();
    await expect(response.json()).resolves.toMatchObject({
      error: `Approval '${approvalRequestId}' is temporarily locked after repeated invalid secure-link attempts`,
    });
  });

  it('rejects reused approval capability links after the first queued update', async () => {
    const createApp = await loadCreateApp();
    const createEncryptedUpdate = vi.fn();
    const app = createApp({
      clearApprovalCapabilityFailures: vi.fn().mockResolvedValue(undefined),
      consumeApprovalCapability: vi.fn().mockResolvedValue(false),
      createEncryptedUpdate,
      getApprovalRequest: vi.fn().mockResolvedValue(approvalRecord),
      hasActiveApprovalUpdate: vi.fn().mockResolvedValue(false),
      ping: vi.fn(),
    } as unknown as RelayCacheService);

    const response = await app.request(
      `http://relay.test/v1/approvals/${approvalRequestId}/updates`,
      {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
        },
        body: JSON.stringify(publicApprovalUpdatePayload),
      },
    );

    expect(response.status).toBe(409);
    expect(createEncryptedUpdate).not.toHaveBeenCalled();
    await expect(response.json()).resolves.toMatchObject({
      error: `Approval '${approvalRequestId}' secure link was already used; request a fresh approval link before retrying`,
    });
  });

  it('maps cache-layer duplicate approval update conflicts to 409 and releases the consumed capability', async () => {
    const createApp = await loadCreateApp();
    const createEncryptedUpdate = vi.fn().mockRejectedValue(
      new CacheError({
        code: cacheErrorCodes.invalidPayload,
        message: `Approval '${approvalRequestId}' already has a queued operator update`,
        operation: 'createEncryptedUpdate',
      }),
    );
    const releaseApprovalCapabilityConsumption = vi.fn().mockResolvedValue(undefined);
    const app = createApp({
      clearApprovalCapabilityFailures: vi.fn().mockResolvedValue(undefined),
      consumeApprovalCapability: vi.fn().mockResolvedValue(true),
      createEncryptedUpdate,
      getApprovalRequest: vi.fn().mockResolvedValue(approvalRecord),
      hasActiveApprovalUpdate: vi.fn().mockResolvedValue(false),
      ping: vi.fn(),
      releaseApprovalCapabilityConsumption,
    } as unknown as RelayCacheService);

    const response = await app.request(
      `http://relay.test/v1/approvals/${approvalRequestId}/updates`,
      {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
        },
        body: JSON.stringify(publicApprovalUpdatePayload),
      },
    );

    expect(response.status).toBe(409);
    expect(createEncryptedUpdate).toHaveBeenCalledOnce();
    expect(releaseApprovalCapabilityConsumption).toHaveBeenCalledWith(
      approvalRequestId,
      approvalRecord.metadata.approvalCapabilityHash,
    );
    await expect(response.json()).resolves.toMatchObject({
      error: `Approval '${approvalRequestId}' already has a queued operator update`,
    });
  });

  it('maps cache-layer missing approval targets to 404 and releases the consumed capability', async () => {
    const createApp = await loadCreateApp();
    const createEncryptedUpdate = vi.fn().mockRejectedValue(
      new CacheError({
        code: cacheErrorCodes.notFound,
        message: `Unknown approval '${approvalRequestId}'`,
        operation: 'createEncryptedUpdate',
      }),
    );
    const releaseApprovalCapabilityConsumption = vi.fn().mockResolvedValue(undefined);
    const app = createApp({
      clearApprovalCapabilityFailures: vi.fn().mockResolvedValue(undefined),
      consumeApprovalCapability: vi.fn().mockResolvedValue(true),
      createEncryptedUpdate,
      getApprovalRequest: vi.fn().mockResolvedValue(approvalRecord),
      hasActiveApprovalUpdate: vi.fn().mockResolvedValue(false),
      ping: vi.fn(),
      releaseApprovalCapabilityConsumption,
    } as unknown as RelayCacheService);

    const response = await app.request(
      `http://relay.test/v1/approvals/${approvalRequestId}/updates`,
      {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
        },
        body: JSON.stringify(publicApprovalUpdatePayload),
      },
    );

    expect(response.status).toBe(404);
    expect(createEncryptedUpdate).toHaveBeenCalledOnce();
    expect(releaseApprovalCapabilityConsumption).toHaveBeenCalledWith(
      approvalRequestId,
      approvalRecord.metadata.approvalCapabilityHash,
    );
    await expect(response.json()).resolves.toMatchObject({
      error: `Unknown approval '${approvalRequestId}'`,
    });
  });

  it('rejects malformed public approval update envelopes before hitting storage', async () => {
    const createApp = await loadCreateApp();
    const getApprovalRequest = vi.fn();
    const app = createApp({
      createEncryptedUpdate: vi.fn(),
      getApprovalRequest,
      hasActiveApprovalUpdate: vi.fn(),
      ping: vi.fn(),
    } as unknown as RelayCacheService);

    const response = await app.request(
      `http://relay.test/v1/approvals/${approvalRequestId}/updates`,
      {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          daemonId,
          envelope: {
            algorithm: 'x25519-xchacha20poly1305-v1',
            ciphertext: 'not-hex',
            ephemeralPublicKey: 'bb'.repeat(32),
            nonce: 'cc'.repeat(24),
          },
        }),
      },
    );

    expect(response.status).toBe(400);
    expect(getApprovalRequest).not.toHaveBeenCalled();
    await expect(response.json()).resolves.toMatchObject({
      error: 'Invalid request payload',
    });
  });
});
