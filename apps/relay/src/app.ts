import { createHash, timingSafeEqual } from 'node:crypto';
import { trpcServer } from '@hono/trpc-server';
import { CacheError, cacheErrorCodes } from '@worldlibertyfinancial/agent-cache/errors';
import {
  type RelayApprovalRequestRecord,
  RelayCacheService,
  type RelayEncryptedUpdateRecord,
} from '@worldlibertyfinancial/agent-cache/service';
import { type Context, Hono } from 'hono';
import { cors } from 'hono/cors';
import { z } from 'zod';
import { env } from '@/env';
import { hasAdminAccess, hasDaemonAccess } from '@/lib/auth';
import { createContext, type RelayBindings } from '@/lib/core/create-context';
import { log } from '@/lib/logger';
import {
  daemonRegisterInputSchema,
  pollUpdatesInputSchema,
  submitFeedbackInputSchema,
  submitPublicApprovalUpdateInputSchema,
} from '@/lib/schemas';
import { router } from '@/routers';

const createCorsOrigins = (): string[] | '*' => {
  return env.RELAY_ALLOWED_ORIGINS.length > 0 ? env.RELAY_ALLOWED_ORIGINS : '*';
};

const mapApprovalRecord = (record: {
  approvalRequestId: string;
  daemonId: string;
  agentKeyId?: string;
  status: string;
  reason?: string;
  transactionType: string;
  chainId?: number;
  destination: string;
  tokenAddress?: string;
  amountWei?: string;
  requestedAt: string;
  updatedAt: string;
}) => ({
  approvalId: record.approvalRequestId,
  daemonId: record.daemonId,
  agentKeyId: record.agentKeyId ?? 'unknown',
  status: record.status,
  reason: record.reason ?? '',
  actionType: record.transactionType,
  chainId: record.chainId ?? 0,
  recipient: record.destination,
  asset: record.tokenAddress ? `erc20:${record.tokenAddress}` : 'native_eth',
  amountWei: record.amountWei ?? '0',
  createdAt: record.requestedAt,
  updatedAt: record.updatedAt,
});

const readJson = async <T>(request: Request, schema: z.ZodType<T>): Promise<T> => {
  const json = await request.json();
  return schema.parse(json);
};

const badRequest = (c: Context<RelayBindings>, error: unknown) => {
  if (error instanceof z.ZodError) {
    log.warn('request.invalid', { issues: error.issues });
    return c.json({ error: 'Invalid request payload', issues: error.issues }, 400);
  }
  if (error instanceof CacheError) {
    return c.json({ error: error.message }, 503);
  }
  const message = error instanceof Error ? error.message : 'Invalid request payload';
  return c.json({ error: message }, 400);
};

const notFound = (c: Context<RelayBindings>, message: string) => c.json({ error: message }, 404);

const conflict = (c: Context<RelayBindings>, message: string) => c.json({ error: message }, 409);

const unauthorized = (c: Context<RelayBindings>, message: string) =>
  c.json({ error: message }, 401);

const tooManyRequests = (c: Context<RelayBindings>, message: string) =>
  c.json({ error: message }, 429);

const applySensitiveNoStoreHeaders = (c: Context<RelayBindings>): void => {
  c.header('Cache-Control', 'private, no-store, max-age=0');
  c.header('Pragma', 'no-cache');
  c.header('Expires', '0');
};

const adminApprovalFrontendBaseUrl = (): string | null => {
  const candidate = env.RELAY_FRONTEND_BASE_URL?.trim() || env.RELAY_BASE_URL.trim();
  return candidate ? candidate.replace(/\/$/u, '') : null;
};

const approvalCapabilityToken = (metadata: Record<string, string> | undefined): string | null => {
  const candidate = metadata?.approvalCapabilityToken?.trim();
  return candidate ? candidate : null;
};

const buildSecureApprovalUrl = (record: {
  approvalRequestId: string;
  daemonId: string;
  status: string;
  metadata?: Record<string, string>;
}): string | null => {
  if (record.status !== 'pending') {
    return null;
  }

  const baseUrl = adminApprovalFrontendBaseUrl();
  const capability = approvalCapabilityToken(record.metadata);
  if (!baseUrl || !capability) {
    return null;
  }

  return `${baseUrl}/approvals/${record.approvalRequestId}?daemonId=${record.daemonId}&approvalCapability=${capability}`;
};

const sha256Hex = (value: string): string => createHash('sha256').update(value).digest('hex');

const constantTimeEquals = (expected: string, actual: string): boolean => {
  const expectedBuffer = Buffer.from(expected, 'utf8');
  const actualBuffer = Buffer.from(actual, 'utf8');
  if (expectedBuffer.length !== actualBuffer.length) {
    return false;
  }

  return timingSafeEqual(expectedBuffer, actualBuffer);
};

const requireDaemonAccess = (c: Context<RelayBindings>) => {
  if (hasDaemonAccess(c.req.header('x-relay-daemon-token'))) {
    return null;
  }

  return unauthorized(c, 'Daemon token is required');
};

export const createApp = (
  cacheService = new RelayCacheService({ namespace: env.RELAY_CACHE_NAMESPACE }),
) => {
  const app = new Hono<RelayBindings>();

  app.use('*', async (c, next) => {
    c.set('relayCacheService', cacheService);
    const startedAt = Date.now();
    await next();
    log.info('request.completed', {
      durationMs: Date.now() - startedAt,
      method: c.req.method,
      path: c.req.path,
      status: c.res.status,
    });
  });

  app.use(
    '/trpc/*',
    cors({
      allowHeaders: ['authorization', 'content-type', 'x-relay-daemon-token'],
      allowMethods: ['GET', 'HEAD', 'OPTIONS', 'POST'],
      credentials: true,
      origin: createCorsOrigins(),
    }),
  );

  app.use(
    '/v1/*',
    cors({
      allowHeaders: ['authorization', 'content-type', 'x-relay-daemon-token'],
      allowMethods: ['GET', 'HEAD', 'OPTIONS', 'POST'],
      credentials: true,
      origin: createCorsOrigins(),
    }),
  );

  app.use('/v1/*', async (c, next) => {
    await next();
    applySensitiveNoStoreHeaders(c);
  });

  app.get('/healthz', (c) => {
    return c.json({ ok: true, service: 'agentpay-relay' });
  });

  app.post('/v1/daemon/register', async (c) => {
    const daemonAccessError = requireDaemonAccess(c);
    if (daemonAccessError) {
      return daemonAccessError;
    }

    try {
      const input = await readJson(c.req.raw, daemonRegisterInputSchema);
      const daemonId = input.daemon.daemonId;
      const result = await cacheService.syncDaemonRegistration({
        ...input,
        agentKeys: input.agentKeys.map((agentKey) => ({ ...agentKey, daemonId })),
        approvalRequests: input.approvalRequests.map((request) => ({ ...request, daemonId })),
        policies: input.policies.map((policy) => ({ ...policy, daemonId })),
      });
      return c.json({
        daemonId,
        registeredAt: input.daemon.registeredAt,
        summary: result,
      });
    } catch (error) {
      return badRequest(c, error);
    }
  });

  app.post('/v1/daemon/poll-updates', async (c) => {
    const daemonAccessError = requireDaemonAccess(c);
    if (daemonAccessError) {
      return daemonAccessError;
    }

    try {
      const input = await readJson(c.req.raw, pollUpdatesInputSchema);
      const updates = await cacheService.claimEncryptedUpdates({
        daemonId: input.daemonId,
        leaseSeconds: input.leaseSeconds ?? env.RELAY_UPDATE_LEASE_SECONDS,
        limit: input.limit ?? env.RELAY_POLL_MAX_UPDATES,
      });
      return c.json({
        items: updates,
        polledAt: new Date().toISOString(),
      });
    } catch (error) {
      return badRequest(c, error);
    }
  });

  app.post('/v1/daemon/submit-feedback', async (c) => {
    const daemonAccessError = requireDaemonAccess(c);
    if (daemonAccessError) {
      return daemonAccessError;
    }

    try {
      const input = await readJson(c.req.raw, submitFeedbackInputSchema);
      const update = await cacheService.submitUpdateFeedback(input);
      return c.json({
        status: update.status,
        updateId: update.updateId,
        updatedAt: update.updatedAt,
      });
    } catch (error) {
      return badRequest(c, error);
    }
  });

  app.get('/v1/daemons/:daemonId', async (c) => {
    const daemonId = c.req.param('daemonId');
    const daemon = await cacheService.getDaemonProfile(daemonId);
    if (!daemon) {
      return c.json({ error: `Unknown daemon '${daemonId}'` }, 404);
    }
    return c.json({
      daemonId: daemon.daemonId,
      daemonPublicKey: daemon.daemonPublicKey,
      vaultEthereumAddress: daemon.ethereumAddress,
      relayBaseUrl: daemon.relayUrl ?? env.RELAY_BASE_URL,
      updatedAt: daemon.updatedAt,
    });
  });

  app.get('/v1/daemons/:daemonId/approvals', async (c) => {
    const daemonId = c.req.param('daemonId');
    const approvals = await cacheService.listApprovalRequests({ daemonId, limit: 200 });
    return c.json(approvals.map(mapApprovalRecord));
  });

  app.get('/v1/approvals/:approvalId', async (c) => {
    const approvalId = c.req.param('approvalId');
    const approval = await cacheService.getApprovalRequest(approvalId);
    if (!approval) {
      return c.json({ error: `Unknown approval '${approvalId}'` }, 404);
    }
    return c.json(mapApprovalRecord(approval));
  });

  app.post('/v1/admin/approvals/:approvalId/secure-link', async (c) => {
    if (!hasAdminAccess(c.req.header('authorization'))) {
      return unauthorized(c, 'Admin token is required');
    }

    const approvalId = c.req.param('approvalId');
    let approval: RelayApprovalRequestRecord;
    try {
      approval = await cacheService.rotateApprovalCapability(approvalId);
    } catch (error) {
      const cacheError = error as { code?: string; message?: string };
      if (cacheError?.code === cacheErrorCodes.notFound) {
        return notFound(c, cacheError.message ?? `Unknown approval '${approvalId}'`);
      }

      if (cacheError?.code === cacheErrorCodes.invalidPayload) {
        return conflict(
          c,
          cacheError.message ?? `Approval '${approvalId}' cannot accept a new secure approval link`,
        );
      }

      if (error instanceof CacheError) {
        return c.json({ error: error.message }, 503);
      }

      throw error;
    }

    const approvalUrl = buildSecureApprovalUrl(approval);
    if (!approvalUrl) {
      return conflict(
        c,
        `Approval '${approvalId}' does not have a reissuable secure approval link`,
      );
    }

    return c.json({
      approvalCapability: approvalCapabilityToken(approval.metadata),
      approvalId,
      approvalUrl,
      daemonId: approval.daemonId,
    });
  });

  app.post('/v1/approvals/:approvalId/updates', async (c) => {
    const approvalId = c.req.param('approvalId');
    try {
      const input = await readJson(c.req.raw, submitPublicApprovalUpdateInputSchema);
      const approval = await cacheService.getApprovalRequest(approvalId);

      if (!approval) {
        return notFound(c, `Unknown approval '${approvalId}'`);
      }

      if (approval.daemonId !== input.daemonId) {
        return conflict(
          c,
          `Approval '${approvalId}' belongs to daemon '${approval.daemonId}', not '${input.daemonId}'`,
        );
      }

      if (approval.status !== 'pending') {
        return conflict(
          c,
          `Approval '${approvalId}' is '${approval.status}' and cannot accept new updates`,
        );
      }

      const expectedCapabilityHash = approval.metadata?.approvalCapabilityHash?.trim();
      if (!expectedCapabilityHash) {
        return conflict(
          c,
          `Approval '${approvalId}' requires a secure CLI-issued approval link; public relay submission is unavailable for this record`,
        );
      }

      const providedCapabilityHash = sha256Hex(input.approvalCapability.trim());
      if (!constantTimeEquals(expectedCapabilityHash, providedCapabilityHash)) {
        const failure = await cacheService.recordApprovalCapabilityFailure(approvalId);
        if (failure.blocked) {
          return tooManyRequests(
            c,
            `Approval '${approvalId}' is temporarily locked after repeated invalid secure-link attempts`,
          );
        }

        return unauthorized(c, `Approval '${approvalId}' requires a valid secure approval link`);
      }

      await cacheService.clearApprovalCapabilityFailures(approvalId);

      const alreadyQueued = await cacheService.hasActiveApprovalUpdate(input.daemonId, approvalId);
      if (alreadyQueued) {
        return conflict(c, `Approval '${approvalId}' already has a queued operator update`);
      }

      const consumed = await cacheService.consumeApprovalCapability(
        approvalId,
        expectedCapabilityHash,
      );
      if (!consumed) {
        return conflict(
          c,
          `Approval '${approvalId}' secure link was already used; request a fresh approval link before retrying`,
        );
      }

      let update: RelayEncryptedUpdateRecord;
      try {
        update = await cacheService.createEncryptedUpdate({
          daemonId: input.daemonId,
          metadata: {
            source: 'approval_console',
          },
          payload: {
            algorithm: input.envelope.algorithm,
            ciphertextBase64: input.envelope.ciphertext,
            encapsulatedKeyBase64: input.envelope.ephemeralPublicKey,
            nonceBase64: input.envelope.nonce,
            schemaVersion: 1,
          },
          targetApprovalRequestId: approvalId,
          type: 'manual_approval_decision',
        });
      } catch (error) {
        await cacheService.releaseApprovalCapabilityConsumption(approvalId, expectedCapabilityHash);
        const cacheError = error as { code?: string; message?: string };
        if (cacheError?.code === cacheErrorCodes.notFound) {
          return notFound(c, cacheError.message ?? `Unknown approval '${approvalId}'`);
        }

        if (cacheError?.code === cacheErrorCodes.invalidPayload) {
          return conflict(
            c,
            cacheError.message ?? `Approval '${approvalId}' already has a queued operator update`,
          );
        }
        throw error;
      }

      return c.json({
        approvalId,
        daemonId: input.daemonId,
        status: update.status,
        updateId: update.updateId,
      });
    } catch (error) {
      return badRequest(c, error);
    }
  });

  app.get('/readyz', async (c) => {
    try {
      await cacheService.ping();
      return c.json({ ok: true, cache: 'ready' });
    } catch (error) {
      log.error('cache.not_ready', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      return c.json({ cache: 'unavailable', ok: false }, 503);
    }
  });

  app.use(
    '/trpc/*',
    trpcServer({
      createContext,
      endpoint: '/trpc',
      onError({ error, path }) {
        log.error('trpc.error', {
          code: error.code,
          message: error.message,
          path,
        });
      },
      router,
    }),
  );

  return app;
};

export const app = createApp();
