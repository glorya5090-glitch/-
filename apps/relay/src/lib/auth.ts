import { timingSafeEqual } from 'node:crypto';
import { TRPCError } from '@trpc/server';
import { env } from '@/env';

const extractBearerToken = (authorizationHeader: string | undefined): string | undefined => {
  if (!authorizationHeader) {
    return undefined;
  }

  const [scheme, value] = authorizationHeader.split(' ');
  if (scheme?.toLowerCase() !== 'bearer' || !value) {
    return undefined;
  }

  return value.trim();
};

const constantTimeEquals = (expected: string, actual: string | undefined): boolean => {
  if (!actual) {
    return false;
  }

  const expectedBuffer = Buffer.from(expected);
  const actualBuffer = Buffer.from(actual);
  if (expectedBuffer.length !== actualBuffer.length) {
    return false;
  }

  return timingSafeEqual(expectedBuffer, actualBuffer);
};

export const hasAdminAccess = (authorizationHeader: string | undefined): boolean => {
  const token = extractBearerToken(authorizationHeader);
  return constantTimeEquals(env.RELAY_ADMIN_TOKEN, token);
};

export const hasDaemonAccess = (daemonTokenHeader: string | undefined): boolean => {
  return constantTimeEquals(env.RELAY_DAEMON_TOKEN, daemonTokenHeader?.trim());
};

export const assertAdminAccess = (authorizationHeader: string | undefined): void => {
  if (!hasAdminAccess(authorizationHeader)) {
    throw new TRPCError({ code: 'UNAUTHORIZED', message: 'Admin token is required' });
  }
};

export const assertDaemonAccess = (daemonTokenHeader: string | undefined): void => {
  if (!hasDaemonAccess(daemonTokenHeader)) {
    throw new TRPCError({ code: 'UNAUTHORIZED', message: 'Daemon token is required' });
  }
};
