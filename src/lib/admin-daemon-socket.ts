import type { WlfiConfig } from '../../packages/config/src/index.js';
import { assertTrustedAdminDaemonSocketPath } from './fs-trust.js';

export const DEFAULT_MANAGED_ADMIN_DAEMON_SOCKET = '/Library/AgentPay/run/daemon.sock';

export type AdminDaemonSocketSource =
  | 'explicit'
  | 'env-daemon-socket'
  | 'config-daemon-socket'
  | 'default';

export interface ResolvedAdminDaemonSocketSelection {
  value: string;
  source: AdminDaemonSocketSource;
}

interface ResolveValidatedAdminDaemonSocketDeps {
  env?: NodeJS.ProcessEnv;
  assertTrustedAdminDaemonSocketPath?: (targetPath: string, label?: string) => string;
}

function presentString(value: string | undefined): string | null {
  const normalized = value?.trim();
  return normalized ? normalized : null;
}

export function resolveAdminDaemonSocketSelection(
  explicitValue: string | undefined,
  config: WlfiConfig,
  env: NodeJS.ProcessEnv = process.env,
): ResolvedAdminDaemonSocketSelection {
  if (explicitValue !== undefined) {
    const explicitSocket = presentString(explicitValue);
    if (!explicitSocket) {
      throw new Error('--daemon-socket requires a path');
    }
    return { value: explicitSocket, source: 'explicit' };
  }

  const envSocket = presentString(env.AGENTPAY_DAEMON_SOCKET);
  if (envSocket) {
    return { value: envSocket, source: 'env-daemon-socket' };
  }

  const configuredSocket = presentString(config.daemonSocket);
  if (configuredSocket) {
    return { value: configuredSocket, source: 'config-daemon-socket' };
  }

  return {
    value: DEFAULT_MANAGED_ADMIN_DAEMON_SOCKET,
    source: 'default',
  };
}

export function wrapAdminDaemonSocketTrustError(
  message: string,
  source: AdminDaemonSocketSource,
  env: NodeJS.ProcessEnv = process.env,
): Error {
  const lines = [message];

  if (source === 'explicit') {
    lines.push(
      `Recovery: rerun without \`--daemon-socket\`, or point it at the managed root-owned socket \`${DEFAULT_MANAGED_ADMIN_DAEMON_SOCKET}\`.`,
    );
  } else if (source === 'env-daemon-socket') {
    lines.push(
      `Recovery: unset \`AGENTPAY_DAEMON_SOCKET\` or point it at the managed root-owned socket \`${DEFAULT_MANAGED_ADMIN_DAEMON_SOCKET}\`.`,
    );
  } else if (source === 'config-daemon-socket') {
    lines.push(
      `Recovery: if this override was not intentional, run \`agentpay config unset daemonSocket\` to fall back to \`${DEFAULT_MANAGED_ADMIN_DAEMON_SOCKET}\`.`,
    );
  } else if (presentString(env.AGENTPAY_HOME)) {
    lines.push(
      'Recovery: unset `AGENTPAY_HOME` before rerunning this root-managed admin command unless you intentionally want a custom local AgentPay home.',
    );
  }

  lines.push('Then verify with `agentpay status --strict`.');
  lines.push(
    'If the managed daemon/socket is missing, run `agentpay admin setup --reuse-existing-wallet` or `agentpay admin setup`.',
  );
  return new Error(lines.join('\n'));
}

export function resolveValidatedAdminDaemonSocket(
  explicitValue: string | undefined,
  config: WlfiConfig,
  deps: ResolveValidatedAdminDaemonSocketDeps = {},
): string {
  const env = deps.env ?? process.env;
  const selection = resolveAdminDaemonSocketSelection(explicitValue, config, env);
  const trustAdminDaemonSocketPath =
    deps.assertTrustedAdminDaemonSocketPath ?? assertTrustedAdminDaemonSocketPath;

  try {
    return trustAdminDaemonSocketPath(selection.value);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw wrapAdminDaemonSocketTrustError(message, selection.source, env);
  }
}
