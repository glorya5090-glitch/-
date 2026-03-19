import { spawn } from 'node:child_process';
import fs from 'node:fs';
import { constants as osConstants } from 'node:os';
import type { WlfiConfig } from '../../packages/config/src/index.js';
import * as configModule from '../../packages/config/src/index.js';
import { assertTrustedExecutablePath } from './fs-trust.js';
import { resolveValidatedPassthroughDaemonSocket } from './passthrough-security.js';
import { prepareSpawnOptions, type RunRustBinaryOptions } from './rust-spawn-options.js';

const { readConfig, resolveRustBinaryPath } =
  configModule as typeof import('../../packages/config/src/index.js');

export type RustBinaryName = 'agentpay-daemon' | 'agentpay-admin' | 'agentpay-agent';

const MAX_STDOUT_SNIPPET_CHARS = 200;

function summarizeRustStderr(binaryName: RustBinaryName, code: number, stderr: string): string {
  const uniqueLines: string[] = [];
  const seen = new Set<string>();

  for (const rawLine of stderr.split(/\r?\n/u)) {
    const normalized = rawLine
      .trim()
      .replace(/^(?:Error:|Caused by:)\s*/iu, '')
      .replace(/^\d+:\s*/u, '')
      .trim();
    if (!normalized) {
      continue;
    }
    const dedupeKey = normalized.replace(/\s+/gu, ' ');
    if (seen.has(dedupeKey)) {
      continue;
    }
    seen.add(dedupeKey);
    uniqueLines.push(normalized);
  }

  return uniqueLines.join('\n') || `${binaryName} exited with code ${code}`;
}

export class RustBinaryExitError extends Error {
  readonly binaryName: RustBinaryName;
  readonly code: number;
  readonly stdout: string;
  readonly stderr: string;

  constructor(binaryName: RustBinaryName, code: number, stdout: string, stderr: string) {
    super(summarizeRustStderr(binaryName, code, stderr));
    this.name = 'RustBinaryExitError';
    this.binaryName = binaryName;
    this.code = code;
    this.stdout = stdout;
    this.stderr = stderr;
  }
}

export class RustBinaryJsonParseError extends Error {
  readonly binaryName: RustBinaryName;
  readonly stdout: string;
  readonly cause: unknown;

  constructor(binaryName: RustBinaryName, stdout: string, cause: unknown) {
    const snippet =
      stdout.length > MAX_STDOUT_SNIPPET_CHARS
        ? `${stdout.slice(0, MAX_STDOUT_SNIPPET_CHARS)}...`
        : stdout;
    const message =
      cause instanceof Error
        ? `${binaryName} produced invalid JSON: ${cause.message}. stdout: ${snippet}`
        : `${binaryName} produced invalid JSON. stdout: ${snippet}`;
    super(message);
    this.name = 'RustBinaryJsonParseError';
    this.binaryName = binaryName;
    this.stdout = stdout;
    this.cause = cause;
  }
}

function ensureBinary(binaryName: RustBinaryName, config?: WlfiConfig): string {
  /* c8 ignore next -- both provided-config and readConfig fallback paths are exercised, but c8 misattributes this nullish expression under --experimental-strip-types */
  const resolved = resolveRustBinaryPath(binaryName, config ?? readConfig());
  if (!fs.existsSync(resolved)) {
    throw new Error(
      `${binaryName} is not installed at ${resolved}. Reinstall the AgentPay SDK from source or rerun the one-click installer.`,
    );
  }
  assertTrustedExecutablePath(resolved);
  return resolved;
}

function forwardedArgsIncludeDaemonSocket(args: string[]): boolean {
  return args.some(
    (arg, _index) => arg === '--daemon-socket' || arg.startsWith('--daemon-socket='),
  );
}

function signalExitCode(signal: NodeJS.Signals | null): number {
  if (!signal) {
    return 1;
  }

  const signalNumber = osConstants.signals[signal];
  return typeof signalNumber === 'number' ? 128 + signalNumber : 128;
}

async function writeChildStdin(child: ReturnType<typeof spawn>, stdin: string): Promise<void> {
  const stream = child.stdin;
  /* c8 ignore next 3 -- child.stdin is expected whenever this helper is used, but keep the guard for defensive mocked/process edge cases */
  if (!stream) {
    return;
  }

  await new Promise<void>((resolve, reject) => {
    let settled = false;

    const cleanup = () => {
      stream.off('close', handleClose);
      /* c8 ignore next 3 -- defensive re-entry guard */
      stream.off('error', handleError);
      child.off('close', handleChildClose);
    };

    const finish = () => {
      /* c8 ignore next 3 -- defensive re-entry guard */
      if (settled) {
        return;
      }
      settled = true;
      cleanup();
      resolve();
    };

    const handleError = (error: NodeJS.ErrnoException) => {
      /* c8 ignore next 3 -- defensive re-entry guard */
      if (settled) {
        return;
      }
      if (error?.code === 'EPIPE' || error?.code === 'ERR_STREAM_DESTROYED') {
        finish();
        return;
      }
      settled = true;
      cleanup();
      reject(error);
    };

    const handleClose = () => {
      finish();
    };

    const handleChildClose = () => {
      finish();
    };

    stream.on('error', handleError);
    stream.on('close', handleClose);
    child.on('close', handleChildClose);
    try {
      stream.end(stdin, () => {
        // Keep the error listener attached until the pipe or child actually closes.
      });
    } catch (error) {
      handleError(error as NodeJS.ErrnoException);
    }
  });
}

export async function passthroughRustBinary(
  binaryName: RustBinaryName,
  args: string[],
  config?: WlfiConfig,
): Promise<number> {
  /* c8 ignore next -- both provided-config and readConfig fallback paths are exercised, but c8 misattributes this nullish expression under --experimental-strip-types */
  const resolvedConfig = config ?? readConfig();
  const resolvedDaemonSocket = resolveValidatedPassthroughDaemonSocket(
    binaryName,
    args,
    resolvedConfig,
  );
  const executable = ensureBinary(binaryName, resolvedConfig);
  const prepared = await prepareSpawnOptions(binaryName, args, {});
  const env = { ...prepared.env };
  if (
    resolvedDaemonSocket &&
    !forwardedArgsIncludeDaemonSocket(args) &&
    /* c8 ignore next -- explicit env override is exercised, but c8 misattributes this optional-chain/nullish check */
    !env.AGENTPAY_DAEMON_SOCKET?.trim()
  ) {
    env.AGENTPAY_DAEMON_SOCKET = resolvedDaemonSocket;
  }
  const child = spawn(executable, prepared.args, {
    stdio: [prepared.stdin !== undefined ? 'pipe' : 'inherit', 'inherit', 'inherit'],
    env,
  });

  const codePromise = new Promise<number>((resolve, reject) => {
    child.on('error', reject);
    child.on('close', (code, signal) => {
      if (code !== null && code !== undefined) {
        resolve(code);
        return;
      }
      resolve(signalExitCode(signal));
    });
  });
  const stdinPromise =
    prepared.stdin !== undefined ? writeChildStdin(child, prepared.stdin) : Promise.resolve();
  const [code] = await Promise.all([codePromise, stdinPromise]);
  return code;
}

export async function runRustBinary(
  binaryName: RustBinaryName,
  args: string[],
  config?: WlfiConfig,
  options: RunRustBinaryOptions = {},
): Promise<{ stdout: string; stderr: string; code: number }> {
  const resolvedConfig = config ?? readConfig();
  const resolvedDaemonSocket = resolveValidatedPassthroughDaemonSocket(
    binaryName,
    args,
    resolvedConfig,
  );
  const executable = ensureBinary(binaryName, resolvedConfig);
  const prepared = await prepareSpawnOptions(binaryName, args, options);
  const env = { ...prepared.env };
  if (
    resolvedDaemonSocket &&
    !forwardedArgsIncludeDaemonSocket(args) &&
    !env.AGENTPAY_DAEMON_SOCKET?.trim()
  ) {
    env.AGENTPAY_DAEMON_SOCKET = resolvedDaemonSocket;
  }
  const child = spawn(executable, prepared.args, {
    stdio: [prepared.stdin !== undefined ? 'pipe' : 'ignore', 'pipe', 'pipe'],
    env,
  });

  let stdout = '';
  let stderr = '';
  child.stdout?.on('data', (chunk) => {
    stdout += chunk.toString();
  });
  child.stderr?.on('data', (chunk) => {
    stderr += chunk.toString();
  });

  const codePromise = new Promise<number>((resolve, reject) => {
    child.on('error', reject);
    child.on('close', (code, signal) => {
      if (code !== null && code !== undefined) {
        resolve(code);
      } else {
        // Terminated by signal. Preserve the remote behavior while still waiting for stdin writes.
        resolve(signalExitCode(signal));
      }
    });
  });
  const stdinPromise =
    prepared.stdin !== undefined ? writeChildStdin(child, prepared.stdin) : Promise.resolve();
  const [code] = await Promise.all([codePromise, stdinPromise]);

  if (code !== 0) {
    throw new RustBinaryExitError(binaryName, code, stdout, stderr);
  }

  return { stdout, stderr, code };
}

export async function runRustBinaryJson<T>(
  binaryName: RustBinaryName,
  args: string[],
  config?: WlfiConfig,
  options: RunRustBinaryOptions = {},
): Promise<T> {
  const { stdout } = await runRustBinary(binaryName, args, config, options);
  try {
    return JSON.parse(stdout) as T;
  } catch (error) {
    throw new RustBinaryJsonParseError(binaryName, stdout, error);
  }
}
