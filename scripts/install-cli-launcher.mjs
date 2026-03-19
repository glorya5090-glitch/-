import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { installCliLauncher } from './install-rust-binaries.mjs';

function resolveAgentPayHome(env) {
  return env.AGENTPAY_HOME?.trim() || path.join(os.homedir(), '.agentpay');
}

function installLocalCliLauncher({
  env = process.env,
  platform = process.platform,
  cliEntrypoint,
} = {}) {
  const agentpayHome = resolveAgentPayHome(env);
  const binDir = path.join(agentpayHome, 'bin');
  return installCliLauncher({ binDir, platform, cliEntrypoint });
}

function isDirectExecution() {
  return (
    Boolean(process.argv[1]) &&
    import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href
  );
}

if (isDirectExecution()) {
  try {
    installLocalCliLauncher();
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    process.stderr.write(`${message}\n`);
    process.exitCode = 1;
  }
}

export { installLocalCliLauncher };
