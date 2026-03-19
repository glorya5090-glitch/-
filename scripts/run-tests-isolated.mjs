#!/usr/bin/env node

import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

function fail(message) {
  console.error(message);
  process.exit(1);
}

const forwardedArgs = process.argv.slice(2);
const commandArgs = forwardedArgs[0] === '--' ? forwardedArgs.slice(1) : forwardedArgs;

if (commandArgs.length === 0) {
  fail('usage: node ./scripts/run-tests-isolated.mjs -- <command> [args...]');
}

const hostHome = process.env.HOME;
const sandboxBaseDir = hostHome ? path.join(hostHome, '.wt') : os.tmpdir();
fs.mkdirSync(sandboxBaseDir, { recursive: true, mode: 0o700 });
const sandboxRoot = fs.mkdtempSync(path.join(sandboxBaseDir, 't-'));
const homeDir = path.join(sandboxRoot, 'h');
const agentpayHome = path.join(sandboxRoot, 'w');
const tmpDir = path.join(sandboxRoot, 't');
const binDir = path.join(sandboxRoot, 'b');
const fakeKeychainRoot = path.join(sandboxRoot, 'k');
const keepSandbox = process.env.AGENTPAY_TEST_KEEP_SANDBOX === '1';
const cargoHome = process.env.CARGO_HOME ?? (hostHome ? path.join(hostHome, '.cargo') : undefined);
const rustupHome =
  process.env.RUSTUP_HOME ?? (hostHome ? path.join(hostHome, '.rustup') : undefined);
const xdgCacheHome = path.join(sandboxRoot, 'c');
const xdgConfigHome = path.join(sandboxRoot, 'g');

for (const dir of [
  homeDir,
  agentpayHome,
  tmpDir,
  binDir,
  fakeKeychainRoot,
  xdgCacheHome,
  xdgConfigHome,
]) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
}

function writeExecutable(targetPath, contents) {
  fs.writeFileSync(targetPath, contents, { mode: 0o755 });
}

writeExecutable(
  path.join(binDir, 'security'),
  `#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';

const root = process.env.AGENTPAY_TEST_FAKE_KEYCHAIN_ROOT;
if (!root) {
  console.error('AGENTPAY_TEST_FAKE_KEYCHAIN_ROOT is required');
  process.exit(70);
}

const dbPath = path.join(root, 'keychain.json');
const [command, ...args] = process.argv.slice(2);

function loadDb() {
  try {
    return JSON.parse(fs.readFileSync(dbPath, 'utf8'));
  } catch (error) {
    if (error && typeof error === 'object' && error.code === 'ENOENT') {
      return {};
    }
    throw error;
  }
}

function saveDb(db) {
  fs.writeFileSync(dbPath, JSON.stringify(db, null, 2) + '\\n', { mode: 0o600 });
}

function readFlag(flag) {
  const index = args.indexOf(flag);
  if (index === -1 || index === args.length - 1) {
    console.error('isolated security shim requires ' + flag);
    process.exit(64);
  }
  return args[index + 1];
}

const service = readFlag('-s');
const account = readFlag('-a');
const key = service + '\\u0000' + account;
const db = loadDb();

switch (command) {
  case 'add-generic-password': {
    const secretHex = readFlag('-X');
    db[key] = Buffer.from(secretHex, 'hex').toString('utf8');
    saveDb(db);
    process.exit(0);
  }
  case 'find-generic-password': {
    if (!(key in db)) {
      console.error('The specified item could not be found in the keychain.');
      process.exit(44);
    }
    process.stdout.write(String(db[key]));
    process.exit(0);
  }
  case 'delete-generic-password': {
    if (!(key in db)) {
      console.error('The specified item could not be found in the keychain.');
      process.exit(44);
    }
    delete db[key];
    saveDb(db);
    process.exit(0);
  }
  default:
    console.error('isolated security shim does not implement: ' + command);
    process.exit(64);
}
`,
);

for (const commandName of ['sudo', 'launchctl']) {
  writeExecutable(
    path.join(binDir, commandName),
    `#!/bin/sh
echo "isolated test harness blocked real ${commandName}; inject a test double if this path is expected" >&2
exit 99
`,
  );
}

const child = spawn(commandArgs[0], commandArgs.slice(1), {
  stdio: 'inherit',
  env: {
    ...process.env,
    HOME: homeDir,
    AGENTPAY_HOME: agentpayHome,
    TMPDIR: tmpDir,
    XDG_CACHE_HOME: xdgCacheHome,
    XDG_CONFIG_HOME: xdgConfigHome,
    PATH: `${binDir}${path.delimiter}${process.env.PATH ?? ''}`,
    AGENTPAY_TEST_FAKE_KEYCHAIN_ROOT: fakeKeychainRoot,
    AGENTPAY_TEST_SANDBOX_ROOT: sandboxRoot,
    AGENTPAY_TEST_ISOLATED: '1',
    ...(cargoHome ? { CARGO_HOME: cargoHome } : {}),
    ...(rustupHome ? { RUSTUP_HOME: rustupHome } : {}),
  },
});

let cleanedUp = false;

function cleanup() {
  if (cleanedUp) {
    return;
  }
  cleanedUp = true;

  if (keepSandbox) {
    console.error(`kept test sandbox: ${sandboxRoot}`);
    return;
  }

  fs.rmSync(sandboxRoot, { recursive: true, force: true });
  try {
    fs.rmdirSync(sandboxBaseDir);
  } catch (error) {
    if (!error || typeof error !== 'object') {
      throw error;
    }
    if (!('code' in error) || (error.code !== 'ENOENT' && error.code !== 'ENOTEMPTY')) {
      throw error;
    }
  }
}

function signalExitCode(signal) {
  if (!signal) {
    return 1;
  }

  const signalNumber = os.constants.signals[signal];
  return typeof signalNumber === 'number' ? 128 + signalNumber : 128;
}

for (const signal of ['SIGHUP', 'SIGINT', 'SIGTERM']) {
  process.on(signal, () => {
    if (!child.killed) {
      child.kill(signal);
    }
  });
}

child.on('error', (error) => {
  cleanup();
  fail(`failed to start isolated test command: ${error.message}`);
});

child.on('exit', (code, signal) => {
  cleanup();
  if (signal) {
    process.exit(signalExitCode(signal));
  }
  process.exit(code ?? 1);
});
