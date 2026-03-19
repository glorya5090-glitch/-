const CONFIG_KEYS = [
  'rpcUrl',
  'chainId',
  'chainName',
  'daemonSocket',
  'stateFile',
  'rustBinDir',
  'agentKeyId',
] as const;

export type WritableConfigKey = (typeof CONFIG_KEYS)[number];

export function assertWritableConfigKey(value: string): WritableConfigKey {
  if ((CONFIG_KEYS as readonly string[]).includes(value)) {
    return value as WritableConfigKey;
  }
  if (value === 'agentAuthToken') {
    throw new Error(
      'agentAuthToken must be stored with `agentpay config agent-auth set --agent-key-id <uuid> --agent-auth-token-stdin`',
    );
  }
  throw new Error(`Unsupported config key: ${value}`);
}

export function resolveConfigMutationCommandLabel(command: 'set' | 'unset', key: string): string {
  return `agentpay config ${command} ${assertWritableConfigKey(key)}`;
}
