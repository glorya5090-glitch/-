import {
  assertSafeRpcUrl,
  resolveChainProfile,
  type WlfiConfig,
} from '../../packages/config/src/index.js';

function presentString(value: string | undefined | null): string | undefined {
  const normalized = value?.trim();
  return normalized ? normalized : undefined;
}

function isNumericSelector(value: string): boolean {
  return /^[0-9]+$/u.test(value);
}

function resolveActiveNetworkSelector(config: WlfiConfig): string | undefined {
  const activeName = presentString(config.chainName);
  if (activeName) {
    return activeName;
  }
  if (config.chainId !== undefined) {
    return String(config.chainId);
  }
  return undefined;
}

export function resolveCliNetworkProfile(
  selector: string | undefined,
  config: WlfiConfig,
  label = 'network',
) {
  const explicitSelector = presentString(selector);
  if (explicitSelector && isNumericSelector(explicitSelector)) {
    throw new Error(`${label} must be a chain name, not a chain id`);
  }

  const resolvedSelector = explicitSelector ?? resolveActiveNetworkSelector(config);
  if (!resolvedSelector) {
    throw new Error(`${label} is required`);
  }

  const profile = resolveChainProfile(resolvedSelector, config);
  if (!profile) {
    throw new Error(`${label} '${resolvedSelector}' is not a configured or builtin chain name`);
  }

  return profile;
}

export function resolveCliRpcUrl(
  rpcUrl: string | undefined,
  selector: string | undefined,
  config: WlfiConfig,
): string {
  const explicitRpcUrl = presentString(rpcUrl);
  if (explicitRpcUrl) {
    return assertSafeRpcUrl(explicitRpcUrl, 'rpcUrl');
  }

  const profileRpcUrl = presentString(resolveCliNetworkProfile(selector, config).rpcUrl);
  if (profileRpcUrl) {
    return assertSafeRpcUrl(profileRpcUrl, 'rpcUrl');
  }

  const configuredRpcUrl = presentString(config.rpcUrl);
  if (configuredRpcUrl) {
    return assertSafeRpcUrl(configuredRpcUrl, 'rpcUrl');
  }

  throw new Error('rpcUrl is required');
}
