import { z } from 'zod';

function normalizeLoopbackHostname(hostname: string): string {
  if (hostname.startsWith('[') && hostname.endsWith(']')) {
    return hostname.slice(1, -1).toLowerCase();
  }

  return hostname.toLowerCase();
}

function isIpv4Loopback(hostname: string): boolean {
  const parts = hostname.split('.');
  if (parts.length !== 4 || parts.some((part) => !/^\d+$/u.test(part))) {
    return false;
  }

  const octets = parts.map((part) => Number(part));
  if (octets.some((octet) => octet < 0 || octet > 255)) {
    return false;
  }

  return octets[0] === 127;
}

function isLoopbackHostname(hostname: string): boolean {
  const normalized = normalizeLoopbackHostname(hostname);
  return (
    normalized === 'localhost' ||
    normalized.endsWith('.localhost') ||
    normalized === '::1' ||
    isIpv4Loopback(normalized)
  );
}

export function assertSafeRelayBaseUrl(value: string, label = 'relayBaseUrl'): string {
  const normalized = value.trim();
  if (!normalized) {
    throw new Error(`${label} is required`);
  }

  let parsed: URL;
  try {
    parsed = new URL(normalized);
  } catch {
    throw new Error(`${label} must be a valid http(s) URL`);
  }

  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    throw new Error(`${label} must use https or localhost http`);
  }
  if (parsed.username || parsed.password) {
    throw new Error(`${label} must not include embedded credentials`);
  }
  if (!parsed.hostname) {
    throw new Error(`${label} must include a hostname`);
  }
  if (parsed.protocol === 'http:' && !isLoopbackHostname(parsed.hostname)) {
    throw new Error(`${label} must use https unless it targets localhost or a loopback address`);
  }

  return normalized.replace(/\/$/u, '');
}

const clientConfigSchema = z.object({
  relayBaseUrl: z
    .string()
    .default('http://localhost:8787')
    .transform((value) => assertSafeRelayBaseUrl(value, 'relayBaseUrl')),
  siteName: z.string().default('AgentPay Approval Console'),
});

export const clientConfig = clientConfigSchema.parse({
  relayBaseUrl: process.env.NEXT_PUBLIC_AGENTPAY_RELAY_BASE_URL,
  siteName: process.env.NEXT_PUBLIC_AGENTPAY_SITE_NAME,
});
