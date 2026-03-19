/** biome-ignore-all lint/style/noProcessEnv: relay cache config is environment driven */
import Redis from 'ioredis';

export interface CacheClientOptions {
  connectTimeoutMs?: number;
  enableOfflineQueue?: boolean;
  keyPrefix?: string;
  lazyConnect?: boolean;
  maxRetriesPerRequest?: number | null;
  url?: string;
}

let singletonClient: Redis | null = null;

const getDefaultCacheUrl = (): string => {
  const explicitUrl = process.env.CACHE_URL?.trim();
  if (explicitUrl) {
    return explicitUrl;
  }

  const host = process.env.CACHE_HOST?.trim() || '127.0.0.1';
  const port = Number(process.env.CACHE_PORT?.trim() || '6379');

  return `redis://${host}:${port}`;
};

export const createCacheClient = (options: CacheClientOptions = {}): Redis => {
  return new Redis(options.url ?? getDefaultCacheUrl(), {
    connectTimeout: options.connectTimeoutMs ?? 5_000,
    enableOfflineQueue: options.enableOfflineQueue ?? true,
    keyPrefix: options.keyPrefix,
    lazyConnect: options.lazyConnect ?? false,
    maxRetriesPerRequest: options.maxRetriesPerRequest ?? 2,
    reconnectOnError(error) {
      return error.message.includes('READONLY') || error.message.includes('ETIMEDOUT');
    },
  });
};

export const getCacheClient = (options: CacheClientOptions = {}): Redis => {
  if (!singletonClient) {
    singletonClient = createCacheClient(options);
  }

  return singletonClient;
};

export const closeCacheClient = async (): Promise<void> => {
  if (!singletonClient) {
    return;
  }

  const client = singletonClient;
  singletonClient = null;
  await client.quit();
};
