import type { FetchCreateContextFnOptions } from '@trpc/server/adapters/fetch';
import type { RelayCacheService } from '@worldlibertyfinancial/agent-cache/service';
import type { Context } from 'hono';
import { env } from '@/env';

export interface RelayBindings {
  Variables: {
    relayCacheService: RelayCacheService;
  };
}

export type RelayContext = Record<string, unknown> & {
  cache: RelayCacheService;
  env: typeof env;
  hono: Context<RelayBindings>;
};

export const createContext = async (
  _opts: FetchCreateContextFnOptions,
  hono: Context<RelayBindings>,
): Promise<RelayContext> => {
  return {
    cache: hono.get('relayCacheService'),
    env,
    hono,
  };
};
