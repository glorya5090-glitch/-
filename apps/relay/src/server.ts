import { serve } from '@hono/node-server';
import { app } from '@/app';
import { env } from '@/env';
import { log } from '@/lib/logger';

serve(
  {
    fetch: app.fetch,
    hostname: env.HOST,
    port: env.PORT,
  },
  (info) => {
    log.info('relay.server.started', {
      host: info.address,
      port: info.port,
      relayBaseUrl: env.RELAY_BASE_URL,
    });
  },
);
