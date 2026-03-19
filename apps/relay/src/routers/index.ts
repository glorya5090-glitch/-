import { t } from '@/lib/core/trpc';
import { adminRouter } from './admin';
import { daemonRouter } from './daemon';
import { publicRouter } from './public';

export const router = t.router({
  admin: adminRouter,
  daemon: daemonRouter,
  public: publicRouter,
});

export type AppRouter = typeof router;
