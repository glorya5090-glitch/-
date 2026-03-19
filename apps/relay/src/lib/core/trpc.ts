import { initTRPC, TRPCError } from '@trpc/server';
import superjson from 'superjson';
import { assertAdminAccess, assertDaemonAccess } from '@/lib/auth';
import type { RelayContext } from './create-context';

const t = initTRPC.context<RelayContext>().create({
  errorFormatter({ shape }) {
    const {
      data: { stack: _stack, ...data },
      ...rest
    } = shape;

    return {
      ...rest,
      data,
    };
  },
  transformer: superjson,
});

const adminMiddleware = t.middleware(({ ctx, next }) => {
  assertAdminAccess(ctx.hono.req.header('authorization'));
  return next();
});

const daemonMiddleware = t.middleware(({ ctx, next }) => {
  assertDaemonAccess(ctx.hono.req.header('x-relay-daemon-token'));
  return next();
});

const publicProcedure = t.procedure;
const adminProcedure = t.procedure.use(adminMiddleware);
const daemonProcedure = t.procedure.use(daemonMiddleware);

export { TRPCError, adminProcedure, daemonProcedure, publicProcedure, t };
