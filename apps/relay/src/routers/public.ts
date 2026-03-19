import { publicProcedure, TRPCError, t } from '@/lib/core/trpc';
import { daemonIdSchema } from '@/lib/schemas';

export const publicRouter = t.router({
  getDaemonDirectoryEntry: publicProcedure.input(daemonIdSchema).query(async ({ ctx, input }) => {
    const daemon = await ctx.cache.getDaemonProfile(input);
    if (!daemon) {
      throw new TRPCError({ code: 'NOT_FOUND', message: `Unknown daemon '${input}'` });
    }

    return {
      daemonId: daemon.daemonId,
      daemonPublicKey: daemon.daemonPublicKey,
      ethereumAddress: daemon.ethereumAddress,
      label: daemon.label,
      lastSeenAt: daemon.lastSeenAt,
      relayUrl: daemon.relayUrl ?? ctx.env.RELAY_BASE_URL,
      status: daemon.status,
      updatedAt: daemon.updatedAt,
      version: daemon.version,
    };
  }),
});
