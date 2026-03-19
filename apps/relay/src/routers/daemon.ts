import { daemonProcedure, t } from '@/lib/core/trpc';
import {
  daemonRegisterInputSchema,
  pollUpdatesInputSchema,
  submitFeedbackInputSchema,
} from '@/lib/schemas';

export const daemonRouter = t.router({
  pollUpdates: daemonProcedure.input(pollUpdatesInputSchema).query(async ({ ctx, input }) => {
    const updates = await ctx.cache.claimEncryptedUpdates({
      daemonId: input.daemonId,
      leaseSeconds: input.leaseSeconds ?? ctx.env.RELAY_UPDATE_LEASE_SECONDS,
      limit: input.limit ?? ctx.env.RELAY_POLL_MAX_UPDATES,
    });

    return {
      items: updates,
      polledAt: new Date().toISOString(),
    };
  }),
  register: daemonProcedure.input(daemonRegisterInputSchema).mutation(async ({ ctx, input }) => {
    const daemonId = input.daemon.daemonId;
    const result = await ctx.cache.syncDaemonRegistration({
      ...input,
      agentKeys: input.agentKeys.map((agentKey) => ({ ...agentKey, daemonId })),
      approvalRequests: input.approvalRequests.map((request) => ({ ...request, daemonId })),
      policies: input.policies.map((policy) => ({ ...policy, daemonId })),
    });
    return {
      daemonId,
      registeredAt: input.daemon.registeredAt,
      summary: result,
    };
  }),
  submitFeedback: daemonProcedure
    .input(submitFeedbackInputSchema)
    .mutation(async ({ ctx, input }) => {
      const update = await ctx.cache.submitUpdateFeedback(input);
      return {
        status: update.status,
        updateId: update.updateId,
        updatedAt: update.updatedAt,
      };
    }),
});
