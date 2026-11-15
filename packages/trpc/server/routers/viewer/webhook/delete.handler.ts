import { updateTriggerForExistingBookings } from "@calcom/features/webhooks/lib/scheduleTrigger";
import { prisma } from "@calcom/prisma";
import type { Prisma } from "@calcom/prisma/client";
import type { TrpcSessionUser } from "@calcom/trpc/server/types";

import type { TDeleteInputSchema } from "./delete.schema";

type DeleteOptions = {
  ctx: {
    user: NonNullable<TrpcSessionUser>;
  };
  input: TDeleteInputSchema;
};

export const deleteHandler = async ({ ctx, input }: DeleteOptions): Promise<{ id: string }> => {
  const { id } = input;

  const where: Prisma.WebhookWhereInput = { AND: [{ id: id }] };

  if (Array.isArray(where.AND)) {
    // Team membership is enforced in the procedure middleware; without this filter an
    // admin's delete would silently no-op on team webhooks (userId is null on them).
    if (input.teamId) {
      where.AND.push({ teamId: input.teamId });
    } else if (input.eventTypeId) {
      where.AND.push({ eventTypeId: input.eventTypeId });
    } else if (ctx.user.role === "ADMIN") {
      where.AND.push({ OR: [{ platform: true }, { userId: ctx.user.id }] });
    } else {
      where.AND.push({ userId: ctx.user.id });
    }
  }

  const webhookToDelete = await prisma.webhook.findFirst({
    where,
  });

  if (webhookToDelete) {
    await prisma.webhook.delete({
      where: {
        id: webhookToDelete.id,
      },
    });

    await updateTriggerForExistingBookings(webhookToDelete, webhookToDelete.eventTriggers, []);
  }

  return {
    id,
  };
};
