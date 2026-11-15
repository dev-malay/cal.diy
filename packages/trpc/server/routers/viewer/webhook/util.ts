import { prisma } from "@calcom/prisma";
import { MembershipRole } from "@calcom/prisma/enums";

import { TRPCError } from "@trpc/server";

import authedProcedure from "../../../procedures/authedProcedure";
import { webhookIdAndEventTypeIdSchema } from "./types";

type WebhookManagementInput = {
  id?: string;
  webhookId?: string;
  eventTypeId?: number;
  teamId?: number;
};

/**
 * Resolves the scope a webhook operation may act on and throws unless the caller is
 * allowed to manage it. Exported for direct unit testing of the authorization logic.
 *
 * The webhook record itself is the source of truth for the scope, because callers send
 * only a webhook id in flows like edit and delete:
 * - team webhook or event-type-attached webhook on a team -> team membership admin/owner
 * - webhook on a user-owned event type or a personal webhook -> owner must be the caller
 * - platform webhook (no userId, no teamId, no eventTypeId) -> instance admins only
 */
export async function assertWebhookManagementPermission(
  user: { id: number; role: string },
  input: WebhookManagementInput
): Promise<void> {
  const { id, webhookId, eventTypeId, teamId } = input;
  const lookupId = id || webhookId;

  let owningTeamId: number | null = teamId ?? null;

  if (lookupId) {
    const webhook = await prisma.webhook.findUnique({
      where: { id: lookupId },
      select: { id: true, userId: true, teamId: true, eventTypeId: true },
    });

    if (!webhook) {
      throw new TRPCError({ code: "NOT_FOUND" });
    }

    if (eventTypeId && eventTypeId !== webhook.eventTypeId) {
      throw new TRPCError({ code: "UNAUTHORIZED" });
    }

    if (webhook.teamId) {
      owningTeamId = webhook.teamId;
    } else if (webhook.eventTypeId) {
      const eventType = await prisma.eventType.findUnique({
        where: { id: webhook.eventTypeId },
        select: { id: true, userId: true, teamId: true },
      });

      if (!eventType) {
        throw new TRPCError({ code: "NOT_FOUND" });
      }

      if (eventType.teamId) {
        owningTeamId = eventType.teamId;
      } else if (eventType.userId !== user.id) {
        throw new TRPCError({ code: "FORBIDDEN" });
      }
    } else if (webhook.userId === null) {
      if (user.role !== "ADMIN") {
        throw new TRPCError({ code: "FORBIDDEN" });
      }
    } else if (webhook.userId !== user.id) {
      throw new TRPCError({ code: "FORBIDDEN" });
    }
  } else if (eventTypeId) {
    const eventType = await prisma.eventType.findUnique({
      where: { id: eventTypeId },
      select: { id: true, userId: true, teamId: true },
    });

    if (!eventType) {
      throw new TRPCError({ code: "NOT_FOUND" });
    }

    if (!eventType.teamId && eventType.userId !== user.id) {
      throw new TRPCError({ code: "FORBIDDEN" });
    }
  }

  if (owningTeamId) {
    const membership = await prisma.membership.findUnique({
      where: {
        userId_teamId: {
          userId: user.id,
          teamId: owningTeamId,
        },
      },
      select: { role: true },
    });

    if (
      !membership ||
      (membership.role !== MembershipRole.ADMIN && membership.role !== MembershipRole.OWNER)
    ) {
      throw new TRPCError({ code: "FORBIDDEN", message: "You are not authorized to manage this webhook" });
    }
  }
}

export const createWebhookProcedure = () => {
  return authedProcedure.input(webhookIdAndEventTypeIdSchema.optional()).use(async ({ ctx, input, next }) => {
    if (!input) return next();

    await assertWebhookManagementPermission(ctx.user, input);

    return next();
  });
};

export const webhookProcedure = createWebhookProcedure();
