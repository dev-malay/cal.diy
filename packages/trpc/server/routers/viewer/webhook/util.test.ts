import { describe, expect, it, beforeEach, vi } from "vitest";

import prisma from "@calcom/prisma";
import { MembershipRole } from "@calcom/prisma/enums";
import type { TrpcSessionUser } from "@calcom/trpc/server/types";

import { deleteHandler } from "./delete.handler";
import { assertWebhookManagementPermission } from "./util";

vi.mock("@calcom/prisma", () => {
  const mockObj = {
    webhook: { findUnique: vi.fn(), findFirst: vi.fn(), delete: vi.fn() },
    eventType: { findUnique: vi.fn() },
    membership: { findUnique: vi.fn() },
  };
  return {
    default: mockObj,
    prisma: mockObj,
  };
});

vi.mock("@calcom/features/webhooks/lib/scheduleTrigger", () => ({
  updateTriggerForExistingBookings: vi.fn(),
  deleteWebhookScheduledTriggers: vi.fn(),
  cancelNoShowTasksForBooking: vi.fn(),
}));

const adminUser = { id: 1, role: "ADMIN" };
const regularUser = { id: 2, role: "USER" };

function mockWebhookLookup(webhook: unknown): void {
  vi.mocked(prisma.webhook.findUnique).mockResolvedValueOnce(webhook as never);
}

function mockEventTypeLookup(eventType: unknown): void {
  vi.mocked(prisma.eventType.findUnique).mockResolvedValueOnce(eventType as never);
}

function mockMembershipLookup(role: MembershipRole | null): void {
  if (role) {
    vi.mocked(prisma.membership.findUnique).mockResolvedValueOnce({ role } as never);
  } else {
    vi.mocked(prisma.membership.findUnique).mockResolvedValueOnce(null as never);
  }
}

describe("assertWebhookManagementPermission", () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  describe("personal webhooks", () => {
    it("allows the owner", async () => {
      mockWebhookLookup({ id: "w1", userId: 2, teamId: null, eventTypeId: null });

      await expect(
        assertWebhookManagementPermission(regularUser, { id: "w1" })
      ).resolves.toBeUndefined();
    });

    it("rejects a non-owner", async () => {
      mockWebhookLookup({ id: "w1", userId: 2, teamId: null, eventTypeId: null });

      await expect(
        assertWebhookManagementPermission({ id: 3, role: "USER" }, { id: "w1" })
      ).rejects.toMatchObject({ code: "FORBIDDEN" });
    });

    it("rejects instance admins from managing someone else's personal webhook", async () => {
      mockWebhookLookup({ id: "w1", userId: 2, teamId: null, eventTypeId: null });

      await expect(
        assertWebhookManagementPermission(adminUser, { id: "w1" })
      ).rejects.toMatchObject({ code: "FORBIDDEN" });
    });
  });

  describe("team webhooks", () => {
    it("allows a team admin", async () => {
      mockWebhookLookup({ id: "tw1", userId: null, teamId: 10, eventTypeId: null });
      mockMembershipLookup(MembershipRole.ADMIN);

      await expect(
        assertWebhookManagementPermission(regularUser, { id: "tw1" })
      ).resolves.toBeUndefined();
    });

    it("allows a team owner", async () => {
      mockWebhookLookup({ id: "tw1", userId: null, teamId: 10, eventTypeId: null });
      mockMembershipLookup(MembershipRole.OWNER);

      await expect(
        assertWebhookManagementPermission(regularUser, { id: "tw1", teamId: 10 })
      ).resolves.toBeUndefined();
    });

    it("rejects a team member", async () => {
      mockWebhookLookup({ id: "tw1", userId: null, teamId: 10, eventTypeId: null });
      mockMembershipLookup(MembershipRole.MEMBER);

      await expect(
        assertWebhookManagementPermission(regularUser, { id: "tw1", teamId: 10 })
      ).rejects.toMatchObject({ code: "FORBIDDEN" });
    });

    it("rejects a non-member", async () => {
      mockWebhookLookup({ id: "tw1", userId: null, teamId: 10, eventTypeId: null });
      mockMembershipLookup(null);

      await expect(
        assertWebhookManagementPermission(adminUser, { id: "tw1", teamId: 10 })
      ).rejects.toMatchObject({ code: "FORBIDDEN" });
    });
  });

  describe("event-type webhooks", () => {
    it("allows a team admin of the event type's team", async () => {
      mockWebhookLookup({ id: "ew1", userId: null, teamId: null, eventTypeId: 55 });
      mockEventTypeLookup({ id: 55, userId: null, teamId: 10 });
      mockMembershipLookup(MembershipRole.ADMIN);

      await expect(
        assertWebhookManagementPermission(regularUser, { id: "ew1", eventTypeId: 55 })
      ).resolves.toBeUndefined();
    });

    it("rejects a team member of the event type's team", async () => {
      mockWebhookLookup({ id: "ew1", userId: null, teamId: null, eventTypeId: 55 });
      mockEventTypeLookup({ id: 55, userId: null, teamId: 10 });
      mockMembershipLookup(MembershipRole.MEMBER);

      await expect(
        assertWebhookManagementPermission(regularUser, { id: "ew1", eventTypeId: 55 })
      ).rejects.toMatchObject({ code: "FORBIDDEN" });
    });

    it("rejects editing another user's user-owned event type webhook", async () => {
      mockWebhookLookup({ id: "ew1", userId: null, teamId: null, eventTypeId: 55 });
      mockEventTypeLookup({ id: 55, userId: 9, teamId: null });

      await expect(
        assertWebhookManagementPermission(regularUser, { id: "ew1", eventTypeId: 55 })
      ).rejects.toMatchObject({ code: "FORBIDDEN" });
    });
  });

  describe("creating against an event type or team", () => {
    it("rejects a team member creating a team webhook via teamId", async () => {
      mockMembershipLookup(MembershipRole.MEMBER);

      await expect(
        assertWebhookManagementPermission(regularUser, { teamId: 10 })
      ).rejects.toMatchObject({ code: "FORBIDDEN" });
    });

    it("allows a team admin creating a team webhook via teamId", async () => {
      mockMembershipLookup(MembershipRole.ADMIN);

      await expect(
        assertWebhookManagementPermission(regularUser, { teamId: 10 })
      ).resolves.toBeUndefined();
    });

    it("rejects another user attaching to their event type", async () => {
      mockEventTypeLookup({ id: 55, userId: 9, teamId: null });

      await expect(
        assertWebhookManagementPermission(regularUser, { eventTypeId: 55 })
      ).rejects.toMatchObject({ code: "FORBIDDEN" });
    });

    it("allows attaching to the caller's own event type", async () => {
      mockEventTypeLookup({ id: 55, userId: 2, teamId: null });

      await expect(
        assertWebhookManagementPermission(regularUser, { eventTypeId: 55 })
      ).resolves.toBeUndefined();
    });
  });

  describe("platform webhooks", () => {
    it("rejects non-admins from platform webhooks", async () => {
      mockWebhookLookup({ id: "pw1", userId: null, teamId: null, eventTypeId: null });

      await expect(
        assertWebhookManagementPermission(regularUser, { id: "pw1" })
      ).rejects.toMatchObject({ code: "FORBIDDEN" });
    });

    it("allows instance admins", async () => {
      mockWebhookLookup({ id: "pw1", userId: null, teamId: null, eventTypeId: null });

      await expect(
        assertWebhookManagementPermission(adminUser, { id: "pw1" })
      ).resolves.toBeUndefined();
    });
  });

  it("throws NOT_FOUND when the webhook does not exist", async () => {
    mockWebhookLookup(null);

    await expect(
      assertWebhookManagementPermission(regularUser, { id: "missing" })
    ).rejects.toMatchObject({ code: "NOT_FOUND" });
  });

  it("throws UNAUTHORIZED when the input eventTypeId does not match the webhook", async () => {
    mockWebhookLookup({ id: "w1", userId: 2, teamId: null, eventTypeId: 55 });

    await expect(
      assertWebhookManagementPermission(regularUser, { id: "w1", eventTypeId: 99 })
    ).rejects.toMatchObject({ code: "UNAUTHORIZED" });
  });
});

describe("deleteHandler team scope", () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it("scopes an admin's delete to the given team", async () => {
    vi.mocked(prisma.webhook.findFirst).mockResolvedValueOnce({ id: "tw1" } as never);
    vi.mocked(prisma.webhook.delete).mockResolvedValueOnce({} as never);

    const ctx = {
      user: {
        id: 1,
        role: "ADMIN",
      } as NonNullable<TrpcSessionUser>,
    };

    await deleteHandler({ ctx, input: { id: "tw1", teamId: 10 } });

    const whereArg = vi.mocked(prisma.webhook.findFirst).mock.calls[0][0]?.where as {
      AND: unknown[];
    };
    expect(whereArg.AND).toContainEqual({ teamId: 10 });
    expect(vi.mocked(prisma.webhook.delete)).toHaveBeenCalledWith({ where: { id: "tw1" } });
  });

  it("does not delete when the webhook outside the team scope is requested by team id", async () => {
    vi.mocked(prisma.webhook.findFirst).mockResolvedValueOnce(null);

    const ctx = {
      user: {
        id: 1,
        role: "ADMIN",
      } as NonNullable<TrpcSessionUser>,
    };

    await deleteHandler({ ctx, input: { id: "tw1", teamId: 10 } });

    expect(vi.mocked(prisma.webhook.delete)).not.toHaveBeenCalled();
  });
});
