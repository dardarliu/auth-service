import { db } from "@/lib/db/client";
import { sessions } from "@/lib/db/schema";
import { eq, and, isNull, sql } from "drizzle-orm";
import { randomUUID } from "crypto";
import { generateSecureToken, hashToken } from "./tokens";

const REFRESH_TOKEN_TTL_DAYS = 30;

interface CreateSessionOpts {
  userId: string;
  ipAddress?: string;
  userAgent?: string;
  tokenFamily?: string;
}

export async function createSession(opts: CreateSessionOpts) {
  const token = generateSecureToken();
  const tokenHash = hashToken(token);
  const family = opts.tokenFamily || randomUUID();
  const expiresAt = new Date(
    Date.now() + REFRESH_TOKEN_TTL_DAYS * 24 * 60 * 60 * 1000
  );

  await db.insert(sessions).values({
    userId: opts.userId,
    tokenHash,
    tokenFamily: family,
    ipAddress: opts.ipAddress,
    userAgent: opts.userAgent,
    expiresAt,
  });

  return { token, family };
}

export async function rotateSession(
  refreshToken: string,
  ipAddress?: string,
  userAgent?: string
) {
  const tokenHash = hashToken(refreshToken);

  const session = await db.query.sessions.findFirst({
    where: eq(sessions.tokenHash, tokenHash),
  });

  if (!session) return null;

  // Token already revoked — replay attack, revoke entire family
  if (session.revokedAt) {
    await db
      .update(sessions)
      .set({ revokedAt: new Date(), revokeReason: "replay_detected" })
      .where(
        and(
          eq(sessions.tokenFamily, session.tokenFamily),
          isNull(sessions.revokedAt)
        )
      );
    return null;
  }

  // Token expired
  if (session.expiresAt < new Date()) return null;

  // Atomic revocation — only one concurrent request can succeed
  const [revoked] = await db
    .update(sessions)
    .set({ revokedAt: new Date(), revokeReason: "rotated" })
    .where(and(eq(sessions.id, session.id), isNull(sessions.revokedAt)))
    .returning({ id: sessions.id });

  // Another request already rotated this token — treat as replay
  if (!revoked) {
    await db
      .update(sessions)
      .set({ revokedAt: new Date(), revokeReason: "replay_detected" })
      .where(
        and(
          eq(sessions.tokenFamily, session.tokenFamily),
          isNull(sessions.revokedAt)
        )
      );
    return null;
  }

  // Issue new token in same family
  const newSession = await createSession({
    userId: session.userId,
    ipAddress,
    userAgent,
    tokenFamily: session.tokenFamily,
  });

  return { ...newSession, userId: session.userId };
}

export async function revokeSession(sessionId: string) {
  await db
    .update(sessions)
    .set({ revokedAt: new Date(), revokeReason: "user_logout" })
    .where(eq(sessions.id, sessionId));
}

export async function revokeAllUserSessions(userId: string) {
  await db
    .update(sessions)
    .set({ revokedAt: new Date(), revokeReason: "user_logout_all" })
    .where(and(eq(sessions.userId, userId), isNull(sessions.revokedAt)));
}

export async function getUserSessions(userId: string) {
  return db.query.sessions.findMany({
    where: and(eq(sessions.userId, userId), isNull(sessions.revokedAt)),
    orderBy: (s, { desc }) => [desc(s.lastUsedAt)],
  });
}
