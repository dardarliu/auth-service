import { NextRequest } from "next/server";
import { db } from "@/lib/db/client";
import { users } from "@/lib/db/schema";
import { eq, and, isNull } from "drizzle-orm";
import {
  verifyPassword,
  dummyHash,
} from "@/lib/auth/password";
import { signAccessToken } from "@/lib/auth/tokens";
import { createSession } from "@/lib/auth/sessions";
import { json, jsonWithTokenCookies, error, rateLimit, normalizeEmail, getIP } from "@/lib/api/helpers";

const INVALID_CREDENTIALS = error(
  "Invalid email or password",
  401,
  "invalid_credentials"
);

export async function POST(request: NextRequest) {
  const rateLimited = await rateLimit(request);
  if (rateLimited) return rateLimited;

  const body = await request.json();
  const { email, password } = body;

  if (!email || !password) {
    return error("Email and password are required", 400, "validation_error");
  }

  const emailNorm = normalizeEmail(email);
  const user = await db.query.users.findFirst({
    where: and(eq(users.emailNormalized, emailNorm), isNull(users.deletedAt)),
  });

  if (!user) {
    await dummyHash(password);
    return INVALID_CREDENTIALS;
  }

  // Check account lock
  if (user.status === "locked") {
    // Permanent lock (admin review required) — no lockedUntil set
    if (!user.lockedUntil) {
      await dummyHash(password);
      return INVALID_CREDENTIALS;
    }
    // Temporary lock — still active
    if (user.lockedUntil > new Date()) {
      await dummyHash(password);
      return INVALID_CREDENTIALS;
    }
    // Temporary lock expired — allow attempt but keep the counter
  }

  const valid = await verifyPassword(user.passwordHash, password);

  if (!valid) {
    const attempts = user.failedLoginAttempts + 1;
    const updates: Record<string, any> = {
      failedLoginAttempts: attempts,
      lastFailedLoginAt: new Date(),
    };

    if (attempts >= 20) {
      updates.status = "locked";
      updates.lockedUntil = null; // locked until admin review
    } else if (attempts % 5 === 0) {
      // Re-lock every 5 consecutive failures
      updates.status = "locked";
      updates.lockedUntil = new Date(Date.now() + 15 * 60 * 1000);
    }

    await db.update(users).set(updates).where(eq(users.id, user.id));
    return INVALID_CREDENTIALS;
  }

  if (!user.emailVerified) {
    return error("Please verify your email before signing in", 403, "email_not_verified");
  }

  // Only a successful login resets the counter
  await db
    .update(users)
    .set({ failedLoginAttempts: 0, status: "active", lockedUntil: null })
    .where(eq(users.id, user.id));

  const ip = getIP(request);
  const ua = request.headers.get("user-agent") || undefined;
  const { token: refreshToken } = await createSession({
    userId: user.id,
    ipAddress: ip,
    userAgent: ua,
  });

  const accessToken = await signAccessToken({
    sub: user.id,
    email: user.email,
    email_verified: user.emailVerified,
    username: user.username || undefined,
    display_name: user.displayName || undefined,
  });

  return jsonWithTokenCookies(
    { access_token: accessToken, token_type: "Bearer", expires_in: 900 },
    accessToken,
    refreshToken
  );
}
