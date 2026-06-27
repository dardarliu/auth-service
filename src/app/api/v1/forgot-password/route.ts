import { NextRequest } from "next/server";
import { db } from "@/lib/db/client";
import { users, passwordResets } from "@/lib/db/schema";
import { eq, and, isNull } from "drizzle-orm";
import { generateSecureToken, hashToken } from "@/lib/auth/tokens";
import { sendPasswordResetEmail } from "@/lib/email/send";
import { emailLimiter } from "@/lib/security/rate-limit";
import { json, error, rateLimit, normalizeEmail, getIP } from "@/lib/api/helpers";

export async function POST(request: NextRequest) {
  const rateLimited = await rateLimit(request);
  if (rateLimited) return rateLimited;

  const body = await request.json();
  const { email } = body;

  const RESPONSE = json({
    message:
      "If an account with that email exists, we've sent a password reset link.",
  });

  if (!email) return RESPONSE;

  const emailNorm = normalizeEmail(email);

  // Rate limit per email
  const { success } = await emailLimiter.limit(emailNorm);
  if (!success) return RESPONSE;

  const user = await db.query.users.findFirst({
    where: and(eq(users.emailNormalized, emailNorm), isNull(users.deletedAt)),
  });

  if (!user) return RESPONSE;

  const token = generateSecureToken();
  const ip = getIP(request);

  await db.insert(passwordResets).values({
    userId: user.id,
    tokenHash: hashToken(token),
    expiresAt: new Date(Date.now() + 60 * 60 * 1000), // 1 hour
    ipAddress: ip,
  });

  await sendPasswordResetEmail(user.email, token);

  return RESPONSE;
}
