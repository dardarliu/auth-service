import { NextRequest } from "next/server";
import { db } from "@/lib/db/client";
import { passwordResets, users } from "@/lib/db/schema";
import { eq, and, isNull } from "drizzle-orm";
import { hashToken } from "@/lib/auth/tokens";
import { hashPassword, validatePassword } from "@/lib/auth/password";
import { revokeAllUserSessions } from "@/lib/auth/sessions";
import { sendPasswordChangedEmail } from "@/lib/email/send";
import { json, error } from "@/lib/api/helpers";

export async function POST(request: NextRequest) {
  const body = await request.json();
  const { token, new_password } = body;

  if (!token || !new_password) {
    return error("Token and new_password are required", 400, "validation_error");
  }

  const passwordError = validatePassword(new_password);
  if (passwordError) {
    return error(passwordError, 400, "validation_error");
  }

  const tokenHash = hashToken(token);
  const reset = await db.query.passwordResets.findFirst({
    where: and(
      eq(passwordResets.tokenHash, tokenHash),
      isNull(passwordResets.usedAt)
    ),
  });

  if (!reset || reset.expiresAt < new Date()) {
    return error("Invalid or expired token", 400, "invalid_token");
  }

  const newHash = await hashPassword(new_password);

  // Atomic claim — prevents concurrent use of same token
  const [claimed] = await db
    .update(passwordResets)
    .set({ usedAt: new Date() })
    .where(and(eq(passwordResets.id, reset.id), isNull(passwordResets.usedAt)))
    .returning({ id: passwordResets.id });

  if (!claimed) {
    return error("Invalid or expired token", 400, "invalid_token");
  }

  await db
    .update(users)
    .set({
      passwordHash: newHash,
      passwordChangedAt: new Date(),
      updatedAt: new Date(),
    })
    .where(eq(users.id, reset.userId));

  await revokeAllUserSessions(reset.userId);

  const user = await db.query.users.findFirst({
    where: eq(users.id, reset.userId),
  });
  if (user) {
    await sendPasswordChangedEmail(user.email);
  }

  return json({
    message: "Password reset successfully. Please log in with your new password.",
  });
}
