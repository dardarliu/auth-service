import { NextRequest } from "next/server";
import { db } from "@/lib/db/client";
import { emailVerifications, users } from "@/lib/db/schema";
import { eq, and, isNull } from "drizzle-orm";
import { hashToken } from "@/lib/auth/tokens";
import { json, error } from "@/lib/api/helpers";

export async function GET(request: NextRequest) {
  const token = request.nextUrl.searchParams.get("token");
  return verifyToken(token);
}

export async function POST(request: NextRequest) {
  const body = await request.json();
  const { token } = body;
  return verifyToken(token);
}

async function verifyToken(token: string | null) {

  if (!token) {
    return error("Token is required", 400, "validation_error");
  }

  const tokenHash = hashToken(token);
  const verification = await db.query.emailVerifications.findFirst({
    where: and(
      eq(emailVerifications.tokenHash, tokenHash),
      isNull(emailVerifications.usedAt)
    ),
  });

  if (!verification || verification.expiresAt < new Date()) {
    return error("Invalid or expired token", 400, "invalid_token");
  }

  await db
    .update(emailVerifications)
    .set({ usedAt: new Date() })
    .where(eq(emailVerifications.id, verification.id));

  await db
    .update(users)
    .set({ emailVerified: true, updatedAt: new Date() })
    .where(eq(users.id, verification.userId));

  return json({ message: "Email verified successfully." });
}
