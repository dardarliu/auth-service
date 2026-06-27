import { NextRequest } from "next/server";
import { db } from "@/lib/db/client";
import { users } from "@/lib/db/schema";
import { eq } from "drizzle-orm";
import { rotateSession } from "@/lib/auth/sessions";
import { signAccessToken } from "@/lib/auth/tokens";
import { json, jsonWithTokenCookies, error, rateLimit, getIP } from "@/lib/api/helpers";

export async function POST(request: NextRequest) {
  const rateLimited = await rateLimit(request);
  if (rateLimited) return rateLimited;

  const body = await request.json();
  const { refresh_token } = body;

  if (!refresh_token) {
    return error("refresh_token is required", 400, "validation_error");
  }

  const ip = getIP(request);
  const ua = request.headers.get("user-agent") || undefined;
  const result = await rotateSession(refresh_token, ip, ua);

  if (!result) {
    return error(
      "Session expired. Please log in again.",
      401,
      "invalid_token"
    );
  }

  const user = await db.query.users.findFirst({
    where: eq(users.id, result.userId),
  });

  if (!user || user.deletedAt) {
    return error("Session expired. Please log in again.", 401, "invalid_token");
  }

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
    result.token
  );
}
