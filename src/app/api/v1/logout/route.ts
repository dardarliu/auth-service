import { NextRequest } from "next/server";
import { revokeSession, revokeAllUserSessions } from "@/lib/auth/sessions";
import { hashToken } from "@/lib/auth/tokens";
import { db } from "@/lib/db/client";
import { sessions } from "@/lib/db/schema";
import { eq } from "drizzle-orm";
import { error, authenticate } from "@/lib/api/helpers";
import { NextResponse } from "next/server";

export async function POST(request: NextRequest) {
  const { user, error: authError } = await authenticate(request);
  if (authError) return authError;

  const body = await request.json().catch(() => ({}));
  const refreshToken =
    body.refresh_token || request.cookies.get("refresh_token")?.value;

  if (body.all_sessions) {
    await revokeAllUserSessions(user!.sub);
  } else if (refreshToken) {
    const tokenHash = hashToken(refreshToken);
    const session = await db.query.sessions.findFirst({
      where: eq(sessions.tokenHash, tokenHash),
    });
    if (session) {
      await revokeSession(session.id);
    }
  } else {
    return error("Provide refresh_token or set all_sessions: true", 400, "validation_error");
  }

  const response = new NextResponse(null, { status: 204 });
  response.cookies.set("access_token", "", { maxAge: 0, path: "/" });
  response.cookies.set("refresh_token", "", {
    maxAge: 0,
    path: "/api/v1/refresh",
  });
  return response;
}
