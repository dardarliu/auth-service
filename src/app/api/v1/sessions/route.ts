import { NextRequest } from "next/server";
import { getUserSessions } from "@/lib/auth/sessions";
import { json, authenticate } from "@/lib/api/helpers";

export async function GET(request: NextRequest) {
  const { user, error: authError } = await authenticate(request);
  if (authError) return authError;

  const userSessions = await getUserSessions(user!.sub);

  return json({
    sessions: userSessions.map((s) => ({
      id: s.id,
      ip_address: s.ipAddress,
      user_agent: s.userAgent,
      created_at: s.createdAt,
      last_used_at: s.lastUsedAt,
    })),
  });
}
