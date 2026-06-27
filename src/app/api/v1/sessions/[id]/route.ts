import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db/client";
import { sessions } from "@/lib/db/schema";
import { eq, and } from "drizzle-orm";
import { revokeSession } from "@/lib/auth/sessions";
import { error, authenticate } from "@/lib/api/helpers";

export async function DELETE(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { user, error: authError } = await authenticate(request);
  if (authError) return authError;

  const { id } = await params;

  // Verify the session belongs to this user
  const session = await db.query.sessions.findFirst({
    where: and(eq(sessions.id, id), eq(sessions.userId, user!.sub)),
  });

  if (!session) {
    return error("Session not found", 404, "not_found");
  }

  await revokeSession(id);
  return new NextResponse(null, { status: 204 });
}
