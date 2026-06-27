import { NextRequest } from "next/server";
import { db } from "@/lib/db/client";
import { users } from "@/lib/db/schema";
import { eq } from "drizzle-orm";
import { verifyPassword } from "@/lib/auth/password";
import { revokeAllUserSessions } from "@/lib/auth/sessions";
import { json, error, authenticate } from "@/lib/api/helpers";
import { NextResponse } from "next/server";

export async function GET(request: NextRequest) {
  const { user, error: authError } = await authenticate(request);
  if (authError) return authError;

  const dbUser = await db.query.users.findFirst({
    where: eq(users.id, user!.sub),
  });

  if (!dbUser || dbUser.deletedAt) {
    return error("User not found", 404, "not_found");
  }

  return json({
    id: dbUser.id,
    email: dbUser.email,
    email_verified: dbUser.emailVerified,
    username: dbUser.username,
    display_name: dbUser.displayName,
    created_at: dbUser.createdAt,
  });
}

export async function PATCH(request: NextRequest) {
  const { user, error: authError } = await authenticate(request);
  if (authError) return authError;

  const body = await request.json();
  const updates: Record<string, any> = {};

  if (body.display_name !== undefined) {
    if (body.display_name && body.display_name.length > 25) {
      return error("Display name must be 25 characters or fewer", 400, "validation_error");
    }
    updates.displayName = body.display_name;
  }

  if (body.username !== undefined) {
    if (body.username && !/^[a-zA-Z0-9_]{3,25}$/.test(body.username)) {
      return error(
        "Username must be 3-25 characters, alphanumeric and underscores only",
        400,
        "validation_error"
      );
    }
    updates.username = body.username || null;
    updates.usernameNormalized = body.username
      ? body.username.toLowerCase()
      : null;
  }

  if (Object.keys(updates).length === 0) {
    return error("No fields to update", 400, "validation_error");
  }

  updates.updatedAt = new Date();

  try {
    const [updated] = await db
      .update(users)
      .set(updates)
      .where(eq(users.id, user!.sub))
      .returning({
        id: users.id,
        email: users.email,
        emailVerified: users.emailVerified,
        username: users.username,
        displayName: users.displayName,
        createdAt: users.createdAt,
      });

    return json({
      id: updated.id,
      email: updated.email,
      email_verified: updated.emailVerified,
      username: updated.username,
      display_name: updated.displayName,
      created_at: updated.createdAt,
    });
  } catch (e: any) {
    if (e?.code === "23505") {
      return error("That username is already in use.", 409, "username_taken");
    }
    throw e;
  }
}

export async function DELETE(request: NextRequest) {
  const { user, error: authError } = await authenticate(request);
  if (authError) return authError;

  const body = await request.json();
  if (!body.password) {
    return error("Password is required to delete account", 400, "validation_error");
  }

  const dbUser = await db.query.users.findFirst({
    where: eq(users.id, user!.sub),
  });

  if (!dbUser) {
    return error("User not found", 404, "not_found");
  }

  const valid = await verifyPassword(dbUser.passwordHash, body.password);
  if (!valid) {
    return error("Invalid password", 401, "invalid_credentials");
  }

  // Soft delete
  await db
    .update(users)
    .set({ deletedAt: new Date(), status: "deleted", updatedAt: new Date() })
    .where(eq(users.id, user!.sub));

  await revokeAllUserSessions(user!.sub);

  return new NextResponse(null, { status: 204 });
}
