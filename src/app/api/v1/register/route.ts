import { NextRequest } from "next/server";
import { db } from "@/lib/db/client";
import { users, emailVerifications } from "@/lib/db/schema";
import { hashPassword, validatePassword } from "@/lib/auth/password";
import { generateSecureToken, hashToken } from "@/lib/auth/tokens";
import { sendVerificationEmail } from "@/lib/email/send";
import { json, error, rateLimit, normalizeEmail, getIP } from "@/lib/api/helpers";

export async function POST(request: NextRequest) {
  const rateLimited = await rateLimit(request);
  if (rateLimited) return rateLimited;

  const body = await request.json();
  const { email, password, username, display_name } = body;

  if (!email || !password) {
    return error("Email and password are required", 400, "validation_error");
  }

  const passwordError = validatePassword(password);
  if (passwordError) {
    return error(passwordError, 400, "validation_error");
  }

  if (display_name && display_name.length > 25) {
    return error("Display name must be 25 characters or fewer", 400, "validation_error");
  }

  if (username) {
    if (!/^[a-zA-Z0-9_]{3,25}$/.test(username)) {
      return error(
        "Username must be 3-25 characters, alphanumeric and underscores only",
        400,
        "validation_error"
      );
    }
  }

  const emailNorm = normalizeEmail(email);
  const passwordHash = await hashPassword(password);

  try {
    const [user] = await db
      .insert(users)
      .values({
        email,
        emailNormalized: emailNorm,
        displayName: display_name || null,
        username: username || null,
        usernameNormalized: username ? username.toLowerCase() : null,
        passwordHash,
      })
      .returning({ id: users.id });

    // Send verification email
    const token = generateSecureToken();
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
    await db.insert(emailVerifications).values({
      userId: user.id,
      tokenHash: hashToken(token),
      expiresAt,
    });

    await sendVerificationEmail(email, token);
  } catch (e: any) {
    // Unique constraint violation — account exists, but don't reveal that
    if (e?.code === "23505") {
      return json(
        { message: "Please check your email to verify your account." },
        201
      );
    }
    throw e;
  }

  return json(
    { message: "Please check your email to verify your account." },
    201
  );
}
