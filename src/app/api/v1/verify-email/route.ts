import { NextRequest } from "next/server";
import { db } from "@/lib/db/client";
import { emailVerifications, users } from "@/lib/db/schema";
import { eq, and, isNull } from "drizzle-orm";
import { hashToken } from "@/lib/auth/tokens";
import { json, error } from "@/lib/api/helpers";

export async function GET(request: NextRequest) {
  const token = request.nextUrl.searchParams.get("token");
  const result = await verifyToken(token);
  const ok = result.status === 200;

  const html = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${ok ? "Email Verified" : "Verification Failed"}</title></head>
<body style="margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#0a0a0a;color:#fafafa;font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace">
<div style="text-align:center;max-width:360px;padding:2rem">
<h1 style="font-size:1.25rem;font-weight:600;margin:0">${ok ? "email verified" : "verification failed"}</h1>
<p style="color:#737373;font-size:0.8rem;margin-top:0.75rem">${ok ? "your email has been verified. you can now sign in." : "this link is invalid or has expired."}</p>
</div></body></html>`;

  return new Response(html, {
    status: ok ? 200 : 400,
    headers: { "Content-Type": "text/html" },
  });
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
