import { NextRequest, NextResponse } from "next/server";
import { verifyAccessToken } from "@/lib/auth/tokens";
import { authLimiter } from "@/lib/security/rate-limit";

export function json(data: unknown, status = 200) {
  return NextResponse.json(data, { status });
}

export function jsonWithTokenCookies(
  data: unknown,
  accessToken: string,
  refreshToken: string
) {
  const response = NextResponse.json(data, { status: 200 });
  response.cookies.set("access_token", accessToken, {
    httpOnly: true,
    secure: true,
    sameSite: "none",
    path: "/",
    maxAge: 900,
  });
  response.cookies.set("refresh_token", refreshToken, {
    httpOnly: true,
    secure: true,
    sameSite: "none",
    path: "/api/v1",
    maxAge: 30 * 24 * 60 * 60,
  });
  return response;
}

export function error(message: string, status: number, code?: string) {
  return NextResponse.json(
    { error: code || "error", message },
    { status }
  );
}

export function getIP(request: NextRequest): string {
  return (
    request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
    request.headers.get("x-real-ip") ||
    "unknown"
  );
}

export async function rateLimit(request: NextRequest) {
  const ip = getIP(request);
  const { success } = await authLimiter.limit(ip);
  if (!success) {
    return error("Too many requests", 429, "rate_limited");
  }
  return null;
}

export async function authenticate(request: NextRequest) {
  const authHeader = request.headers.get("authorization");
  const token = authHeader?.startsWith("Bearer ")
    ? authHeader.slice(7)
    : request.cookies.get("access_token")?.value || null;

  if (!token) {
    return { user: null, error: error("Unauthorized", 401, "unauthorized") };
  }

  try {
    const payload = await verifyAccessToken(token);
    return { user: payload, error: null };
  } catch {
    return { user: null, error: error("Invalid token", 401, "invalid_token") };
  }
}

export function normalizeEmail(email: string): string {
  return email.toLowerCase().trim();
}
