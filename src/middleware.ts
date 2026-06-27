import { NextRequest, NextResponse } from "next/server";
import { SECURITY_HEADERS } from "@/lib/security/headers";
import { getCorsHeaders, isAllowedOrigin } from "@/lib/security/cors";

const STATE_CHANGING_METHODS = new Set(["POST", "PATCH", "PUT", "DELETE"]);

export function middleware(request: NextRequest) {
  const origin = request.headers.get("origin");

  // Handle CORS preflight
  if (request.method === "OPTIONS") {
    const corsHeaders = getCorsHeaders(origin);
    if (!corsHeaders) {
      return new NextResponse(null, { status: 403 });
    }
    return new NextResponse(null, {
      status: 204,
      headers: { ...SECURITY_HEADERS, ...corsHeaders },
    });
  }

  // Reject state-changing requests with missing or invalid Origin
  if (STATE_CHANGING_METHODS.has(request.method)) {
    if (!origin || !isAllowedOrigin(origin)) {
      return NextResponse.json(
        { error: "forbidden", message: "Invalid origin" },
        { status: 403, headers: SECURITY_HEADERS }
      );
    }
  }

  const response = NextResponse.next();

  // Security headers on all responses
  for (const [key, value] of Object.entries(SECURITY_HEADERS)) {
    response.headers.set(key, value);
  }

  // CORS headers if origin is allowed
  const corsHeaders = getCorsHeaders(origin);
  if (corsHeaders) {
    for (const [key, value] of Object.entries(corsHeaders)) {
      response.headers.set(key, value);
    }
  }

  return response;
}

export const config = {
  matcher: "/api/:path*",
};
