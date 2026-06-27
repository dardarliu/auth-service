# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Centralized authentication service (token issuer) for first-party apps: a URL shortener and a messaging platform. Deployed on Vercel (serverless) + Neon (serverless Postgres). The full design is in `auth-service-plan.md`.

## Tech Stack

- **Framework:** Next.js App Router (API routes as Node.js serverless functions, not Edge — argon2 needs native bindings)
- **Database:** Neon Serverless Postgres
- **ORM:** Drizzle
- **Password hashing:** argon2 (argon2id, 64MB memory, 3 iterations)
- **JWT:** ES256 via `jose` library — 15-min access tokens, 30-day refresh tokens with rotation
- **Rate limiting:** Upstash Redis (Edge middleware)
- **Email:** Resend
- **Token generation:** `crypto.randomBytes(32)` — store SHA-256 hashes, never raw tokens

## Build & Dev Commands

```bash
npm install
npm run dev          # local dev server
npm run build        # production build
npm run lint         # lint
npx drizzle-kit generate   # generate migrations
npx drizzle-kit migrate    # run migrations
```

## Architecture

### API Routes (`src/app/api/v1/`)

All endpoints under `/api/v1`. Auth service issues identity tokens only — consuming apps own their own authorization logic.

### Key Modules (`src/lib/`)

| Module | Responsibility |
|--------|---------------|
| `db/` | Drizzle client, schema definitions, migrations |
| `auth/password.ts` | Argon2id hashing, common-password-list check, 12-128 char policy |
| `auth/tokens.ts` | ES256 JWT sign/verify, JWKS endpoint, secure token generation |
| `auth/sessions.ts` | Refresh token rotation, token-family replay detection |
| `security/rate-limit.ts` | Upstash Redis per-IP + per-account limiting |
| `security/headers.ts` | HSTS, CSP, X-Frame-Options |
| `security/cors.ts` | Allowlisted origins only (from `ALLOWED_ORIGINS` env var) |
| `email/` | Resend integration, verification/reset templates |

### Security Invariants

- Timing-safe: always hash even when account not found (dummy argon2 hash)
- Account enumeration: identical responses regardless of account existence
- Token replay: refresh token reuse triggers family-wide revocation
- All cookies: httpOnly, Secure, SameSite=Strict
- DB tokens: only SHA-256 hashes stored, never plaintext
- Account lockout: 5 failures = 15min lock, 20 failures = admin review

### Environment Variables

- `JWT_PRIVATE_KEY` / `JWT_PUBLIC_KEY` — ES256 key pair
- `DATABASE_URL` — Neon connection string
- `UPSTASH_REDIS_REST_URL` / `UPSTASH_REDIS_REST_TOKEN`
- `RESEND_API_KEY`
- `ALLOWED_ORIGINS` — comma-separated consumer origins for CORS

## Status

Pre-implementation. Only `auth-service-plan.md` exists. Phase 1 (foundation) is next: project scaffold, DB migrations, core auth endpoints.
