# Auth Service

Centralized authentication service that acts as a standalone token issuer for first-party applications. Deployed on Vercel (serverless functions) with Neon (serverless Postgres).

All consumers are first-party (same trust boundary), so they call the auth service directly — no OAuth redirect flow needed.

## Architecture

```
Consumer App                        Auth Service
────────────                        ────────────
User clicks "Login"
  → POST /api/v1/login              ← Validates credentials, creates session
  ← { access_token }                  Sets httpOnly cookies
  (verify JWT locally via JWKS)

Token expires (15 min)
  → POST /api/v1/refresh            ← Rotates refresh token, issues new AT
  ← { access_token }                  Detects replay if old token reused
```

**Why a standalone token issuer (not a shared library or subdomain cookies):**
- Shared library: causes schema drift, N user tables, painful credential rotation
- Subdomain cookies: ties you to one root domain forever
- Token issuer: each site verifies JWTs locally via the public key, auth service is the single source of truth

### Runtime Split

| Layer | Runtime | Why |
|-------|---------|-----|
| API routes | Node.js serverless | Argon2 requires native bindings |
| Middleware | Edge | Sub-ms CORS, security headers, origin enforcement |

## Tech Stack

| Concern | Choice | Rationale |
|---------|--------|-----------|
| Framework | Next.js 15 App Router | API routes as serverless functions |
| Database | Neon Serverless Postgres | Connection pooling, branching for dev |
| ORM | Drizzle | Type-safe, parameterized queries (prevents SQLi) |
| Password hashing | Argon2id | Memory-hard, PHC winner, no 72-byte truncation |
| JWT signing | ES256 via `jose` | 64-byte signatures (vs 256+ for RS256), asymmetric |
| Rate limiting | Upstash Redis | Global state without DB load |
| Email | Resend | Transactional email delivery |

## API Endpoints

Base URL: `/api/v1`

| Endpoint | Method | Auth | Purpose |
|----------|--------|------|---------|
| `/register` | POST | No | Create account, send verification email |
| `/login` | POST | No | Authenticate, returns tokens + sets cookies |
| `/logout` | POST | Yes | Revoke session(s), clears cookies |
| `/refresh` | POST | No | Rotate refresh token, get new access token |
| `/me` | GET | Yes | Get current user profile |
| `/me` | PATCH | Yes | Update username or display name |
| `/me` | DELETE | Yes | Soft-delete account (requires password confirmation) |
| `/sessions` | GET | Yes | List active sessions |
| `/sessions/:id` | DELETE | Yes | Revoke a specific session |
| `/verify-email` | POST | No | Consume email verification token |
| `/forgot-password` | POST | No | Request password reset email |
| `/reset-password` | POST | No | Consume reset token, change password |
| `/.well-known/jwks` | GET | No | Public key for JWT verification (cacheable) |

## Security Design

### Token Strategy

| | Access Token (JWT) | Refresh Token (Opaque) |
|---|---|---|
| Lifetime | 15 minutes | 30 days |
| Storage | httpOnly/Secure/SameSite=Strict cookie | httpOnly cookie scoped to `/api/v1/refresh` |
| Verification | Stateless (ES256 signature check) | Stateful (DB lookup via SHA-256 hash) |
| Revocation | Not individually revocable (short-lived) | Immediately revocable |

### Refresh Token Rotation

Every refresh exchanges the old token for a new one within the same token family. If the old token is ever reused after rotation, the **entire family is revoked** — this detects stolen tokens.

The rotation uses an atomic `UPDATE ... WHERE revokedAt IS NULL RETURNING` to prevent race conditions where two concurrent requests could both succeed.

### Password Handling

- **Algorithm:** Argon2id (64 MB memory, 3 iterations, 1 thread)
- **Policy:** 12-128 characters, no complexity rules (per NIST SP 800-63B)
- **Timing safety:** Always performs a hash operation even when the account doesn't exist, preventing timing-based account enumeration

### Account Lockout

Failed login attempts persist across lockout cycles:
- Every 5 consecutive failures: 15-minute temporary lock
- 20 total failures: permanent lock requiring admin review
- Only a successful login resets the counter

### Anti-Enumeration

All public endpoints return identical responses regardless of whether an account exists:
- Register: "Please check your email to verify your account."
- Login: "Invalid email or password"
- Forgot password: "If an account with that email exists, we've sent a password reset link."

### Origin Enforcement

Edge middleware rejects all state-changing requests (POST/PATCH/PUT/DELETE) that arrive without a valid `Origin` header matching the configured allowlist. This is enforced server-side, not just via CORS response headers.

### Rate Limiting

- **Auth endpoints** (login, register, refresh): 10 requests per 60s per IP
- **Email sends** (forgot-password, verification): 3 per hour per email address

### Input Validation

- **Username:** 3-25 characters, alphanumeric + underscores, case-insensitive uniqueness (stored normalized)
- **Display name:** max 25 characters
- **Password:** 12-128 characters
- **Email:** normalized (lowercased, trimmed) for uniqueness checks, original preserved for display

## Database Schema

Four tables: `users`, `sessions`, `email_verifications`, `password_resets`.

Key design decisions:
- **Soft deletes** on users (allows re-registration without data loss)
- **Token hashes only** — raw tokens never touch the database
- **`token_family` column** on sessions enables replay detection across rotations
- **`password_changed_at`** — allows consumers to reject JWTs issued before a password change
- **Partial unique indexes** — email uniqueness only enforced among non-deleted accounts

## Project Structure

```
src/
├── app/
│   ├── api/v1/          # Route handlers (one per endpoint)
│   └── .well-known/     # JWKS endpoint
├── lib/
│   ├── auth/
│   │   ├── password.ts  # Argon2id hashing + validation
│   │   ├── tokens.ts    # JWT sign/verify, JWKS, secure token generation
│   │   └── sessions.ts  # Create, rotate, revoke sessions
│   ├── db/
│   │   ├── client.ts    # Neon + Drizzle client
│   │   └── schema.ts    # Table definitions + indexes
│   ├── security/
│   │   ├── rate-limit.ts # Upstash rate limiters
│   │   ├── cors.ts       # Origin allowlist
│   │   └── headers.ts    # Security response headers
│   ├── email/
│   │   └── send.ts      # Resend transactional emails
│   └── api/
│       └── helpers.ts   # Response builders, auth middleware, IP extraction
└── middleware.ts        # Edge: CORS preflight, origin enforcement, security headers
```

## Setup

```bash
npm install
cp .env.example .env    # Fill in credentials
```

Generate an ES256 key pair:
```bash
openssl ecparam -name prime256v1 -genkey -noout -out private.pem
openssl ec -in private.pem -pubout -out public.pem
```

Set `JWT_PRIVATE_KEY` and `JWT_PUBLIC_KEY` in `.env` with the PEM contents (newlines as `\n`).

Run migrations and start:
```bash
npm run db:generate
npm run db:migrate
npm run dev
```

## Consumer Integration

```typescript
// 1. Fetch JWKS once (cache it)
const jwks = await fetch("https://auth.yourdomain.com/.well-known/jwks").then(r => r.json());

// 2. Login: proxy to auth service
const { access_token } = await fetch("https://auth.yourdomain.com/api/v1/login", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ email, password }),
}).then(r => r.json());

// 3. Verify JWTs locally using the public key from JWKS
// 4. On expiry: call /refresh with the stored refresh token
```

To add a new consumer app:
1. Add its origin to the `ALLOWED_ORIGINS` environment variable
2. Implement the token storage and refresh pattern above

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `DATABASE_URL` | Neon Postgres connection string |
| `JWT_PRIVATE_KEY` | ES256 private key (PEM) |
| `JWT_PUBLIC_KEY` | ES256 public key (PEM) |
| `UPSTASH_REDIS_REST_URL` | Upstash Redis endpoint |
| `UPSTASH_REDIS_REST_TOKEN` | Upstash Redis auth token |
| `RESEND_API_KEY` | Resend transactional email key |
| `ALLOWED_ORIGINS` | Comma-separated consumer origins |
| `AUTH_URL` | This service's public URL |
