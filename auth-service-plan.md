# Auth Service — Implementation Plan

Centralized authentication service deployed on Vercel (serverless) + Neon (serverless Postgres). Acts as a standalone token issuer that first-party sites integrate with via direct API calls. Serves a URL shortener (link management) and a messaging platform.

---

## 1. Architecture

**Decision: Standalone Auth API as a Central Token Issuer**

A dedicated auth service at `auth.yourdomain.com` that issues signed tokens to consuming applications.

**Why not alternatives:**
- Shared package embedded in each app — causes schema drift, N user tables, painful credential rotation
- Subdomain shared cookies — ties you to one root domain forever
- Token issuer (chosen) — each site calls the auth service, verifies tokens locally via public key

### High-Level Flow

```
Consumer Site (app.example.com)         Auth Service (auth.yourdomain.com)
─────────────────────────────────       ──────────────────────────────────
User clicks "Login"
  → POST /login { email, password }     ← Validates credentials, creates session
  ← { access_token, refresh_token }
Store refresh_token server-side
Set access_token in httpOnly cookie (site-scoped)
```

All consuming apps are first-party (same trust boundary), so they call the auth service directly — no redirect/authorization-code flow needed yet.

### Project Structure

```
auth-service/
├── src/
│   ├── app/
│   │   ├── api/v1/
│   │   │   ├── register/route.ts
│   │   │   ├── login/route.ts
│   │   │   ├── logout/route.ts
│   │   │   ├── refresh/route.ts
│   │   │   ├── verify-email/route.ts
│   │   │   ├── forgot-password/route.ts
│   │   │   ├── reset-password/route.ts
│   │   │   ├── me/route.ts
│   │   │   ├── sessions/route.ts
│   │   │   └── sessions/[id]/route.ts
│   │   └── .well-known/jwks/route.ts
│   ├── lib/
│   │   ├── db/
│   │   │   ├── client.ts
│   │   │   ├── schema.ts
│   │   │   └── migrations/
│   │   ├── auth/
│   │   │   ├── password.ts
│   │   │   ├── tokens.ts
│   │   │   └── sessions.ts
│   │   ├── security/
│   │   │   ├── rate-limit.ts
│   │   │   ├── headers.ts
│   │   │   └── cors.ts
│   │   └── email/
│   │       ├── send.ts
│   │       └── templates/
│   ├── middleware.ts
│   └── types/
├── drizzle.config.ts
├── package.json
└── vercel.json
```

### Runtime Decisions

- API routes run as Node.js serverless functions (argon2 needs native bindings, cannot run on Edge)
- Edge middleware handles rate limiting, CORS, and security headers

---

## 2. Database Schema

```sql
-- Users
CREATE TABLE users (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email                 TEXT NOT NULL,
    email_normalized      TEXT NOT NULL,
    email_verified        BOOLEAN NOT NULL DEFAULT FALSE,
    display_name          TEXT,
    username              TEXT UNIQUE,
    password_hash         TEXT NOT NULL,
    password_changed_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status                TEXT NOT NULL DEFAULT 'active'
                          CHECK (status IN ('active', 'locked', 'suspended', 'deleted')),
    locked_until          TIMESTAMPTZ,
    failed_login_attempts INTEGER NOT NULL DEFAULT 0,
    last_failed_login_at  TIMESTAMPTZ,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at            TIMESTAMPTZ
);

CREATE UNIQUE INDEX idx_users_email_active
    ON users (email_normalized) WHERE (deleted_at IS NULL);
CREATE UNIQUE INDEX idx_users_username_active
    ON users (username) WHERE (deleted_at IS NULL AND username IS NOT NULL);

-- Sessions (opaque refresh tokens)
CREATE TABLE sessions (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash    TEXT NOT NULL UNIQUE,
    token_family  UUID NOT NULL,
    ip_address    INET,
    user_agent    TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at    TIMESTAMPTZ NOT NULL,
    last_used_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at    TIMESTAMPTZ,
    revoke_reason TEXT
);

CREATE INDEX idx_sessions_user_id ON sessions (user_id) WHERE (revoked_at IS NULL);
CREATE INDEX idx_sessions_token_family ON sessions (token_family);
CREATE INDEX idx_sessions_expires_at ON sessions (expires_at) WHERE (revoked_at IS NULL);

-- Email verification tokens
CREATE TABLE email_verifications (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    used_at    TIMESTAMPTZ
);

CREATE INDEX idx_email_verifications_user
    ON email_verifications (user_id) WHERE (used_at IS NULL);

-- Password reset tokens
CREATE TABLE password_resets (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    used_at    TIMESTAMPTZ,
    ip_address INET
);

CREATE INDEX idx_password_resets_user
    ON password_resets (user_id) WHERE (used_at IS NULL);
```

### Schema Security Rationale

| Decision | Rationale |
|----------|-----------|
| Store `token_hash` not raw tokens | DB breach doesn't yield usable tokens |
| `email_normalized` separate column | Prevents case-sensitivity bypass; original preserved for display |
| `token_family` on sessions | Detects refresh token replay — reuse triggers family-wide revocation |
| `password_changed_at` | Invalidate JWTs issued before password change |
| Partial unique index on email | Allows re-registration after deletion without data loss |
| `failed_login_attempts` on user row | Application-level lockout after N failures |
| `username` unique where not null | Optional — users can set one later for the messaging platform |

---

## 3. Password Handling

### Algorithm: Argon2id

**Why not bcrypt:** bcrypt silently truncates at 72 bytes, is only CPU-hard (not memory-hard), and has limited scaling options. Argon2id is the PHC winner, GPU/ASIC-resistant.

**Parameters (target ~250ms per hash on Vercel function):**

```typescript
const ARGON2_CONFIG = {
  type: argon2.argon2id,
  memoryCost: 65536,    // 64 MB
  timeCost: 3,          // 3 iterations
  parallelism: 1,       // 1 thread (serverless)
  hashLength: 32,       // 256-bit output
  saltLength: 16,       // 128-bit random salt (auto-generated)
};
```

### Password Policy

```typescript
const PASSWORD_POLICY = {
  minLength: 12,
  maxLength: 128,             // Prevent DoS via long passwords
  requireComplexity: false,   // NIST says no forced composition rules
  blockCommonPasswords: true, // Top 100k list
};
```

No complexity rules — NIST SP 800-63B recommends against them. Length + common-password-list is sufficient for these applications.

### Rules

- Never log passwords
- Never reveal which policy check failed beyond what's necessary
- Re-hash on login if stored hash uses outdated parameters

---

## 4. Session Management

### Dual-Token Strategy

| | Access Token (JWT) | Refresh Token (Opaque) |
|---|---|---|
| Lifetime | 15 min | 30 days |
| Storage | httpOnly cookie or Authorization header | httpOnly cookie (auth service origin only) |
| Verification | Stateless (signature check) | Stateful (DB lookup) |
| Revocation | Not individually revocable (short-lived) | Immediately revocable |
| Cross-site | Forwarded to any API | Only sent to auth service |

### JWT Structure

```typescript
// Header
{ alg: "ES256", typ: "JWT", kid: "key-2024-01" }

// Payload
{
  sub: string;          // User ID (UUID)
  iss: string;          // "https://auth.yourdomain.com"
  iat: number;
  exp: number;          // iat + 900s
  jti: string;
  email: string;
  email_verified: boolean;
  username?: string;
  display_name?: string;
}
```

**ES256 over RS256:** Smaller signatures (64 bytes vs 256+), faster signing, same security level.

### Signing Key

Store the ES256 key pair in environment variables (`JWT_PRIVATE_KEY`, `JWT_PUBLIC_KEY`). Expose the public key at `/.well-known/jwks.json` so consumers can verify tokens locally. Add key rotation infrastructure when you actually need to rotate.

### Refresh Token Rotation

Every refresh exchanges the old token for a new one (same family). If the old token is reused after rotation, the entire token family is revoked — this detects stolen tokens.

```
POST /refresh { token: RT1 }
→ Verify hash(RT1): not revoked, not expired, family matches
→ Generate RT2, insert session, mark RT1 revoked (reason: rotated)
→ Return new AT + RT2

If RT1 used again after rotation:
→ Entire token_family revoked (all sessions)
→ User must re-authenticate
```

### Token Storage

| Token | Storage | Why |
|-------|---------|-----|
| Access Token | httpOnly, Secure, SameSite=Strict cookie | Not accessible to JS |
| Refresh Token | httpOnly, Secure, SameSite=Strict on auth origin | Never exposed to consumer JS |

### WebSocket Authentication (Messaging Platform)

WebSocket connections authenticate at connection time:

```
1. Client establishes WS connection with access token:
   - Option A: token in the first message after connect
   - Option B: token in Sec-WebSocket-Protocol header or URL query param

2. Server verifies JWT signature + expiry
   - Valid → connection accepted, user associated with socket
   - Invalid → connection closed with 4001

3. Token refresh mid-session:
   - Client detects upcoming expiry (check iat + 900 client-side)
   - Client refreshes via HTTP (POST /refresh)
   - Client sends new access token over the existing socket
   - Server updates the association

4. Forced disconnect:
   - Account suspended/deleted → messaging app closes socket directly
   - This is app logic, not auth — no need for "instant JWT revocation"
```

---

## 5. Security Hardening

### 5.1 Brute Force / Credential Stuffing

**Layer 1 — Edge (Upstash Redis):** Rate limit auth endpoints per IP (10 requests per 60s on login, 100 per hour globally).

**Layer 2 — Account lockout:**
- 5 failures → lock 15 min
- 20 failures → lock until admin review
- Resets on successful login

Never return different errors for "locked" vs "wrong password."

### 5.2 Timing Attacks

Always hash even when account not found:

```typescript
export async function login(email: string, password: string) {
  const user = await findUserByEmail(normalize(email));

  if (!user) {
    await argon2.hash(password, ARGON2_CONFIG); // dummy hash
    return { error: 'Invalid email or password' };
  }

  const valid = await argon2.verify(user.password_hash, password);
  if (!valid) {
    await incrementFailedAttempts(user.id);
    return { error: 'Invalid email or password' };
  }
  // ...
}
```

### 5.3 Session Fixation / Hijacking

- Never accept client-supplied session IDs
- Bind sessions loosely to User-Agent (flag changes, don't invalidate)
- Short JWT lifetime limits hijacking window
- Refresh rotation detects stolen tokens

### 5.4 CSRF

- `SameSite=Strict` on all cookies
- Verify `Origin` header on state-changing requests
- Tokens in `Authorization` headers are inherently CSRF-safe

### 5.5 XSS Token Theft

- httpOnly cookies prevent JS access
- Never store tokens in localStorage/sessionStorage
- CSP headers restrict script sources

### 5.6 SQL Injection

- Drizzle ORM = parameterized queries only
- DB user has only SELECT/INSERT/UPDATE (no DDL)
- Migrations use a separate privileged connection

### 5.7 Account Enumeration

Identical responses regardless of whether account exists:

| Endpoint | Response |
|----------|----------|
| Register | "Verification email sent" (always) |
| Login | "Invalid email or password" (always) |
| Forgot Password | "If an account exists, we sent a reset link" (always) |

### 5.8 Password Reset Flow

1. Generate 256-bit token, store SHA-256(token) with 1-hour expiry
2. Send link via email
3. Invalidate previous unused resets for this user
4. On submission: validate new password, hash with argon2id, update user
5. Revoke ALL sessions (force re-auth everywhere)
6. Send "password was changed" notification email
7. Rate limit: max 3 resets per email per hour

### 5.9 Email Verification

- Same token pattern (256-bit, store hash, 24-hour expiry)
- Unverified accounts have limited capabilities (`email_verified` in JWT)
- Re-send limited to 3 per hour
- Required for messaging (anti-spam), optional for URL shortener

### 5.10 Token Entropy

| Token Type | Entropy | Expiration |
|------------|---------|------------|
| Access Token (JWT) | Cryptographically signed | 15 minutes |
| Refresh Token | 256 bits | 30 days |
| Email Verification | 256 bits | 24 hours |
| Password Reset | 256 bits | 1 hour |

```typescript
import { randomBytes } from 'crypto';

export function generateSecureToken(prefix: string = ''): string {
  return prefix + randomBytes(32).toString('base64url');
}
```

### 5.11 Security Headers

```typescript
const SECURITY_HEADERS = {
  'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'X-XSS-Protection': '0',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  'Content-Security-Policy': "default-src 'self'; script-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'",
};
```

### 5.12 CORS

Allowlist of known consumer origins (no `*` with credentials):

```typescript
{
  'Access-Control-Allow-Origin': allowedOrigin,
  'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Access-Control-Allow-Credentials': 'true',
  'Access-Control-Max-Age': '86400',
}
```

Allowed origins configured via environment variable.

---

## 6. API Design

**Base URL:** `https://auth.yourdomain.com/api/v1`

### POST /register

```typescript
// Request
{ email: string, password: string, username?: string, display_name?: string }

// Response: 201 (always)
{ message: "Please check your email to verify your account." }

// Error: 429 | 400
{ error: "validation_error", details: [{ field, message }] }
```

Username validation: 3-30 characters, alphanumeric + underscores, case-insensitive uniqueness.

### POST /login

```typescript
// Request
{ email: string, password: string }

// Response 200
{ access_token, refresh_token, token_type: "Bearer", expires_in: 900 }

// Error: 401
{ error: "invalid_credentials", message: "Invalid email or password" }
```

### POST /logout

```typescript
// Authorization: Bearer {access_token}
{ refresh_token?: string, all_sessions?: boolean }
// Response: 204
```

### POST /refresh

```typescript
{ refresh_token: string }
// Response 200
{ access_token, refresh_token, token_type: "Bearer", expires_in: 900 }
// Error 401 (expired/revoked/replay)
{ error: "invalid_token", message: "Session expired. Please log in again." }
```

### GET /me

```typescript
// Authorization: Bearer {access_token}
// Response 200
{ id, email, email_verified, username, display_name, created_at }
```

### PATCH /me

```typescript
// Authorization: Bearer {access_token}
{ display_name?: string, username?: string }
// Response 200
{ id, email, email_verified, username, display_name, created_at }
// Error 409
{ error: "username_taken", message: "That username is already in use." }
```

### DELETE /me

```typescript
// Authorization: Bearer {access_token}
{ password: string }  // Confirm identity before deletion
// Response 204
```

Soft-deletes the user, revokes all sessions. Consuming apps should handle cleanup (delete links, anonymize messages) via a webhook or polling.

### GET /sessions

```typescript
// Authorization: Bearer {access_token}
// Response 200
{ sessions: [{ id, ip_address, user_agent, created_at, last_used_at, current: boolean }] }
```

`current: true` marks the session that issued this access token.

### DELETE /sessions/:id

```typescript
// Authorization: Bearer {access_token}
// Response 204
```

Revokes a specific session. If the user revokes their *current* session, they'll need to log in again on their next refresh.

### POST /verify-email

```typescript
{ token: string }
// Response 200
{ message: "Email verified successfully." }
```

### POST /forgot-password

```typescript
{ email: string }
// Response 200 (always)
{ message: "If an account with that email exists, we've sent a password reset link." }
```

### POST /reset-password

```typescript
{ token: string, new_password: string }
// Response 200
{ message: "Password reset successfully. Please log in with your new password." }
```

### GET /.well-known/jwks.json

```typescript
// Response 200 (public, cacheable)
{ keys: [{ kty: "EC", crv: "P-256", kid, use: "sig", alg: "ES256", x, y }] }
```

---

## 7. Cross-Site Integration

All consuming apps are first-party and trusted. Integration is straightforward:

### Consumer-Side Pattern

```typescript
// In your consuming app's server code:

// Login: proxy to auth service
const res = await fetch('https://auth.yourdomain.com/api/v1/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ email, password }),
});
const { access_token, refresh_token } = await res.json();

// Store refresh_token server-side (encrypted in session store or DB)
// Set access_token as httpOnly cookie scoped to your app

// Verify: check JWT signature against JWKS
// On expiry: call /refresh with stored refresh_token
```

### Adding a New Consumer App

1. Add its origin to the `ALLOWED_ORIGINS` env var
2. Implement the login proxy and token storage pattern above
3. Fetch the JWKS once (cache it) for local JWT verification

### User Deletion Cleanup

When a user deletes their account, consuming apps need to clean up:
- **URL shortener:** Delete or anonymize their links (or transfer to a "deleted user" placeholder)
- **Messaging platform:** Anonymize messages, remove from conversations

Options: webhook notification from auth service on deletion, or apps poll `/me` and handle 401/404.

### Future: Third-Party / OAuth Flow

When a non-first-party app needs to integrate, add:
- `clients` table with `client_id`, `client_secret_hash`, `redirect_uris`
- `authorization_codes` table
- `/authorize` redirect endpoint + `/token` code-exchange endpoint
- PKCE support
- SDK package

This is additive — the direct API flow continues working for first-party apps.

---

## 8. Extensibility Hooks (Future)

### OAuth Providers (Google, GitHub)

```sql
CREATE TABLE oauth_connections (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id                  UUID NOT NULL REFERENCES users(id),
    provider                 TEXT NOT NULL,
    provider_id              TEXT NOT NULL,
    access_token_encrypted   TEXT,
    refresh_token_encrypted  TEXT,
    metadata                 JSONB DEFAULT '{}',
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(provider, provider_id)
);
```

### MFA/TOTP

After password succeeds, return partial session requiring MFA challenge:
```
POST /login → { mfa_required: true, mfa_token: "partial_..." }
POST /mfa/verify { mfa_token, code } → { access_token, refresh_token }
```

### Magic Links

Reuses token infrastructure — generate token, send email, validate on click, create session.

### Key Rotation

Move signing keys from env vars to a `signing_keys` table with `active_from`/`retired_at`. Add a rotation cron and grace period for old keys.

### Audit Log

```sql
CREATE TABLE audit_log (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID REFERENCES users(id),
    action     TEXT NOT NULL,
    ip_address INET,
    user_agent TEXT,
    metadata   JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_log_user_id ON audit_log (user_id, created_at DESC);
CREATE INDEX idx_audit_log_action ON audit_log (action, created_at DESC);
```

Add when you need compliance or anomaly detection.

---

## 9. Implementation Phases

### Phase 1: Foundation (Week 1-2)
- [ ] Next.js App Router + Drizzle + Neon setup
- [ ] Database migrations (users, sessions, email_verifications, password_resets)
- [ ] `lib/auth/password.ts` — Argon2id + common-password-list validation
- [ ] `lib/auth/tokens.ts` — ES256 JWT signing/verification via env var key pair + JWKS endpoint
- [ ] `lib/security/rate-limit.ts` — Upstash Redis (per-IP + per-account)
- [ ] Endpoints: register, login, logout, refresh, me (GET + PATCH), sessions (GET + DELETE), jwks
- [ ] Edge middleware: security headers, CORS, rate limiting

### Phase 2: Account Recovery + Management (Week 2-3)
- [ ] Email provider integration (Resend)
- [ ] Endpoints: verify-email, forgot-password, reset-password, DELETE /me
- [ ] Email templates
- [ ] Account lockout (2-tier)

### Phase 3: Hardening (Week 3-4)
- [ ] Audit logging on all auth events
- [ ] Monitoring + alerting on failed auth spikes
- [ ] Load testing
- [ ] Pen testing checklist

### Phase 4: Multi-Site (When Needed)
- [ ] Client registration system
- [ ] Authorization Code + PKCE flow
- [ ] Hosted login page
- [ ] SDK package
- [ ] Per-client CORS
- [ ] Signing key rotation

### Phase 5: Extensibility (Future)
- [ ] OAuth providers (Google, GitHub)
- [ ] MFA/TOTP
- [ ] Magic links
- [ ] Admin dashboard

---

## 10. Common Mistakes to Avoid

| Mistake | Do Instead |
|---------|-----------|
| Storing raw tokens in DB | Store SHA-256 hashes |
| `Math.random()` for tokens | `crypto.randomBytes(32)` |
| Different error for "locked" vs "wrong password" | Generic "Invalid credentials" |
| Long-lived JWTs (hours/days) | 15-min JWTs + refresh tokens |
| Refresh token without rotation | Rotate every use, detect replay |
| `Access-Control-Allow-Origin: *` with credentials | Whitelist specific origins |
| Tokens in localStorage | httpOnly cookies |
| bcrypt with long passwords | Argon2id (no length limit) |
| Not invalidating sessions on password change | Revoke all sessions |
| Checking email uniqueness before insert | DB unique constraint, handle violation |
| Auth service enforcing app-level permissions | Auth = identity only; apps own their own authorization |

---

## 11. Technology Stack

| Concern | Choice | Rationale |
|---------|--------|-----------|
| Runtime | Node.js (Vercel Serverless) | Argon2 needs native bindings |
| Middleware | Vercel Edge | Sub-ms cold starts for rate limiting/headers |
| Database | Neon Serverless Postgres | Connection pooling, branching for dev |
| ORM | Drizzle | Type-safe, parameterized, lightweight |
| Password hashing | argon2 (`argon2` npm) | Memory-hard, PHC winner |
| JWT signing | ES256 via `jose` | Small tokens, fast, asymmetric |
| Rate limiting | Upstash Redis | Global state without DB load |
| Email | Resend | Reliable transactional email |
| Token generation | `crypto.randomBytes` | OS-level CSPRNG |
