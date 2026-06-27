import { SignJWT, jwtVerify, importPKCS8, importSPKI, exportJWK } from "jose";
import { randomBytes, createHash } from "crypto";

const ALG = "ES256";
const KID = "key-2024-01";
const ISSUER = process.env.AUTH_URL || "https://auth.yourdomain.com";
const ACCESS_TOKEN_TTL = 900; // 15 minutes

let privateKey: CryptoKey;
let publicKey: CryptoKey;

async function getPrivateKey() {
  if (!privateKey) {
    privateKey = await importPKCS8(process.env.JWT_PRIVATE_KEY!, ALG);
  }
  return privateKey;
}

async function getPublicKey() {
  if (!publicKey) {
    publicKey = await importSPKI(process.env.JWT_PUBLIC_KEY!, ALG);
  }
  return publicKey;
}

export interface TokenPayload {
  sub: string;
  email: string;
  email_verified: boolean;
  username?: string;
  display_name?: string;
}

export async function signAccessToken(payload: TokenPayload): Promise<string> {
  const key = await getPrivateKey();
  return new SignJWT({ ...payload })
    .setProtectedHeader({ alg: ALG, typ: "JWT", kid: KID })
    .setIssuer(ISSUER)
    .setIssuedAt()
    .setExpirationTime(`${ACCESS_TOKEN_TTL}s`)
    .setJti(randomBytes(16).toString("base64url"))
    .sign(key);
}

export async function verifyAccessToken(token: string) {
  const key = await getPublicKey();
  const { payload } = await jwtVerify(token, key, { issuer: ISSUER });
  return payload as TokenPayload & { iat: number; exp: number; jti: string };
}

export async function getJWKS() {
  const key = await getPublicKey();
  const jwk = await exportJWK(key);
  return {
    keys: [{ ...jwk, kid: KID, use: "sig", alg: ALG }],
  };
}

export function generateSecureToken(): string {
  return randomBytes(32).toString("base64url");
}

export function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("base64url");
}
