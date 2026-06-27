import argon2 from "argon2";

const ARGON2_CONFIG = {
  type: argon2.argon2id,
  memoryCost: 65536,
  timeCost: 3,
  parallelism: 1,
  hashLength: 32,
  saltLength: 16,
};

export async function hashPassword(password: string): Promise<string> {
  return argon2.hash(password, ARGON2_CONFIG);
}

export async function verifyPassword(
  hash: string,
  password: string
): Promise<boolean> {
  return argon2.verify(hash, password);
}

// Dummy hash to prevent timing attacks when account doesn't exist
export async function dummyHash(password: string): Promise<void> {
  await argon2.hash(password, ARGON2_CONFIG);
}

const PASSWORD_MIN = 12;
const PASSWORD_MAX = 128;

export function validatePassword(password: string): string | null {
  if (password.length < PASSWORD_MIN) {
    return `Password must be at least ${PASSWORD_MIN} characters`;
  }
  if (password.length > PASSWORD_MAX) {
    return `Password must be at most ${PASSWORD_MAX} characters`;
  }
  return null;
}
