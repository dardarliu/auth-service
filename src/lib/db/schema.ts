import {
  pgTable,
  uuid,
  text,
  boolean,
  integer,
  timestamp,
  uniqueIndex,
  index,
} from "drizzle-orm/pg-core";
import { sql } from "drizzle-orm";

export const users = pgTable(
  "users",
  {
    id: uuid("id").primaryKey().default(sql`gen_random_uuid()`),
    email: text("email").notNull(),
    emailNormalized: text("email_normalized").notNull(),
    emailVerified: boolean("email_verified").notNull().default(false),
    displayName: text("display_name"),
    username: text("username"),
    usernameNormalized: text("username_normalized"),
    passwordHash: text("password_hash").notNull(),
    passwordChangedAt: timestamp("password_changed_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
    status: text("status").notNull().default("active"),
    lockedUntil: timestamp("locked_until", { withTimezone: true }),
    failedLoginAttempts: integer("failed_login_attempts").notNull().default(0),
    lastFailedLoginAt: timestamp("last_failed_login_at", {
      withTimezone: true,
    }),
    createdAt: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
    deletedAt: timestamp("deleted_at", { withTimezone: true }),
  },
  (table) => [
    uniqueIndex("idx_users_email_active")
      .on(table.emailNormalized)
      .where(sql`deleted_at IS NULL`),
    uniqueIndex("idx_users_username_active")
      .on(table.usernameNormalized)
      .where(sql`deleted_at IS NULL AND username_normalized IS NOT NULL`),
  ]
);

export const sessions = pgTable(
  "sessions",
  {
    id: uuid("id").primaryKey().default(sql`gen_random_uuid()`),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    tokenHash: text("token_hash").notNull().unique(),
    tokenFamily: uuid("token_family").notNull(),
    ipAddress: text("ip_address"),
    userAgent: text("user_agent"),
    createdAt: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    lastUsedAt: timestamp("last_used_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
    revokeReason: text("revoke_reason"),
  },
  (table) => [
    index("idx_sessions_user_id")
      .on(table.userId)
      .where(sql`revoked_at IS NULL`),
    index("idx_sessions_token_family").on(table.tokenFamily),
    index("idx_sessions_expires_at")
      .on(table.expiresAt)
      .where(sql`revoked_at IS NULL`),
  ]
);

export const emailVerifications = pgTable(
  "email_verifications",
  {
    id: uuid("id").primaryKey().default(sql`gen_random_uuid()`),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    tokenHash: text("token_hash").notNull().unique(),
    createdAt: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    usedAt: timestamp("used_at", { withTimezone: true }),
  },
  (table) => [
    index("idx_email_verifications_user")
      .on(table.userId)
      .where(sql`used_at IS NULL`),
  ]
);

export const passwordResets = pgTable(
  "password_resets",
  {
    id: uuid("id").primaryKey().default(sql`gen_random_uuid()`),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    tokenHash: text("token_hash").notNull().unique(),
    createdAt: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    usedAt: timestamp("used_at", { withTimezone: true }),
    ipAddress: text("ip_address"),
  },
  (table) => [
    index("idx_password_resets_user")
      .on(table.userId)
      .where(sql`used_at IS NULL`),
  ]
);
