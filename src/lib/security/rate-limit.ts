import { Ratelimit } from "@upstash/ratelimit";
import { Redis } from "@upstash/redis";

const redis = new Redis({
  url: process.env.UPSTASH_REDIS_REST_URL!,
  token: process.env.UPSTASH_REDIS_REST_TOKEN!,
});

// 10 auth attempts per 60s per IP
export const authLimiter = new Ratelimit({
  redis,
  limiter: Ratelimit.slidingWindow(10, "60s"),
  prefix: "rl:auth",
});

// 3 email sends per hour
export const emailLimiter = new Ratelimit({
  redis,
  limiter: Ratelimit.slidingWindow(3, "1h"),
  prefix: "rl:email",
});
