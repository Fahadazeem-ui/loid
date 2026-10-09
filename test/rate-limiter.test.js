import test from "node:test";
import assert from "node:assert/strict";
import { UserRateLimiter } from "../src/lib/rate-limiter.js";

test("rate limiter allows the configured number, then enforces cooldown/window", () => {
  const limiter = new UserRateLimiter({ limit: 2, windowMs: 10_000, cooldownMs: 1_000 });
  assert.equal(limiter.take("u1", 0).allowed, true);
  assert.deepEqual(limiter.take("u1", 500), { allowed: false, retryAfterMs: 500, reason: "cooldown" });
  assert.equal(limiter.take("u1", 1_000).allowed, true);
  assert.deepEqual(limiter.take("u1", 2_000), { allowed: false, retryAfterMs: 8_000, reason: "window" });
  assert.equal(limiter.take("u1", 10_000).allowed, true);
});

test("rate limits are isolated per user and the map is bounded", () => {
  const limiter = new UserRateLimiter({ limit: 1, windowMs: 10_000, cooldownMs: 0, maxUsers: 2 });
  assert.equal(limiter.take("one", 0).allowed, true);
  assert.equal(limiter.take("two", 0).allowed, true);
  assert.equal(limiter.take("three", 0).allowed, true);
  assert.equal(limiter.users.size, 2);
  assert.equal(limiter.take("one", 1).allowed, true);
});
