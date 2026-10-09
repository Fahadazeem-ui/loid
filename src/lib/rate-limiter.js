const DEFAULT_LIMIT = 6;
const DEFAULT_WINDOW_MS = 60_000;
const DEFAULT_COOLDOWN_MS = 3_000;
const DEFAULT_MAX_USERS = 10_000;

/** Small in-memory per-user limiter for AI calls; Discord's own limits still apply. */
export class UserRateLimiter {
  constructor({ limit = DEFAULT_LIMIT, windowMs = DEFAULT_WINDOW_MS, cooldownMs = DEFAULT_COOLDOWN_MS, maxUsers = DEFAULT_MAX_USERS } = {}) {
    for (const [name, value] of Object.entries({ limit, windowMs, cooldownMs, maxUsers })) {
      if (!Number.isInteger(value) || value < (name === "cooldownMs" ? 0 : 1)) {
        throw new RangeError(`${name} has an invalid value`);
      }
    }
    this.limit = limit;
    this.windowMs = windowMs;
    this.cooldownMs = cooldownMs;
    this.maxUsers = maxUsers;
    this.users = new Map();
  }

  take(userId, now = Date.now()) {
    const key = String(userId);
    let entry = this.users.get(key);

    if (entry && now >= entry.resetAt) {
      this.users.delete(key);
      entry = undefined;
    }

    if (entry && now - entry.lastRequestAt < this.cooldownMs) {
      return { allowed: false, retryAfterMs: this.cooldownMs - (now - entry.lastRequestAt), reason: "cooldown" };
    }

    if (entry && entry.count >= this.limit) {
      return { allowed: false, retryAfterMs: Math.max(1, entry.resetAt - now), reason: "window" };
    }

    if (!entry) entry = { count: 0, resetAt: now + this.windowMs, lastRequestAt: Number.NEGATIVE_INFINITY };
    entry.count += 1;
    entry.lastRequestAt = now;
    this.users.delete(key);
    this.users.set(key, entry);

    while (this.users.size > this.maxUsers) {
      const oldestKey = this.users.keys().next().value;
      if (oldestKey === undefined) break;
      this.users.delete(oldestKey);
    }

    return { allowed: true, retryAfterMs: 0, remaining: this.limit - entry.count };
  }
}
