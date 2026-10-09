const DEFAULT_TTL_MS = 2 * 60 * 60 * 1000;
const DEFAULT_MAX_ENTRIES = 1_000;
const DEFAULT_MAX_MESSAGES = 12;

/**
 * In-memory, per-user conversation storage. Nothing is written to disk.
 * Callers should use withLock() around read → model request → write sequences
 * so two rapid slash commands cannot overwrite each other's context.
 */
export class ConversationStore {
  constructor({ ttlMs = DEFAULT_TTL_MS, maxEntries = DEFAULT_MAX_ENTRIES, maxMessages = DEFAULT_MAX_MESSAGES, cleanupIntervalMs } = {}) {
    if (!Number.isInteger(ttlMs) || ttlMs <= 0) throw new RangeError("ttlMs must be a positive integer");
    if (!Number.isInteger(maxEntries) || maxEntries <= 0) throw new RangeError("maxEntries must be a positive integer");
    if (!Number.isInteger(maxMessages) || maxMessages <= 0) throw new RangeError("maxMessages must be a positive integer");

    const cleanupEveryMs = cleanupIntervalMs ?? Math.min(ttlMs, 60_000);
    if (!Number.isInteger(cleanupEveryMs) || cleanupEveryMs < 0) throw new RangeError("cleanupIntervalMs must be zero or a positive integer");

    this.ttlMs = ttlMs;
    this.maxEntries = maxEntries;
    this.maxMessages = maxMessages;
    this.entries = new Map();
    this.locks = new Map();
    this.keyVersions = new Map();
    this.userVersions = new Map();
    this.activeByUser = new Map();
    this.cleanupTimer = cleanupEveryMs > 0
      ? setInterval(() => this.#prune(Date.now()), Math.min(cleanupEveryMs, ttlMs))
      : undefined;
    this.cleanupTimer?.unref?.();
  }

  #prune(now) {
    for (const [key, entry] of this.entries) {
      if (now - entry.touchedAt >= this.ttlMs) this.entries.delete(key);
    }

    while (this.entries.size > this.maxEntries) {
      const oldestKey = this.entries.keys().next().value;
      if (oldestKey === undefined) break;
      this.entries.delete(oldestKey);
    }
  }

  get(key, now = Date.now()) {
    this.#prune(now);
    const entry = this.entries.get(key);
    if (!entry) return [];

    // Reinsert to keep the Map in least-recently-used order.
    this.entries.delete(key);
    entry.touchedAt = now;
    this.entries.set(key, entry);
    return entry.messages.map((message) => ({ ...message }));
  }

  getVersion(key, userId) {
    const user = String(userId);
    return { key: this.keyVersions.get(key) ?? 0, user: this.userVersions.get(user) ?? 0 };
  }

  set(key, userId, messages, now = Date.now(), expectedVersion) {
    const user = String(userId);
    if (expectedVersion) {
      const current = this.getVersion(key, user);
      if (current.key !== expectedVersion.key || current.user !== expectedVersion.user) return false;
    }

    this.#prune(now);
    const safeMessages = Array.isArray(messages)
      ? messages
          .filter((message) => message && ["user", "assistant"].includes(message.role) && typeof message.content === "string")
          .slice(-this.maxMessages)
          .map(({ role, content }) => ({ role, content }))
      : [];

    if (safeMessages.length === 0) {
      this.entries.delete(key);
      return true;
    }

    this.entries.delete(key);
    this.entries.set(key, { userId: user, messages: safeMessages, touchedAt: now });
    this.#prune(now);
    return true;
  }

  clear(key) {
    if (this.locks.has(key)) this.keyVersions.set(key, (this.keyVersions.get(key) ?? 0) + 1);
    return this.entries.delete(key);
  }

  clearUser(userId) {
    const target = String(userId);
    if ((this.activeByUser.get(target) ?? 0) > 0) {
      this.userVersions.set(target, (this.userVersions.get(target) ?? 0) + 1);
    }
    let removed = 0;
    for (const [key, entry] of this.entries) {
      if (entry.userId === target) {
        this.entries.delete(key);
        removed += 1;
      }
    }
    return removed;
  }

  /** Stop the background expiry timer (used by tests and graceful shutdown). */
  dispose() {
    if (this.cleanupTimer) clearInterval(this.cleanupTimer);
    this.cleanupTimer = undefined;
  }

  /** Run asynchronous work one-at-a-time for a conversation key. */
  async withLock(key, task, userId) {
    const user = userId === undefined ? undefined : String(userId);
    if (user !== undefined) this.activeByUser.set(user, (this.activeByUser.get(user) ?? 0) + 1);

    const previous = this.locks.get(key) ?? Promise.resolve();
    let release;
    const gate = new Promise((resolve) => {
      release = resolve;
    });
    const tail = previous.then(() => gate);
    this.locks.set(key, tail);

    await previous;
    try {
      return await task();
    } finally {
      release();
      if (this.locks.get(key) === tail) this.locks.delete(key);
      if (!this.locks.has(key) && !this.entries.has(key)) this.keyVersions.delete(key);

      if (user !== undefined) {
        const active = Math.max(0, (this.activeByUser.get(user) ?? 1) - 1);
        if (active === 0) {
          this.activeByUser.delete(user);
          this.userVersions.delete(user);
        } else {
          this.activeByUser.set(user, active);
        }
      }
    }
  }
}

export function makeConversationKey({ userId, guildId, channelId }) {
  return [guildId ?? "dm", channelId ?? "unknown-channel", userId].map(String).join(":");
}
