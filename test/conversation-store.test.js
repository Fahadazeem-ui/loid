import test from "node:test";
import assert from "node:assert/strict";
import { ConversationStore, makeConversationKey } from "../src/lib/conversation-store.js";

const keyFor = (userId, channelId = "channel-a", guildId = "guild-a") => makeConversationKey({ userId, channelId, guildId });

test("conversation memory is scoped and returned as a defensive copy", () => {
  const store = new ConversationStore({ cleanupIntervalMs: 0 });
  const key = keyFor("user-a");
  store.set(key, "user-a", [{ role: "user", content: "hello" }], 100);
  const copy = store.get(key, 101);
  copy[0].content = "changed";
  assert.equal(store.get(key, 102)[0].content, "hello");
  assert.deepEqual(store.get(keyFor("user-b"), 102), []);
  assert.deepEqual(store.get(keyFor("user-a", "channel-b"), 102), []);
});

test("memory expires, is bounded, and can be cleared per user", () => {
  const store = new ConversationStore({ ttlMs: 50, maxEntries: 2, maxMessages: 4, cleanupIntervalMs: 0 });
  const first = keyFor("user-a", "one");
  const second = keyFor("user-a", "two");
  store.set(first, "user-a", [{ role: "user", content: "1" }], 0);
  store.set(second, "user-a", [{ role: "user", content: "2" }], 1);
  assert.equal(store.get(first, 50).length, 0);
  store.set(first, "user-a", [{ role: "user", content: "3" }], 60);
  store.set(keyFor("user-b"), "user-b", [{ role: "user", content: "4" }], 61);
  assert.equal(store.entries.size, 2);
  assert.equal(store.clearUser("user-a"), 1);
  assert.equal(store.entries.size, 1);
});

test("message history is capped to the newest entries", () => {
  const store = new ConversationStore({ maxMessages: 3, cleanupIntervalMs: 0 });
  const messages = Array.from({ length: 5 }, (_, index) => ({ role: index % 2 ? "assistant" : "user", content: String(index) }));
  store.set("key", "user", messages, 1);
  assert.deepEqual(store.get("key", 2).map(({ content }) => content), ["2", "3", "4"]);
});

test("clear invalidates an in-flight request so it cannot restore stale memory", async () => {
  const store = new ConversationStore({ cleanupIntervalMs: 0 });
  const key = keyFor("user-a");
  let finish;
  const request = store.withLock(key, async () => {
    const version = store.getVersion(key, "user-a");
    await new Promise((resolve) => { finish = resolve; });
    const saved = store.set(key, "user-a", [{ role: "assistant", content: "old answer" }], 10, version);
    return saved;
  }, "user-a");
  await new Promise((resolve) => setImmediate(resolve));
  store.clear(key);
  finish();
  assert.equal(await request, false);
  assert.deepEqual(store.get(key, 11), []);
});

test("same-key async operations are serialized", async () => {
  const store = new ConversationStore({ cleanupIntervalMs: 0 });
  const order = [];
  await Promise.all([
    store.withLock("same", async () => { order.push("first-start"); await new Promise((resolve) => setTimeout(resolve, 15)); order.push("first-end"); }, "u"),
    store.withLock("same", async () => { order.push("second-start"); order.push("second-end"); }, "u"),
  ]);
  assert.deepEqual(order, ["first-start", "first-end", "second-start", "second-end"]);
});
