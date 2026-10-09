import test from "node:test";
import assert from "node:assert/strict";
import { buildChatInstructions, buildTaskInstructions, CLAUDE_MODEL_ID, generateText } from "../src/lib/ai.js";

test("the provider is pinned to Claude Sonnet 5 with no fallback", async () => {
  assert.equal(CLAUDE_MODEL_ID, "claude-sonnet-5");
  let received;
  const mockClient = {
    messages: {
      create: async (request) => {
        received = request;
        return { content: [{ type: "text", text: "A clear answer." }] };
      },
    },
  };
  assert.equal(await generateText(mockClient, { system: "system", messages: [{ role: "user", content: "hello" }] }), "A clear answer.");
  assert.equal(received.model, "claude-sonnet-5");
  assert.equal("temperature" in received, false);
  assert.equal("top_p" in received, false);
});

test("chat style instructions fall back safely and task instructions remain explicit", () => {
  assert.match(buildChatInstructions("not-a-style"), /warm, clear/i);
  assert.match(buildTaskInstructions("Translate faithfully."), /Translate faithfully/);
});
