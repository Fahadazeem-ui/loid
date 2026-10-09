import test from "node:test";
import assert from "node:assert/strict";
import { splitDiscordText } from "../src/lib/discord-ui.js";

test("long answers split below the Discord embed description limit without losing text", () => {
  const source = `${"Readable paragraph with an emoji 🙂 and enough words. ".repeat(220)}\nEnd.`;
  const chunks = splitDiscordText(source, 500);
  assert.ok(chunks.length > 1);
  assert.ok(chunks.every((chunk) => chunk.length <= 500));
  assert.equal(chunks.join(""), source.trim());
});

test("short text remains a single chunk and empty text gets a safe fallback", () => {
  assert.deepEqual(splitDiscordText("  hello  "), ["hello"]);
  assert.equal(splitDiscordText("  ").length, 1);
});

test("splitter rejects limits that could create unusable embeds", () => {
  assert.throws(() => splitDiscordText("hello", 0), RangeError);
});
