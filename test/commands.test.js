import test from "node:test";
import assert from "node:assert/strict";
import { commandDefinitions } from "../src/commands.js";

test("registered slash commands are unique and include the user-facing core", () => {
  const names = commandDefinitions.map((command) => command.name);
  assert.equal(new Set(names).size, names.length);
  for (const name of ["ask", "summarize", "translate", "explain", "clear", "privacy", "status", "help"]) {
    assert.ok(names.includes(name), `expected /${name}`);
  }
});
