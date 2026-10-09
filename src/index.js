import "dotenv/config";
import { Client, Events, GatewayIntentBits } from "discord.js";
import Anthropic from "@anthropic-ai/sdk";
import { createCommandHandler, handleCommandError } from "./handlers.js";
import { ConversationStore } from "./lib/conversation-store.js";
import { UserRateLimiter } from "./lib/rate-limiter.js";

const discordToken = process.env.DISCORD_TOKEN?.trim();
const anthropicApiKey = process.env.ANTHROPIC_API_KEY?.trim();

if (!discordToken || !anthropicApiKey) {
  console.error("Loid is not configured. Set DISCORD_TOKEN and ANTHROPIC_API_KEY in .env (see .env.example).");
  process.exit(1);
}

// Guilds is the only gateway intent Loid needs. It never subscribes to message content.
const client = new Client({ intents: [GatewayIntentBits.Guilds] });
const anthropic = new Anthropic({ apiKey: anthropicApiKey, timeout: 45_000, maxRetries: 1 });
const conversationStore = new ConversationStore({ ttlMs: 2 * 60 * 60 * 1_000, maxEntries: 1_000, maxMessages: 12 });
const rateLimiter = new UserRateLimiter({ limit: 6, windowMs: 60_000, cooldownMs: 3_000 });
const globalRateLimiter = new UserRateLimiter({ limit: 60, windowMs: 60_000, cooldownMs: 0, maxUsers: 1 });
const handleInteraction = createCommandHandler({ anthropic, client, conversationStore, rateLimiter, globalRateLimiter });

client.once(Events.ClientReady, (readyClient) => {
  console.log(`Loid is ready as ${readyClient.user.tag}. Model: Claude Sonnet 5. Intents: Guilds only.`);
});

client.on(Events.InteractionCreate, async (interaction) => {
  if (!interaction.isChatInputCommand()) return;
  try {
    await handleInteraction(interaction);
  } catch (error) {
    await handleCommandError(interaction, error);
  }
});

client.on(Events.Error, (error) => {
  const errorName = typeof error?.name === "string" ? error.name : "unknown";
  console.error(`[discord] ${errorName}`);
});

async function shutdown(signal) {
  console.log(`Received ${signal}; shutting Loid down gracefully.`);
  conversationStore.dispose();
  client.destroy();
  process.exit(0);
}

process.once("SIGINT", () => void shutdown("SIGINT"));
process.once("SIGTERM", () => void shutdown("SIGTERM"));

try {
  await client.login(discordToken);
} catch (error) {
  const errorName = typeof error?.name === "string" ? error.name : "unknown";
  console.error(`Discord login failed (${errorName}). Check DISCORD_TOKEN and network access.`);
  process.exit(1);
}
