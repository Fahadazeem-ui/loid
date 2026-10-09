import "dotenv/config";
import { REST, Routes } from "discord.js";
import { commandDefinitions } from "../src/commands.js";

const token = process.env.DISCORD_TOKEN?.trim();
const clientId = process.env.DISCORD_CLIENT_ID?.trim();
const guildId = process.env.DISCORD_GUILD_ID?.trim();

if (!token || !clientId) {
  console.error("Set DISCORD_TOKEN and DISCORD_CLIENT_ID in .env before registering commands.");
  process.exit(1);
}

const rest = new REST({ version: "10" }).setToken(token);
const route = guildId
  ? Routes.applicationGuildCommands(clientId, guildId)
  : Routes.applicationCommands(clientId);

try {
  await rest.put(route, { body: commandDefinitions.map((command) => command.toJSON()) });
  const scope = guildId ? `test server ${guildId}` : "all servers (global; updates may take time to appear)";
  console.log(`Registered ${commandDefinitions.length} Loid slash commands for ${scope}.`);
} catch (error) {
  const status = Number.isInteger(error?.status) ? ` (HTTP ${error.status})` : "";
  console.error(`Command registration failed${status}. Check the bot token, application ID, and server permissions.`);
  process.exitCode = 1;
}
