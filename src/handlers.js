import { commandDefinitions } from "./commands.js";
import { buildChatInstructions, buildTaskInstructions, generateText, MAX_OUTPUT_TOKENS } from "./lib/ai.js";
import { COLORS, makeAnswerEmbed, makeNoticeEmbed, makePrivacyEmbed, NO_MENTIONS, splitDiscordText } from "./lib/discord-ui.js";
import { makeConversationKey } from "./lib/conversation-store.js";

const AI_COMMANDS = new Set(["ask", "summarize", "translate", "explain"]);
const MAX_TASK_OUTPUT_TOKENS = 1_400;

function privateReply(interaction) {
  return !(interaction.options.getBoolean("public") ?? false);
}

async function startAIRequest(interaction, userLimiter, globalLimiter) {
  const userResult = userLimiter.take(interaction.user.id);
  if (!userResult.allowed) {
    const seconds = Math.max(1, Math.ceil(userResult.retryAfterMs / 1_000));
    const note = userResult.reason === "cooldown"
      ? `Give Loid a moment, then try again in about ${seconds} second${seconds === 1 ? "" : "s"}.`
      : `You've reached the short-term request limit. Please try again in about ${seconds} second${seconds === 1 ? "" : "s"}.`;
    await interaction.reply({
      embeds: [makeNoticeEmbed("A small pause", note, { color: COLORS.amber })],
      ephemeral: true,
      allowedMentions: NO_MENTIONS,
    });
    return false;
  }

  const globalResult = globalLimiter.take("global");
  if (!globalResult.allowed) {
    const seconds = Math.max(1, Math.ceil(globalResult.retryAfterMs / 1_000));
    await interaction.reply({
      embeds: [makeNoticeEmbed("Loid is at capacity", `The shared AI request limit has been reached. Please try again in about ${seconds} second${seconds === 1 ? "" : "s"}.`, { color: COLORS.amber })],
      ephemeral: true,
      allowedMentions: NO_MENTIONS,
    });
    return false;
  }

  await interaction.deferReply({ ephemeral: privateReply(interaction) });
  return true;
}

async function sendAnswer(interaction, answer, { isPrivate, color = COLORS.brand } = {}) {
  const chunks = splitDiscordText(answer);
  await interaction.editReply({
    embeds: [makeAnswerEmbed(chunks[0], { isPrivate, continuation: chunks.length > 1, color })],
    allowedMentions: NO_MENTIONS,
  });

  for (const chunk of chunks.slice(1)) {
    await interaction.followUp({
      embeds: [makeAnswerEmbed(chunk, { isPrivate, continuation: true, color })],
      ephemeral: isPrivate,
      allowedMentions: NO_MENTIONS,
    });
  }
}

function requestScope(interaction) {
  return makeConversationKey({
    userId: interaction.user.id,
    guildId: interaction.guildId,
    channelId: interaction.channelId,
  });
}

function formatUptime(ms) {
  const seconds = Math.max(0, Math.floor(ms / 1_000));
  const days = Math.floor(seconds / 86_400);
  const hours = Math.floor((seconds % 86_400) / 3_600);
  const minutes = Math.floor((seconds % 3_600) / 60);
  return days > 0 ? `${days}d ${hours}h ${minutes}m` : hours > 0 ? `${hours}h ${minutes}m` : `${minutes}m`;
}

function buildHelpEmbed() {
  return makeNoticeEmbed(
    "A calmer way to get unstuck",
    "Loid is a private-by-default AI assistant. Start with `/ask`; use `/help` any time you need a reminder.",
    { color: COLORS.brand, footer: "LOID  ·  BUILT FOR CLEAR, COMFORTABLE CONVERSATION" },
  ).addFields(
    { name: "Chat", value: "`/ask` — ask follow-up questions; memory is scoped to you and this channel. Pick a response style if you like." },
    { name: "Work with text", value: "`/summarize` — a skimmable brief\n`/translate` — preserve meaning and tone\n`/explain` — choose your experience level" },
    { name: "Your controls", value: "`/clear` — forget one or all of your active chats\n`/privacy` — see what is and is not stored\n`/status` — check model and bot health" },
    { name: "Private or shared?", value: "AI commands reply privately by default. Set the `public` option to `True` only when you want the answer visible in-channel." },
  );
}

function userSafeError(error) {
  if (error?.status === 401 || error?.status === 403) {
    return "Loid could not authenticate with a required service. Ask the bot owner to check its Discord token, Anthropic API key, and account access.";
  }
  if (error?.status === 429) {
    return "A service rate limit was reached. Please wait briefly and try again.";
  }
  if (error?.status >= 500) {
    return "A service is temporarily unavailable. Please try again shortly; Loid does not write prompt text to its logs.";
  }
  if (error?.name?.includes("Timeout") || error?.name?.includes("Connection")) {
    return "That request took too long to complete. Please try again with a shorter prompt.";
  }
  return "Something went wrong while Loid handled that command. Prompt text is not written to Loid's logs; please try again.";
}

export async function handleCommandError(interaction, error) {
  const status = Number.isInteger(error?.status) ? ` HTTP ${error.status}` : "";
  const errorName = typeof error?.name === "string" ? error.name.slice(0, 60) : "unknown";
  console.error(`[command:${interaction.commandName}] ${errorName}${status}`);

  const response = {
    embeds: [makeNoticeEmbed("That didn't go through", userSafeError(error), { color: COLORS.rose })],
    allowedMentions: NO_MENTIONS,
  };
  try {
    if (interaction.deferred || interaction.replied) {
      await interaction.editReply(response);
    } else {
      await interaction.reply({ ...response, ephemeral: true });
    }
  } catch {
    // Interaction may have expired or been acknowledged by Discord already.
  }
}

export function createCommandHandler({ anthropic, client, conversationStore, rateLimiter, globalRateLimiter }) {
  const knownCommands = new Set(commandDefinitions.map((command) => command.name));

  return async function handleInteraction(interaction) {
    if (!interaction.isChatInputCommand() || !knownCommands.has(interaction.commandName)) return;

    const commandName = interaction.commandName;
    if (AI_COMMANDS.has(commandName)) {
      const requiredTextOptions = {
        ask: ["question"],
        summarize: ["text"],
        translate: ["text", "language"],
        explain: ["topic"],
      }[commandName];
      const hasBlankInput = requiredTextOptions.some((name) => !(interaction.options.getString(name, true) ?? "").trim());
      if (hasBlankInput) {
        await interaction.reply({
          embeds: [makeNoticeEmbed("Add a little text", "This field cannot be only spaces. Add a question, passage, topic, or target language and try again.", { color: COLORS.amber })],
          ephemeral: true,
          allowedMentions: NO_MENTIONS,
        });
        return;
      }
      if (!(await startAIRequest(interaction, rateLimiter, globalRateLimiter))) return;
    }

    if (commandName === "ask") {
      const question = interaction.options.getString("question", true).trim();
      const tone = interaction.options.getString("style") ?? "balanced";
      const key = requestScope(interaction);
      const answer = await conversationStore.withLock(key, async () => {
        const history = conversationStore.get(key);
        const version = conversationStore.getVersion(key, interaction.user.id);
        const reply = await generateText(anthropic, {
          system: buildChatInstructions(tone),
          messages: [...history, { role: "user", content: question }],
          maxTokens: MAX_OUTPUT_TOKENS,
        });
        conversationStore.set(key, interaction.user.id, [
          ...history,
          { role: "user", content: question },
          { role: "assistant", content: reply },
        ], Date.now(), version);
        return reply;
      }, interaction.user.id);

      await sendAnswer(interaction, answer, { isPrivate: privateReply(interaction), color: COLORS.brand });
      return;
    }

    if (commandName === "summarize") {
      const suppliedText = interaction.options.getString("text", true).trim();
      const answer = await generateText(anthropic, {
        system: buildTaskInstructions("Summarize the user's supplied text faithfully. Preserve key facts, caveats, and decisions; do not add claims not present in the source. Use a short title and a few concise bullets when useful."),
        messages: [{ role: "user", content: `Summarize this text:\n\n${suppliedText}` }],
        maxTokens: MAX_TASK_OUTPUT_TOKENS,
      });
      await sendAnswer(interaction, answer, { isPrivate: privateReply(interaction), color: COLORS.cyan });
      return;
    }

    if (commandName === "translate") {
      const suppliedText = interaction.options.getString("text", true).trim();
      const language = interaction.options.getString("language", true).trim();
      const answer = await generateText(anthropic, {
        system: buildTaskInstructions(`Translate the user's supplied text into ${language}. Preserve meaning, tone, names, and formatting. Return only the translation unless a short clarification is essential.`),
        messages: [{ role: "user", content: suppliedText }],
        maxTokens: MAX_TASK_OUTPUT_TOKENS,
      });
      await sendAnswer(interaction, answer, { isPrivate: privateReply(interaction), color: COLORS.green });
      return;
    }

    if (commandName === "explain") {
      const topic = interaction.options.getString("topic", true).trim();
      const level = interaction.options.getString("level") ?? "beginner";
      const levelInstruction = {
        beginner: "Assume the reader is new to the subject. Define necessary terms and use one simple example.",
        intermediate: "Assume basic familiarity. Explain the mechanism, then give a practical example or implication.",
        advanced: "Assume strong background knowledge. Focus on nuance, trade-offs, and technical precision without padding.",
      }[level];
      const answer = await generateText(anthropic, {
        system: buildTaskInstructions(`Explain the user's topic at the selected level. ${levelInstruction} Keep the answer structured and readable.`),
        messages: [{ role: "user", content: topic }],
        maxTokens: MAX_TASK_OUTPUT_TOKENS,
      });
      await sendAnswer(interaction, answer, { isPrivate: privateReply(interaction), color: COLORS.amber });
      return;
    }

    if (commandName === "clear") {
      const scope = interaction.options.getString("scope", true);
      let description;
      if (scope === "all") {
        const count = conversationStore.clearUser(interaction.user.id);
        description = count === 0
          ? "There was no cached conversation to remove. Any in-flight answer will not restore cleared memory."
          : `Cleared **${count}** cached conversation${count === 1 ? "" : "s"} from Loid's memory. Any in-flight answer will not restore it.`;
      } else {
        const removed = conversationStore.clear(requestScope(interaction));
        description = removed
          ? "This channel's Loid conversation has been cleared from memory."
          : "There was no saved conversation for this channel. An in-flight answer will not be added to memory.";
      }
      await interaction.reply({
        embeds: [makeNoticeEmbed("Memory cleared", `${description}\n\nThis only clears Loid's short-lived in-process memory; it cannot recall text already sent to Anthropic for a reply.`, { color: COLORS.green })],
        ephemeral: true,
        allowedMentions: NO_MENTIONS,
      });
      return;
    }

    if (commandName === "privacy") {
      await interaction.reply({ embeds: [makePrivacyEmbed()], ephemeral: true, allowedMentions: NO_MENTIONS });
      return;
    }

    if (commandName === "status") {
      const ping = Number.isFinite(client.ws.ping) && client.ws.ping >= 0 ? `${Math.round(client.ws.ping)} ms` : "connecting";
      const uptime = formatUptime(client.uptime ?? 0);
      const status = makeNoticeEmbed("Loid is here", "The assistant is online and ready for a slash command.", { color: COLORS.green })
        .addFields(
          { name: "Model", value: "Claude Sonnet 5", inline: true },
          { name: "Gateway ping", value: ping, inline: true },
          { name: "Uptime", value: uptime, inline: true },
          { name: "Memory", value: "RAM only · 2-hour expiry", inline: true },
        );
      await interaction.reply({ embeds: [status], ephemeral: true, allowedMentions: NO_MENTIONS });
      return;
    }

    if (commandName === "help") {
      await interaction.reply({ embeds: [buildHelpEmbed()], ephemeral: true, allowedMentions: NO_MENTIONS });
    }
  };
}
