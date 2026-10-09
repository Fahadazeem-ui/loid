import { SlashCommandBuilder } from "discord.js";

const publicOption = (option) => option
  .setName("public")
  .setDescription("Show the reply in the channel instead of privately (default: private)")
  .setRequired(false);

export const commandDefinitions = [
  new SlashCommandBuilder()
    .setName("ask")
    .setDescription("Ask Loid and continue a private, short-lived conversation")
    .addStringOption((option) => option
      .setName("question")
      .setDescription("What would you like help with?")
      .setMinLength(1)
      .setMaxLength(1_800)
      .setRequired(true))
    .addStringOption((option) => option
      .setName("style")
      .setDescription("Choose the tone for this reply")
      .setRequired(false)
      .addChoices(
        { name: "Balanced", value: "balanced" },
        { name: "Concise", value: "concise" },
        { name: "Encouraging", value: "encouraging" },
        { name: "Professional", value: "professional" },
        { name: "Lightly playful", value: "playful" },
      ))
    .addBooleanOption(publicOption),

  new SlashCommandBuilder()
    .setName("summarize")
    .setDescription("Summarize text you provide into a clear, skimmable brief")
    .addStringOption((option) => option
      .setName("text")
      .setDescription("Paste the text to summarize; Loid will not fetch channel history")
      .setMinLength(1)
      .setMaxLength(1_800)
      .setRequired(true))
    .addBooleanOption(publicOption),

  new SlashCommandBuilder()
    .setName("translate")
    .setDescription("Translate text while preserving its tone and meaning")
    .addStringOption((option) => option
      .setName("text")
      .setDescription("Text you want translated")
      .setMinLength(1)
      .setMaxLength(1_800)
      .setRequired(true))
    .addStringOption((option) => option
      .setName("language")
      .setDescription("Target language, for example Spanish or Urdu")
      .setMinLength(2)
      .setMaxLength(60)
      .setRequired(true))
    .addBooleanOption(publicOption),

  new SlashCommandBuilder()
    .setName("explain")
    .setDescription("Get an explanation tuned to your experience level")
    .addStringOption((option) => option
      .setName("topic")
      .setDescription("A concept, question, or short passage to explain")
      .setMinLength(1)
      .setMaxLength(1_800)
      .setRequired(true))
    .addStringOption((option) => option
      .setName("level")
      .setDescription("How much background to assume")
      .setRequired(false)
      .addChoices(
        { name: "New to this", value: "beginner" },
        { name: "Some background", value: "intermediate" },
        { name: "Go deeper", value: "advanced" },
      ))
    .addBooleanOption(publicOption),

  new SlashCommandBuilder()
    .setName("clear")
    .setDescription("Forget Loid's short-lived conversation memory")
    .addStringOption((option) => option
      .setName("scope")
      .setDescription("Choose which of your conversations to clear")
      .setRequired(true)
      .addChoices(
        { name: "This channel", value: "channel" },
        { name: "All my active chats", value: "all" },
      )),

  new SlashCommandBuilder()
    .setName("privacy")
    .setDescription("See exactly what Loid reads, sends, and remembers"),

  new SlashCommandBuilder()
    .setName("status")
    .setDescription("Check whether Loid is online and which model it uses"),

  new SlashCommandBuilder()
    .setName("help")
    .setDescription("Browse Loid's commands and learn how to get started"),
];
