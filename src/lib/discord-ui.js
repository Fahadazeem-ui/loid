import { EmbedBuilder } from "discord.js";

export const COLORS = Object.freeze({
  brand: 0x8276f7,
  cyan: 0x4dc8d2,
  green: 0x50bf9e,
  amber: 0xe6ae64,
  rose: 0xe88196,
  slate: 0x69758d,
});

export const NO_MENTIONS = Object.freeze({ parse: [], users: [], roles: [], repliedUser: false });

export function splitDiscordText(value, maxLength = 3_800) {
  if (!Number.isInteger(maxLength) || maxLength < 16) throw new RangeError("maxLength must be an integer of at least 16");
  const text = String(value ?? "").trim();
  if (!text) return ["I couldn't form a useful answer from that request. Please try rephrasing it."];

  const chunks = [];
  let start = 0;
  while (start < text.length) {
    let end = Math.min(start + maxLength, text.length);
    if (end < text.length) {
      const floor = start + Math.floor(maxLength * 0.55);
      const lastAllowedIndex = end - 1;
      const lineBreak = text.lastIndexOf("\n", lastAllowedIndex);
      const space = text.lastIndexOf(" ", lastAllowedIndex);
      const boundary = Math.max(lineBreak, space);
      if (boundary >= floor) end = boundary + 1;
    }

    // Avoid cutting a UTF-16 surrogate pair in half (e.g. emoji).
    if (end < text.length && end > start) {
      const before = text.charCodeAt(end - 1);
      const after = text.charCodeAt(end);
      if (before >= 0xd800 && before <= 0xdbff && after >= 0xdc00 && after <= 0xdfff) end -= 1;
    }

    if (end <= start) end = Math.min(start + maxLength, text.length);
    chunks.push(text.slice(start, end));
    start = end;
  }
  return chunks;
}

export function makeAnswerEmbed(text, { isPrivate = true, continuation = false, color = COLORS.brand } = {}) {
  const footer = continuation
    ? `LOID  ·  CONTINUED${isPrivate ? "  ·  PRIVATE" : ""}`
    : `LOID  ·  CLAUDE SONNET 5${isPrivate ? "  ·  PRIVATE REPLY" : ""}`;

  return new EmbedBuilder()
    .setColor(color)
    .setDescription(text)
    .setFooter({ text: footer })
    .setTimestamp();
}

export function makeNoticeEmbed(title, description, { color = COLORS.cyan, footer = "LOID  ·  DISCORD ASSISTANT" } = {}) {
  return new EmbedBuilder()
    .setColor(color)
    .setTitle(title)
    .setDescription(description)
    .setFooter({ text: footer });
}

export function makePrivacyEmbed() {
  return new EmbedBuilder()
    .setColor(COLORS.cyan)
    .setTitle("Your privacy, in plain language")
    .setDescription("Loid sends only text you submit through an AI slash command—and your short-lived `/ask` context when continuing that chat—to Anthropic for a Claude Sonnet 5 response. It does not read channel history, attachments, or other server messages.")
    .addFields(
      { name: "Conversation memory", value: "Short-lived and in RAM only. It is scoped to you, this server, and this channel; it expires after 2 hours or on restart." },
      { name: "Your controls", value: "Use `/clear` to remove this channel's memory, or choose **All my active chats** to clear every cached conversation for your account." },
      { name: "Logging", value: "Prompts and replies are not written to Loid's logs or stored in a database. Anthropic processes submitted text to generate the reply; review its terms and privacy policy before use." },
    )
    .setFooter({ text: "LOID  ·  NO MESSAGE-CONTENT INTENT" });
}
