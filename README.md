# Loid — a calmer AI assistant for Discord

Loid is a slash-command Discord assistant built from the ground up for this repository. It uses **Claude Sonnet 5 only** (`claude-sonnet-5`) through Anthropic's API—there is no model fallback. It is deliberately private by default, straightforward to learn, and designed not to read channel history.

> The repository originally contained only `berserk.jpg`; there was no bot implementation to patch. This is a complete, runnable starter project. It needs your own Discord application credentials and Anthropic API key before it can connect.

## What it can do

| Command | What it does |
| --- | --- |
| `/ask` | Follow-up chat with a selectable tone. Context is private to the user, server, and channel. |
| `/summarize` | Turn text you paste into a concise, skimmable brief. |
| `/translate` | Translate supplied text while preserving meaning and tone. |
| `/explain` | Explain a topic at beginner, intermediate, or advanced level. |
| `/clear` | Clear the current conversation or all of your cached Loid conversations. |
| `/privacy` | Explain what Loid reads, sends to Anthropic, and keeps in memory. |
| `/status` | Check model, gateway ping, and uptime. |
| `/help` | A quick, readable command guide. |

AI replies are **ephemeral by default**. On an AI command, choose `public: True` only when you want the answer visible in the channel. Discord controls the actual message/embedding appearance; its embeds support a single accent color rather than a gradient. The accompanying web page uses restrained gradients for the product/setup experience.

## Privacy and safety

- Loid uses only Discord's `Guilds` gateway intent. It does **not** subscribe to Message Content, read arbitrary messages, fetch channel history, or inspect attachments.
- Only text explicitly submitted through `/ask`, `/summarize`, `/translate`, or `/explain` is sent to Anthropic. A continuing `/ask` also resends that user's short-lived conversation context so Claude can answer follow-ups. Do not submit sensitive information unless you are comfortable with Anthropic processing it under your account's terms.
- `/ask` context is in process memory only, scoped to one user + one server + one channel, capped at 12 messages, and expires after 2 hours or when the bot restarts. Expired entries are purged on cache access; a bounded cache prevents unrestrained growth.
- `/summarize`, `/translate`, and `/explain` are stateless. Their input is not added to the chat history.
- `/clear` deletes cached context. It cannot retract a prompt already submitted to Anthropic.
- Prompt and reply text are not written to Loid's logs or stored in a database. Error logs contain only command name and safe error metadata.
- AI calls are limited to 6 per user per minute with a 3-second cooldown, plus a shared bot-wide cap of 60 calls per minute. Mentions are disabled on Loid's replies to prevent accidental pings.

## Requirements

- Node.js 20 or newer
- A Discord application and bot token
- An Anthropic API key with access to Claude Sonnet 5

## Setup

1. **Create the Discord application.** In the [Discord Developer Portal](https://discord.com/developers/applications), create an application, add a bot, and copy its token. Keep the token private.
2. **Invite the bot.** In OAuth2 → URL Generator, select the `bot` and `applications.commands` scopes. Grant `Send Messages` and `Embed Links` for in-channel replies. Do not enable privileged message-content or member intents; Loid does not need them.
3. **Get an Anthropic API key** from the Anthropic Console. The code is pinned to Claude Sonnet 5; it does not silently switch providers or models.
4. **Install and configure.**
   ```bash
   npm ci
   cp .env.example .env
   ```
   Fill in `DISCORD_TOKEN`, `DISCORD_CLIENT_ID`, and `ANTHROPIC_API_KEY` in `.env`. Optionally set `DISCORD_GUILD_ID` while testing in one server. Never commit `.env`.
5. **Register commands and start Loid.**
   ```bash
   npm run register
   npm start
   ```
   Guild-scoped commands appear quickly. Global commands can take a while to propagate. Keep the bot process running for commands to respond.

### Local product/setup page

```bash
npm run dashboard
```

Then open `http://localhost:4173` (or set `PORT`). This is a static, self-hosted guide and design preview—not a fake Discord OAuth dashboard. It never receives your bot token or Anthropic key.

### Docker

After creating `.env`:

```bash
docker compose up --build -d
```

The provided container runs the bot only. It does not copy `.env` into the image.

## Development checks

```bash
npm test
npm run check
```

The test suite covers private conversation scoping, expiry and clearing (including in-flight requests), request limits, text chunking, slash-command presence, and the fixed model ID. Tests make no network or AI-provider calls.

## Configuration reference

| Variable | Required | Purpose |
| --- | --- | --- |
| `DISCORD_TOKEN` | Yes | Bot token from the Developer Portal. |
| `DISCORD_CLIENT_ID` | Yes for `npm run register` | Application ID. |
| `DISCORD_GUILD_ID` | No | Register commands to one test server; omit for global commands. |
| `ANTHROPIC_API_KEY` | Yes | API key for Claude Sonnet 5. |
| `PORT` | No | Static guide server port; defaults to `4173`. |

The model identifier is intentionally a code constant, not an environment variable: `claude-sonnet-5`. There is no OpenAI/other-model configuration or fallback.

## Project map

```text
src/
  index.js                  Discord client and graceful shutdown
  commands.js               Slash-command definitions
  handlers.js               Privacy-aware command routing and replies
  lib/ai.js                 Claude Sonnet 5 request construction
  lib/conversation-store.js Bounded, expiring, in-memory chat context
  lib/discord-ui.js         Accessible embed palette and safe text splitting
  lib/rate-limiter.js       Per-user AI request limiting
scripts/
  register-commands.js      Publish slash-command definitions
web/
  index.html                Responsive product/setup guide
  styles.css                Gradient panels and accessible theme
  app.js                    Search, copy, mobile navigation, demo controls
  server.js                 Dependency-light static server
 test/                      Offline Node.js tests
```

## Troubleshooting

- **Commands are missing:** run `npm run register` again. Check `DISCORD_CLIENT_ID`; during development use `DISCORD_GUILD_ID` for fast registration. Confirm the app was invited with `applications.commands`.
- **Private command replies fail:** check that the application is installed in the context where the command is invoked and that it has permission to use application commands.
- **Public embeds do not appear:** grant the bot `Send Messages` and `Embed Links` in that channel. You can still use the default private reply.
- **AI requests fail:** verify `ANTHROPIC_API_KEY`, account access to Claude Sonnet 5, and API billing/rate limits. Loid never changes to another model automatically.

## License

No license has been added. Add the license you intend before distributing the source publicly.
