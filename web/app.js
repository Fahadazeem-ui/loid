const nav = document.querySelector("#main-nav");
const menuToggle = document.querySelector(".menu-toggle");

menuToggle?.addEventListener("click", () => {
  const open = menuToggle.getAttribute("aria-expanded") !== "true";
  menuToggle.setAttribute("aria-expanded", String(open));
  menuToggle.setAttribute("aria-label", open ? "Close navigation" : "Open navigation");
  nav?.classList.toggle("is-open", open);
});

nav?.querySelectorAll("a").forEach((link) => {
  link.addEventListener("click", () => {
    nav.classList.remove("is-open");
    menuToggle?.setAttribute("aria-expanded", "false");
    menuToggle?.setAttribute("aria-label", "Open navigation");
  });
});

const searchInput = document.querySelector("#command-search");
const commandCards = [...document.querySelectorAll(".command-card")];
const resultCount = document.querySelector("#search-result");
const noResults = document.querySelector("#no-results");

searchInput?.addEventListener("input", () => {
  const term = searchInput.value.trim().toLowerCase();
  let visible = 0;
  for (const card of commandCards) {
    const haystack = `${card.dataset.search ?? ""} ${card.textContent ?? ""}`.toLowerCase();
    const matches = haystack.includes(term);
    card.hidden = !matches;
    if (matches) visible += 1;
  }
  if (resultCount) resultCount.textContent = `${visible} ${visible === 1 ? "command" : "commands"}${term ? " found" : " available"}`;
  if (noResults) noResults.hidden = visible !== 0;
});

async function copyText(value) {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(value);
    return;
  }
  const temporary = document.createElement("textarea");
  temporary.value = value;
  temporary.setAttribute("readonly", "");
  temporary.style.position = "fixed";
  temporary.style.opacity = "0";
  document.body.append(temporary);
  temporary.select();
  const copied = document.execCommand("copy");
  temporary.remove();
  if (!copied) throw new Error("Clipboard access is unavailable");
}

const copyStatus = document.querySelector("#copy-status");
for (const button of document.querySelectorAll(".copy-command")) {
  button.addEventListener("click", async () => {
    try {
      await copyText(button.dataset.copy ?? "");
      if (copyStatus) copyStatus.textContent = `Copied ${button.dataset.copy} to your clipboard.`;
      button.textContent = "Copied";
      window.setTimeout(() => { button.textContent = "Copy command"; }, 1_500);
    } catch {
      if (copyStatus) copyStatus.textContent = "Clipboard access was blocked. You can select the command text instead.";
    }
  });
}

const copySetup = document.querySelector("#copy-setup");
const setupStatus = document.querySelector("#setup-status");
copySetup?.addEventListener("click", async () => {
  try {
    await copyText("npm ci && cp .env.example .env");
    if (setupStatus) setupStatus.textContent = "Copied. Add your own credentials to .env on your server.";
    copySetup.textContent = "Copied";
    window.setTimeout(() => { copySetup.textContent = "Copy"; }, 1_500);
  } catch {
    if (setupStatus) setupStatus.textContent = "Clipboard access was blocked. You can copy the commands shown above.";
  }
});
