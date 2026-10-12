# FileSorter 2.0

**Zip/folder ko naam se nahi, *andar* dekh kar pehchanta hai.**
Har file ek faisla nahi — har detector ek **saboot** (evidence) deta hai, aur ek fusion layer un sabooton ko jod kar probability nikalta hai. Jab tak confidence na bane, engine aur gehra padhta hai (list → header → descriptor → content → bytecode → nested archive). Jo cheez sach men pehchan na aaye, wo galat folder men nahi jati — `_Review` men jati hai.

Ye us FileSorter ka v2 hai jo bot/software wali zips ko `Archives` men daal deta tha aur shaderpack vs resource pack men confuse hota tha.

---

## 1. Kya theek hua (aapki 3-shikayatein)

| Shikayat | Asli wajah (v1) | Ab kya hota hai |
| --- | --- | --- |
| Bot/software wali zip `Archives` men | sirf root par marker dhoondta tha; nested layout (`repo-main/src/bot/index.js`) par kuch nahi milta tha, to fallback `Archives` | poore tree men markers dhoonde jate hain (har level), phir content score hota hai. `Archives` **hata diya** — ab `Collections`/`Other`/`_Review` hai, aur zip apne content ke domain men jati hai (`Developer/Discord-Bots`, `Software/Portable`, `Media/Images`...) |
| Shader vs resource pack differentiate nahi | "pehla match jeete" wali rules; `assets/minecraft/shaders/core` ko shader samajh leta tha | scoring + **core-shader guard**: `shaders/*.fsh`, `shaders.properties`, `world0/` = shaderpack; `assets/minecraft/...` = resource pack (core shaders par counter-evidence) |
| Mods miss ho jate | sirf `fabric.mod.json`/`mods.toml` root par; `.jar.disabled`, MANIFEST-only mods, odd casing | base naam (`MyMod.jar.disabled` → jar), MANIFEST FML/TweakClass, Quilt, NeoForge, `jarjar`, aur agar descriptor bilkul na ho to **bytecode constant-pool scan** (`net/fabricmc`, `net/minecraftforge`, `org/bukkit`, `com/velocitypowered`...) |

---

## 2. Chalane ka tareeqa

Windows:

```bat
run.bat                     :: current folder (dry run)
run.bat D:\Downloads        :: wo folder
run.bat D:\Downloads --apply
```

Ya seedha Python (3.8+, koi dependency nahi — sirf standard library):

```bash
python file_sorter.py                        # dry run (kuch move nahi hota)
python file_sorter.py D:\Downloads --apply   # asli sorting
python file_sorter.py D:\Downloads --deep    # early-stop off: har stage chalega
python file_sorter.py some.zip --explain     # poori evidence chain dikhao
python file_sorter.py --report report_dir    # JSON + CSV + Markdown report
python file_sorter.py --teach mc.plugin MyPlugin-2.1.jar   # "ye plugin hai" — yaad rakh lo
python file_sorter.py --undo D:\Downloads    # pichhli sorting wapas
```

Useful flags: `--copy`, `--recursive`, `--include "*.zip"`, `--exclude "*.part"`, `--max-stage 3`, `--time-budget 2`, `--no-review`, `--json`, `--quiet`.

---

## 3. Folders (taxonomy)

```
Minecraft/{Mods, Plugins, Shaderpacks, Resourcepacks, Datapacks, Modpacks, Worlds, Servers, Other}
Developer/{Discord-Bots, Bots/{Telegram,Minecraft-AFK}, Editors/{VSCode-Extensions,Obsidian-Plugins},
           Browsers/Extensions, Web/WordPress, Python, Node, Java, Rust, Go, DotNet, Web, Scripts, Other}
Software/{Installers, Portable, Android, Libraries}   Games/
Media/{Video, Audio, Images, Fonts, Ebooks, Other}    Documents/{PDF, Office, Text, Data, Code}
Collections/    Other/    _Review/
```

`_Review` = engine ne faisla nahi kiya (kam score, do hypotheses barabar, ya RAR/7z jo khul hi nahi sakta). Aisi files **guess** kar ke kahin nahi daali jati.

---

## 4. Andar kaise kaam karta hai (analysis ladder)

| Stage | Kya dekhta hai | Cost |
| --- | --- | --- |
| 0 | naam, base naam (`.disabled`/`.old` hatata hai), modifiers, extension | free |
| 1 | magic bytes (PE/ELF/ZIP/RAR/PNG/…), PE header, installer/framework strings | 1 chhoti read |
| 2 | archive listing: poora tree, folder structure, extension mix, multi-root | central directory |
| 3 | descriptors: `plugin.yml`, `fabric.mod.json`, `mods.toml`, `pack.mcmeta`, `package.json`, `requirements.txt`, `build.gradle`, MANIFEST… | kuch chhoti reads |
| 4 | content grep (discord.js/discord.py/mineflayer/`@bot.command`/bukkit…), **credential scan** | bounded |
| 5 | bytecode constant-pool scan (Bukkit/Forge/Fabric/Velocity…), binary strings (Unity/BepInEx/NSIS…) | bounded |
| 6 | nested archives (`mods/*.jar`, `plugins/*.jar`, zip ke andar zip) | bounded, recursion |

- **Early stop**: agar stage 2/3 par hi pukhta saboot mil jaye (e.g. `plugin.yml` + `org/bukkit` bytecode), aage nahi padhta. `--deep` se sab chal jata hai.
- **Substantive evidence rule**: sirf naam/extension se kabhi faisla nahi hota. Isi liye `photo.png` jo asal men text hai, `_Review` men jati hai (pehle `Images` men jati thi).
- **Counter-evidence**: rules negative weight bhi de sakti hain (`assets/minecraft/shaders/core` dekh kar shaderpack par −4).
- **Confidence/margin**: `0.30 + 0.50·coverage + 0.18·decisiveness`; score kam ya margin kam → `_Review`.

Har input pe budget lagu hota hai: 4s per file, 8000 entries, 64 KB per member, 12 MB total reads, nested depth 2, zip-bomb aur `../` path-traversal guards ke saath. **Kabhi disk par extract nahi karta** — sab kuch bounded memory men.

---

## 5. Internet: haan, magar booster ki tarah (default OFF)

Aapka sawal tha "internet se connect karo to accuracy badhegi?" — Jawab: **primary ilaaj nahi hai** (asli masla local reading ki gehrai thi), magar do jagah asli faida hai:

```bash
python file_sorter.py D:\Downloads --online
```

1. **Hash lookup (exact identity)** — sirf **SHA-1 hash** bhejta hai, file kabhi nahi:
   - **Modrinth**: bata deta hai file *mod, resourcepack, shader, datapack* ya *modpack* hai (shader vs resourcepack ka masla published packs ke liye yahin khatam).
   - **Maven Central**: library jar ka exact `groupId:artifactId:version`.
   - Results cache hote hain (`~/.filesorter/netkb.json`, 30 din), offline men chup-chaap skip.
2. **Rule packs** (naye loaders/formats bina naya exe banaye):
   `python file_sorter.py --rules https://example.com/rules.json`
   JSON men `path_sigs`, `name_hints`, `text_sigs` add ho jate hain.

Internet ke bagair bhi tool poora chalta hai — jo bhi `--online` deta hai wo sirf *confirmation* hai, engine ka local faisla overwrite nahi hota jab tak hash exact na ho.

---

## 6. Claude assist (optional, default OFF)

```bash
set ANTHROPIC_API_KEY=sk-ant-...
python file_sorter.py D:\Downloads --ai
```

- Sirf **ambiguous** files par chalta hai (jab engine `_Review` keh raha ho), max 25 calls.
- **File content nahi jata** — sirf naam, structure (extensions, top-level folders), aur detectors ka output.
- Model se sirf taxonomy ke labels men se ek label maanga jata hai; ulta-seedha jawab discard ho jata hai, yaad rakha jata hai (`ai_suggestion`) taake aap khud dekh sakein.
- Sirf **Claude** models (`--ai-model`, default `claude-sonnet-4-5`).

---

## 7. Teach once (aapki corrections se seekhna)

```bash
python file_sorter.py "MyPlugin-2.1.jar" --teach mc.plugin
python file_sorter.py --corrections        # list
python file_sorter.py --forget "MyPlugin*" # hatao
```

Pattern + label local file men save hota hai (`filesorter_corrections.json` ya `~/.filesorter/corrections.json`), weight 9.0 ke saath sab se pehle lagu hota hai. Ye file aap ki machine se bahar nahi jati.

---

## 8. "98% accuracy" — ab ehsaas nahi, naap hai

```bash
python benchmark.py            # 49 labelled fixtures (31 tuning + 18 holdout)
python benchmark.py --deep
python benchmark.py --json report.json
```

Output: overall accuracy, per-label precision/recall/F1, confusion matrix, aur har ghalat file poori wajah ke saath.

**Apni asli files par naapne ke liye** (yehi asli test hai):

```
corpus/mc.shaderpack/BSL_v8.2.zip
corpus/mc.resourcepack/Faithful32x.zip
corpus/dev.discordbot/MyBot.zip
corpus/misc.review/some-weird-file.zip     ← jo _Review men aana chahiye
python benchmark.py --real corpus
```

Folder ke naam hi ground truth hain (koi bhi `TAXONOMY` label, ya `*.review` = "flag hona chahiye").

Filhaal: **49/49 = 100.0%** synthetic + holdout par, fast aur `--deep` dono men (jab ye likha gaya). Ye corpus synthetic structures hain (aapke `FileSorter.zip` aur `FileSorter-exe.zip` ki asli listing samet) — apni files `corpus/` men daal kar benchmark chalaiye, tab aap dekhenge ke *aapke* data par kya score hai.

---

## 9. Privacy & safety

- Koi extraction nahi, koi temp file nahi, koi network call nahi (jab tak `--online`/`--ai` na dein).
- `--online` sirf SHA-1 hash bhejta hai; `--ai` sirf naam + structure.
- Zip-bomb guard (expansion ratio + entry count), path-traversal members sirf note hote hain.
- Credential scan: `.env`/`config.json` men Discord/Telegram/AWS/OpenAI keys ya private keys milen to **warning** milti hai — value kabhi output/report men nahi likhi jati, sirf "kis file men kya shape hai".
- Dry run default hai; `--apply` ke bagair kuch move nahi hota. Har run `_filesorter_undo.json` likhta hai → `--undo`.

---

## 10. Tests

```bash
python test_sorter.py      # 35 tests (unittest, koi dependency nahi)
python benchmark.py        # accuracy + per-label report
```

Tests wahi galtiyan pakadte hain jo pehle hui thi: wrapper folder wala project, single-exe zip, shaderpack vs resourcepack, plugin vs mod vs library jar, bots/extensions, collections, credential scan, bomb/traversal safety, plan→apply→undo.

---

## 11. Module map

```
file_sorter.py          CLI (dry run default, --apply par move)
run.bat                 Windows launcher
fsengine/
  model.py              taxonomy, Evidence/Candidate/Decision/Config
  budget.py             time/bytes/entry budgets + bomb & traversal guards
  magic.py              magic bytes, PE header/version-info, strings
  listing.py            Container (zip/tar/dir/nested bytes) + Listing
  readers.py            tolerant text decode, budgeted grep, class-marker scan
  knowledge.py          SAARA knowledge: path/text/bytecode/name signatures
  context.py            AnalysisContext (jo detector dekhta hai)
  detectors.py          stage 0-2 detectors
  descriptors.py        stage 3 (descriptor files)
  deepscan.py           stage 4-6 (content, bytecode, nested)
  fusion.py             evidence -> ranked decision (+ conflict policies)
  classify.py           iterative-deepening scheduler
  facts.py              observed-facts summary + AI payload
  media.py              image/audio/video/pdf probing
  corrections.py        "teach once" (local)
  ai_assist.py          optional Claude second opinion
  netkb.py              optional hash lookups + rule packs
  sorter.py             planning, apply, reports, undo
fixtures_builder.py     synthetic corpus (31 cases)
fixtures_holdout.py     independent holdout (18 cases)
benchmark.py            accuracy measurement
test_sorter.py          test suite
```

---

## 12. Known limitations (honest list)

- **RAR / 7z**: stdlib se khol nahi sakte → unke content par faisla nahi hota; naam ke hints + `_Review` (Windows par `7z.exe` mila to `--rules`-style plugin baad men add ho sakta hai).
- **Encrypted zips** ki listing nahi milti → `_Review`.
- Bytecode scan string-based hai (Java decompile nahi) — obfuscated mods men sirf descriptors/MANIFEST bacha hai.
- Bade archives (4000+ files, ~1 MB/s zip): default budget 4s per file; `--time-budget` se barha sakte hain.
- Synthetic corpus 100% hai; **asli** accuracy aapki `corpus/` se hi pata chalegi.
