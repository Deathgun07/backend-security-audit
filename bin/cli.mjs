#!/usr/bin/env node
// CLI d'installation du skill backend-security-audit pour différents assistants IA.
// Aucune dépendance : Node ≥ 18. Copie skills/backend-security-audit/ dans le dossier de l'assistant choisi.
import { cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync, chmodSync, readdirSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const NAME = "backend-security-audit";
const PKG_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const SRC = join(PKG_ROOT, "skills", NAME);
const VERSION = JSON.parse(readFileSync(join(PKG_ROOT, "package.json"), "utf8")).version;

// root : dossier de l'assistant ; dir : sous-dossier des skills ;
// file : si défini, l'instruction principale est un fichier séparé (les ressources vont dans dir/NAME) ;
// fm : "full" (frontmatter name+description), "description" (description seule), "none".
const PLATFORMS = {
  claude:      { label: "Claude Code",             root: ".claude",    dir: "skills" },
  cursor:      { label: "Cursor",                  root: ".cursor",    dir: "skills" },
  windsurf:    { label: "Windsurf",                root: ".windsurf",  dir: "skills" },
  codex:       { label: "Codex CLI",               root: ".agents",    dir: "skills" },
  gemini:      { label: "Gemini CLI",              root: ".gemini",    dir: "skills" },
  antigravity: { label: "Antigravity",             root: ".agents",    dir: "skills" },
  copilot:     { label: "GitHub Copilot",          root: ".github",    dir: "prompts", file: `${NAME}.prompt.md`, fm: "description" },
  kiro:        { label: "Kiro",                    root: ".kiro",      dir: "steering" },
  opencode:    { label: "OpenCode",                root: ".opencode",  dir: "skills" },
  roocode:     { label: "Roo Code",                root: ".roo",       dir: "skills" },
  kilocode:    { label: "Kilo Code",               root: ".kilocode",  dir: "skills" },
  continue:    { label: "Continue",                root: ".continue",  dir: "skills" },
  trae:        { label: "Trae",                    root: ".trae",      dir: "skills" },
  qoder:       { label: "Qoder",                   root: ".qoder",     dir: "skills" },
  codebuddy:   { label: "CodeBuddy",               root: ".codebuddy", dir: "skills" },
  droid:       { label: "Droid (Factory)",         root: ".factory",   dir: "skills" },
  augment:     { label: "Augment",                 root: ".augment",   dir: "skills" },
  warp:        { label: "Warp",                    root: ".warp",      dir: "skills" },
  amazonq:     { label: "Amazon Q Developer",      root: ".amazonq",   dir: "rules", file: `${NAME}.md`, fm: "none" },
  universal:   { label: "Standard Agent Skills",   root: ".agents",    dir: "skills" },
};

// Langue : français si la locale système est française (ou BSA_LANG=fr), anglais sinon
const FR = /^fr/i.test(process.env.BSA_LANG || process.env.LC_ALL || process.env.LANG || Intl.DateTimeFormat().resolvedOptions().locale || "");
const t = (en, fr) => (FR ? fr : en);

const c = process.stdout.isTTY ? { g: (s) => `\x1b[32m${s}\x1b[0m`, y: (s) => `\x1b[33m${s}\x1b[0m`, r: (s) => `\x1b[31m${s}\x1b[0m`, b: (s) => `\x1b[1m${s}\x1b[0m` }
                                : { g: (s) => s, y: (s) => s, r: (s) => s, b: (s) => s };

function help() {
  console.log(`${c.b(NAME)} v${VERSION} : ${t("backend security audit skill for AI coding assistants", "audit de sécurité backend pour assistants IA")}

${t("Usage", "Usage")} :
  npx ${NAME} init [--ai <assistant>[,…] | --ai all] [--global] [--force] [--dry-run]
  npx ${NAME} uninstall [--ai <assistant>] [--global]
  npx ${NAME} list
  (bunx / pnpm dlx / yarn dlx ${t("work the same way", "fonctionnent pareil")})

${t("Options", "Options")} :
  --ai       ${t("target assistant(s). Without --ai: detects existing folders (.claude, .cursor…),", "assistant(s) cible(s). Sans --ai : détection des dossiers présents (.claude, .cursor…),")}
             ${t("Claude Code by default if nothing is detected.", "Claude Code par défaut si rien n'est détecté.")}
  --global   ${t("install in your home folder (~/.claude/skills…) instead of the current project", "installe dans le dossier personnel (~/.claude/skills…) au lieu du projet courant")}
  --force    ${t("replace an existing installation (update)", "remplace une installation existante (mise à jour)")}
  --dry-run  ${t("show what would be done without writing anything", "affiche ce qui serait fait sans rien écrire")}

${t("Assistants", "Assistants")} : ${Object.keys(PLATFORMS).join(", ")}`);
}

function parseArgs(argv) {
  const o = { cmd: argv[0], ai: null, global: false, force: false, dry: false };
  for (let i = 1; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--ai") o.ai = argv[++i];
    else if (a.startsWith("--ai=")) o.ai = a.slice(5);
    else if (a === "--global" || a === "-g") o.global = true;
    else if (a === "--force" || a === "-f") o.force = true;
    else if (a === "--dry-run") o.dry = true;
    else { console.error(c.r(`${t("Unknown option", "Option inconnue")} : ${a}`)); process.exit(1); }
  }
  return o;
}

function resolveTargets(ai, base) {
  if (ai === "all") return Object.keys(PLATFORMS);
  if (ai) {
    const list = ai.split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);
    const bad = list.filter((p) => !PLATFORMS[p]);
    if (bad.length) { console.error(c.r(`${t("Unknown assistant", "Assistant inconnu")} : ${bad.join(", ")}`)); console.error(`${t("Available", "Disponibles")} : ${Object.keys(PLATFORMS).join(", ")}`); process.exit(1); }
    return list;
  }
  const found = Object.keys(PLATFORMS).filter((p) => !["universal", "antigravity", "codex"].includes(p) && existsSync(join(base, PLATFORMS[p].root)));
  if (existsSync(join(base, ".agents")) || existsSync(join(base, ".codex"))) found.push("universal");
  if (found.length) { console.log(`${t("Detected assistants", "Assistants détectés")} : ${found.join(", ")}`); return found; }
  console.log(t("No assistant detected: installing for Claude Code (use --ai to choose another one).", "Aucun assistant détecté : installation pour Claude Code (utilisez --ai pour en choisir un autre)."));
  return ["claude"];
}

// Chemins d'installation pour une plateforme
function paths(p, base) {
  const P = PLATFORMS[p];
  const dataDir = join(base, P.root, P.dir, NAME);
  const mainFile = P.file ? join(base, P.root, P.dir, P.file) : join(dataDir, "SKILL.md");
  return { P, dataDir, mainFile };
}

function rewriteSkill(md, P, dataDir, base) {
  if (!P.file) return md;
  // Instruction séparée de ses ressources : indiquer où sont scripts/ et checklists/
  const m = md.match(/^---\n([\s\S]*?)\n---\n/);
  const desc = m ? (m[1].match(/^description:\s*(.*)$/m) || [])[1] : "";
  let body = m ? md.slice(m[0].length) : md;
  const rel = relative(base, dataDir) || dataDir;
  body = body.replace(/`SKILL_DIR` = [^.]*\./, `\`SKILL_DIR\` = \`${rel}\` (scripts/, checklists/, templates/).`);
  if (P.fm === "description" && desc) return `---\ndescription: ${desc}\n---\n${body}`;
  return body;
}

function install(p, base, o) {
  const { P, dataDir, mainFile } = paths(p, base);
  const exists = existsSync(dataDir) || existsSync(mainFile);
  if (exists && !o.force) { console.log(`${c.y("•")} ${P.label} : ${t("already installed", "déjà installé")} (${relOrAbs(dataDir, base, o)}), ${t("use --force to update", "--force pour mettre à jour")}`); return; }
  if (o.dry) { console.log(`${c.y("[dry-run]")} ${P.label} → ${relOrAbs(dataDir, base, o)}${P.file ? ` + ${relOrAbs(mainFile, base, o)}` : ""}`); return; }
  if (exists) { rmSync(dataDir, { recursive: true, force: true }); if (P.file) rmSync(mainFile, { force: true }); }
  mkdirSync(dirname(dataDir), { recursive: true });
  cpSync(SRC, dataDir, { recursive: true });
  for (const f of readdirSync(join(dataDir, "scripts"))) if (f.endsWith(".sh")) chmodSync(join(dataDir, "scripts", f), 0o755);
  if (P.file) {
    const md = readFileSync(join(SRC, "SKILL.md"), "utf8");
    writeFileSync(mainFile, rewriteSkill(md, P, dataDir, base));
    rmSync(join(dataDir, "SKILL.md"), { force: true });
  }
  console.log(`${c.g("✔")} ${P.label} → ${relOrAbs(P.file ? mainFile : dataDir, base, o)}`);
}

function uninstall(p, base, o) {
  const { P, dataDir, mainFile } = paths(p, base);
  if (!existsSync(dataDir) && !existsSync(mainFile)) return false;
  if (o.dry) { console.log(`${c.y("[dry-run]")} ${t("remove", "suppression")} ${relOrAbs(dataDir, base, o)}`); return true; }
  rmSync(dataDir, { recursive: true, force: true });
  if (P.file) rmSync(mainFile, { force: true });
  console.log(`${c.g("✔")} ${P.label} : ${t("uninstalled", "désinstallé")}`);
  return true;
}

const relOrAbs = (pth, base, o) => (o.global ? pth.replace(homedir(), "~") : relative(base, pth));

const argv = process.argv.slice(2);
if (!argv.length || ["-h", "--help", "help"].includes(argv[0])) { help(); process.exit(0); }
if (["-v", "--version"].includes(argv[0])) { console.log(VERSION); process.exit(0); }

const o = parseArgs(argv);
const base = o.global ? homedir() : process.cwd();

switch (o.cmd) {
  case "init":
  case "install": {
    for (const p of [...new Set(resolveTargets(o.ai, base))]) install(p, base, o);
    if (!o.dry) console.log(t(`\nAsk your assistant: "audit the security of this project" (Claude Code: /${NAME}).`, `\nDans votre assistant, demandez : « audite la sécurité de ce projet » (Claude Code : /${NAME}).`));
    break;
  }
  case "uninstall":
  case "remove": {
    const targets = o.ai ? resolveTargets(o.ai, base) : Object.keys(PLATFORMS);
    const done = [...new Set(targets)].map((p) => uninstall(p, base, o)).some(Boolean);
    if (!done) console.log(t("Nothing to uninstall.", "Rien à désinstaller."));
    break;
  }
  case "list": {
    for (const [k, P] of Object.entries(PLATFORMS)) {
      const { dataDir, mainFile } = paths(k, base);
      const ok = existsSync(dataDir) || existsSync(mainFile);
      console.log(`${ok ? c.g("✔") : " "} ${k.padEnd(12)} ${P.label.padEnd(22)} ${P.root}/${P.dir}/${P.file || NAME}`);
    }
    break;
  }
  default:
    console.error(c.r(`${t("Unknown command", "Commande inconnue")} : ${o.cmd}`)); help(); process.exit(1);
}
