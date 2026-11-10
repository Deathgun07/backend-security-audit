#!/usr/bin/env bash
# test_cli.sh — installe le paquet npm (tarball local) puis vérifie init/list/uninstall sur plusieurs assistants.
set -uo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
ok=0; ko=0
check() { if eval "$2"; then ok=$((ok+1)); else ko=$((ko+1)); echo "ÉCHEC : $1"; fi; }

TGZ="$(cd "$WORK" && npm pack "$REPO" --silent 2>/dev/null | tail -1)"
check "npm pack" "[ -f '$WORK/$TGZ' ]"
mkdir -p "$WORK/proj" "$WORK/home"
cd "$WORK/proj"
CLI=(npx --yes --package "$WORK/$TGZ" backend-security-audit)
export HOME="$WORK/home"

"${CLI[@]}" init --ai claude,cursor,codex,copilot,kiro,amazonq >/dev/null
check "claude"   "[ -f .claude/skills/backend-security-audit/SKILL.md ] && [ -x .claude/skills/backend-security-audit/scripts/find_secrets.sh ]"
check "cursor"   "[ -f .cursor/skills/backend-security-audit/checklists/firebase.md ]"
check "codex"    "[ -f .agents/skills/backend-security-audit/SKILL.md ]"
check "copilot"  "[ -f .github/prompts/backend-security-audit.prompt.md ] && [ -f .github/prompts/backend-security-audit/scripts/scan_mysql.sql ] && [ ! -f .github/prompts/backend-security-audit/SKILL.md ]"
check "copilot frontmatter" "head -2 .github/prompts/backend-security-audit.prompt.md | grep -q '^description:' && ! grep -q '^name:' .github/prompts/backend-security-audit.prompt.md"
check "copilot SKILL_DIR"   "grep -q 'SKILL_DIR\` = \`.github/prompts/backend-security-audit\`' .github/prompts/backend-security-audit.prompt.md"
check "kiro"     "[ -f .kiro/steering/backend-security-audit/SKILL.md ]"
check "amazonq"  "[ -f .amazonq/rules/backend-security-audit.md ] && ! head -1 .amazonq/rules/backend-security-audit.md | grep -q '^---'"
check "pas d'écrasement sans --force" "\"\${CLI[@]}\" init --ai claude | grep -q 'déjà installé'"
check "list"     "\"\${CLI[@]}\" list | grep -q '✔ cursor'"
"${CLI[@]}" uninstall --ai cursor >/dev/null
check "uninstall" "[ ! -e .cursor/skills/backend-security-audit ] && [ -e .claude/skills/backend-security-audit ]"
"${CLI[@]}" init --ai gemini --global >/dev/null
check "global"   "[ -f '$WORK/home/.gemini/skills/backend-security-audit/SKILL.md' ]"
mkdir -p ../auto/.windsurf && cd ../auto && "${CLI[@]}" init >/dev/null
check "détection auto" "[ -f .windsurf/skills/backend-security-audit/SKILL.md ] && [ ! -e .claude ]"
check "dry-run"  "\"\${CLI[@]}\" init --ai trae --dry-run | grep -q dry-run && [ ! -e .trae ]"

echo "$ok réussis, $ko échoués"
[ "$ko" -eq 0 ]
