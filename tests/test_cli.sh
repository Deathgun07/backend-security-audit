#!/usr/bin/env bash
# test_cli.sh — installs the npm package (local tarball) and checks init/list/uninstall for several assistants, then install.sh.
set -uo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
ok=0; ko=0
check() { if eval "$2"; then ok=$((ok+1)); else ko=$((ko+1)); echo "FAIL: $1"; fi; }

TGZ="$(cd "$WORK" && npm pack "$REPO" --silent 2>/dev/null | tail -1)"
check "npm pack" "[ -f '$WORK/$TGZ' ]"
mkdir -p "$WORK/proj" "$WORK/home"
cd "$WORK/proj" || exit 1
CLI=(npx --yes --package "$WORK/$TGZ" backend-security-audit)
export HOME="$WORK/home" BSA_LANG=fr

"${CLI[@]}" init --ai claude,cursor,codex,copilot,kiro,amazonq >/dev/null
check "claude"   "[ -f .claude/skills/backend-security-audit/SKILL.md ] && [ -x .claude/skills/backend-security-audit/scripts/find_secrets.sh ]"
check "cursor"   "[ -f .cursor/skills/backend-security-audit/checklists/firebase.md ]"
check "codex"    "[ -f .agents/skills/backend-security-audit/SKILL.md ]"
check "copilot"  "[ -f .github/prompts/backend-security-audit.prompt.md ] && [ -f .github/prompts/backend-security-audit/scripts/scan_mysql.sql ] && [ ! -f .github/prompts/backend-security-audit/SKILL.md ]"
check "copilot frontmatter" "head -2 .github/prompts/backend-security-audit.prompt.md | grep -q '^description:' && ! grep -q '^name:' .github/prompts/backend-security-audit.prompt.md"
check "copilot SKILL_DIR"   "grep -q 'SKILL_DIR\` = \`.github/prompts/backend-security-audit\`' .github/prompts/backend-security-audit.prompt.md"
check "kiro"     "[ -f .kiro/steering/backend-security-audit/SKILL.md ]"
check "amazonq"  "[ -f .amazonq/rules/backend-security-audit.md ] && ! head -1 .amazonq/rules/backend-security-audit.md | grep -q '^---'"
check "no overwrite without --force" "\"\${CLI[@]}\" init --ai claude | grep -q 'déjà installé'"
check "list"     "\"\${CLI[@]}\" list | grep -q '✔ cursor'"
"${CLI[@]}" uninstall --ai cursor >/dev/null
check "uninstall" "[ ! -e .cursor/skills/backend-security-audit ] && [ -e .claude/skills/backend-security-audit ]"
"${CLI[@]}" init --ai gemini --global >/dev/null
check "global"   "[ -f '$WORK/home/.gemini/skills/backend-security-audit/SKILL.md' ]"
mkdir -p ../auto/.windsurf && cd ../auto && "${CLI[@]}" init >/dev/null
check "auto-detection" "[ -f .windsurf/skills/backend-security-audit/SKILL.md ] && [ ! -e .claude ]"
check "dry-run"  "\"\${CLI[@]}\" init --ai trae --dry-run | grep -q dry-run && [ ! -e .trae ]"

echo "CLI: $ok passed, $ko failed"

# ── install.sh (no Node)
ok2=$ok; ko2=$ko
mkdir -p "$WORK/sh" && cd "$WORK/sh" || exit 1
bash "$REPO/install.sh" --ai claude,copilot,amazonq >/dev/null
check "sh claude"  "[ -x .claude/skills/backend-security-audit/scripts/grep_patterns.sh ]"
check "sh copilot" "[ -f .github/prompts/backend-security-audit.prompt.md ] && head -2 .github/prompts/backend-security-audit.prompt.md | grep -q '^description:' && grep -q 'SKILL_DIR\` = \`.github/prompts/backend-security-audit\`' .github/prompts/backend-security-audit.prompt.md && [ ! -f .github/prompts/backend-security-audit/SKILL.md ]"
check "sh amazonq" "[ -f .amazonq/rules/backend-security-audit.md ] && ! head -1 .amazonq/rules/backend-security-audit.md | grep -q '^---'"
check "sh already installed (fr)" "grep -q 'déjà installé' <<< \"\$(BSA_LANG=fr bash '$REPO/install.sh' --ai claude)\""
check "sh already installed (en)" "grep -q 'already installed' <<< \"\$(BSA_LANG=en bash '$REPO/install.sh' --ai claude)\""
check "sh list" "grep -q '✔ copilot' <<< \"\$(bash '$REPO/install.sh' --list)\""
bash "$REPO/install.sh" --ai codex --global >/dev/null
check "sh global" "[ -f '$WORK/home/.agents/skills/backend-security-audit/SKILL.md' ]"
# curl | bash mode: script alone, downloads from GitHub
if [ "${OFFLINE:-0}" != 1 ]; then
  mkdir -p "$WORK/curl" && cp "$REPO/install.sh" "$WORK/curl/i.sh" && mkdir -p "$WORK/curlproj" && cd "$WORK/curlproj" || exit 1
  bash "$WORK/curl/i.sh" --ai cursor >/dev/null 2>&1
  check "sh GitHub download" "[ -f .cursor/skills/backend-security-audit/checklists/go.md ]"
fi
echo "install.sh: $((ok-ok2)) passed, $((ko-ko2)) failed"
echo "TOTAL: $ok passed, $ko failed"
[ "$ko" -eq 0 ]
