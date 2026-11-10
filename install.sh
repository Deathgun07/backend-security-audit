#!/usr/bin/env bash
# install.sh — installs the backend-security-audit skill without Node (bash + curl or wget + tar).
# Installe le skill backend-security-audit sans Node.
#
#   curl -fsSL https://raw.githubusercontent.com/Deathgun07/backend-security-audit/main/install.sh | bash -s -- --ai cursor
#   ./install.sh --ai claude,codex [--global] [--force] [--dry-run] [--ref v1.3.0]
#   ./install.sh --list
set -euo pipefail

NAME="backend-security-audit"
REPO="Deathgun07/backend-security-audit"
REF="main"
AI=""; GLOBAL=false; FORCE=false; DRY=false; LIST=false

# Language: French if the system locale is French, English otherwise
case "${BSA_LANG:-${LC_ALL:-${LANG:-}}}" in fr*) FR=true ;; *) FR=false ;; esac
t() { if $FR; then printf '%s' "$2"; else printf '%s' "$1"; fi; }

# assistant|label|root|dir|file(optional, separate main instruction file)
PLATFORMS="claude|Claude Code|.claude|skills|
cursor|Cursor|.cursor|skills|
windsurf|Windsurf|.windsurf|skills|
codex|Codex CLI|.agents|skills|
gemini|Gemini CLI|.gemini|skills|
antigravity|Antigravity|.agents|skills|
copilot|GitHub Copilot|.github|prompts|$NAME.prompt.md
kiro|Kiro|.kiro|steering|
opencode|OpenCode|.opencode|skills|
roocode|Roo Code|.roo|skills|
kilocode|Kilo Code|.kilocode|skills|
continue|Continue|.continue|skills|
trae|Trae|.trae|skills|
qoder|Qoder|.qoder|skills|
codebuddy|CodeBuddy|.codebuddy|skills|
droid|Droid (Factory)|.factory|skills|
augment|Augment|.augment|skills|
warp|Warp|.warp|skills|
amazonq|Amazon Q Developer|.amazonq|rules|$NAME.md
universal|Agent Skills standard|.agents|skills|"

usage() {
  cat <<EOF
$NAME — $(t "installer for AI coding assistants" "installeur pour assistants IA")

  install.sh --ai <$(t "assistant" "assistant")>[,...] | --ai all  [--global] [--force] [--dry-run] [--ref <tag>]
  install.sh --list

$(t "Assistants" "Assistants") : $(echo "$PLATFORMS" | cut -d'|' -f1 | tr '\n' ' ')
$(t "Without --ai: detects assistant folders in the current directory, Claude Code by default." "Sans --ai : détecte les dossiers d'assistants du dossier courant, Claude Code par défaut.")
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --ai) AI="$2"; shift ;;
    --ai=*) AI="${1#--ai=}" ;;
    --global|-g) GLOBAL=true ;;
    --projet|--project) GLOBAL=false ;;
    --force|-f) FORCE=true ;;
    --dry-run) DRY=true ;;
    --ref) REF="$2"; shift ;;
    --list) LIST=true ;;
    -h|--help) usage; exit 0 ;;
    *) echo "$(t "Unknown option" "Option inconnue") : $1" >&2; usage; exit 1 ;;
  esac
  shift
done

BASE="$PWD"; $GLOBAL && BASE="$HOME"
row() { echo "$PLATFORMS" | grep "^$1|" || true; }

if $LIST; then
  echo "$PLATFORMS" | while IFS='|' read -r id label root dir file; do
    d="$BASE/$root/$dir/$NAME"; f="$BASE/$root/$dir/${file:-$NAME/SKILL.md}"
    if [ -e "$d" ] || [ -e "$f" ]; then mark="✔"; else mark=" "; fi
    printf '%s %-12s %-22s %s\n' "$mark" "$id" "$label" "$root/$dir/${file:-$NAME}"
  done
  exit 0
fi

# Targets
if [ "$AI" = "all" ]; then
  TARGETS="$(echo "$PLATFORMS" | cut -d'|' -f1)"
elif [ -n "$AI" ]; then
  TARGETS="$(echo "$AI" | tr ',' '\n' | tr 'A-Z' 'a-z')"
  for id in $TARGETS; do [ -n "$(row "$id")" ] || { echo "$(t "Unknown assistant" "Assistant inconnu") : $id" >&2; usage; exit 1; }; done
else
  TARGETS=""
  while IFS='|' read -r id label root dir file; do
    case "$id" in codex|antigravity|universal) continue ;; esac
    [ -d "$BASE/$root" ] && TARGETS="$TARGETS $id"
  done <<< "$PLATFORMS"
  { [ -d "$BASE/.agents" ] || [ -d "$BASE/.codex" ]; } && TARGETS="$TARGETS universal"
  if [ -z "$TARGETS" ]; then TARGETS="claude"; echo "$(t "No assistant detected: installing for Claude Code (use --ai to choose)." "Aucun assistant détecté : installation pour Claude Code (--ai pour choisir).")"
  else echo "$(t "Detected" "Détectés") :$TARGETS"; fi
fi

# Source: local clone if present, otherwise download the GitHub tarball
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || echo "")"
if [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/skills/$NAME/SKILL.md" ]; then
  SRC="$SCRIPT_DIR/skills/$NAME"
else
  TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
  URL="https://codeload.github.com/$REPO/tar.gz/$REF"
  if command -v curl >/dev/null; then curl -fsSL "$URL" -o "$TMP/src.tgz"
  elif command -v wget >/dev/null; then wget -qO "$TMP/src.tgz" "$URL"
  else echo "$(t "curl or wget is required" "curl ou wget est requis")" >&2; exit 1; fi
  tar -xzf "$TMP/src.tgz" -C "$TMP"
  SRC="$(find "$TMP" -maxdepth 3 -type d -path "*/skills/$NAME" | head -1)"
  [ -f "$SRC/SKILL.md" ] || { echo "$(t "Download failed" "Échec du téléchargement")" >&2; exit 1; }
fi

disp() { if $GLOBAL; then echo "${1/#$HOME/~}"; else echo "${1#"$BASE"/}"; fi; }

for id in $(echo "$TARGETS" | tr ' ' '\n' | awk 'NF && !s[$0]++'); do
  IFS='|' read -r _ label root dir file <<< "$(row "$id")"
  data="$BASE/$root/$dir/$NAME"
  main="$data/SKILL.md"; [ -n "$file" ] && main="$BASE/$root/$dir/$file"
  if { [ -e "$data" ] || [ -e "$main" ]; } && ! $FORCE; then
    echo "• $label : $(t "already installed, use --force to update" "déjà installé, --force pour mettre à jour") ($(disp "$data"))"; continue
  fi
  if $DRY; then echo "[dry-run] $label → $(disp "$main")"; continue; fi
  rm -rf "$data"; [ -n "$file" ] && rm -f "$main"
  mkdir -p "$(dirname "$data")"
  cp -r "$SRC" "$data"
  chmod +x "$data"/scripts/*.sh
  if [ -n "$file" ]; then
    rel="$root/$dir/$NAME"
    # Separate instruction file: point SKILL_DIR to the resources, adapt the frontmatter
    awk -v rel="$rel" -v keepdesc="$([ "$id" = copilot ] && echo 1 || echo 0)" '
      NR==1 && /^---$/ { fm=1; next }
      fm && /^---$/ { fm=0; if (keepdesc && desc!="") print "---\n" desc "\n---"; next }
      fm { if ($0 ~ /^description:/) desc=$0; next }
      { sub(/`SKILL_DIR` = [^.]*\./, "`SKILL_DIR` = `" rel "` (scripts/, checklists/, templates/)."); print }
    ' "$SRC/SKILL.md" > "$main"
    rm -f "$data/SKILL.md"
  fi
  echo "✔ $label → $(disp "$main")"
done

$DRY || echo "$(t "Ask your assistant: \"audit the security of this project\" (Claude Code: /$NAME)." "Demandez à votre assistant : « audite la sécurité de ce projet » (Claude Code : /$NAME).")"
