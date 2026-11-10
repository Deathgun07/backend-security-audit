#!/usr/bin/env bash
# install.sh — installe le skill sans passer par le système de plugins.
#   ./install.sh            → ~/.claude/skills/ (disponible dans tous les projets)
#   ./install.sh --projet   → ./.claude/skills/ du dossier courant (à committer avec le projet)
set -euo pipefail
SRC="$(cd "$(dirname "$0")" && pwd)/skills/backend-security-audit"
case "${1:-}" in
  --projet|--project) DEST="$PWD/.claude/skills" ;;
  ""|--global)        DEST="$HOME/.claude/skills" ;;
  *) echo "Usage : $0 [--global|--projet]" >&2; exit 1 ;;
esac
mkdir -p "$DEST"
if [ -e "$DEST/backend-security-audit" ]; then
  echo "Mise à jour de $DEST/backend-security-audit"
  rm -rf "$DEST/backend-security-audit"
fi
cp -r "$SRC" "$DEST/"
chmod +x "$DEST/backend-security-audit/scripts/"*.sh
echo "Installé dans $DEST/backend-security-audit — relancez Claude Code puis tapez /backend-security-audit"
