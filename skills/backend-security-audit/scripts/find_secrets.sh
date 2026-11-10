#!/usr/bin/env bash
# find_secrets.sh — cherche des secrets en dur, des .env suivis par git et des traces dans l'historique.
# Usage : find_secrets.sh [dossier_projet]
# Sortie : fichier:ligne:type:sévérité   (la valeur du secret n'est JAMAIS affichée)
# Dépendances : bash, grep, git (optionnel), ripgrep (optionnel, plus rapide). Lecture seule.
set -uo pipefail

ROOT="${1:-.}"
cd "$ROOT" 2>/dev/null || { echo "dossier introuvable : $ROOT" >&2; exit 1; }

EXCL_DIRS=(node_modules vendor .git .next dist build venv .venv __pycache__ pb_data coverage .claude)
# Fichiers bruités : lockfiles, sources minifiées, exemples d'env
EXCL_FILES=('*.lock' 'bun.lockb' 'package-lock.json' 'pnpm-lock.yaml' 'yarn.lock' 'composer.lock' '*.min.js' '*.map' '.env.example' '.env.sample' '.env.template' 'SECURITY_AUDIT.md')

HAS_RG=false; command -v rg >/dev/null 2>&1 && HAS_RG=true

# scan <type> <sévérité> <regex ERE> [i]  → imprime fichier:ligne:type:sévérité
scan() {
  local type="$1" sev="$2" re="$3" ci="${4:-}" args=()
  if $HAS_RG; then
    args=(-n --no-heading --hidden -o -e "$re")
    [ "$ci" = i ] && args+=(-i)
    for d in "${EXCL_DIRS[@]}"; do args+=(-g "!$d/"); done
    for f in "${EXCL_FILES[@]}"; do args+=(-g "!$f"); done
    rg "${args[@]}" . 2>/dev/null
  else
    args=(-rnoE -I)
    [ "$ci" = i ] && args+=(-i)
    for d in "${EXCL_DIRS[@]}"; do args+=(--exclude-dir="$d"); done
    for f in "${EXCL_FILES[@]}"; do args+=(--exclude="$f"); done
    grep "${args[@]}" -e "$re" . 2>/dev/null
  fi | cut -d: -f1,2 | sort -u | sed 's|^\./||' | while IFS= read -r loc; do printf '%s:%s:%s\n' "$loc" "$type" "$sev"; done
}

echo "### Secrets en dur dans les fichiers"
scan "cle_privee"            Critique '-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY'
scan "stripe_sk_live"        Critique '(sk|rk)_live_[0-9a-zA-Z]{16,}'
scan "stripe_sk_test"        Basse    'sk_test_[0-9a-zA-Z]{16,}'
scan "aws_access_key"        Critique 'AKIA[0-9A-Z]{16}'
scan "github_token"          Critique 'gh[pousr]_[A-Za-z0-9]{36,}'
scan "slack_token"           Haute    'xox[abprs]-[A-Za-z0-9-]{10,}'
scan "google_api_key"        Moyenne  'AIza[0-9A-Za-z_-]{35}'
scan "openai_anthropic_key"  Critique 'sk-(ant-|proj-)?[A-Za-z0-9_-]{32,}'
scan "firebase_compte_service" Critique '"type"\s*:\s*"service_account"'
scan "django_secret_key"     Haute    'django-insecure-[A-Za-z0-9!@#$%^&*(=+_-]{20,}'
scan "laravel_app_key"       Haute    'APP_KEY=base64:[A-Za-z0-9+/=]{30,}'
scan "jwt_a_decoder"         Haute    'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'
scan "supabase_secret_key"   Critique 'sb_secret_[A-Za-z0-9_-]{20,}'
scan "url_bdd_avec_mdp"      Haute    '(postgres(ql)?|mysql|mariadb|mongodb(\+srv)?|redis|amqp)://[^:/"'"'"' ]+:[^@"'"'"' ]{3,}@'
scan "mdp_ou_cle_en_dur"     Haute    '(password|passwd|pwd|mot_?de_?passe|mdp|secret|api_?key|access_?token|auth_?token|client_secret)["'"'"']?\s*[:=]>?\s*["'"'"'][^"'"'"'${}<>\s]{6,}["'"'"']' i
scan "secret_key_flask"      Haute    'SECRET_KEY["'"'"'\]]*\s*=\s*["'"'"'][^"'"'"']+["'"'"']'

echo
echo "### Fichiers .env suivis par git"
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  PREFIX="$(git rev-parse --show-prefix)"
  git ls-files -- . | grep -E '(^|/)\.env(\.[A-Za-z0-9_-]+)?$' | grep -vE '\.(example|sample|template|dist)$' \
    | while read -r f; do echo "${f#"$PREFIX"}:0:env_suivi_par_git:Critique"; done
  # .env présent mais non ignoré
  for f in $(find . -maxdepth 3 -name '.env*' -not -path '*/node_modules/*' -type f 2>/dev/null | grep -vE '\.(example|sample|template|dist)$'); do
    git check-ignore -q "$f" || echo "${f#./}:0:env_non_ignore_par_gitignore:Haute"
  done

  echo
  echo "### Historique git (commits ayant ajouté/supprimé un secret)"
  # Fichiers .env ajoutés un jour dans l'historique (même supprimés depuis)
  git log --all --diff-filter=A --name-only --pretty=format:'%h' -- . 2>/dev/null \
    | awk '/^[0-9a-f]{7,}$/{c=$0;next} /(^|\/)\.env(\.[A-Za-z0-9_-]+)?$/ && !/\.(example|sample|template|dist)$/ {print $0":commit "c":env_dans_historique:Critique"}'
  # Motifs à forte confiance dans les diffs (limité à 500 commits)
  for pat in '(sk|rk)_live_[0-9a-zA-Z]{16,}' 'AKIA[0-9A-Z]{16}' 'PRIVATE KEY-----' 'sb_secret_[A-Za-z0-9_-]{20,}' 'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.' 'gh[pousr]_[A-Za-z0-9]{36,}'; do
    git log --all -E -G"$pat" --max-count=500 --pretty=format:'%h' -- . 2>/dev/null \
      | while read -r c; do [ -n "$c" ] && echo "commit $c:0:historique_motif[$pat]:Haute"; done
  done
else
  echo "(pas un dépôt git — étape ignorée)"
fi
