#!/usr/bin/env bash
# find_secrets.sh — looks for hardcoded secrets, .env files tracked by git and traces in git history.
# Usage: find_secrets.sh [project_dir]
# Output: file:line:type:severity   (the secret value is NEVER printed)
# Requires: bash, grep, git (optional), ripgrep (optional, faster). Read-only.
set -uo pipefail

ROOT="${1:-.}"
cd "$ROOT" 2>/dev/null || { echo "directory not found: $ROOT" >&2; exit 1; }

EXCL_DIRS=(node_modules vendor .git .next dist build venv .venv __pycache__ pb_data coverage .claude)
# Noisy files: lockfiles, minified sources, env examples
EXCL_FILES=('*.lock' 'bun.lockb' 'package-lock.json' 'pnpm-lock.yaml' 'yarn.lock' 'composer.lock' '*.min.js' '*.map' '.env.example' '.env.sample' '.env.template' 'SECURITY_AUDIT.md')

HAS_RG=false; command -v rg >/dev/null 2>&1 && HAS_RG=true

# scan <type> <severity> <ERE regex> [i]  → prints file:line:type:severity
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

echo "### Hardcoded secrets in files"
scan "private_key"            Critical '-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY'
scan "stripe_sk_live"        Critical '(sk|rk)_live_[0-9a-zA-Z]{16,}'
scan "stripe_sk_test"        Low    'sk_test_[0-9a-zA-Z]{16,}'
scan "aws_access_key"        Critical 'AKIA[0-9A-Z]{16}'
scan "github_token"          Critical 'gh[pousr]_[A-Za-z0-9]{36,}'
scan "slack_token"           High    'xox[abprs]-[A-Za-z0-9-]{10,}'
scan "google_api_key"        Medium  'AIza[0-9A-Za-z_-]{35}'
scan "openai_anthropic_key"  Critical 'sk-(ant-|proj-)?[A-Za-z0-9_-]{32,}'
scan "firebase_service_account" Critical '"type"\s*:\s*"service_account"'
scan "django_secret_key"     High    'django-insecure-[A-Za-z0-9!@#$%^&*(=+_-]{20,}'
scan "laravel_app_key"       High    'APP_KEY=base64:[A-Za-z0-9+/=]{30,}'
scan "jwt_to_decode"         High    'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'
scan "supabase_secret_key"   Critical 'sb_secret_[A-Za-z0-9_-]{20,}'
scan "db_url_with_password"      High    '(postgres(ql)?|mysql|mariadb|mongodb(\+srv)?|redis|amqp)://[^:/"'"'"' ]+:[^@"'"'"' ]{3,}@'
scan "hardcoded_password_or_key"     High    '(password|passwd|pwd|mot_?de_?passe|mdp|secret|api_?key|access_?token|auth_?token|client_secret)["'"'"']?\s*[:=]>?\s*["'"'"'][^"'"'"'${}<>\s]{6,}["'"'"']' i
scan "secret_key_flask"      High    'SECRET_KEY["'"'"'\]]*\s*=\s*["'"'"'][^"'"'"']+["'"'"']'

echo
echo "### .env files tracked by git"
[ -f .gitignore ] || echo ".gitignore:0:no_gitignore:Medium"
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  PREFIX="$(git rev-parse --show-prefix)"
  git ls-files -- . | grep -E '(^|/)\.env(\.[A-Za-z0-9_-]+)?$' | grep -vE '\.(example|sample|template|dist)$' \
    | while read -r f; do echo "${f#"$PREFIX"}:0:env_tracked_by_git:Critical"; done
  # .env present but not ignored
  for f in $(find . -maxdepth 3 -name '.env*' -not -path '*/node_modules/*' -type f 2>/dev/null | grep -vE '\.(example|sample|template|dist)$'); do
    git check-ignore -q "$f" || echo "${f#./}:0:env_not_gitignored:High"
  done

  echo
  echo "### Git history (commits that added/removed a secret)"
  # .env files added at some point in history (even if deleted since)
  git log --all --diff-filter=A --name-only --pretty=format:'%h' -- . 2>/dev/null \
    | awk '/^[0-9a-f]{7,}$/{c=$0;next} /(^|\/)\.env(\.[A-Za-z0-9_-]+)?$/ && !/\.(example|sample|template|dist)$/ {print $0":commit "c":env_in_git_history:Critical"}'
  # High-confidence patterns in diffs (limited to 500 commits)
  for pat in '(sk|rk)_live_[0-9a-zA-Z]{16,}' 'AKIA[0-9A-Z]{16}' 'PRIVATE KEY-----' 'sb_secret_[A-Za-z0-9_-]{20,}' 'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.' 'gh[pousr]_[A-Za-z0-9]{36,}'; do
    git log --all -E -G"$pat" --max-count=500 --pretty=format:'%h' -- . 2>/dev/null \
      | while read -r c; do [ -n "$c" ] && echo "commit $c:0:history_pattern[$pat]:High"; done
  done
else
  echo "(not a git repository: step skipped)"
fi
