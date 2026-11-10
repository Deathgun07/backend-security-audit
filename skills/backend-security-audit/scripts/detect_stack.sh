#!/usr/bin/env bash
# detect_stack.sh — detects a project's backend stacks and prints the result as JSON.
# Usage: detect_stack.sh [project_dir]   (default: current directory)
# Requires: bash, find, grep. Read-only.
set -uo pipefail

ROOT="${1:-.}"
ROOT="$(cd "$ROOT" 2>/dev/null && pwd)" || { echo '{"error":"directory not found"}'; exit 1; }

# Directories ignored everywhere (dependencies, builds, data)
PRUNE=( -name node_modules -o -name vendor -o -name .git -o -name .next -o -name dist -o -name build
        -o -name venv -o -name .venv -o -name __pycache__ -o -name pb_data -o -name coverage -o -name .claude )

# Finds files by name (depth 4), returns relative paths
find_files() { find "$ROOT" -maxdepth 4 \( "${PRUNE[@]}" \) -prune -o -type f \( "$@" \) -print 2>/dev/null | sed "s|^$ROOT/||"; }
find_dirs()  { find "$ROOT" -maxdepth 3 \( "${PRUNE[@]}" \) -prune -o -type d \( "$@" \) -print 2>/dev/null | sed "s|^$ROOT/||"; }
# True if one of the files contains the pattern
any_contains() { local pat="$1"; shift; for f in "$@"; do [ -f "$ROOT/$f" ] && grep -qiE "$pat" "$ROOT/$f" && return 0; done; return 1; }

declare -a STACKS=() INDICES=()
add() { STACKS+=("$1"); INDICES+=("\"$1\": \"$2\""); }

mapfile -t PKG   < <(find_files -name package.json)
mapfile -t COMP  < <(find_files -name composer.json)
mapfile -t PYREQ < <(find_files -name requirements.txt -o -name pyproject.toml -o -name Pipfile -o -name setup.py)

# --- Next.js
if any_contains '"next"\s*:' "${PKG[@]}" || [ -n "$(find_files -name 'next.config.*' | head -1)" ]; then
  add nextjs "package.json (next) or next.config.*"
fi

# --- Supabase
SUPA_DIR="$(find_dirs -name supabase | head -1)"
if [ -n "$SUPA_DIR" ] || any_contains '@supabase/|supabase' "${PKG[@]}" "${PYREQ[@]}" "${COMP[@]}"; then
  add supabase "${SUPA_DIR:-supabase dependency}"
fi

# --- PocketBase
PB_DIR="$(find_dirs -name pb_migrations -o -name pb_hooks | head -1)"
if [ -n "$PB_DIR" ] || any_contains '"pocketbase"\s*:|pocketbase' "${PKG[@]}" "${PYREQ[@]}"; then
  add pocketbase "${PB_DIR:-pocketbase dependency}"
fi

# --- PHP / MySQL
PHP_COUNT="$(find_files -name '*.php' | wc -l)"
if [ "${#COMP[@]}" -gt 0 ] || [ "$PHP_COUNT" -gt 0 ]; then
  add php-mysql "composer.json=${#COMP[@]}, .php files=$PHP_COUNT"
fi

# --- Flask
if any_contains '(^|[^a-z])flask' "${PYREQ[@]}" \
   || grep -rqlE --include='*.py' --exclude-dir={venv,.venv,node_modules,__pycache__} '^\s*(from flask import|import flask)' "$ROOT" 2>/dev/null; then
  add flask "requirements/pyproject or import flask"
fi

# --- FastAPI
if any_contains '(^|[^a-z])fastapi' "${PYREQ[@]}" \
   || grep -rqlE --include='*.py' --exclude-dir={venv,.venv,node_modules,__pycache__} '^\s*from fastapi import' "$ROOT" 2>/dev/null; then
  add fastapi "requirements/pyproject or import fastapi"
fi

# --- Django
if [ -n "$(find_files -name manage.py | head -1)" ] || any_contains '(^|[^a-z_-])django([^a-z_-]|$)' "${PYREQ[@]}"; then
  add django "manage.py or django dependency"
fi

# --- Go
mapfile -t GOMOD < <(find_files -name go.mod)
[ "${#GOMOD[@]}" -gt 0 ] && add go "${GOMOD[0]}"

# --- Node.js backend (hors Next.js)
if any_contains '"(express|fastify|koa|hono|@nestjs/core|@hapi/hapi|restify)"\s*:' "${PKG[@]}"; then
  add node-express "package.json (express/fastify/koa/hono/nestjs)"
fi

# --- Laravel
if any_contains 'laravel/framework' "${COMP[@]}" || [ -n "$(find_files -name artisan | head -1)" ]; then
  add laravel "composer.json (laravel/framework) or artisan"
fi

# --- Firebase
FB_FILE="$(find_files -name firebase.json -o -name firestore.rules -o -name storage.rules -o -name database.rules.json -o -name .firebaserc | head -1)"
if [ -n "$FB_FILE" ] || any_contains '"(firebase|firebase-admin|firebase-functions)"\s*:|firebase[-_]admin' "${PKG[@]}" "${PYREQ[@]}"; then
  add firebase "${FB_FILE:-firebase dependency}"
fi

# --- MySQL / MariaDB (the database itself, whatever the language)
mapfile -t COMPOSE < <(find_files -name 'docker-compose*.yml' -o -name 'docker-compose*.yaml' -o -name 'compose.yml' -o -name 'compose.yaml')
mapfile -t CNF < <(find_files -name '*.cnf')
mapfile -t SQLF < <(find_files -name '*.sql' | head -50)
mapfile -t ENVS < <(find_files -name '.env*')
if any_contains 'image:\s*["'"'"']?(mysql|mariadb|bitnami/mysql|bitnami/mariadb)' "${COMPOSE[@]}" \
   || [ "${#CNF[@]}" -gt 0 ] \
   || any_contains '"(mysql|mysql2|mariadb)"\s*:|pymysql|mysqlclient|mysql-connector|aiomysql' "${PKG[@]}" "${PYREQ[@]}" \
   || any_contains 'go-sql-driver/mysql' "${GOMOD[@]}" \
   || any_contains 'ENGINE\s*=\s*(InnoDB|MyISAM)|AUTO_INCREMENT' "${SQLF[@]}" \
   || any_contains '^DB_CONNECTION=mysql|mysql://|DATABASE_URL=.?mysql' "${ENVS[@]}" \
   || grep -rqlE --include='*.php' --exclude-dir={vendor,node_modules} '(mysqli_connect|new\s+mysqli|mysql:host=)' "$ROOT" 2>/dev/null; then
  add mysql "docker-compose / dependency / schema / MySQL DSN"
fi

# --- Available dependency audit tools
tools=()
for t in bun npm composer pip-audit govulncheck psql mysql rg git; do command -v "$t" >/dev/null 2>&1 && tools+=("\"$t\""); done

# --- Lockfiles (to pick the audit tool)
mapfile -t LOCKS < <(find_files -name bun.lock -o -name bun.lockb -o -name package-lock.json -o -name pnpm-lock.yaml -o -name yarn.lock -o -name composer.lock -o -name poetry.lock -o -name go.sum -o -name Pipfile.lock)

json_list() { local out="" x; for x in "$@"; do out+="${out:+, }\"$x\""; done; printf '[%s]' "$out"; }
join_by_comma() { local out="" x; for x in "$@"; do out+="${out:+, }$x"; done; printf '%s' "$out"; }

GIT=false; git -C "$ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1 && GIT=true
GIT_ROOT="$($GIT && git -C "$ROOT" rev-parse --show-toplevel)"

cat <<EOF
{
  "root": "$ROOT",
  "git": $GIT,
  "git_root": "${GIT_ROOT}",
  "stacks": $(json_list "${STACKS[@]}"),
  "evidence": { $(join_by_comma "${INDICES[@]}") },
  "lockfiles": $(json_list "${LOCKS[@]}"),
  "available_tools": [ $(join_by_comma "${tools[@]}") ]
}
EOF
