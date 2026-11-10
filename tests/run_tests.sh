#!/usr/bin/env bash
# run_tests.sh — checks that the skill scripts detect the known vulnerabilities of the fixture.
# Usage: bash tests/run_tests.sh   (Linux / macOS with bash ≥ 4 / WSL)
set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPTS="$REPO/skills/backend-security-audit/scripts"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

# Copy the fixture into a throwaway git repo + fake secrets built by concatenation
# (no string resembling a real key is stored in this repository).
cp -r "$REPO/tests/fixtures/app-vulnerable/." "$WORK/"
{
  echo "NEXT_PUBLIC_SUPABASE_URL=http://127.0.0.1:54321"
  echo "NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=faux"
  echo "STRIPE_SECRET_KEY=sk_""live_""FAUXFAUXFAUXFAUXFAUX0000"
} > "$WORK/.env"
git -C "$WORK" init -q && git -C "$WORK" add -A \
  && git -C "$WORK" -c user.name=test -c user.email=test@example.invalid commit -qm fixture

OUT="$WORK/.sortie"
{ bash "$SCRIPTS/detect_stack.sh" "$WORK"; bash "$SCRIPTS/find_secrets.sh" "$WORK"; bash "$SCRIPTS/grep_patterns.sh" "$WORK"; } > "$OUT" 2>&1

# Each line: expected pattern (grep -E regex) in the output
EXPECTED=(
  '"stacks": \["nextjs", "supabase", "pocketbase", "php-mysql", "flask", "fastapi", "django", "go", "node-express", "laravel", "firebase", "mysql"\]'
  '^\.env:3:stripe_sk_live:Critical'
  '^\.env:0:env_tracked_by_git:Critical'
  'env_in_git_history:Critical'
  '^\.env:2:secret_in_public_env:Critical'
  '^components/AdminPanel\.tsx:[0-9]+:secret_in_public_env:Critical'
  '^components/AdminPanel\.tsx:[0-9]+:service_role_client_side:Critical'
  '^components/AdminPanel\.tsx:[0-9]+:dangerouslySetInnerHTML'
  '^app/api/preview/route\.ts:[0-9]+:ssrf_fetch_user_url'
  '^middleware\.ts:[0-9]+:supabase_getSession_server'
  '^middleware\.ts:[0-9]+:middleware_matcher'
  '^middleware\.ts:[0-9]+:middleware_matcher_narrow:Medium'
  '^package\.json:[0-9]+:next_version_cve_2025_29927:High'
  '^supabase/migrations/.*:10:table_without_rls:Critical'
  '^\.gitignore:0:no_gitignore:Medium'
  '^app/actions\.ts:1:server_action_to_check'
  '^supabase/migrations/.*:8:policy_using_true:High'
  '^supabase/migrations/.*:with_check_true|policy_with_check_true'
  '^supabase/migrations/.*:security_definer:High'
  '^supabase/migrations/.*:grant_to_anon'
  '^supabase/migrations/.*:view_without_security_invoker:High'
  '^pb_migrations/.*:empty_api_rule_public:High'
  '^pb_migrations/.*:rule_auth_too_broad'
  '^pb_hooks/main\.pb\.js:[0-9]+:hook_sql_concat:High'
  '^pb_hooks/main\.pb\.js:[0-9]+:custom_route_to_check'
  '^php/config\.php:[0-9]+:hardcoded_db_credentials:High'
  '^php/config\.php:[0-9]+:display_errors_on'
  '^php/login\.php:[0-9]+:sql_concat_or_interpolated:High'
  '^php/login\.php:[0-9]+:weak_password_hash:High'
  '^php/login\.php:[0-9]+:open_redirect'
  '^php/login\.php:[0-9]+:xss_echo_superglobal:High'
  '^php/upload\.php:[0-9]+:include_user_input:Critical'
  '^php/upload\.php:[0-9]+:client_supplied_mime'
  '^php/upload\.php:[0-9]+:upload_to_check'
  '^flask/app\.py:[0-9]+:debug_true:High'
  '^flask/app\.py:[0-9]+:hardcoded_secret_key:High'
  '^flask/app\.py:[0-9]+:sql_fstring:Critical'
  '^flask/app\.py:[0-9]+:ssti_render_template_string:High'
  '^flask/app\.py:[0-9]+:unsafe_pickle:High'
  '^flask/app\.py:[0-9]+:unsafe_yaml_load:High'
  '^flask/app\.py:[0-9]+:cors_wildcard'
  # Firebase
  '^firebase/firestore\.rules:[0-9]+:rule_if_true:Critical'
  '^firebase/firestore\.rules:[0-9]+:rule_test_mode_date:High'
  '^firebase/firestore\.rules:[0-9]+:rule_auth_only:High'
  '^firebase/storage\.rules:[0-9]+:rule_without_condition:Critical'
  '^firebase/database\.rules\.json:[0-9]+:rtdb_rule_true:Critical'
  '^firebase/database\.rules\.json:[0-9]+:rtdb_auth_only:High'
  '^firebase/functions/index\.js:[0-9]+:http_function_to_check'
  # MySQL
  '^mysql/init\.sql:[0-9]+:user_without_password:Critical'
  '^mysql/init\.sql:[0-9]+:grant_all_global:High'
  '^mysql/init\.sql:[0-9]+:weak_password_hash_sql:High'
  '^mysql/init\.sql:[0-9]+:dynamic_sql_procedure'
  '^mysql/docker-compose\.yml:[0-9]+:weak_root_password:High'
  '^mysql/docker-compose\.yml:[0-9]+:port_3306_published'
  '^mysql/docker-compose\.yml:[0-9]+:db_admin_exposed'
  '^express/server\.js:[0-9]+:multiple_statements'
  # Django
  '^django/shop/settings\.py:[0-9]+:debug_true:High'
  '^django/shop/settings\.py:[0-9]+:allowed_hosts_wildcard'
  '^django/shop/settings\.py:[0-9]+:permission_allowany:High'
  '^django/shop/settings\.py:[0-9]+:weak_password_hasher:High'
  '^django/shop/views\.py:[0-9]+:sql_raw_interpolated:Critical'
  '^django/shop/views\.py:[0-9]+:csrf_exempt'
  '^django/shop/views\.py:[0-9]+:fields_all'
  '^django/shop/settings\.py:[0-9]+:django_secret_key:High'
  # Go
  '^go/main\.go:[0-9]+:sql_sprintf_or_concat:Critical'
  '^go/main\.go:[0-9]+:shell_command:High'
  '^go/main\.go:[0-9]+:path_traversal:High'
  '^go/main\.go:[0-9]+:ssrf_user_url'
  '^go/main\.go:[0-9]+:server_without_timeouts'
  # Node / Express
  '^express/server\.js:[0-9]+:sql_concatenated:Critical'
  '^express/server\.js:[0-9]+:nosql_raw_request:High'
  '^express/server\.js:[0-9]+:mass_assignment:High'
  '^express/server\.js:[0-9]+:path_traversal:High'
  '^express/server\.js:[0-9]+:hardcoded_jwt_secret:High'
  '^express/server\.js:[0-9]+:cors_open'
  # Laravel
  '^laravel/app/Http/Controllers/ProductController\.php:[0-9]+:raw_query_interpolated:Critical'
  '^laravel/app/Http/Controllers/ProductController\.php:[0-9]+:mass_assignment_request_all:High'
  '^laravel/app/Http/Controllers/ProductController\.php:[0-9]+:upload_client_filename:High'
  '^laravel/app/Models/Product\.php:[0-9]+:empty_guarded'
  '^laravel/resources/views/product\.blade\.php:[0-9]+:blade_unescaped'
  '^laravel/routes/web\.php:[0-9]+:without_auth_middleware'
  # Block-level checks (missing auth)
  '^go/main\.go:22:go_auth_response_without_return:Critical'
  '^go/main\.go:[0-9]+:jwt_parse_error_ignored:Critical'
  '^fastapi/main\.py:13:write_endpoint_without_auth:High'
  '^flask/app\.py:19:write_endpoint_without_auth:High'
  '^firebase/functions/index\.js:5:cloud_function_without_auth:High'
  '^firebase/functions/index\.js:9:cloud_function_without_auth:High'
  '^express/server\.js:23:write_route_without_middleware:Medium'
  # FastAPI
  '^fastapi/main\.py:[0-9]+:jwt_unverified:Critical'
  '^fastapi/main\.py:[0-9]+:cors_wildcard_credentials:High'
  '^fastapi/main\.py:[0-9]+:sql_fstring:Critical'
)

ok=0; ko=0
for e in "${EXPECTED[@]}"; do
  if grep -qE -- "$e" "$OUT"; then ok=$((ok+1)); else ko=$((ko+1)); echo "FAIL: $e"; fi
done

# False-positive guard: the block-level checks must stay silent on correct code
FP="$(bash "$SCRIPTS/grep_patterns.sh" "$REPO/tests/fixtures/app-safe" 2>&1 | grep -E 'without_return|parse_error_ignored|without_auth|without_middleware')"
if [ -z "$FP" ]; then ok=$((ok+1)); else ko=$((ko+1)); echo "FAIL: false positives on app-safe:"; echo "$FP"; fi
# Express /login (public by nature) must not be flagged
if grep -q '^express/server\.js:13:write_route_without_middleware' "$OUT"; then ko=$((ko+1)); echo "FAIL: /login flagged"; else ok=$((ok+1)); fi

# No duplicate lines in the output
if [ -z "$(grep -E '^[^ #].*:[0-9]+:[a-z0-9_]+:(Critical|High|Medium|Low|Info)$' "$OUT" | sort | uniq -d)" ]; then ok=$((ok+1)); else ko=$((ko+1)); echo "FAIL: duplicate lines in the output"; fi

# Secret values must never appear in the output
if grep -q 'FAUXFAUX' "$OUT"; then ko=$((ko+1)); echo "FAIL: a secret value appears in the output"; else ok=$((ok+1)); fi

echo "$ok passed, $ko failed"
[ "${VERBOSE:-0}" = 1 ] && cat "$OUT"
[ "$ko" -eq 0 ]
