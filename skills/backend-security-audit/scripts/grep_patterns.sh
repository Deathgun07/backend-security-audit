#!/usr/bin/env bash
# grep_patterns.sh — flags dangerous code patterns per language/stack.
# Usage: grep_patterns.sh [project_dir] [stacks]
#   stacks: comma-separated list (nextjs,supabase,firebase,pocketbase,mysql,php-mysql,laravel,
#            flask,fastapi,django,go,node-express). Default: all.
# Output: file:line:pattern:severity   — these are LEADS, every line must be re-read.
# Requires: bash, grep (ripgrep used if present). Read-only.
set -uo pipefail

ROOT="${1:-.}"
STACKS=",${2:-nextjs,supabase,php-mysql,flask,pocketbase,firebase,mysql,django,go,node-express,laravel,fastapi},"
MAX_PER_PATTERN="${MAX_PER_PATTERN:-40}"   # keeps a noisy pattern from drowning the rest
cd "$ROOT" 2>/dev/null || { echo "directory not found: $ROOT" >&2; exit 1; }

EXCL_DIRS=(node_modules vendor .git .next dist build venv .venv __pycache__ pb_data coverage .claude)
HAS_RG=false; command -v rg >/dev/null 2>&1 && HAS_RG=true

# chk <stack> <severity> <pattern> <regex> <comma-separated globs> [exclusion regex] [i]
chk() {
  local stack="$1" sev="$2" label="$3" re="$4" globs="$5" excl="${6:-}" ci="${7:-}" args=() g
  [[ "$STACKS" == *",$stack,"* ]] || return 0
  IFS=',' read -ra G <<< "$globs"
  if $HAS_RG; then
    args=(-n --no-heading --hidden -e "$re")
    [ "$ci" = i ] && args+=(-i)
    for d in "${EXCL_DIRS[@]}"; do args+=(-g "!$d/"); done
    for g in "${G[@]}"; do args+=(-g "$g"); done
    args+=(-g '!*.min.js')
    rg "${args[@]}" . 2>/dev/null
  else
    args=(-rnE -I)
    [ "$ci" = i ] && args+=(-i)
    for d in "${EXCL_DIRS[@]}"; do args+=(--exclude-dir="$d"); done
    for g in "${G[@]}"; do args+=(--include="$g"); done
    grep "${args[@]}" -e "$re" . 2>/dev/null
  fi | { if [ -n "$excl" ]; then grep -viE -- "$excl"; else cat; fi; } \
     | sed 's|^\./||' | cut -d: -f1,2 | sort -u -t: -k1,1 -k2,2n | head -n "$MAX_PER_PATTERN" \
     | while IFS= read -r loc; do printf '%s:%s:%s\n' "$loc" "$label" "$sev"; done
}

# All checks run inside main() so the output can be de-duplicated at the end
main() {
JS='*.ts,*.tsx,*.js,*.jsx,*.mjs,*.cjs'
SQL='*.sql'
PHP='*.php,*.phtml,*.inc'
PY='*.py'
ENVF='.env*,*.ts,*.tsx,*.js,*.mjs'
TPL='*.html,*.jinja,*.jinja2,*.j2'
PBJS='*.pb.js,*.js,*.json'

# ───────────── Next.js / Node
chk nextjs Critical "secret_in_public_env"     '(NEXT_PUBLIC|EXPO_PUBLIC|VITE|REACT_APP)_[A-Z0-9_]*(SECRET|SERVICE_ROLE|PRIVATE|PASSWORD|DB_|DATABASE)' "$ENVF"
chk nextjs High    "eval_or_new_Function"         '(^|[^.a-zA-Z_])(eval|new Function)\s*\('                       "$JS"
chk nextjs High    "shell_command"               "(child_process|execSync\(|spawnSync\(|exec\(\s*\`)"             "$JS"
chk nextjs High    "raw_sql_unparameterized"       '(\$queryRawUnsafe|\$executeRawUnsafe|sql\.raw\(|\.unsafe\()'   "$JS"
chk nextjs High    "sql_template_interpolated"       "(query|execute|run|all|get|prepare)\(\s*\`[^\`]*(SELECT|INSERT|UPDATE|DELETE)[^\`]*\\$\{" "$JS" '' i
chk nextjs Medium  "dangerouslySetInnerHTML"      'dangerouslySetInnerHTML'                                         "$JS" 'DOMPurify|sanitize'
chk nextjs Medium  "ssrf_fetch_user_url"   '(fetch|axios(\.get|\.post)?|got)\(\s*(req|request|body|params|searchParams|query|input|data|formData)[.\[]' "$JS"
chk nextjs Medium  "cors_wildcard_origin"           "(Access-Control-Allow-Origin['\"]?\s*[,:]\s*['\"]\*|origin\s*:\s*['\"]\*['\"]|origin\s*:\s*true)" "$JS"
chk nextjs Medium  "jwt_decode_without_verify"        '(jwt\.decode\(|jwtDecode\(|decodeJwt\()'                          "$JS"
chk nextjs Medium  "supabase_getSession_server"  'auth\.getSession\(\)'                                            "$JS"
chk nextjs Medium  "cookie_without_httpOnly"         'httpOnly\s*:\s*false'                                            "$JS"
chk nextjs Medium  "open_redirect"          'redirect\(\s*(req|request|searchParams|params|query)[.\[]'      "$JS"
chk nextjs Low    "non_crypto_random"            'Math\.random\(\).*(token|code|otp|secret|password|id)'          "$JS" '' i
chk nextjs Low    "sensitive_data_logged"          'console\.(log|info|debug)\(.*(password|token|secret|authorization)' "$JS" '' i
chk nextjs Info     "server_action_to_check"     "^\s*['\"]use server['\"]"                                        "$JS"
chk nextjs Info     "api_route_to_check"         'export\s+(async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE)\b'   "$JS"
chk nextjs High     "next_version_cve_2025_29927"  '"next"\s*:\s*"[~^]?(1[0-3]\.|14\.([01]\.|2\.([0-9]|1[0-9]|2[0-4])([^0-9]|$))|15\.([01]\.|2\.[0-2]([^0-9]|$)))' 'package.json'
chk nextjs Medium   "middleware_matcher_narrow"    "matcher\s*:\s*(\[\s*[\"'][/A-Za-z0-9_-]*[\"']\s*\]|[\"'][/A-Za-z0-9_-]*[\"']\s*[,}])"  "$JS"
chk nextjs Info     "middleware_matcher"           'matcher\s*:'                                                     "$JS"

# ───────────── Supabase (SQL + client)
chk supabase Critical "rls_disabled"             'disable\s+row\s+level\s+security'                                "$SQL" '' i
chk supabase High    "policy_using_true"          'using\s*\(\s*true\s*\)'                                          "$SQL" '' i
chk supabase High    "policy_with_check_true"     'with\s+check\s*\(\s*true\s*\)'                                   "$SQL" '' i
chk supabase High    "policy_user_metadata"       "user_metadata"                                                   "$SQL" '' i
chk supabase High    "security_definer"           'security\s+definer'                                              "$SQL" 'search_path' i
chk supabase Medium  "grant_to_anon"       '(to|grant[^;]*to)\s+(anon|public)\b'                             "$SQL" 'schema|usage' i
chk supabase Medium  "grant_all"                  'grant\s+all'                                                     "$SQL" '' i
chk supabase Medium  "bucket_public"              "(public\s*[:=]\s*true|insert\s+into\s+storage\.buckets[^;]*true)" "$SQL,$JS" '' i
chk supabase Medium  "edge_function_verify_jwt_off" 'verify_jwt\s*=\s*false'                                        '*.toml'
chk supabase High     "view_without_security_invoker" 'create\s+(or\s+replace\s+)?view'                            "$SQL" 'security_invoker' i
chk supabase Info     "rpc_called"                '\.rpc\(\s*['"'"'"]'                                              "$JS"
chk supabase Info     "service_role_server_to_check" '(service_role|SERVICE_ROLE)'                              "$JS" 'use client'
# Supabase tables created without "enable row level security" in any migration
if [[ "$STACKS" == *",supabase,"* ]]; then
  MIG=(); while IFS= read -r f; do MIG+=("$f"); done < <(find . -path ./node_modules -prune -o -type f -path '*supabase/migrations/*.sql' -print 2>/dev/null | sort)
  if [ "${#MIG[@]}" -gt 0 ]; then
    grep -HniE 'create[[:space:]]+table' "${MIG[@]}" 2>/dev/null | while IFS=: read -r f l txt; do
      t="$(printf '%s' "$txt" | tr 'A-Z' 'a-z' | sed -E 's/.*create[[:space:]]+table[[:space:]]+(if[[:space:]]+not[[:space:]]+exists[[:space:]]+)?("?[a-z0-9_]+"?\.)?"?([a-z0-9_]+).*/\3/')"
      [ -n "$t" ] || continue
      grep -qiE "alter[[:space:]]+table[[:space:]]+(if[[:space:]]+exists[[:space:]]+)?(only[[:space:]]+)?(\"?[a-z0-9_]+\"?\.)?\"?${t}\"?[[:space:]]+enable[[:space:]]+row[[:space:]]+level[[:space:]]+security" "${MIG[@]}" \
        || echo "${f#./}:$l:table_without_rls:Critical"
    done
  fi
fi

# service_role in a "use client" file: shipped to the browser
if [[ "$STACKS" == *",supabase,"* ]]; then
  ex=(); for d in "${EXCL_DIRS[@]}"; do ex+=(--exclude-dir="$d"); done
  grep -rlE "${ex[@]}" --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' "^\s*['\"]use client['\"]" . 2>/dev/null \
    | while read -r f; do grep -nE 'service_role|SERVICE_ROLE' "$f" | cut -d: -f1 \
        | while read -r l; do echo "${f#./}:$l:service_role_client_side:Critical"; done; done
fi

# ───────────── PHP / MySQL
chk php-mysql Critical "sql_with_superglobal"     '(SELECT|INSERT|UPDATE|DELETE|WHERE)[^;]*\$_(GET|POST|REQUEST|COOKIE)' "$PHP" '' i
chk php-mysql High    "sql_concat_or_interpolated" '(query|exec|mysqli_query|mysql_query|prepare)\s*\([^;]*(["'"'"']\s*\.\s*\$|\{?\$[a-zA-Z_]+[^;]*(SELECT|INSERT|UPDATE|DELETE|WHERE))' "$PHP" '' i
chk php-mysql High    "sql_string_interpolated"     '"\s*(SELECT|INSERT|UPDATE|DELETE)[^"]*\$[a-zA-Z_]'               "$PHP" '' i
chk php-mysql Critical "include_user_input" '(include|require)(_once)?\s*\(?[^;]*\$_(GET|POST|REQUEST|COOKIE)' "$PHP"
chk php-mysql Medium  "include_variable"          '(include|require)(_once)?\s*\(?\s*\$'                             "$PHP"
chk php-mysql Critical "unserialize_input"        'unserialize\s*\(\s*\$_'                                           "$PHP"
chk php-mysql High    "command_execution"        '(^|[^a-z_])(eval|assert|system|exec|shell_exec|passthru|popen|proc_open)\s*\(' "$PHP" '->exec\(|pdo->exec|db->exec'
chk php-mysql High    "extract_superglobal"      'extract\s*\(\s*\$_'                                               "$PHP"
chk php-mysql High    "xss_echo_superglobal"     '(echo|print|<\?=)\s*[^;]*\$_(GET|POST|REQUEST|COOKIE|SERVER)'      "$PHP" 'htmlspecialchars|htmlentities|intval|\(int\)'
chk php-mysql Medium  "xss_echo_variable"         '(<\?=|echo)\s+\$[a-zA-Z_]'                                        "$PHP" 'htmlspecialchars|htmlentities|intval|\(int\)|json_encode'
chk php-mysql Medium  "php_self"                  '\$_SERVER\[.PHP_SELF.\]'                                          "$PHP" 'htmlspecialchars'
chk php-mysql High    "weak_password_hash"           '(md5|sha1|crypt)\s*\([^)]*(pass|pwd|mdp|password)'               "$PHP" '' i
chk php-mysql Low    "md5_sha1"                  '(md5|sha1)\s*\('                                                  "$PHP"
chk php-mysql High    "hardcoded_db_credentials"   '(new\s+PDO|mysqli_connect|new\s+mysqli)\s*\([^)]*["'"'"'][^"'"'"']+["'"'"']\s*,\s*["'"'"'][^"'"'"']*["'"'"']\s*,\s*["'"'"'][^"'"'"']+["'"'"']' "$PHP" '' i
chk php-mysql Medium  "display_errors_on"      "(display_errors['\"]?\s*,\s*['\"]?(1|on|true)|display_errors\s*=\s*(1|on))" "$PHP,*.ini,.htaccess" '' i
chk php-mysql Medium  "upload_to_check"         'move_uploaded_file\s*\('                                          "$PHP"
chk php-mysql Medium  "client_supplied_mime"    "\\\$_FILES\[[^]]*\]\[['\"]type['\"]\]"                            "$PHP"
chk php-mysql Medium  "open_redirect"       'header\s*\(\s*["'"'"']Location:[^;]*\$_(GET|POST|REQUEST)'         "$PHP" '' i
chk php-mysql Medium  "insecure_session_cookie" '(session\.cookie_(httponly|secure)["'"'"']?\s*,\s*["'"'"']?(0|off|false)|setcookie\s*\([^)]*\)\s*;)' "$PHP" 'httponly|secure' i
chk php-mysql Info     "session_start"             'session_start\s*\('                                               "$PHP"
chk php-mysql Info     "post_form_csrf_check"      '<form[^>]*method=["'"'"']?post'                                   "$PHP,*.html" 'csrf' i

# ───────────── Flask / Python
chk flask High    "debug_true"                    '(debug\s*=\s*True|DEBUG\s*=\s*True|FLASK_DEBUG\s*=\s*1)'         "$PY,.env*,*.cfg,*.toml"
chk flask High    "hardcoded_secret_key"             "SECRET_KEY['\"]?\s*\]?\s*=\s*['\"][^'\"]*['\"]"                   "$PY"
chk flask Critical "sql_fstring"                   "(execute|executemany|text|raw)\(\s*f['\"]"                        "$PY"
chk flask High    "sql_format_or_concat"          "(execute|executemany|text)\(\s*['\"][^'\"]*['\"]\s*(%|\.format\(|\+)" "$PY"
chk flask High    "ssti_render_template_string"   'render_template_string\s*\('                                      "$PY"
chk flask High    "unsafe_pickle"                '(pickle|cPickle|dill|shelve)\.(loads?|open)\s*\('                 "$PY"
chk flask High    "unsafe_yaml_load"             'yaml\.(load|load_all|unsafe_load)\s*\('                           "$PY" 'SafeLoader|safe_load'
chk flask High    "shell_command"                '(os\.system\(|os\.popen\(|shell\s*=\s*True)'                      "$PY"
chk flask High    "eval_exec"                     '(^|[^.a-z_])(eval|exec)\s*\('                                     "$PY"
chk flask Medium  "cors_wildcard"                    "(CORS\(\s*app\s*\)|origins\s*=\s*['\"]\*['\"]|supports_credentials\s*=\s*True)" "$PY"
chk flask Medium  "safe_filter_or_Markup"         '(\|\s*safe\b|Markup\()'                                           "$PY,$TPL"
chk flask Medium  "tls_verify_false"              'verify\s*=\s*False'                                               "$PY"
chk flask Medium  "file_from_request"        '(send_file|send_from_directory|open)\([^)]*request\.'             "$PY"
chk flask Medium  "ssrf_requests_user_url" 'requests\.(get|post|put|request)\([^)]*request\.(args|form|json)' "$PY"
chk flask Low    "weak_hash"                   'hashlib\.(md5|sha1)\('                                            "$PY"
chk flask Low    "insecure_cookie"           'SESSION_COOKIE_(SECURE|HTTPONLY)\s*=\s*False'                    "$PY"

# ───────────── PocketBase
chk pocketbase High   "empty_api_rule_public"    '(list|view|create|update|delete)Rule["'"'"']?\s*[:=]\s*["'"'"']{2}' "$PBJS"
chk pocketbase Medium "rule_auth_too_broad"      '(list|view|create|update|delete)Rule["'"'"']?\s*[:=]\s*["'"'"']\s*@request\.auth\.id\s*!=\s*\\?["'"'"']{1,2}\\?["'"'"']?\s*["'"'"']' "$PBJS"
chk pocketbase High   "hook_sql_concat"   '(newQuery|\.db\(\)\.newQuery)\([^)]*\+'                          "$PBJS"
chk pocketbase High   "hook_command_exec"        '\$os\.(exec|cmd)\('                                               "$PBJS"
chk pocketbase Medium "hook_save_without_check" '(\$app|app)\.(save|saveNoValidate|dao\(\)\.saveRecord)\('       "$PBJS" 'pb_migrations/|save\(\s*record\s*\)'
chk pocketbase Info    "custom_route_to_check"   'routerAdd\(\s*["'"'"'](GET|POST|PUT|PATCH|DELETE)'               "$PBJS"
chk pocketbase Info    "sensitive_field_to_check" '"name"\s*:\s*"(role|is_?admin|password|token|secret|api_?key|credits|balance|plan)"' "$PBJS" '' i

# ───────────── Firebase (rules + Cloud Functions)
RULES='*.rules,firestore.rules,storage.rules'
chk firebase Critical "rule_if_true"               'allow\s+[a-z, ]+:\s*if\s+true\s*;'                              "$RULES"
chk firebase Critical "rule_without_condition"        'allow\s+[a-z, ]+\s*;'                                            "$RULES"
chk firebase High    "rule_test_mode_date"        'request\.time\s*<\s*timestamp\.date'                             "$RULES"
chk firebase High    "rule_auth_only"             'if\s+request\.auth\s*!=\s*null\s*;'                              "$RULES"
chk firebase High    "rule_global_wildcard"          'match\s+/\{[a-zA-Z]+=\*\*\}'                                      "$RULES"
chk firebase Critical "rtdb_rule_true"            '"\.(read|write)"\s*:\s*(true|"true")'                            '*.rules.json,database.rules.json'
chk firebase High    "rtdb_auth_only"             '"\.(read|write)"\s*:\s*"auth\s*!==?\s*null"'                     '*.rules.json,database.rules.json'
chk firebase Critical "service_account"          '"type"\s*:\s*"service_account"'                                  '*.json'
chk firebase Info     "http_function_to_check"   '(onRequest|https\.onRequest|onCall|https\.onCall)\('            "$JS"
chk firebase Medium  "function_cors_open"       '(cors\s*:\s*true|cors\(\{\s*origin\s*:\s*true)'                  "$JS"

# ───────────── MySQL / MariaDB (base)
DBF='*.sql,*.cnf,*.ini,docker-compose*.yml,docker-compose*.yaml,compose.yml,compose.yaml,.env*,*.env'
chk mysql Critical "empty_password_allowed"             'MYSQL_ALLOW_EMPTY_PASSWORD["'"'"']?\s*[:=]\s*["'"'"']?(yes|1|true)'   "$DBF" '' i
chk mysql Critical "skip_grant_tables"             'skip[-_]grant[-_]tables'                                         "$DBF"
chk mysql Critical "user_without_password"          "IDENTIFIED\s+BY\s+''"                                            "$DBF" '' i
chk mysql High    "weak_root_password"               "(MYSQL|MARIADB)_ROOT_PASSWORD[\"']?\s*[:=]\s*[\"']?(root|password|123456|admin|mysql|secret|toor|pass)?[\"']?\s*$" "$DBF"
chk mysql High    "grant_all_global"              'GRANT\s+ALL[^;]*ON\s+\*\.\*'                                     "$DBF" '' i
chk mysql High    "file_super_privilege"          'GRANT[^;]*\b(FILE|SUPER|PROCESS)\b'                               "$DBF" '' i
chk mysql Medium  "user_wildcard_host"        "(CREATE\s+USER|GRANT)[^;]*@\s*'%'"                               "$DBF" '' i
chk mysql Medium  "port_3306_published"              "^\s*-\s*[\"']?(0\.0\.0\.0:)?330[67]:330[67]"                     "$DBF"
chk mysql Medium  "bind_address_open"           'bind[-_]address\s*=\s*0\.0\.0\.0'                                "$DBF"
chk mysql Medium  "local_infile_on"            'local[-_]infile\s*=\s*(1|on)'                                    "$DBF" '' i
chk mysql Medium  "multiple_statements"           'multipleStatements\s*:\s*true'                                   "$JS"
chk mysql Medium  "tls_disabled"                 '(sslmode=disable|tls=false|ssl\s*:\s*false|useSSL=false)'        "$JS,$PY,*.go,$PHP,$DBF" '' i
chk mysql High    "weak_password_hash_sql"           '(MD5|SHA1|PASSWORD)\s*\(\s*'"'"'[^'"'"']+'"'"'\s*\)'              '*.sql' '' i
chk mysql Medium  "dynamic_sql_procedure"       'PREPARE\s+\w+\s+FROM\s+@'                                        '*.sql' '' i
chk mysql Medium  "db_admin_exposed"              'image:\s*["'"'"']?(phpmyadmin|adminer)'                          "$DBF" '' i
chk mysql Medium  "outdated_version"              'image:\s*["'"'"']?(mysql:5\.|mariadb:10\.[0-3]\b)'               "$DBF"

# ───────────── Django
chk django High    "debug_true"                   '^\s*DEBUG\s*=\s*True'                                            "$PY"
chk django High    "hardcoded_secret_key"            "^\s*SECRET_KEY\s*=\s*['\"]"                                      "$PY"
chk django Medium  "allowed_hosts_wildcard"          "ALLOWED_HOSTS\s*=\s*\[\s*['\"]\*['\"]"                           "$PY"
chk django Critical "sql_raw_interpolated"            "(\.raw\(|\.extra\(|RawSQL\(|\.execute\()\s*(f['\"]|['\"][^'\"]*['\"]\s*(%|\.format\(|\+))" "$PY"
chk django Medium  "csrf_exempt"                  '@csrf_exempt'                                                    "$PY"
chk django Medium  "mark_safe"                    '(mark_safe\(|\|\s*safe\b|autoescape\s+off)'                     "$PY,$TPL"
chk django Medium  "cors_all_origins"         'CORS_(ALLOW_ALL_ORIGINS|ORIGIN_ALLOW_ALL)\s*=\s*True'           "$PY"
chk django Medium  "fields_all"                   "fields\s*=\s*['\"]__all__['\"]"                                  "$PY"
chk django High    "permission_allowany"          'AllowAny'                                                        "$PY"
chk django High    "weak_password_hasher"                '(MD5PasswordHasher|UnsaltedMD5PasswordHasher|SHA1PasswordHasher|UnsaltedSHA1PasswordHasher)' "$PY"
chk django Low    "insecure_cookie"          '(SESSION_COOKIE_SECURE|CSRF_COOKIE_SECURE|SECURE_SSL_REDIRECT)\s*=\s*False' "$PY"
chk django Info     "object_by_id_to_check"      '\.(get|filter)\(\s*(pk|id)\s*=\s*(pk|id|request|kwargs)'       "$PY"

# ───────────── Go
GO='*.go'
chk go Critical "sql_sprintf_or_concat"            '\.(Query|QueryRow|Exec|QueryContext|QueryRowContext|ExecContext|Raw|Where|Select|Get)\(\s*(ctx\s*,\s*)?(fmt\.Sprintf|"[^"]*"\s*\+)' "$GO"
chk go High    "sql_built_with_sprintf"            'fmt\.Sprintf\(\s*"[^"]*(SELECT|INSERT|UPDATE|DELETE|WHERE)'      "$GO" '' i
chk go Critical "jwt_none_or_unverified"           '(UnsafeAllowNoneSignatureType|SigningMethodNone|ParseUnverified)' "$GO"
chk go Info     "jwt_parse_to_check"             'jwt\.Parse(WithClaims)?\('                                       "$GO"
chk go High    "shell_command"                   'exec\.Command(Context)?\(\s*(ctx\s*,\s*)?"(sh|bash|cmd|/bin/sh|powershell)"' "$GO"
chk go High    "path_traversal"                   '(ServeFile|\.File|SaveUploadedFile|os\.Open|os\.ReadFile|filepath\.Join)\([^)]*(URL\.Query|FormValue|\.Param\(|\.Query\(|PostForm|Filename)' "$GO"
chk go Medium  "template_html_unescaped"        '(template\.HTML\(|"text/template")'                             "$GO"
chk go Medium  "tls_insecure"                     'InsecureSkipVerify\s*:\s*true'                                   "$GO"
chk go Medium  "cors_wildcard"                       '(AllowOrigins\s*:\s*\[\]string\{\s*"\*"|AllowAllOrigins\s*:\s*true|"Access-Control-Allow-Origin"\s*,\s*"\*"|"Access-Control-Allow-Origin"\s*,\s*r\.Header\.Get)' "$GO"
chk go Medium  "ssrf_user_url"             'http\.(Get|Post|Head)\(\s*(r\.|c\.|req\.|url\b)'               "$GO"
chk go Medium  "non_crypto_random"                '"math/rand"'                                                     "$GO"
chk go Low    "weak_hash"                      '(md5|sha1)\.(New|Sum)\('                                         "$GO"
chk go Low    "server_without_timeouts"            'http\.ListenAndServe(TLS)?\('                                    "$GO"
chk go Low    "error_exposed"                   '"error"\s*:\s*err\.Error\(\)'                                    "$GO"
chk go Info     "route_to_check"                 '\.(GET|POST|PUT|PATCH|DELETE|HandleFunc|Handle)\(\s*"/'          "$GO"

# ───────────── Node.js backend (Express, Fastify, NestJS…)
chk node-express Critical "sql_concatenated"          '\.(query|execute|raw)\(\s*("[^"]*(SELECT|INSERT|UPDATE|DELETE|WHERE)[^"]*"\s*\+|'"'"'[^'"'"']*(SELECT|INSERT|UPDATE|DELETE|WHERE)[^'"'"']*'"'"'\s*\+|`[^`]*(SELECT|INSERT|UPDATE|DELETE|WHERE)[^`]*\$\{)' "$JS" '' i
chk node-express High    "nosql_raw_request"       '\.(find|findOne|findOneAndUpdate|updateOne|deleteOne|countDocuments)\(\s*req\.(body|query|params)' "$JS"
chk node-express Critical "nosql_where"            '\$where'                                                         "$JS"
chk node-express High    "mass_assignment"        '(\.create|\.update|\.findByIdAndUpdate|\.updateOne|Object\.assign)\([^)]*req\.body\s*\)' "$JS"
chk node-express Medium  "cors_open"            '(cors\(\s*\)|origin\s*:\s*(true|["'"'"']\*["'"'"']))'          "$JS"
chk node-express High    "path_traversal"         '(sendFile|readFile|readFileSync|createReadStream|download)\([^)]*req\.(params|query|body)' "$JS"
chk node-express Critical "unsafe_deserialization"        '(node-serialize|serialize-to-js|\.unserialize\()'               "$JS"
chk node-express High    "shell_command"         '(child_process|execSync\(|exec\(\s*`)'                           "$JS"
chk node-express High    "eval"                   '(^|[^.a-zA-Z_])(eval|new Function)\s*\(|vm\.runIn'             "$JS"
chk node-express High    "hardcoded_jwt_secret"      "jwt\.(sign|verify)\([^)]*,\s*['\"][^'\"]{1,40}['\"]"             "$JS"
chk node-express Medium  "jwt_decode_without_verify"  'jwt\.decode\('                                                  "$JS"
chk node-express Medium  "ssrf_user_url"   '(axios(\.get|\.post)?|fetch|got|request)\(\s*req\.(query|body|params)' "$JS"
chk node-express Low    "error_exposed"         '(err|error)\.(stack|message)\s*[,})]'                            "$JS"
chk node-express Low    "insecure_cookie"    '(secure\s*:\s*false|httpOnly\s*:\s*false)'                       "$JS"
chk node-express Info     "route_to_check"       '(app|router|fastify)\.(get|post|put|patch|delete)\(\s*["'"'"'`]/' "$JS"

# ───────────── Laravel
chk laravel Critical "app_debug_true"              '^APP_DEBUG\s*=\s*true'                                           '.env,.env.production,.env.prod'
chk laravel Critical "app_key_committed"             '^APP_KEY\s*=\s*base64:'                                          '.env,.env.production,.env.prod'
chk laravel Critical "raw_query_interpolated"    '(DB::(raw|select|statement|unprepared|insert|update|delete)|(where|having|orderBy|select|groupBy)Raw)\(\s*(["'"'"'][^"'"'"']*\$|[^,)]*\$request|\$[a-zA-Z_]+\s*\))' "$PHP"
chk laravel High    "mass_assignment_request_all" '(::create|->update|->fill|->forceFill|::insert)\(\s*\$request->(all|input)\(\s*\)' "$PHP"
chk laravel Medium  "empty_guarded"                '\$guarded\s*=\s*\[\s*\]'                                        "$PHP"
chk laravel Medium  "blade_unescaped"           '\{!!\s*\$'                                                       '*.blade.php'
chk laravel Medium  "csrf_except"                 "(protected\s+\\\$except\s*=\s*\[[^]]*['\"]|validateCsrfTokens\(\s*except)" "$PHP"
chk laravel Medium  "without_auth_middleware"     "withoutMiddleware\(\s*\[?\s*['\"](auth|verified|can)"            "$PHP"
chk laravel High    "upload_client_filename"           'getClientOriginalName\(\)'                                       "$PHP"
chk laravel Medium  "cors_wildcard"                  "'allowed_origins'\s*=>\s*\[\s*'\*'"                              "$PHP"
chk laravel Info     "route_to_check"            'Route::(get|post|put|patch|delete|resource|apiResource)\('      "$PHP"

# ───────────── FastAPI
chk fastapi Critical "jwt_unverified"              '(verify_signature["'"'"']?\s*:\s*False|algorithms\s*=\s*\[[^]]*none)' "$PY" '' i
chk fastapi High    "cors_wildcard_credentials"      'allow_origins\s*=\s*\[\s*["'"'"']\*["'"'"']'                    "$PY"
chk fastapi Critical "sql_fstring"                 "(execute|text|raw)\(\s*f['\"]"                                   "$PY"
chk fastapi Info     "route_to_check"            '@(app|router)\.(get|post|put|patch|delete)\('                   "$PY"

# ───────────── Block-level checks (awk, portable): missing auth that a single-line regex cannot see
# files <find -name args...>: matching files, excluded directories pruned
files() { find . \( -name node_modules -o -name vendor -o -name .git -o -name .next -o -name dist -o -name build -o -name venv -o -name .venv -o -name __pycache__ -o -name pb_data -o -name coverage -o -name .claude \) -prune -o -type f \( "$@" \) -print 2>/dev/null | sed 's|^\./||' | sort; }

# Go: 401/403 response not followed by return / Abort → the handler keeps running
if [[ "$STACKS" == *",go,"* ]]; then
  files -name '*.go' | while IFS= read -r f; do
    awk -v f="$f" '
      pending && NF { t=$0; gsub(/^[ \t]+/, "", t)
        if (t !~ /^(return|panic)/ && t !~ /Abort/) print f ":" pl ":go_auth_response_without_return:Critical"
        pending=0 }
      /(JSON|String|Status|XML|Error|WriteHeader)\(.*(401|403|StatusUnauthorized|StatusForbidden)/ && !/Abort|return/ { pending=1; pl=FNR }
    ' "$f"
  done
  chk go Critical "jwt_parse_error_ignored" ',\s*_\s*:?=\s*jwt\.Parse' "$GO"
fi

# FastAPI / Flask: endpoint without an auth dependency / decorator
if [[ "$STACKS" == *",fastapi,"* || "$STACKS" == *",flask,"* ]]; then
  grep -rlE --include='*.py' --exclude-dir={venv,.venv,node_modules,__pycache__,.git} '@[A-Za-z_]+\.(get|post|put|patch|delete|route)\(' . 2>/dev/null | sed 's|^\./||' | sort | while IFS= read -r f; do
    # A global dependency on the app/router protects every endpoint of the file
    grep -qE '(FastAPI|APIRouter)\([^)]*dependencies\s*=|before_request' "$f" && continue
    awk -v f="$f" '
      function check(  low, write, auth) {
        low = tolower(sig)
        write = (deco ~ /\.(post|put|patch|delete)\(/ || deco ~ /methods[ \t]*=[^)]*(POST|PUT|PATCH|DELETE)/)
        auth = (low ~ /(depends|security)\([^)]*(user|auth|token|current|verify|admin|session|principal|api_key)/ \
             || deco ~ /login_required|jwt_required|auth_required|permission_required|roles_required|token_required|requires_auth|admin_required/)
        if (!auth) print f ":" dl ":" (write ? "write_endpoint_without_auth:High" : "endpoint_without_auth:Info")
        indec = 0; insig = 0; deco = ""; sig = ""
      }
      /^[ \t]*@[A-Za-z_]+\.(get|post|put|patch|delete|route)\(/ { if (!indec) { indec = 1; dl = FNR; deco = "" } deco = deco $0; next }
      indec && !insig && /^[ \t]*@/ { deco = deco $0; next }
      indec && !insig && /^[ \t]*(async[ \t]+)?def[ \t]/ { insig = 1; sig = $0; if ($0 ~ /\)[ \t]*(->[^:]*)?:[ \t]*(#.*)?$/) check(); next }
      insig { sig = sig $0; if ($0 ~ /\)[ \t]*(->[^:]*)?:[ \t]*(#.*)?$/) check(); next }
    ' "$f"
  done
fi

# Firebase Cloud Functions: onCall / onRequest whose body never checks the caller
if [[ "$STACKS" == *",firebase,"* ]]; then
  grep -rlE --include='*.js' --include='*.ts' --include='*.mjs' --exclude-dir={node_modules,.git,dist,build,lib} '(onCall|onRequest)\s*\(' . 2>/dev/null | sed 's|^\./||' | sort | while IFS= read -r f; do
    awk -v f="$f" '
      function flush() {
        if (start && body !~ /(request|req|context)\.auth|verifyIdToken|verifySessionCookie|constructEvent|[Ss]ignature|hmac|HMAC/)
          print f ":" start ":cloud_function_without_auth:High"
        start = 0; body = ""
      }
      /(onCall|onRequest)[ \t]*\(/ { flush(); start = FNR; body = $0; next }
      start && /^(exports\.|export[ \t]|module\.exports)/ { flush(); next }
      start { body = body "\n" $0 }
      END { flush() }
    ' "$f"
  done
fi

# Express / Node: write route whose handler is passed directly, with no middleware in between
chk node-express Medium "write_route_without_middleware" "(app|router)\.(post|put|patch|delete)\(\s*[\"'\`][^\"'\`]+[\"'\`]\s*,\s*(async\s+)?(\([^)]*\)\s*=>|function)" "$JS" "(login|signin|sign-in|signup|register|webhook|forgot|reset|callback|health)"

# ───────────── Common: sensitive endpoints to check for rate limiting
chk nextjs  Info "endpoint_auth_rate_limit" '(login|signin|sign-in|signup|reset[-_]?password|forgot|otp|verify|magic)' "$JS" '^[^:]*:[0-9]+:\s*(//|\*|import)' i
chk php-mysql Info "endpoint_auth_rate_limit" '(login|connexion|reset[-_]?password|otp|mot_?de_?passe_oublie)' "$PHP" '' i
chk flask   Info "endpoint_auth_rate_limit" '@.*route\([^)]*(login|signin|reset|otp|verify)' "$PY" '' i
chk django  Info "endpoint_auth_rate_limit" 'path\(\s*["'"'"'][^"'"'"']*(login|signin|reset|otp|token)' "$PY" '' i
chk go      Info "endpoint_auth_rate_limit" '\(\s*"/[^"]*(login|signin|reset|otp|token)' "$GO" '' i
chk node-express Info "endpoint_auth_rate_limit" '\.(post|get)\(\s*["'"'"'`][^"'"'"'`]*(login|signin|reset|otp|token)' "$JS" '' i
chk laravel Info "endpoint_auth_rate_limit" "Route::post\(\s*['\"][^'\"]*(login|reset|otp|token)" "$PHP" '' i
}

main | awk '!seen[$0]++'
exit 0
