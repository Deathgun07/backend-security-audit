#!/usr/bin/env bash
# grep_patterns.sh — repère les motifs de code dangereux par langage/stack.
# Usage : grep_patterns.sh [dossier_projet] [stacks]
#   stacks : liste séparée par des virgules (nextjs,supabase,firebase,pocketbase,mysql,php-mysql,laravel,
#            flask,fastapi,django,go,node-express). Défaut : toutes.
# Sortie : fichier:ligne:pattern:sévérité   — ce sont des PISTES, chaque ligne doit être relue.
# Dépendances : bash, grep (ripgrep utilisé s'il est présent). Lecture seule.
set -uo pipefail

ROOT="${1:-.}"
STACKS=",${2:-nextjs,supabase,php-mysql,flask,pocketbase,firebase,mysql,django,go,node-express,laravel,fastapi},"
MAX_PAR_MOTIF="${MAX_PAR_MOTIF:-40}"   # évite qu'un motif bruyant noie le reste
cd "$ROOT" 2>/dev/null || { echo "dossier introuvable : $ROOT" >&2; exit 1; }

EXCL_DIRS=(node_modules vendor .git .next dist build venv .venv __pycache__ pb_data coverage .claude)
HAS_RG=false; command -v rg >/dev/null 2>&1 && HAS_RG=true

# chk <stack> <sévérité> <pattern> <regex> <globs séparés par ,> [exclusion regex] [i]
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
     | sed 's|^\./||' | cut -d: -f1,2 | sort -u -t: -k1,1 -k2,2n | head -n "$MAX_PAR_MOTIF" \
     | while IFS= read -r loc; do printf '%s:%s:%s\n' "$loc" "$label" "$sev"; done
}

JS='*.ts,*.tsx,*.js,*.jsx,*.mjs,*.cjs'
SQL='*.sql'
PHP='*.php,*.phtml,*.inc'
PY='*.py'
ENVF='.env*,*.ts,*.tsx,*.js,*.mjs'
TPL='*.html,*.jinja,*.jinja2,*.j2'
PBJS='*.pb.js,*.js,*.json'

# ───────────── Next.js / Node
chk nextjs Critique "secret_dans_var_publique"     '(NEXT_PUBLIC|EXPO_PUBLIC|VITE|REACT_APP)_[A-Z0-9_]*(SECRET|SERVICE_ROLE|PRIVATE|PASSWORD|DB_|DATABASE)' "$ENVF"
chk nextjs Haute    "eval_ou_new_Function"         '(^|[^.a-zA-Z_])(eval|new Function)\s*\('                       "$JS"
chk nextjs Haute    "commande_shell"               "(child_process|execSync\(|spawnSync\(|exec\(\s*\`)"             "$JS"
chk nextjs Haute    "sql_brut_non_parametre"       '(\$queryRawUnsafe|\$executeRawUnsafe|sql\.raw\(|\.unsafe\()'   "$JS"
chk nextjs Haute    "sql_template_interpole"       "(query|execute|run|all|get|prepare)\(\s*\`[^\`]*(SELECT|INSERT|UPDATE|DELETE)[^\`]*\\$\{" "$JS" '' i
chk nextjs Moyenne  "dangerouslySetInnerHTML"      'dangerouslySetInnerHTML'                                         "$JS" 'DOMPurify|sanitize'
chk nextjs Moyenne  "ssrf_fetch_url_utilisateur"   '(fetch|axios(\.get|\.post)?|got)\(\s*(req|request|body|params|searchParams|query|input|data|formData)[.\[]' "$JS"
chk nextjs Moyenne  "cors_origine_joker"           "(Access-Control-Allow-Origin['\"]?\s*[,:]\s*['\"]\*|origin\s*:\s*['\"]\*['\"]|origin\s*:\s*true)" "$JS"
chk nextjs Moyenne  "jwt_decode_sans_verif"        '(jwt\.decode\(|jwtDecode\(|decodeJwt\()'                          "$JS"
chk nextjs Moyenne  "supabase_getSession_serveur"  'auth\.getSession\(\)'                                            "$JS"
chk nextjs Moyenne  "cookie_sans_httpOnly"         'httpOnly\s*:\s*false'                                            "$JS"
chk nextjs Moyenne  "redirection_ouverte"          'redirect\(\s*(req|request|searchParams|params|query)[.\[]'      "$JS"
chk nextjs Basse    "random_non_crypto"            'Math\.random\(\).*(token|code|otp|secret|password|id)'          "$JS" '' i
chk nextjs Basse    "log_donnee_sensible"          'console\.(log|info|debug)\(.*(password|token|secret|authorization)' "$JS" '' i
chk nextjs Info     "server_action_a_verifier"     "^\s*['\"]use server['\"]"                                        "$JS"
chk nextjs Info     "route_api_a_verifier"         'export\s+(async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE)\b'   "$JS"
chk nextjs Info     "middleware_matcher"           'matcher\s*:'                                                     "$JS"

# ───────────── Supabase (SQL + client)
chk supabase Critique "rls_desactivee"             'disable\s+row\s+level\s+security'                                "$SQL" '' i
chk supabase Haute    "policy_using_true"          'using\s*\(\s*true\s*\)'                                          "$SQL" '' i
chk supabase Haute    "policy_with_check_true"     'with\s+check\s*\(\s*true\s*\)'                                   "$SQL" '' i
chk supabase Haute    "policy_user_metadata"       "user_metadata"                                                   "$SQL" '' i
chk supabase Haute    "security_definer"           'security\s+definer'                                              "$SQL" 'search_path' i
chk supabase Moyenne  "droit_accorde_a_anon"       '(to|grant[^;]*to)\s+(anon|public)\b'                             "$SQL" 'schema|usage' i
chk supabase Moyenne  "grant_all"                  'grant\s+all'                                                     "$SQL" '' i
chk supabase Moyenne  "bucket_public"              "(public\s*[:=]\s*true|insert\s+into\s+storage\.buckets[^;]*true)" "$SQL,$JS" '' i
chk supabase Moyenne  "edge_function_verify_jwt_off" 'verify_jwt\s*=\s*false'                                        '*.toml'
chk supabase Info     "vue_a_verifier_security_invoker" 'create\s+(or\s+replace\s+)?view'                            "$SQL" 'security_invoker' i
chk supabase Info     "rpc_appelee"                '\.rpc\(\s*['"'"'"]'                                              "$JS"
chk supabase Info     "service_role_serveur_a_verifier" '(service_role|SERVICE_ROLE)'                              "$JS" 'use client'
# service_role dans un fichier "use client" : envoyé au navigateur
if [[ "$STACKS" == *",supabase,"* ]]; then
  ex=(); for d in "${EXCL_DIRS[@]}"; do ex+=(--exclude-dir="$d"); done
  grep -rlE "${ex[@]}" --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' "^\s*['\"]use client['\"]" . 2>/dev/null \
    | while read -r f; do grep -nE 'service_role|SERVICE_ROLE' "$f" | cut -d: -f1 \
        | while read -r l; do echo "${f#./}:$l:service_role_cote_client:Critique"; done; done
fi

# ───────────── PHP / MySQL
chk php-mysql Critique "sql_avec_superglobale"     '(SELECT|INSERT|UPDATE|DELETE|WHERE)[^;]*\$_(GET|POST|REQUEST|COOKIE)' "$PHP" '' i
chk php-mysql Haute    "sql_concatene_ou_interpole" '(query|exec|mysqli_query|mysql_query|prepare)\s*\([^;]*(["'"'"']\s*\.\s*\$|\{?\$[a-zA-Z_]+[^;]*(SELECT|INSERT|UPDATE|DELETE|WHERE))' "$PHP" '' i
chk php-mysql Haute    "sql_string_interpolee"     '"\s*(SELECT|INSERT|UPDATE|DELETE)[^"]*\$[a-zA-Z_]'               "$PHP" '' i
chk php-mysql Critique "include_entree_utilisateur" '(include|require)(_once)?\s*\(?[^;]*\$_(GET|POST|REQUEST|COOKIE)' "$PHP"
chk php-mysql Moyenne  "include_variable"          '(include|require)(_once)?\s*\(?\s*\$'                             "$PHP"
chk php-mysql Critique "unserialize_entree"        'unserialize\s*\(\s*\$_'                                           "$PHP"
chk php-mysql Haute    "execution_commande"        '(^|[^a-z_])(eval|assert|system|exec|shell_exec|passthru|popen|proc_open)\s*\(' "$PHP" '->exec\(|pdo->exec|db->exec'
chk php-mysql Haute    "extract_superglobale"      'extract\s*\(\s*\$_'                                               "$PHP"
chk php-mysql Haute    "xss_echo_superglobale"     '(echo|print|<\?=)\s*[^;]*\$_(GET|POST|REQUEST|COOKIE|SERVER)'      "$PHP" 'htmlspecialchars|htmlentities|intval|\(int\)'
chk php-mysql Moyenne  "xss_echo_variable"         '(<\?=|echo)\s+\$[a-zA-Z_]'                                        "$PHP" 'htmlspecialchars|htmlentities|intval|\(int\)|json_encode'
chk php-mysql Moyenne  "php_self"                  '\$_SERVER\[.PHP_SELF.\]'                                          "$PHP" 'htmlspecialchars'
chk php-mysql Haute    "hash_mdp_faible"           '(md5|sha1|crypt)\s*\([^)]*(pass|pwd|mdp|password)'               "$PHP" '' i
chk php-mysql Basse    "md5_sha1"                  '(md5|sha1)\s*\('                                                  "$PHP"
chk php-mysql Haute    "identifiants_bdd_en_dur"   '(new\s+PDO|mysqli_connect|new\s+mysqli)\s*\([^)]*["'"'"'][^"'"'"']+["'"'"']\s*,\s*["'"'"'][^"'"'"']*["'"'"']\s*,\s*["'"'"'][^"'"'"']+["'"'"']' "$PHP" '' i
chk php-mysql Moyenne  "display_errors_actif"      "(display_errors['\"]?\s*,\s*['\"]?(1|on|true)|display_errors\s*=\s*(1|on))" "$PHP,*.ini,.htaccess" '' i
chk php-mysql Moyenne  "upload_a_verifier"         'move_uploaded_file\s*\('                                          "$PHP"
chk php-mysql Moyenne  "mime_fourni_par_client"    "\\\$_FILES\[[^]]*\]\[['\"]type['\"]\]"                            "$PHP"
chk php-mysql Moyenne  "redirection_ouverte"       'header\s*\(\s*["'"'"']Location:[^;]*\$_(GET|POST|REQUEST)'         "$PHP" '' i
chk php-mysql Moyenne  "cookie_session_non_securise" '(session\.cookie_(httponly|secure)["'"'"']?\s*,\s*["'"'"']?(0|off|false)|setcookie\s*\([^)]*\)\s*;)' "$PHP" 'httponly|secure' i
chk php-mysql Info     "session_start"             'session_start\s*\('                                               "$PHP"
chk php-mysql Info     "formulaire_post_csrf"      '<form[^>]*method=["'"'"']?post'                                   "$PHP,*.html" 'csrf' i

# ───────────── Flask / Python
chk flask Haute    "debug_true"                    '(debug\s*=\s*True|DEBUG\s*=\s*True|FLASK_DEBUG\s*=\s*1)'         "$PY,.env*,*.cfg,*.toml"
chk flask Haute    "secret_key_en_dur"             "SECRET_KEY['\"]?\s*\]?\s*=\s*['\"][^'\"]*['\"]"                   "$PY"
chk flask Critique "sql_fstring"                   "(execute|executemany|text|raw)\(\s*f['\"]"                        "$PY"
chk flask Haute    "sql_format_ou_concat"          "(execute|executemany|text)\(\s*['\"][^'\"]*['\"]\s*(%|\.format\(|\+)" "$PY"
chk flask Haute    "ssti_render_template_string"   'render_template_string\s*\('                                      "$PY"
chk flask Haute    "pickle_non_sur"                '(pickle|cPickle|dill|shelve)\.(loads?|open)\s*\('                 "$PY"
chk flask Haute    "yaml_load_non_sur"             'yaml\.(load|load_all|unsafe_load)\s*\('                           "$PY" 'SafeLoader|safe_load'
chk flask Haute    "commande_shell"                '(os\.system\(|os\.popen\(|shell\s*=\s*True)'                      "$PY"
chk flask Haute    "eval_exec"                     '(^|[^.a-z_])(eval|exec)\s*\('                                     "$PY"
chk flask Moyenne  "cors_joker"                    "(CORS\(\s*app\s*\)|origins\s*=\s*['\"]\*['\"]|supports_credentials\s*=\s*True)" "$PY"
chk flask Moyenne  "filtre_safe_ou_Markup"         '(\|\s*safe\b|Markup\()'                                           "$PY,$TPL"
chk flask Moyenne  "tls_verify_false"              'verify\s*=\s*False'                                               "$PY"
chk flask Moyenne  "fichier_depuis_requete"        '(send_file|send_from_directory|open)\([^)]*request\.'             "$PY"
chk flask Moyenne  "ssrf_requests_url_utilisateur" 'requests\.(get|post|put|request)\([^)]*request\.(args|form|json)' "$PY"
chk flask Basse    "hash_faible"                   'hashlib\.(md5|sha1)\('                                            "$PY"
chk flask Basse    "cookie_non_securise"           'SESSION_COOKIE_(SECURE|HTTPONLY)\s*=\s*False'                    "$PY"

# ───────────── PocketBase
chk pocketbase Haute   "api_rule_vide_publique"    '(list|view|create|update|delete)Rule["'"'"']?\s*[:=]\s*["'"'"']{2}' "$PBJS"
chk pocketbase Moyenne "rule_auth_trop_large"      '(list|view|create|update|delete)Rule["'"'"']?\s*[:=]\s*["'"'"']\s*@request\.auth\.id\s*!=\s*\\?["'"'"']{1,2}\\?["'"'"']?\s*["'"'"']' "$PBJS"
chk pocketbase Haute   "hook_requete_sql_concat"   '(newQuery|\.db\(\)\.newQuery)\([^)]*\+'                          "$PBJS"
chk pocketbase Haute   "hook_exec_commande"        '\$os\.(exec|cmd)\('                                               "$PBJS"
chk pocketbase Moyenne "hook_save_sans_validation" '(\$app|app)\.(save|saveNoValidate|dao\(\)\.saveRecord)\('       "$PBJS" 'pb_migrations/|save\(\s*record\s*\)'
chk pocketbase Info    "route_custom_a_verifier"   'routerAdd\(\s*["'"'"'](GET|POST|PUT|PATCH|DELETE)'               "$PBJS"
chk pocketbase Info    "champ_sensible_a_verifier" '"name"\s*:\s*"(role|is_?admin|password|token|secret|api_?key|credits|balance|plan)"' "$PBJS" '' i

# ───────────── Firebase (rules + Cloud Functions)
RULES='*.rules,firestore.rules,storage.rules'
chk firebase Critique "rule_if_true"               'allow\s+[a-z, ]+:\s*if\s+true\s*;'                              "$RULES"
chk firebase Critique "rule_sans_condition"        'allow\s+[a-z, ]+\s*;'                                            "$RULES"
chk firebase Haute    "rule_mode_test_date"        'request\.time\s*<\s*timestamp\.date'                             "$RULES"
chk firebase Haute    "rule_auth_seul"             'if\s+request\.auth\s*!=\s*null\s*;'                              "$RULES"
chk firebase Haute    "rule_joker_global"          'match\s+/\{[a-zA-Z]+=\*\*\}'                                      "$RULES"
chk firebase Critique "rtdb_regle_true"            '"\.(read|write)"\s*:\s*(true|"true")'                            '*.rules.json,database.rules.json'
chk firebase Haute    "rtdb_auth_seul"             '"\.(read|write)"\s*:\s*"auth\s*!==?\s*null"'                     '*.rules.json,database.rules.json'
chk firebase Critique "compte_de_service"          '"type"\s*:\s*"service_account"'                                  '*.json'
chk firebase Info     "function_http_a_verifier"   '(onRequest|https\.onRequest|onCall|https\.onCall)\('            "$JS"
chk firebase Moyenne  "function_cors_ouvert"       '(cors\s*:\s*true|cors\(\{\s*origin\s*:\s*true)'                  "$JS"

# ───────────── MySQL / MariaDB (base)
DBF='*.sql,*.cnf,*.ini,docker-compose*.yml,docker-compose*.yaml,compose.yml,compose.yaml,.env*,*.env'
chk mysql Critique "mdp_vide_autorise"             'MYSQL_ALLOW_EMPTY_PASSWORD["'"'"']?\s*[:=]\s*["'"'"']?(yes|1|true)'   "$DBF" '' i
chk mysql Critique "skip_grant_tables"             'skip[-_]grant[-_]tables'                                         "$DBF"
chk mysql Critique "utilisateur_sans_mdp"          "IDENTIFIED\s+BY\s+''"                                            "$DBF" '' i
chk mysql Haute    "mdp_root_faible"               "(MYSQL|MARIADB)_ROOT_PASSWORD[\"']?\s*[:=]\s*[\"']?(root|password|123456|admin|mysql|secret|toor|pass)?[\"']?\s*$" "$DBF"
chk mysql Haute    "grant_all_global"              'GRANT\s+ALL[^;]*ON\s+\*\.\*'                                     "$DBF" '' i
chk mysql Haute    "privilege_file_super"          'GRANT[^;]*\b(FILE|SUPER|PROCESS)\b'                               "$DBF" '' i
chk mysql Moyenne  "utilisateur_hote_joker"        "(CREATE\s+USER|GRANT)[^;]*@\s*'%'"                               "$DBF" '' i
chk mysql Moyenne  "port_3306_publie"              "^\s*-\s*[\"']?(0\.0\.0\.0:)?330[67]:330[67]"                     "$DBF"
chk mysql Moyenne  "bind_address_ouvert"           'bind[-_]address\s*=\s*0\.0\.0\.0'                                "$DBF"
chk mysql Moyenne  "local_infile_actif"            'local[-_]infile\s*=\s*(1|on)'                                    "$DBF" '' i
chk mysql Moyenne  "multiple_statements"           'multipleStatements\s*:\s*true'                                   "$JS"
chk mysql Moyenne  "tls_desactive"                 '(sslmode=disable|tls=false|ssl\s*:\s*false|useSSL=false)'        "$JS,$PY,*.go,$PHP,$DBF" '' i
chk mysql Haute    "mdp_hash_faible_sql"           '(MD5|SHA1|PASSWORD)\s*\(\s*'"'"'[^'"'"']+'"'"'\s*\)'              '*.sql' '' i
chk mysql Moyenne  "sql_dynamique_procedure"       'PREPARE\s+\w+\s+FROM\s+@'                                        '*.sql' '' i
chk mysql Moyenne  "admin_bdd_expose"              'image:\s*["'"'"']?(phpmyadmin|adminer)'                          "$DBF" '' i
chk mysql Moyenne  "version_obsolete"              'image:\s*["'"'"']?(mysql:5\.|mariadb:10\.[0-3]\b)'               "$DBF"

# ───────────── Django
chk django Haute    "debug_true"                   '^\s*DEBUG\s*=\s*True'                                            "$PY"
chk django Haute    "secret_key_en_dur"            "^\s*SECRET_KEY\s*=\s*['\"]"                                      "$PY"
chk django Moyenne  "allowed_hosts_joker"          "ALLOWED_HOSTS\s*=\s*\[\s*['\"]\*['\"]"                           "$PY"
chk django Critique "sql_raw_interpole"            "(\.raw\(|\.extra\(|RawSQL\(|\.execute\()\s*(f['\"]|['\"][^'\"]*['\"]\s*(%|\.format\(|\+))" "$PY"
chk django Moyenne  "csrf_exempt"                  '@csrf_exempt'                                                    "$PY"
chk django Moyenne  "mark_safe"                    '(mark_safe\(|\|\s*safe\b|autoescape\s+off)'                     "$PY,$TPL"
chk django Moyenne  "cors_toutes_origines"         'CORS_(ALLOW_ALL_ORIGINS|ORIGIN_ALLOW_ALL)\s*=\s*True'           "$PY"
chk django Moyenne  "fields_all"                   "fields\s*=\s*['\"]__all__['\"]"                                  "$PY"
chk django Haute    "permission_allowany"          'AllowAny'                                                        "$PY"
chk django Haute    "hasher_faible"                '(MD5PasswordHasher|UnsaltedMD5PasswordHasher|SHA1PasswordHasher|UnsaltedSHA1PasswordHasher)' "$PY"
chk django Basse    "cookie_non_securise"          '(SESSION_COOKIE_SECURE|CSRF_COOKIE_SECURE|SECURE_SSL_REDIRECT)\s*=\s*False' "$PY"
chk django Info     "objet_par_id_a_verifier"      '\.(get|filter)\(\s*(pk|id)\s*=\s*(pk|id|request|kwargs)'       "$PY"

# ───────────── Go
GO='*.go'
chk go Critique "sql_sprintf_ou_concat"            '\.(Query|QueryRow|Exec|QueryContext|QueryRowContext|ExecContext|Raw|Where|Select|Get)\(\s*(ctx\s*,\s*)?(fmt\.Sprintf|"[^"]*"\s*\+)' "$GO"
chk go Haute    "sql_construit_sprintf"            'fmt\.Sprintf\(\s*"[^"]*(SELECT|INSERT|UPDATE|DELETE|WHERE)'      "$GO" '' i
chk go Critique "jwt_none_ou_sans_verif"           '(UnsafeAllowNoneSignatureType|SigningMethodNone|ParseUnverified)' "$GO"
chk go Info     "jwt_parse_a_verifier"             'jwt\.Parse(WithClaims)?\('                                       "$GO"
chk go Haute    "commande_shell"                   'exec\.Command(Context)?\(\s*(ctx\s*,\s*)?"(sh|bash|cmd|/bin/sh|powershell)"' "$GO"
chk go Haute    "path_traversal"                   '(ServeFile|\.File|SaveUploadedFile|os\.Open|os\.ReadFile|filepath\.Join)\([^)]*(URL\.Query|FormValue|\.Param\(|\.Query\(|PostForm|Filename)' "$GO"
chk go Moyenne  "template_html_non_echappe"        '(template\.HTML\(|"text/template")'                             "$GO"
chk go Moyenne  "tls_insecure"                     'InsecureSkipVerify\s*:\s*true'                                   "$GO"
chk go Moyenne  "cors_joker"                       '(AllowOrigins\s*:\s*\[\]string\{\s*"\*"|AllowAllOrigins\s*:\s*true|"Access-Control-Allow-Origin"\s*,\s*"\*"|"Access-Control-Allow-Origin"\s*,\s*r\.Header\.Get)' "$GO"
chk go Moyenne  "ssrf_url_utilisateur"             'http\.(Get|Post|Head)\(\s*(r\.|c\.|req\.|url\b)'               "$GO"
chk go Moyenne  "random_non_crypto"                '"math/rand"'                                                     "$GO"
chk go Basse    "hash_faible"                      '(md5|sha1)\.(New|Sum)\('                                         "$GO"
chk go Basse    "serveur_sans_timeouts"            'http\.ListenAndServe(TLS)?\('                                    "$GO"
chk go Basse    "erreur_exposee"                   '"error"\s*:\s*err\.Error\(\)'                                    "$GO"
chk go Info     "route_a_verifier"                 '\.(GET|POST|PUT|PATCH|DELETE|HandleFunc|Handle)\(\s*"/'          "$GO"

# ───────────── Node.js backend (Express, Fastify, NestJS…)
chk node-express Critique "sql_concatene"          '\.(query|execute|raw)\(\s*("[^"]*(SELECT|INSERT|UPDATE|DELETE|WHERE)[^"]*"\s*\+|'"'"'[^'"'"']*(SELECT|INSERT|UPDATE|DELETE|WHERE)[^'"'"']*'"'"'\s*\+|`[^`]*(SELECT|INSERT|UPDATE|DELETE|WHERE)[^`]*\$\{)' "$JS" '' i
chk node-express Haute    "nosql_req_direct"       '\.(find|findOne|findOneAndUpdate|updateOne|deleteOne|countDocuments)\(\s*req\.(body|query|params)' "$JS"
chk node-express Critique "nosql_where"            '\$where'                                                         "$JS"
chk node-express Haute    "mass_assignment"        '(\.create|\.update|\.findByIdAndUpdate|\.updateOne|Object\.assign)\([^)]*req\.body\s*\)' "$JS"
chk node-express Moyenne  "cors_ouvert"            '(cors\(\s*\)|origin\s*:\s*(true|["'"'"']\*["'"'"']))'          "$JS"
chk node-express Haute    "path_traversal"         '(sendFile|readFile|readFileSync|createReadStream|download)\([^)]*req\.(params|query|body)' "$JS"
chk node-express Critique "deserialisation"        '(node-serialize|serialize-to-js|\.unserialize\()'               "$JS"
chk node-express Haute    "commande_shell"         '(child_process|execSync\(|exec\(\s*`)'                           "$JS"
chk node-express Haute    "eval"                   '(^|[^.a-zA-Z_])(eval|new Function)\s*\(|vm\.runIn'             "$JS"
chk node-express Haute    "jwt_secret_en_dur"      "jwt\.(sign|verify)\([^)]*,\s*['\"][^'\"]{1,40}['\"]"             "$JS"
chk node-express Moyenne  "jwt_decode_sans_verif"  'jwt\.decode\('                                                  "$JS"
chk node-express Moyenne  "ssrf_url_utilisateur"   '(axios(\.get|\.post)?|fetch|got|request)\(\s*req\.(query|body|params)' "$JS"
chk node-express Basse    "erreur_exposee"         '(err|error)\.(stack|message)\s*[,})]'                            "$JS"
chk node-express Basse    "cookie_non_securise"    '(secure\s*:\s*false|httpOnly\s*:\s*false)'                       "$JS"
chk node-express Info     "route_a_verifier"       '(app|router|fastify)\.(get|post|put|patch|delete)\(\s*["'"'"'`]/' "$JS"

# ───────────── Laravel
chk laravel Critique "app_debug_true"              '^APP_DEBUG\s*=\s*true'                                           '.env,.env.production,.env.prod'
chk laravel Critique "app_key_commite"             '^APP_KEY\s*=\s*base64:'                                          '.env,.env.production,.env.prod'
chk laravel Critique "requete_brute_interpolee"    '(DB::(raw|select|statement|unprepared|insert|update|delete)|(where|having|orderBy|select|groupBy)Raw)\(\s*(["'"'"'][^"'"'"']*\$|[^,)]*\$request|\$[a-zA-Z_]+\s*\))' "$PHP"
chk laravel Haute    "mass_assignment_request_all" '(::create|->update|->fill|->forceFill|::insert)\(\s*\$request->(all|input)\(\s*\)' "$PHP"
chk laravel Moyenne  "guarded_vide"                '\$guarded\s*=\s*\[\s*\]'                                        "$PHP"
chk laravel Moyenne  "blade_non_echappe"           '\{!!\s*\$'                                                       '*.blade.php'
chk laravel Moyenne  "csrf_except"                 "(protected\s+\\\$except\s*=\s*\[[^]]*['\"]|validateCsrfTokens\(\s*except)" "$PHP"
chk laravel Moyenne  "without_middleware_auth"     "withoutMiddleware\(\s*\[?\s*['\"](auth|verified|can)"            "$PHP"
chk laravel Haute    "upload_nom_client"           'getClientOriginalName\(\)'                                       "$PHP"
chk laravel Moyenne  "cors_joker"                  "'allowed_origins'\s*=>\s*\[\s*'\*'"                              "$PHP"
chk laravel Info     "route_a_verifier"            'Route::(get|post|put|patch|delete|resource|apiResource)\('      "$PHP"

# ───────────── FastAPI
chk fastapi Critique "jwt_sans_verif"              '(verify_signature["'"'"']?\s*:\s*False|algorithms\s*=\s*\[[^]]*none)' "$PY" '' i
chk fastapi Haute    "cors_joker_credentials"      'allow_origins\s*=\s*\[\s*["'"'"']\*["'"'"']'                    "$PY"
chk fastapi Critique "sql_fstring"                 "(execute|text|raw)\(\s*f['\"]"                                   "$PY"
chk fastapi Info     "route_a_verifier"            '@(app|router)\.(get|post|put|patch|delete)\('                   "$PY"

# ───────────── Commun : endpoints sensibles à vérifier pour le rate limiting
chk nextjs  Info "endpoint_auth_rate_limit" '(login|signin|sign-in|signup|reset[-_]?password|forgot|otp|verify|magic)' "$JS" '^[^:]*:[0-9]+:\s*(//|\*|import)' i
chk php-mysql Info "endpoint_auth_rate_limit" '(login|connexion|reset[-_]?password|otp|mot_?de_?passe_oublie)' "$PHP" '' i
chk flask   Info "endpoint_auth_rate_limit" '@.*route\([^)]*(login|signin|reset|otp|verify)' "$PY" '' i
chk django  Info "endpoint_auth_rate_limit" 'path\(\s*["'"'"'][^"'"'"']*(login|signin|reset|otp|token)' "$PY" '' i
chk go      Info "endpoint_auth_rate_limit" '\(\s*"/[^"]*(login|signin|reset|otp|token)' "$GO" '' i
chk node-express Info "endpoint_auth_rate_limit" '\.(post|get)\(\s*["'"'"'`][^"'"'"'`]*(login|signin|reset|otp|token)' "$JS" '' i
chk laravel Info "endpoint_auth_rate_limit" "Route::post\(\s*['\"][^'\"]*(login|reset|otp|token)" "$PHP" '' i
exit 0
