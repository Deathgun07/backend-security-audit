#!/usr/bin/env bash
# run_tests.sh — vérifie que les scripts du skill détectent les failles connues de la fixture.
# Usage : bash tests/run_tests.sh   (Ubuntu / Debian / WSL, bash ≥ 4)
set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPTS="$REPO/skills/backend-security-audit/scripts"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

# Copie de la fixture dans un dépôt git jetable + faux secrets construits par concaténation
# (aucune chaîne ressemblant à une vraie clé n'est stockée dans ce dépôt).
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

# Chaque ligne : motif attendu (regex grep -E) dans la sortie
EXPECTED=(
  '"stacks": \["nextjs", "supabase", "pocketbase", "php-mysql", "flask", "fastapi", "django", "go", "node-express", "laravel", "firebase", "mysql"\]'
  '^\.env:3:stripe_sk_live:Critique'
  '^\.env:0:env_suivi_par_git:Critique'
  'env_dans_historique:Critique'
  '^\.env:2:secret_dans_var_publique:Critique'
  '^components/AdminPanel\.tsx:[0-9]+:secret_dans_var_publique:Critique'
  '^components/AdminPanel\.tsx:[0-9]+:service_role_cote_client:Critique'
  '^components/AdminPanel\.tsx:[0-9]+:dangerouslySetInnerHTML'
  '^app/api/preview/route\.ts:[0-9]+:ssrf_fetch_url_utilisateur'
  '^middleware\.ts:[0-9]+:supabase_getSession_serveur'
  '^middleware\.ts:[0-9]+:middleware_matcher'
  '^app/actions\.ts:1:server_action_a_verifier'
  '^supabase/migrations/.*:8:policy_using_true:Haute'
  '^supabase/migrations/.*:with_check_true|policy_with_check_true'
  '^supabase/migrations/.*:security_definer:Haute'
  '^supabase/migrations/.*:droit_accorde_a_anon'
  '^supabase/migrations/.*:vue_a_verifier_security_invoker'
  '^pb_migrations/.*:api_rule_vide_publique:Haute'
  '^pb_migrations/.*:rule_auth_trop_large'
  '^pb_hooks/main\.pb\.js:[0-9]+:hook_requete_sql_concat:Haute'
  '^pb_hooks/main\.pb\.js:[0-9]+:route_custom_a_verifier'
  '^php/config\.php:[0-9]+:identifiants_bdd_en_dur:Haute'
  '^php/config\.php:[0-9]+:display_errors_actif'
  '^php/login\.php:[0-9]+:sql_concatene_ou_interpole:Haute'
  '^php/login\.php:[0-9]+:hash_mdp_faible:Haute'
  '^php/login\.php:[0-9]+:redirection_ouverte'
  '^php/login\.php:[0-9]+:xss_echo_superglobale:Haute'
  '^php/upload\.php:[0-9]+:include_entree_utilisateur:Critique'
  '^php/upload\.php:[0-9]+:mime_fourni_par_client'
  '^php/upload\.php:[0-9]+:upload_a_verifier'
  '^flask/app\.py:[0-9]+:debug_true:Haute'
  '^flask/app\.py:[0-9]+:secret_key_en_dur:Haute'
  '^flask/app\.py:[0-9]+:sql_fstring:Critique'
  '^flask/app\.py:[0-9]+:ssti_render_template_string:Haute'
  '^flask/app\.py:[0-9]+:pickle_non_sur:Haute'
  '^flask/app\.py:[0-9]+:yaml_load_non_sur:Haute'
  '^flask/app\.py:[0-9]+:cors_joker'
  # Firebase
  '^firebase/firestore\.rules:[0-9]+:rule_if_true:Critique'
  '^firebase/firestore\.rules:[0-9]+:rule_mode_test_date:Haute'
  '^firebase/firestore\.rules:[0-9]+:rule_auth_seul:Haute'
  '^firebase/storage\.rules:[0-9]+:rule_sans_condition:Critique'
  '^firebase/database\.rules\.json:[0-9]+:rtdb_regle_true:Critique'
  '^firebase/database\.rules\.json:[0-9]+:rtdb_auth_seul:Haute'
  '^firebase/functions/index\.js:[0-9]+:function_http_a_verifier'
  # MySQL
  '^mysql/init\.sql:[0-9]+:utilisateur_sans_mdp:Critique'
  '^mysql/init\.sql:[0-9]+:grant_all_global:Haute'
  '^mysql/init\.sql:[0-9]+:mdp_hash_faible_sql:Haute'
  '^mysql/init\.sql:[0-9]+:sql_dynamique_procedure'
  '^mysql/docker-compose\.yml:[0-9]+:mdp_root_faible:Haute'
  '^mysql/docker-compose\.yml:[0-9]+:port_3306_publie'
  '^mysql/docker-compose\.yml:[0-9]+:admin_bdd_expose'
  '^express/server\.js:[0-9]+:multiple_statements'
  # Django
  '^django/shop/settings\.py:[0-9]+:debug_true:Haute'
  '^django/shop/settings\.py:[0-9]+:allowed_hosts_joker'
  '^django/shop/settings\.py:[0-9]+:permission_allowany:Haute'
  '^django/shop/settings\.py:[0-9]+:hasher_faible:Haute'
  '^django/shop/views\.py:[0-9]+:sql_raw_interpole:Critique'
  '^django/shop/views\.py:[0-9]+:csrf_exempt'
  '^django/shop/views\.py:[0-9]+:fields_all'
  '^django/shop/settings\.py:[0-9]+:django_secret_key:Haute'
  # Go
  '^go/main\.go:[0-9]+:sql_sprintf_ou_concat:Critique'
  '^go/main\.go:[0-9]+:commande_shell:Haute'
  '^go/main\.go:[0-9]+:path_traversal:Haute'
  '^go/main\.go:[0-9]+:ssrf_url_utilisateur'
  '^go/main\.go:[0-9]+:serveur_sans_timeouts'
  # Node / Express
  '^express/server\.js:[0-9]+:sql_concatene:Critique'
  '^express/server\.js:[0-9]+:nosql_req_direct:Haute'
  '^express/server\.js:[0-9]+:mass_assignment:Haute'
  '^express/server\.js:[0-9]+:path_traversal:Haute'
  '^express/server\.js:[0-9]+:jwt_secret_en_dur:Haute'
  '^express/server\.js:[0-9]+:cors_ouvert'
  # Laravel
  '^laravel/app/Http/Controllers/ProductController\.php:[0-9]+:requete_brute_interpolee:Critique'
  '^laravel/app/Http/Controllers/ProductController\.php:[0-9]+:mass_assignment_request_all:Haute'
  '^laravel/app/Http/Controllers/ProductController\.php:[0-9]+:upload_nom_client:Haute'
  '^laravel/app/Models/Product\.php:[0-9]+:guarded_vide'
  '^laravel/resources/views/product\.blade\.php:[0-9]+:blade_non_echappe'
  '^laravel/routes/web\.php:[0-9]+:without_middleware_auth'
  # FastAPI
  '^fastapi/main\.py:[0-9]+:jwt_sans_verif:Critique'
  '^fastapi/main\.py:[0-9]+:cors_joker_credentials:Haute'
  '^fastapi/main\.py:[0-9]+:sql_fstring:Critique'
)

ok=0; ko=0
for e in "${EXPECTED[@]}"; do
  if grep -qE -- "$e" "$OUT"; then ok=$((ok+1)); else ko=$((ko+1)); echo "ÉCHEC : $e"; fi
done

# Le contenu des secrets ne doit jamais apparaître dans la sortie
if grep -q 'FAUXFAUX' "$OUT"; then ko=$((ko+1)); echo "ÉCHEC : une valeur secrète apparaît dans la sortie"; else ok=$((ok+1)); fi

echo "$ok réussis, $ko échoués"
[ "${VERBOSE:-0}" = 1 ] && cat "$OUT"
[ "$ko" -eq 0 ]
