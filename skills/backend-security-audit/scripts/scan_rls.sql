-- scan_rls.sql — audit RLS / droits d'une base Postgres (Supabase ou non). LECTURE SEULE.
-- À exécuter UNIQUEMENT sur votre propre base (locale de préférence) :
--   psql "postgresql://postgres:postgres@127.0.0.1:54322/postgres" -f scan_rls.sql   (supabase start)
--   ou coller section par section dans le SQL Editor de votre projet Supabase.
-- Toutes les requêtes sont des SELECT dans une transaction READ ONLY annulée à la fin.

BEGIN READ ONLY;
SET LOCAL statement_timeout = '30s';

-- Schémas système exclus : liste répétée dans chaque requête (aucun objet créé, compatible SQL Editor)
-- Rôles anon/authenticated : testés via pg_roles pour que le script tourne aussi hors Supabase.

\echo '=== 1. Tables SANS RLS (Critique si anon/authenticated ont des droits dessus) ==='
SELECT n.nspname AS schema, c.relname AS table_,
       CASE WHEN EXISTS (SELECT 1 FROM pg_roles WHERE rolname='anon') THEN has_table_privilege('anon', c.oid, 'SELECT') END          AS anon_select,
       CASE WHEN EXISTS (SELECT 1 FROM pg_roles WHERE rolname='anon') THEN has_table_privilege('anon', c.oid, 'INSERT,UPDATE,DELETE') END AS anon_ecriture,
       CASE WHEN EXISTS (SELECT 1 FROM pg_roles WHERE rolname='authenticated') THEN has_table_privilege('authenticated', c.oid, 'INSERT,UPDATE,DELETE') END AS auth_ecriture
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind IN ('r','p') AND NOT c.relrowsecurity
  AND n.nspname <> ALL (ARRAY['pg_catalog','information_schema','pg_toast','auth','storage','realtime','extensions','graphql','graphql_public','vault','pgsodium','pgsodium_masks','net','supabase_functions','supabase_migrations','cron','pgbouncer','_realtime','_analytics']) AND n.nspname NOT LIKE 'pg_temp%' AND n.nspname NOT LIKE 'pg_toast%'
ORDER BY 1,2;

\echo '=== 2. Tables avec RLS mais SANS aucune policy (tout est refusé : Info) ==='
SELECT n.nspname AS schema, c.relname AS table_
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind IN ('r','p') AND c.relrowsecurity
  AND n.nspname <> ALL (ARRAY['pg_catalog','information_schema','pg_toast','auth','storage','realtime','extensions','graphql','graphql_public','vault','pgsodium','pgsodium_masks','net','supabase_functions','supabase_migrations','cron','pgbouncer','_realtime','_analytics'])
  AND NOT EXISTS (SELECT 1 FROM pg_policies p WHERE p.schemaname = n.nspname AND p.tablename = c.relname)
ORDER BY 1,2;

\echo '=== 3. Policies permissives (USING true / WITH CHECK true / écriture anon / user_metadata) ==='
SELECT schemaname AS schema, tablename AS table_, policyname, cmd, roles, permissive,
       qual AS using_, with_check,
       CASE
         WHEN ('anon' = ANY(roles) OR 'public' = ANY(roles)) AND cmd IN ('INSERT','UPDATE','DELETE','ALL') THEN 'Critique: écriture anon/public'
         WHEN coalesce(qual,'') ~* '^\(?true\)?$' AND cmd IN ('UPDATE','DELETE','ALL') THEN 'Critique: USING true en écriture'
         WHEN coalesce(with_check,'') ~* '^\(?true\)?$' THEN 'Haute: WITH CHECK true'
         WHEN coalesce(qual,'') ~* '^\(?true\)?$' THEN 'Moyenne: lecture totale (vérifier si voulu)'
         WHEN coalesce(qual,'') || coalesce(with_check,'') ~* 'user_metadata' THEN 'Haute: user_metadata modifiable par l''utilisateur'
         WHEN cmd = 'UPDATE' AND with_check IS NULL THEN 'Moyenne: UPDATE sans WITH CHECK'
       END AS alerte
FROM pg_policies
WHERE schemaname NOT IN ('auth','realtime','supabase_functions')
  AND ( ('anon' = ANY(roles) OR 'public' = ANY(roles)) AND cmd IN ('INSERT','UPDATE','DELETE','ALL')
     OR coalesce(qual,'') ~* '^\(?true\)?$' OR coalesce(with_check,'') ~* '^\(?true\)?$'
     OR coalesce(qual,'') || coalesce(with_check,'') ~* 'user_metadata'
     OR (cmd = 'UPDATE' AND with_check IS NULL))
ORDER BY 1,2,3;

\echo '=== 4. Fonctions SECURITY DEFINER (Haute si search_path absent ; exposées en RPC si anon/authenticated peuvent EXECUTE) ==='
SELECT n.nspname AS schema, p.proname AS fonction, pg_get_function_identity_arguments(p.oid) AS args,
       coalesce(array_to_string(p.proconfig, ', '), '') AS config,
       (p.proconfig IS NULL OR NOT EXISTS (SELECT 1 FROM unnest(p.proconfig) x WHERE x LIKE 'search_path=%')) AS sans_search_path,
       CASE WHEN EXISTS (SELECT 1 FROM pg_roles WHERE rolname='anon') THEN has_function_privilege('anon', p.oid, 'EXECUTE') END AS anon_execute,
       CASE WHEN EXISTS (SELECT 1 FROM pg_roles WHERE rolname='authenticated') THEN has_function_privilege('authenticated', p.oid, 'EXECUTE') END AS auth_execute
FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE p.prosecdef AND n.nspname <> ALL (ARRAY['pg_catalog','information_schema','pg_toast','auth','storage','realtime','extensions','graphql','graphql_public','vault','pgsodium','pgsodium_masks','net','supabase_functions','supabase_migrations','cron','pgbouncer','_realtime','_analytics'])
ORDER BY 1,2;

\echo '=== 5. Fonctions du schéma public appelables par anon via /rest/v1/rpc (à justifier une par une) ==='
SELECT p.proname AS fonction, pg_get_function_identity_arguments(p.oid) AS args,
       CASE WHEN p.prosecdef THEN 'DEFINER' ELSE 'INVOKER' END AS securite
FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname = 'public' AND p.prokind = 'f'
  AND EXISTS (SELECT 1 FROM pg_roles WHERE rolname='anon')
  AND has_function_privilege('anon', p.oid, 'EXECUTE')
  AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.objid = p.oid AND d.deptype = 'e')  -- hors extensions
ORDER BY 1;

\echo '=== 6. Vues sans security_invoker (contournent la RLS des tables sous-jacentes, PG15+) ==='
SELECT n.nspname AS schema, c.relname AS vue, c.reloptions,
       CASE WHEN EXISTS (SELECT 1 FROM pg_roles WHERE rolname='anon') THEN has_table_privilege('anon', c.oid, 'SELECT') END AS anon_select
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind IN ('v','m') AND n.nspname <> ALL (ARRAY['pg_catalog','information_schema','pg_toast','auth','storage','realtime','extensions','graphql','graphql_public','vault','pgsodium','pgsodium_masks','net','supabase_functions','supabase_migrations','cron','pgbouncer','_realtime','_analytics'])
  AND NOT coalesce(c.reloptions::text[] && ARRAY['security_invoker=true','security_invoker=on'], false)
ORDER BY 1,2;

\echo '=== 7. Colonnes de privilège modifiables par authenticated (role, is_admin, plan, credits...) ==='
SELECT c.table_schema AS schema, c.table_name AS table_, c.column_name AS colonne,
       has_column_privilege('authenticated', format('%I.%I', c.table_schema, c.table_name), c.column_name, 'UPDATE') AS auth_update,
       has_column_privilege('authenticated', format('%I.%I', c.table_schema, c.table_name), c.column_name, 'INSERT') AS auth_insert
FROM information_schema.columns c
WHERE c.table_schema <> ALL (ARRAY['pg_catalog','information_schema','pg_toast','auth','storage','realtime','extensions','graphql','graphql_public','vault','pgsodium','pgsodium_masks','net','supabase_functions','supabase_migrations','cron','pgbouncer','_realtime','_analytics'])
  AND c.column_name ~* '^(role|roles|is_?admin|is_?staff|is_?superuser|admin|plan|tier|credits?|balance|solde|verified|is_?verified|permissions?|status)$'
  AND EXISTS (SELECT 1 FROM pg_roles WHERE rolname='authenticated')
ORDER BY 1,2,3;

\echo '=== 8. Buckets storage publics (Supabase) ==='
DO $$
DECLARE r record;
BEGIN
  IF to_regclass('storage.buckets') IS NULL THEN
    RAISE NOTICE 'pas de table storage.buckets (base non Supabase ou storage non initialisé)';
    RETURN;
  END IF;
  FOR r IN EXECUTE 'SELECT id, public, file_size_limit, allowed_mime_types FROM storage.buckets ORDER BY id' LOOP
    RAISE NOTICE 'bucket=% public=% taille_max=% mimes=%', r.id, r.public, r.file_size_limit, r.allowed_mime_types;
  END LOOP;
END $$;

\echo '=== 9. Policies sur storage.objects (vérifier le filtre par bucket_id ET par propriétaire) ==='
SELECT policyname, cmd, roles, qual AS using_, with_check
FROM pg_policies WHERE schemaname = 'storage' AND tablename = 'objects' ORDER BY 1;

\echo '=== 10. Tables où le propriétaire contourne la RLS (FORCE RLS absent : Info) ==='
SELECT n.nspname AS schema, c.relname AS table_
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind = 'r' AND c.relrowsecurity AND NOT c.relforcerowsecurity
  AND n.nspname <> ALL (ARRAY['pg_catalog','information_schema','pg_toast','auth','storage','realtime','extensions','graphql','graphql_public','vault','pgsodium','pgsodium_masks','net','supabase_functions','supabase_migrations','cron','pgbouncer','_realtime','_analytics'])
ORDER BY 1,2;

ROLLBACK;
