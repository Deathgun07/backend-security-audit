-- scan_rls.sql — audits RLS / privileges of a Postgres database (Supabase or not). READ-ONLY.
-- Run ONLY on your own database (preferably local):
--   psql "postgresql://postgres:postgres@127.0.0.1:54322/postgres" -f scan_rls.sql   (supabase start)
--   or paste it section by section into the SQL Editor of your Supabase project.
-- All queries are SELECTs inside a READ ONLY transaction rolled back at the end.

BEGIN READ ONLY;
SET LOCAL statement_timeout = '30s';

-- System schemas excluded: list repeated in each query (no object created, SQL Editor compatible)
-- anon/authenticated roles: checked through pg_roles so the script also runs outside Supabase.

\echo '=== 1. Tables WITHOUT RLS (Critical if anon/authenticated have privileges on them) ==='
SELECT n.nspname AS schema, c.relname AS table_,
       CASE WHEN EXISTS (SELECT 1 FROM pg_roles WHERE rolname='anon') THEN has_table_privilege('anon', c.oid, 'SELECT') END          AS anon_select,
       CASE WHEN EXISTS (SELECT 1 FROM pg_roles WHERE rolname='anon') THEN has_table_privilege('anon', c.oid, 'INSERT,UPDATE,DELETE') END AS anon_ecriture,
       CASE WHEN EXISTS (SELECT 1 FROM pg_roles WHERE rolname='authenticated') THEN has_table_privilege('authenticated', c.oid, 'INSERT,UPDATE,DELETE') END AS auth_ecriture
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind IN ('r','p') AND NOT c.relrowsecurity
  AND n.nspname <> ALL (ARRAY['pg_catalog','information_schema','pg_toast','auth','storage','realtime','extensions','graphql','graphql_public','vault','pgsodium','pgsodium_masks','net','supabase_functions','supabase_migrations','cron','pgbouncer','_realtime','_analytics']) AND n.nspname NOT LIKE 'pg_temp%' AND n.nspname NOT LIKE 'pg_toast%'
ORDER BY 1,2;

\echo '=== 2. Tables with RLS but NO policy (everything denied: Info) ==='
SELECT n.nspname AS schema, c.relname AS table_
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind IN ('r','p') AND c.relrowsecurity
  AND n.nspname <> ALL (ARRAY['pg_catalog','information_schema','pg_toast','auth','storage','realtime','extensions','graphql','graphql_public','vault','pgsodium','pgsodium_masks','net','supabase_functions','supabase_migrations','cron','pgbouncer','_realtime','_analytics'])
  AND NOT EXISTS (SELECT 1 FROM pg_policies p WHERE p.schemaname = n.nspname AND p.tablename = c.relname)
ORDER BY 1,2;

\echo '=== 3. Permissive policies (USING true / WITH CHECK true / anon writes / user_metadata) ==='
SELECT schemaname AS schema, tablename AS table_, policyname, cmd, roles, permissive,
       qual AS using_, with_check,
       CASE
         WHEN ('anon' = ANY(roles) OR 'public' = ANY(roles)) AND cmd IN ('INSERT','UPDATE','DELETE','ALL') THEN 'Critical: anon/public write'
         WHEN coalesce(qual,'') ~* '^\(?true\)?$' AND cmd IN ('UPDATE','DELETE','ALL') THEN 'Critical: USING true on write'
         WHEN coalesce(with_check,'') ~* '^\(?true\)?$' THEN 'High: WITH CHECK true'
         WHEN coalesce(qual,'') ~* '^\(?true\)?$' THEN 'Medium: full read (check if intended)'
         WHEN coalesce(qual,'') || coalesce(with_check,'') ~* 'user_metadata' THEN 'High: user_metadata is user-editable'
         WHEN cmd = 'UPDATE' AND with_check IS NULL THEN 'Medium: UPDATE without WITH CHECK'
       END AS alert
FROM pg_policies
WHERE schemaname NOT IN ('auth','realtime','supabase_functions')
  AND ( ('anon' = ANY(roles) OR 'public' = ANY(roles)) AND cmd IN ('INSERT','UPDATE','DELETE','ALL')
     OR coalesce(qual,'') ~* '^\(?true\)?$' OR coalesce(with_check,'') ~* '^\(?true\)?$'
     OR coalesce(qual,'') || coalesce(with_check,'') ~* 'user_metadata'
     OR (cmd = 'UPDATE' AND with_check IS NULL))
ORDER BY 1,2,3;

\echo '=== 4. SECURITY DEFINER functions (High if search_path missing; exposed as RPC if anon/authenticated can EXECUTE) ==='
SELECT n.nspname AS schema, p.proname AS function_name, pg_get_function_identity_arguments(p.oid) AS args,
       coalesce(array_to_string(p.proconfig, ', '), '') AS config,
       (p.proconfig IS NULL OR NOT EXISTS (SELECT 1 FROM unnest(p.proconfig) x WHERE x LIKE 'search_path=%')) AS no_search_path,
       CASE WHEN EXISTS (SELECT 1 FROM pg_roles WHERE rolname='anon') THEN has_function_privilege('anon', p.oid, 'EXECUTE') END AS anon_execute,
       CASE WHEN EXISTS (SELECT 1 FROM pg_roles WHERE rolname='authenticated') THEN has_function_privilege('authenticated', p.oid, 'EXECUTE') END AS auth_execute
FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE p.prosecdef AND n.nspname <> ALL (ARRAY['pg_catalog','information_schema','pg_toast','auth','storage','realtime','extensions','graphql','graphql_public','vault','pgsodium','pgsodium_masks','net','supabase_functions','supabase_migrations','cron','pgbouncer','_realtime','_analytics'])
ORDER BY 1,2;

\echo '=== 5. public schema functions callable by anon via /rest/v1/rpc (justify each one) ==='
SELECT p.proname AS function_name, pg_get_function_identity_arguments(p.oid) AS args,
       CASE WHEN p.prosecdef THEN 'DEFINER' ELSE 'INVOKER' END AS security
FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname = 'public' AND p.prokind = 'f'
  AND EXISTS (SELECT 1 FROM pg_roles WHERE rolname='anon')
  AND has_function_privilege('anon', p.oid, 'EXECUTE')
  AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.objid = p.oid AND d.deptype = 'e')  -- excluding extensions
ORDER BY 1;

\echo '=== 6. Views without security_invoker (bypass RLS of underlying tables, PG15+) ==='
SELECT n.nspname AS schema, c.relname AS view_name, c.reloptions,
       CASE WHEN EXISTS (SELECT 1 FROM pg_roles WHERE rolname='anon') THEN has_table_privilege('anon', c.oid, 'SELECT') END AS anon_select
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind IN ('v','m') AND n.nspname <> ALL (ARRAY['pg_catalog','information_schema','pg_toast','auth','storage','realtime','extensions','graphql','graphql_public','vault','pgsodium','pgsodium_masks','net','supabase_functions','supabase_migrations','cron','pgbouncer','_realtime','_analytics'])
  AND NOT coalesce(c.reloptions::text[] && ARRAY['security_invoker=true','security_invoker=on'], false)
ORDER BY 1,2;

\echo '=== 7. Privilege columns writable by authenticated (role, is_admin, plan, credits...) ==='
SELECT c.table_schema AS schema, c.table_name AS table_, c.column_name AS column_name,
       has_column_privilege('authenticated', format('%I.%I', c.table_schema, c.table_name), c.column_name, 'UPDATE') AS auth_update,
       has_column_privilege('authenticated', format('%I.%I', c.table_schema, c.table_name), c.column_name, 'INSERT') AS auth_insert
FROM information_schema.columns c
WHERE c.table_schema <> ALL (ARRAY['pg_catalog','information_schema','pg_toast','auth','storage','realtime','extensions','graphql','graphql_public','vault','pgsodium','pgsodium_masks','net','supabase_functions','supabase_migrations','cron','pgbouncer','_realtime','_analytics'])
  AND c.column_name ~* '^(role|roles|is_?admin|is_?staff|is_?superuser|admin|plan|tier|credits?|balance|solde|verified|is_?verified|permissions?|status)$'
  AND EXISTS (SELECT 1 FROM pg_roles WHERE rolname='authenticated')
ORDER BY 1,2,3;

\echo '=== 8. Public storage buckets (Supabase) ==='
DO $$
DECLARE r record;
BEGIN
  IF to_regclass('storage.buckets') IS NULL THEN
    RAISE NOTICE 'no storage.buckets table (not Supabase, or storage not initialized)';
    RETURN;
  END IF;
  FOR r IN EXECUTE 'SELECT id, public, file_size_limit, allowed_mime_types FROM storage.buckets ORDER BY id' LOOP
    RAISE NOTICE 'bucket=% public=% max_size=% mimes=%', r.id, r.public, r.file_size_limit, r.allowed_mime_types;
  END LOOP;
END $$;

\echo '=== 9. Policies on storage.objects (check filtering by bucket_id AND owner) ==='
SELECT policyname, cmd, roles, qual AS using_, with_check
FROM pg_policies WHERE schemaname = 'storage' AND tablename = 'objects' ORDER BY 1;

\echo '=== 10. Tables where the owner bypasses RLS (no FORCE RLS: Info) ==='
SELECT n.nspname AS schema, c.relname AS table_
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind = 'r' AND c.relrowsecurity AND NOT c.relforcerowsecurity
  AND n.nspname <> ALL (ARRAY['pg_catalog','information_schema','pg_toast','auth','storage','realtime','extensions','graphql','graphql_public','vault','pgsodium','pgsodium_masks','net','supabase_functions','supabase_migrations','cron','pgbouncer','_realtime','_analytics'])
ORDER BY 1,2;

ROLLBACK;
