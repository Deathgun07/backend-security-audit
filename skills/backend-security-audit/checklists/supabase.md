# Checklist Supabase

Sources : `supabase/migrations/*.sql`, `supabase/seed.sql`, `supabase/config.toml`, code client (`createClient`), et si l'utilisateur fournit l'accès à **sa** base : sortie de `scripts/scan_rls.sql`.
Rappel : la clé `anon` est publique. Tout ce que `anon`/`authenticated` peuvent faire via PostgREST, n'importe qui peut le faire avec `curl`. La RLS est la seule barrière.

## S1. Table sans RLS — Critique (A01)
- **Chercher** : `create table` dans les migrations sans `alter table ... enable row level security` correspondant ; section 1 de `scan_rls.sql`.
- **Impact** : lecture/écriture/suppression de toute la table avec la clé anon.
```sql
-- ❌
create table public.invoices (id uuid primary key, user_id uuid, amount int);
-- ✅
create table public.invoices (id uuid primary key, user_id uuid references auth.users not null, amount int);
alter table public.invoices enable row level security;
create policy "lecture propriétaire" on public.invoices for select to authenticated
  using ((select auth.uid()) = user_id);
```
- Exception : table volontairement privée sans aucun `grant` à anon/authenticated → Basse (défense en profondeur).

## S2. Policy `USING (true)` / `WITH CHECK (true)` — Haute à Critique (A01)
- `for select using (true)` : lecture publique — acceptable seulement pour des données réellement publiques (catalogue). Sinon Haute.
- `for update/delete using (true)` ou `with check (true)` : Critique.
```sql
-- ❌
create policy "update" on profiles for update using (true);
-- ✅
create policy "update soi-même" on profiles for update to authenticated
  using ((select auth.uid()) = id) with check ((select auth.uid()) = id);
```
- Policy UPDATE sans `WITH CHECK` : l'utilisateur peut réassigner la ligne à un autre `user_id` → Moyenne.

## S3. Écriture autorisée à `anon` — Critique (A01)
- **Chercher** : `to anon` / `to public` sur `insert|update|delete|all` ; policies sans clause `to` (= `public`, inclut anon).
```sql
-- ❌ (pas de "to" → public)
create policy "insert" on comments for insert with check (true);
-- ✅
create policy "insert connecté" on comments for insert to authenticated
  with check ((select auth.uid()) = author_id);
```
- Exception légitime : formulaire de contact/newsletter → exiger contraintes (`check (length(msg) < 2000)`), rate limiting, captcha. Classer Moyenne.

## S4. `SECURITY DEFINER` sans `search_path` — Haute (A01/A08)
Une fonction DEFINER s'exécute avec les droits de son propriétaire (souvent `postgres`) et **contourne la RLS**.
```sql
-- ❌
create function public.get_user_email(uid uuid) returns text
language sql security definer as $$ select email from auth.users where id = uid $$;
-- ✅
create function private.get_user_email(uid uuid) returns text
language sql security definer set search_path = '' as $$
  select email from auth.users where id = uid and uid = (select auth.uid())
$$;
revoke execute on function private.get_user_email from public, anon;
```
Vérifier aussi : la fonction contrôle-t-elle `auth.uid()` en interne ? Est-elle dans un schéma exposé (`public`) ?

## S5. Vues sans `security_invoker` — Haute (A01)
Une vue s'exécute avec les droits de son créateur → contourne la RLS des tables sous-jacentes.
```sql
-- ❌
create view public.orders_summary as select user_id, sum(total) from orders group by 1;
-- ✅ (Postgres 15+)
create view public.orders_summary with (security_invoker = true) as ...;
-- ou : revoke select on public.orders_summary from anon, authenticated;
```
Les vues matérialisées n'ont pas de RLS : ne jamais les exposer dans `public` si elles contiennent des données privées.

## S6. Buckets storage publics / policies storage — Moyenne à Haute (A01)
- `public = true` : tout fichier lisible par URL sans auth. OK pour avatars/images publiques, pas pour factures, pièces d'identité, documents.
- Policies sur `storage.objects` qui ne filtrent pas `bucket_id` **et** le propriétaire :
```sql
-- ❌
create policy "upload" on storage.objects for insert to authenticated with check (true);
-- ✅
create policy "upload dossier perso" on storage.objects for insert to authenticated
  with check (bucket_id = 'docs' and (storage.foldername(name))[1] = (select auth.uid())::text);
```
- Bucket sans `allowed_mime_types` / `file_size_limit` : Basse (upload de HTML/SVG = XSS si servi inline).

## S7. RPC exposées — Moyenne à Critique (A01)
Toute fonction de `public` est appelable via `POST /rest/v1/rpc/<nom>` par anon si `EXECUTE` n'est pas révoqué (par défaut accordé à `public`).
- **Chercher** : `create function public.` dans les migrations, section 5 de `scan_rls.sql`, appels `.rpc('...')`.
- Fonction DEFINER qui modifie des données (crédits, rôles, paiements) appelable par anon/authenticated sans contrôle interne → Critique.
```sql
-- ✅
revoke execute on function public.add_credits(uuid,int) from public, anon, authenticated;
grant execute on function public.add_credits(uuid,int) to service_role;
```

## S8. Clé `service_role` côté client — Critique (A02)
- **Chercher** : `service_role`, `SUPABASE_SERVICE_ROLE_KEY` dans un fichier `"use client"`, un composant, un bundle mobile (Expo/React Native), une variable `NEXT_PUBLIC_*` / `EXPO_PUBLIC_*` / `VITE_*`.
```ts
// ❌ components/Admin.tsx ("use client")
const supabase = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY!);
// ✅ lib/supabase/admin.ts
import "server-only";
export const admin = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY!, { auth: { persistSession: false } });
```
- Usage serveur de service_role : vérifier que le code contrôle lui-même l'utilisateur (la RLS ne s'applique plus).

## S9. Colonnes `role` / `is_admin` modifiables dans `profiles` — Critique (A01)
Policy « l'utilisateur met à jour son profil » + colonne `role` dans la même table = escalade de privilèges :
`supabase.from('profiles').update({ role: 'admin' }).eq('id', monId)`.
```sql
-- ✅ option 1 : droits par colonne
revoke update on public.profiles from authenticated;
grant update (full_name, avatar_url, bio) on public.profiles to authenticated;
-- ✅ option 2 : trigger qui bloque
create function private.block_role_change() returns trigger language plpgsql set search_path = '' as $$
begin
  if new.role is distinct from old.role and (select auth.role()) <> 'service_role' then
    raise exception 'modification du rôle interdite';
  end if; return new;
end $$;
create trigger t_block_role before update on public.profiles for each row execute function private.block_role_change();
```
Idem pour `plan`, `credits`, `balance`, `is_verified`, `organization_id`.

## S10. `user_metadata` dans les policies — Haute (A01)
`auth.jwt() -> 'user_metadata'` est **modifiable par l'utilisateur** (`supabase.auth.updateUser({ data: { role: 'admin' } })`). Utiliser `app_metadata` (modifiable seulement côté serveur) ou une table de rôles.
```sql
-- ❌ using ((auth.jwt() -> 'user_metadata' ->> 'role') = 'admin')
-- ✅ using ((auth.jwt() -> 'app_metadata' ->> 'role') = 'admin')
```

## S11. `getSession()` côté serveur — Moyenne (A07)
`supabase.auth.getSession()` lit le cookie sans revalider le JWT. Côté serveur (route, server action, middleware) utiliser `auth.getUser()` (ou `getClaims()` avec vérification de signature).

## S12. Edge Functions — Moyenne à Haute (A01/A07)
- `verify_jwt = false` dans `supabase/config.toml` : la fonction doit alors vérifier elle-même (webhook signé Stripe, etc.).
- Fonction utilisant service_role sans lire l'utilisateur appelant.
- `Access-Control-Allow-Origin: *` avec cookies/credentials.

## S13. Config Auth (`supabase/config.toml`) — Basse à Moyenne (A07)
`enable_confirmations = false` en prod, `minimum_password_length < 8`, `double_confirm_changes = false`, redirect URLs trop larges (`additional_redirect_urls = ["https://*"]`).
