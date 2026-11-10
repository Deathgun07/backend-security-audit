# Supabase checklist

Sources: `supabase/migrations/*.sql`, `supabase/seed.sql`, `supabase/config.toml`, client code (`createClient`), and if the user provides access to **their** database: output of `scripts/scan_rls.sql`.
Reminder: the `anon` key is public. Anything `anon`/`authenticated` can do via PostgREST, anyone can do with `curl`. RLS is the only barrier.

## S1. Table without RLS — Critical (A01)
- **Look for**: `create table` in migrations without a matching `alter table ... enable row level security`; section 1 of `scan_rls.sql`.
- **Impact**: read/write/delete of the whole table with the anon key.
```sql
-- ❌
create table public.invoices (id uuid primary key, user_id uuid, amount int);
-- ✅
create table public.invoices (id uuid primary key, user_id uuid references auth.users not null, amount int);
alter table public.invoices enable row level security;
create policy "owner read" on public.invoices for select to authenticated
  using ((select auth.uid()) = user_id);
```
- Exception: table intentionally private with no `grant` to anon/authenticated → Low (defense in depth).

## S2. Policy `USING (true)` / `WITH CHECK (true)` — High to Critical (A01)
- `for select using (true)`: public read — acceptable only for truly public data (catalog). Otherwise High.
- `for update/delete using (true)` or `with check (true)`: Critical.
```sql
-- ❌
create policy "update" on profiles for update using (true);
-- ✅
create policy "update self" on profiles for update to authenticated
  using ((select auth.uid()) = id) with check ((select auth.uid()) = id);
```
- UPDATE policy without `WITH CHECK`: the user can reassign the row to another `user_id` → Medium.

## S3. Write allowed to `anon` — Critical (A01)
- **Look for**: `to anon` / `to public` on `insert|update|delete|all`; policies without a `to` clause (= `public`, includes anon).
```sql
-- ❌ (no "to" → public)
create policy "insert" on comments for insert with check (true);
-- ✅
create policy "insert signed-in" on comments for insert to authenticated
  with check ((select auth.uid()) = author_id);
```
- Legitimate exception: contact/newsletter form → require constraints (`check (length(msg) < 2000)`), rate limiting, captcha. Rate as Medium.

## S4. `SECURITY DEFINER` without `search_path` — High (A01/A08)
A DEFINER function runs with the rights of its owner (often `postgres`) and **bypasses RLS**.
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
Also check: does the function check `auth.uid()` internally? Is it in an exposed schema (`public`)?

## S5. Views without `security_invoker` — High (A01)
A view runs with the rights of its creator → bypasses RLS on the underlying tables.
```sql
-- ❌
create view public.orders_summary as select user_id, sum(total) from orders group by 1;
-- ✅ (Postgres 15+)
create view public.orders_summary with (security_invoker = true) as ...;
-- or: revoke select on public.orders_summary from anon, authenticated;
```
Materialized views have no RLS: never expose them in `public` if they contain private data.

## S6. Public storage buckets / storage policies — Medium to High (A01)
- `public = true`: any file readable by URL without auth. Fine for avatars/public images, not for invoices, ID documents, documents.
- Policies on `storage.objects` that do not filter on `bucket_id` **and** the owner:
```sql
-- ❌
create policy "upload" on storage.objects for insert to authenticated with check (true);
-- ✅
create policy "upload personal folder" on storage.objects for insert to authenticated
  with check (bucket_id = 'docs' and (storage.foldername(name))[1] = (select auth.uid())::text);
```
- Bucket without `allowed_mime_types` / `file_size_limit`: Low (uploading HTML/SVG = XSS if served inline).

## S7. Exposed RPCs — Medium to Critical (A01)
Any function in `public` is callable via `POST /rest/v1/rpc/<name>` by anon if `EXECUTE` is not revoked (granted to `public` by default).
- **Look for**: `create function public.` in migrations, section 5 of `scan_rls.sql`, `.rpc('...')` calls.
- DEFINER function that modifies data (credits, roles, payments) callable by anon/authenticated without internal checks → Critical.
```sql
-- ✅
revoke execute on function public.add_credits(uuid,int) from public, anon, authenticated;
grant execute on function public.add_credits(uuid,int) to service_role;
```

## S8. `service_role` key on the client side — Critical (A02)
- **Look for**: `service_role`, `SUPABASE_SERVICE_ROLE_KEY` in a `"use client"` file, a component, a mobile bundle (Expo/React Native), a `NEXT_PUBLIC_*` / `EXPO_PUBLIC_*` / `VITE_*` variable.
```ts
// ❌ components/Admin.tsx ("use client")
const supabase = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY!);
// ✅ lib/supabase/admin.ts
import "server-only";
export const admin = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY!, { auth: { persistSession: false } });
```
- Server-side use of service_role: check that the code itself verifies the user (RLS no longer applies).

## S9. Modifiable `role` / `is_admin` columns in `profiles` — Critical (A01)
An "the user updates their profile" policy + a `role` column in the same table = privilege escalation:
`supabase.from('profiles').update({ role: 'admin' }).eq('id', myId)`.
```sql
-- ✅ option 1: column-level grants
revoke update on public.profiles from authenticated;
grant update (full_name, avatar_url, bio) on public.profiles to authenticated;
-- ✅ option 2: blocking trigger
create function private.block_role_change() returns trigger language plpgsql set search_path = '' as $$
begin
  if new.role is distinct from old.role and (select auth.role()) <> 'service_role' then
    raise exception 'role change forbidden';
  end if; return new;
end $$;
create trigger t_block_role before update on public.profiles for each row execute function private.block_role_change();
```
Same for `plan`, `credits`, `balance`, `is_verified`, `organization_id`.

## S10. `user_metadata` in policies — High (A01)
`auth.jwt() -> 'user_metadata'` is **modifiable by the user** (`supabase.auth.updateUser({ data: { role: 'admin' } })`). Use `app_metadata` (modifiable only server-side) or a roles table.
```sql
-- ❌ using ((auth.jwt() -> 'user_metadata' ->> 'role') = 'admin')
-- ✅ using ((auth.jwt() -> 'app_metadata' ->> 'role') = 'admin')
```

## S11. `getSession()` on the server side — Medium (A07)
`supabase.auth.getSession()` reads the cookie without revalidating the JWT. On the server side (route, server action, middleware) use `auth.getUser()` (or `getClaims()` with signature verification).

## S12. Edge Functions — Medium to High (A01/A07)
- `verify_jwt = false` in `supabase/config.toml`: the function must then verify by itself (signed Stripe webhook, etc.).
- Function using service_role without reading the calling user.
- `Access-Control-Allow-Origin: *` with cookies/credentials.

## S13. Auth config (`supabase/config.toml`) — Low to Medium (A07)
`enable_confirmations = false` in prod, `minimum_password_length < 8`, `double_confirm_changes = false`, overly broad redirect URLs (`additional_redirect_urls = ["https://*"]`).
