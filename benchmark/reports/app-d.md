# Backend security audit: shopnotes

| | |
|---|---|
| **Date** | 2026-11-17 |
| **Audited commit** | see `git rev-parse --short HEAD` (git repository at project root) |
| **Detected stacks** | nextjs, supabase |
| **Scope** | Local repository code, Supabase migration analysis (no database access) |
| **Out of scope** | Supabase dashboard settings, production env vars, dynamic testing |

> Read-only static analysis: no project file was modified. Fixes are proposed as diffs.

## Summary

**Score: 0/100.** Several tables, RPCs and routes are exposed to any signed-up user (or anonymous visitor), allowing data theft, privilege escalation and free credits.

| Severity | Confirmed | To verify |
|---|---|---|
| Critical | 3 | 0 |
| High | 5 | 1 |
| Medium | 1 | 0 |
| Low | 1 | 2 |
| Info | 0 | 0 |

Score = 100 - (75 + 50 + 4 + 1) + half weights for to-verify = floored at 0.

## Summary table

| ID | Severity | Title | OWASP | Location | Status |
|---|---|---|---|---|---|
| SEC-01 | Critical | `orders` table without RLS | A01 | `supabase/migrations/20250301000000_schema.sql:21-27` | Confirmed |
| SEC-02 | Critical | Users can edit their own `role` and `credits` | A01 | `schema.sql:4-5,9-10` | Confirmed |
| SEC-03 | Critical | `transfer_credits` SECURITY DEFINER RPC callable by anyone, no checks | A01 | `schema.sql:42-47`, `components/Credits.tsx:7` | Confirmed |
| SEC-04 | High | `messages` readable by every authenticated user | A01 | `schema.sql:36` | Confirmed |
| SEC-05 | High | RLS policy trusts user-editable `user_metadata` | A01 | `schema.sql:39-40` | Confirmed |
| SEC-06 | High | `invoices` storage bucket is public | A01 | `schema.sql:58` | Confirmed |
| SEC-07 | High | `cancelOrder` IDOR with service_role client | A01 | `app/orders/actions.ts:9` | Confirmed |
| SEC-08 | High | Admin export has no admin check | A01 | `app/api/admin/export/route.ts:6-8` | Confirmed |
| SEC-09 | Medium | `getSession()` used for server-side auth | A07 | `app/api/admin/export/route.ts:6` | Confirmed |
| SEC-10 | Low | No security headers | A05 | `next.config.js:1-8` | Confirmed |
| SEC-11 | High | Next.js 15.3.2 / React 19.1.0 likely affected by known CVEs | A06 | `package.json:1` | To verify |
| SEC-12 | Low | service_role key injected via `next.config.js` `env` | A02 | `next.config.js:5` | To verify |
| SEC-13 | Low | Auth settings left at defaults (rate limits, confirmations) | A07 | `supabase/config.toml:1-3` | To verify |

## Findings

### SEC-01: `orders` table without RLS
- **Severity**: Critical, **OWASP**: A01, **Status**: Confirmed
```sql
21 create table public.orders (
22   id uuid primary key default gen_random_uuid(),
23   customer_id uuid not null references auth.users,
...
26   shipping_address text
27 );
```
No `enable row level security` for `orders` in any migration. **Impact**: with the public anon key, anyone can read, modify and delete all orders and shipping addresses via `/rest/v1/orders` (default Supabase grants).
```diff
+alter table public.orders enable row level security;
+create policy "own orders" on public.orders for select to authenticated
+  using ((select auth.uid()) = customer_id);
```

### SEC-02: Users can edit their own `role` and `credits`
- **Severity**: Critical, **OWASP**: A01, **Status**: Confirmed
```sql
4  role text not null default 'customer',
5  credits integer not null default 0
9  create policy "update own profile" on public.profiles for update to authenticated
10   using ((select auth.uid()) = id) with check ((select auth.uid()) = id);
```
**Impact**: `supabase.from('profiles').update({ role: 'admin', credits: 1000000 }).eq('id', myId)` succeeds; no column grants or trigger restrict it.
```diff
+revoke update on public.profiles from authenticated;
+grant update (display_name) on public.profiles to authenticated;
```

### SEC-03: `transfer_credits` SECURITY DEFINER RPC callable by anyone, no checks
- **Severity**: Critical, **OWASP**: A01, **Status**: Confirmed
```sql
42 create function public.transfer_credits(from_user uuid, to_user uuid, amount integer) returns void
43 language plpgsql security definer as $$
45   update public.profiles set credits = credits - amount where id = from_user;
46   update public.profiles set credits = credits + amount where id = to_user;
```
```tsx
7 supabase.rpc("transfer_credits", { from_user: me, to_user: to, amount: 10 })
```
**Impact**: Executable by `anon` and `authenticated` (default EXECUTE to public), bypasses RLS, takes `from_user` from the client, no `auth.uid()` check, no `amount > 0` check (a negative amount steals credits), no `search_path`. Anyone can drain or mint credits for any account.
```diff
-create function public.transfer_credits(from_user uuid, to_user uuid, amount integer) returns void
-language plpgsql security definer as $$
+create function public.transfer_credits(to_user uuid, amount integer) returns void
+language plpgsql security definer set search_path = '' as $$
+begin
+  if amount <= 0 or (select auth.uid()) is null then raise exception 'invalid'; end if;
+  update public.profiles set credits = credits - amount where id = (select auth.uid()) and credits >= amount;
+  if not found then raise exception 'insufficient credits'; end if;
+  update public.profiles set credits = credits + amount where id = to_user;
+end $$;
+revoke execute on function public.transfer_credits(uuid,integer) from public, anon;
```

### SEC-04: `messages` readable by every authenticated user
- **Severity**: High, **OWASP**: A01, **Status**: Confirmed
```sql
36 create policy "read messages" on public.messages for select to authenticated using (true);
```
**Impact**: any signed-up user reads all private messages.
```diff
-... using (true);
+... using ((select auth.uid()) in (sender, recipient));
```

### SEC-05: RLS policy trusts user-editable `user_metadata`
- **Severity**: High, **OWASP**: A01, **Status**: Confirmed
```sql
39 create policy "staff can read all profiles" on public.profiles for select to authenticated
40   using ((auth.jwt() -> 'user_metadata' ->> 'staff') = 'true');
```
**Impact**: `supabase.auth.updateUser({ data: { staff: 'true' } })` makes any user read all profiles (including role and credits).
```diff
-using ((auth.jwt() -> 'user_metadata' ->> 'staff') = 'true');
+using ((auth.jwt() -> 'app_metadata' ->> 'staff') = 'true');
```

### SEC-06: `invoices` storage bucket is public
- **Severity**: High, **OWASP**: A01, **Status**: Confirmed
```sql
58 insert into storage.buckets (id, name, public) values ('invoices', 'invoices', true);
```
**Impact**: invoices are readable by URL without authentication (guessable/leaked URLs). No `storage.objects` policies, size or MIME limits are defined either.
```diff
-values ('invoices', 'invoices', true);
+values ('invoices', 'invoices', false);
```
plus a `storage.objects` select policy filtering on `bucket_id` and the owner's folder.

### SEC-07: `cancelOrder` IDOR with service_role client
- **Severity**: High, **OWASP**: A01, **Status**: Confirmed
```ts
7  const { data: { user } } = await supabase.auth.getUser();
8  if (!user) throw new Error("Not authenticated");
9  await admin.from("orders").update({ status: "cancelled" }).eq("id", orderId);
```
**Impact**: the admin client bypasses RLS and the order is not filtered by owner: any signed-in user can cancel any order by ID.
```diff
-await admin.from("orders").update({ status: "cancelled" }).eq("id", orderId);
+await admin.from("orders").update({ status: "cancelled" }).eq("id", orderId).eq("customer_id", user.id);
```
(`myOrders`, line 16, correctly filters by `user.id`.)

### SEC-08: Admin export has no admin check
- **Severity**: High, **OWASP**: A01, **Status**: Confirmed
```ts
6  const { data: { session } } = await supabase.auth.getSession();
7  if (!session) return new Response("Unauthorized", { status: 401 });
8  const { data } = await admin.from("orders").select("id, customer_id, total_cents, shipping_address");
```
**Impact**: route is under `/api/admin/` but only requires a session; sign-up is enabled (`config.toml:3`), so anyone can export all orders and addresses (PII).
```diff
+const { data: { user } } = await supabase.auth.getUser();
+if (!user) return new Response("Unauthorized", { status: 401 });
+if (user.app_metadata?.role !== "admin") return new Response("Forbidden", { status: 403 });
```

### SEC-09: `getSession()` used for server-side auth
- **Severity**: Medium, **OWASP**: A07, **Status**: Confirmed
`app/api/admin/export/route.ts:6` reads the cookie without revalidating the JWT. Use `auth.getUser()` (see diff in SEC-08).

### SEC-10: No security headers
- **Severity**: Low, **OWASP**: A05, **Status**: Confirmed
`next.config.js:1-8` sets only `poweredByHeader: false`; no `headers()` (HSTS, nosniff, frame-ancestors, CSP). Add a `headers()` function as in the Next.js checklist.

### SEC-11: Next.js 15.3.2 / React 19.1.0 likely affected by known CVEs
- **Severity**: High, **OWASP**: A06, **Status**: To verify manually
```json
1 "next": "15.3.2", "react": "19.1.0"
```
No lockfile in the repository and no network audit possible. Next 15.3.2 is past CVE-2025-29927 (fixed in 15.2.3) but I believe the React Server Components advisories of late 2025 affect these versions. Check: generate a lockfile and run `npm audit --omit=dev`, then upgrade to the latest patched 15.x and React.

### SEC-12: service_role key injected via `next.config.js` `env`
- **Severity**: Low, **OWASP**: A02, **Status**: To verify manually
```js
5  SUPABASE_SERVICE_ROLE_KEY: process.env.SUPABASE_SERVICE_ROLE_KEY,
```
The `env` option inlines the value at build time wherever referenced. Today it is only referenced from `lib/supabase/admin.ts` (`server-only`), so no leak is visible, but any client import would embed the key. Check the built `.next/static` for the key; remove this `env` entry (the server reads `process.env` natively).

### SEC-13: Auth settings left at defaults
- **Severity**: Low, **OWASP**: A07, **Status**: To verify manually
`supabase/config.toml:1-3` has no `[auth.rate_limit]`, `enable_confirmations` or password-length setting. Check the hosted project's dashboard for email confirmation, minimum password length and rate limits.

## Strengths
- `notes` RLS is correct with `USING` and `WITH CHECK` on owner (`schema.sql:17-19`), and the route uses `getUser()` plus zod validation (`app/api/notes/route.ts:8-10`).
- `profiles` select policy and `order_stats` view use `security_invoker = true` (`schema.sql:54`); `my_notes()` is invoker with `search_path = ''` (`schema.sql:49-52`).
- `lib/supabase/admin.ts` uses `import "server-only"`; the service_role key is not committed (`.gitignore` ignores `.env*`; no secrets found).
- `app/orders/actions.ts` checks the user with `getUser()` and `myOrders` filters by owner.

## Fix priorities
1. **SEC-01 / SEC-02 / SEC-03**: enable RLS on `orders`, lock `profiles` columns, rewrite and revoke `transfer_credits` (1 h)
2. **SEC-08 / SEC-07**: admin role check and owner filter on server code (15 min)
3. **SEC-04 / SEC-05**: fix messages and metadata policies (15 min)
4. **SEC-06**: make `invoices` private with owner policies (30 min)
5. **SEC-11**: audit and update Next.js / React (30 min)

## Appendices

### Commands run
```
detect_stack.sh, find_secrets.sh, grep_patterns.sh (stacks: supabase,nextjs); manual read of all 12 tracked files. No dependency audit (no lockfile), no database scan.
```

### Discarded leads (false positives)
| Location | Pattern | Reason |
|---|---|---|
| `schema.sql:57` | bucket_public | `avatars` bucket public by design |
| `schema.sql:54` | view | `order_stats` has `security_invoker = true`, but protection depends on SEC-01 fix |
| `components/Credits.tsx:4` | anon key client | public by design |
| `lib/supabase/admin.ts:4` | service_role_server_to_check | server-only module, correct pattern (misuse reported in SEC-07, SEC-08) |
| `.env.example` | env | empty placeholders |
| `app/api/notes/route.ts:6` | api_route_to_check | auth, validation and RLS present |

### Not verified
- Live database state, dashboard settings, deployed versions, dependency vulnerabilities (no lockfile).
