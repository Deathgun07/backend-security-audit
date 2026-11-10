# Audit de sécurité backend : factures-demo

| | |
|---|---|
| **Date** | 2026-11-10 |
| **Commit audité** | `6b0e620` (master) |
| **Stacks détectés** | nextjs, supabase, pocketbase, php-mysql, flask |
| **Périmètre** | Code local du dépôt (application de démonstration `tests/fixtures/app-vulnerable`, secrets factices) |
| **Hors périmètre** | Base Postgres réelle (`scan_rls.sql` non exécuté : pas de base fournie), configuration serveur web, dashboard Supabase / PocketBase |

> Analyse statique en lecture seule : aucun fichier du projet n'a été modifié. Les correctifs sont proposés sous forme de diff.

## Résumé

**Score : 0/100.** Le projet est compromettable sans authentification par au moins six chemins indépendants : clé `service_role` publique, table sans RLS, injections SQL, SSTI, LFI et upload exécutable.

| Sévérité | Confirmées | À vérifier |
|---|---|---|
| 🔴 Critique | 15 | 1 |
| 🟠 Haute | 7 | 1 |
| 🟡 Moyenne | 6 | 2 |
| 🔵 Basse | 0 | 0 |
| ⚪ Info | 0 | 1 |

<!-- 100 − (15×25 + 7×10 + 6×4) − (12,5 + 5 + 2×2) < 0 → 0 -->

## Tableau récapitulatif

| ID | Sévérité | Titre | OWASP | Emplacement | Statut |
|---|---|---|---|---|---|
| SEC-01 | Critique | Clé `service_role` envoyée au navigateur | A02 | `components/AdminPanel.tsx:6` | Confirmé |
| SEC-02 | Critique | `.env` commité avec clé Stripe live | A02 | `.env:3` | Confirmé |
| SEC-03 | Critique | Table `invoices` sans RLS | A01 | `supabase/migrations/20250101000000_init.sql:10` | Confirmé |
| SEC-04 | Critique | Escalade de privilèges via `profiles` (`UPDATE USING (true)`) | A01 | `supabase/migrations/20250101000000_init.sql:8` | Confirmé |
| SEC-05 | Critique | RPC `add_credits` SECURITY DEFINER appelable par tous | A01 | `supabase/migrations/20250101000000_init.sql:20` | Confirmé |
| SEC-06 | Critique | `GET /api/invoices/[id]` sans authentification (IDOR) | A01 | `app/api/invoices/[id]/route.ts:5` | Confirmé |
| SEC-07 | Critique | Server action `deleteInvoice` sans authentification | A01 | `app/actions.ts:6` | Confirmé |
| SEC-08 | Critique | Collection PocketBase `notes` lisible et supprimable par tous | A01 | `pb_migrations/1700000000_created_notes.js:6` | Confirmé |
| SEC-09 | Critique | Injection SQL dans un hook PocketBase public | A03 | `pb_hooks/main.pb.js:5` | Confirmé |
| SEC-10 | Critique | Injection SQL sur le login PHP | A03 | `php/login.php:5` | Confirmé |
| SEC-11 | Critique | Inclusion de fichier contrôlée par l'utilisateur (LFI) | A03 | `php/upload.php:6` | Confirmé |
| SEC-12 | Critique | Upload non sécurisé permettant de déposer un `.php` | A04 | `php/upload.php:3` | Confirmé |
| SEC-13 | Critique | SSTI via `render_template_string` | A03 | `flask/app.py:11` | Confirmé |
| SEC-14 | Critique | Injection SQL (f-string) | A03 | `flask/app.py:16` | Confirmé |
| SEC-15 | Critique | Désérialisation `pickle` / `yaml.Loader` d'une entrée utilisateur | A08 | `flask/app.py:21` | Confirmé |
| SEC-16 | Critique | Débogueur Werkzeug exposé (`debug=True`, `0.0.0.0`) | A05 | `flask/app.py:24` | À vérifier |
| SEC-17 | Haute | Vue `invoice_totals` sans `security_invoker` | A01 | `supabase/migrations/20250101000000_init.sql:26` | Confirmé |
| SEC-18 | Haute | SSRF sur `/api/preview` | A10 | `app/api/preview/route.ts:3` | Confirmé |
| SEC-19 | Haute | Middleware contournable (matcher partiel + `getSession`) | A01 | `middleware.ts:14` | Confirmé |
| SEC-20 | Haute | Next.js 15.1.0 affecté par CVE-2025-29927 | A06 | `package.json:4` | À vérifier |
| SEC-21 | Haute | Rules PocketBase create/update « connecté » au lieu de « propriétaire » | A01 | `pb_migrations/1700000000_created_notes.js:8` | Confirmé |
| SEC-22 | Haute | Mots de passe hachés en MD5 | A02 | `php/login.php:7` | Confirmé |
| SEC-23 | Haute | Identifiants MySQL `root` en dur | A02 | `php/config.php:3` | Confirmé |
| SEC-24 | Haute | `SECRET_KEY` Flask en dur et triviale | A02 | `flask/app.py:6` | Confirmé |
| SEC-25 | Moyenne | Insertion anonyme illimitée dans `comments` | A01 | `supabase/migrations/20250101000000_init.sql:18` | Confirmé |
| SEC-26 | Moyenne | XSS réfléchi sur l'email | A03 | `php/login.php:11` | Confirmé |
| SEC-27 | Moyenne | Redirection ouverte (et pas d'`exit`) | A01 | `php/login.php:9` | Confirmé |
| SEC-28 | Moyenne | Fixation de session (pas de `session_regenerate_id`) | A07 | `php/login.php:8` | Confirmé |
| SEC-29 | Moyenne | `display_errors` activé | A05 | `php/config.php:2` | Confirmé |
| SEC-30 | Moyenne | CORS toutes origines avec credentials | A05 | `flask/app.py:7` | Confirmé |
| SEC-31 | Moyenne | `dangerouslySetInnerHTML` sans assainissement | A03 | `components/AdminPanel.tsx:10` | À vérifier |
| SEC-32 | Moyenne | Pas de rate limiting sur le login | A07 | `php/login.php:5` | À vérifier |
| SEC-33 | Info | Audit des dépendances impossible (aucun lockfile) | A06 | `package.json:1` | À vérifier |

## Détail des failles

### SEC-01 : Clé `service_role` envoyée au navigateur

- **Sévérité** : Critique
- **Catégorie OWASP** : A02 Défaillances cryptographiques / secrets
- **Emplacement** : `components/AdminPanel.tsx:6`, `.env:2`
- **Statut** : Confirmé

**Preuve**
```tsx
// components/AdminPanel.tsx
1  "use client";
4  const supabase = createClient(
5    process.env.NEXT_PUBLIC_SUPABASE_URL!,
6    process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY!,
// .env
2  NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=faux…****
```

**Impact concret**
Next.js inline toute variable `NEXT_PUBLIC_*` dans le bundle JS. N'importe quel visiteur récupère la clé `service_role` dans les DevTools et obtient un accès total à la base (RLS ignorée) : lecture, modification et suppression de toutes les tables, y compris `auth.users`.

**Correctif proposé**
```diff
--- a/.env
+++ b/.env
-NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=…
+SUPABASE_SERVICE_ROLE_KEY=…
--- a/components/AdminPanel.tsx
+++ b/components/AdminPanel.tsx
-const supabase = createClient(
-  process.env.NEXT_PUBLIC_SUPABASE_URL!,
-  process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY!,
-);
+// Les opérations admin passent par une route/action serveur qui vérifie le rôle (voir SEC-06/07).
```
**Régénérer la clé** (Dashboard → Settings → API) : elle a déjà été distribuée.

---

### SEC-02 : `.env` commité avec clé Stripe live

- **Sévérité** : Critique
- **Catégorie OWASP** : A02
- **Emplacement** : `.env:3` ; présent dans l'historique depuis le commit `89aec41`
- **Statut** : Confirmé (aucun `.gitignore` dans le dépôt)

**Preuve**
```
$ git ls-files | grep env   →  .env
.env:3  STRIPE_SECRET_KEY=sk_liv…****
```

**Impact concret**
Toute personne ayant accès au dépôt (ou à un fork, une CI, une sauvegarde) peut émettre des remboursements, lire les clients et créer des paiements sur le compte Stripe de production.

**Correctif proposé**
```diff
--- /dev/null
+++ b/.gitignore
+.env
+.env.*
+!.env.example
```
Puis `git rm --cached .env`, **rotation immédiate** de la clé Stripe et de toutes les autres valeurs du fichier. Supprimer le fichier ne retire pas la clé de l'historique (`89aec41`).

---

### SEC-03 : Table `invoices` sans RLS

- **Sévérité** : Critique
- **Catégorie OWASP** : A01 Contrôle d'accès
- **Emplacement** : `supabase/migrations/20250101000000_init.sql:10-14`
- **Statut** : Confirmé (aucune migration n'active la RLS sur `invoices`)

**Preuve**
```sql
10  create table public.invoices (
11    id uuid primary key default gen_random_uuid(),
12    user_id uuid references auth.users,
13    amount int
14  );
```

**Impact concret**
Avec la clé `anon` (publique), `GET /rest/v1/invoices?select=*` renvoie toutes les factures de tous les clients ; `PATCH`/`DELETE` les modifient ou les suppriment.

**Correctif proposé**
```diff
 create table public.invoices (
   id uuid primary key default gen_random_uuid(),
-  user_id uuid references auth.users,
+  user_id uuid not null references auth.users,
   amount int
 );
+alter table public.invoices enable row level security;
+create policy "factures du propriétaire" on public.invoices for select to authenticated
+  using ((select auth.uid()) = user_id);
```

---

### SEC-04 : Escalade de privilèges via `profiles`

- **Sévérité** : Critique
- **Catégorie OWASP** : A01
- **Emplacement** : `supabase/migrations/20250101000000_init.sql:8`
- **Statut** : Confirmé

**Preuve**
```sql
4  role text not null default 'user',
5  credits int not null default 0
8  create policy "profil modifiable" on public.profiles for update using (true);
```

**Impact concret**
La policy n'a pas de clause `to` (donc `public`, anon compris) et `using (true)` couvre toutes les lignes. N'importe qui peut exécuter `update profiles set role = 'admin', credits = 999999` sur **n'importe quel** profil.

**Correctif proposé**
```diff
-create policy "profil modifiable" on public.profiles for update using (true);
+create policy "profil modifiable" on public.profiles for update to authenticated
+  using ((select auth.uid()) = id) with check ((select auth.uid()) = id);
+revoke update on public.profiles from anon, authenticated;
+grant update (full_name) on public.profiles to authenticated;
```

---

### SEC-05 : RPC `add_credits` SECURITY DEFINER appelable par tous

- **Sévérité** : Critique
- **Catégorie OWASP** : A01
- **Emplacement** : `supabase/migrations/20250101000000_init.sql:20-23`
- **Statut** : Confirmé (aucun `revoke execute` dans les migrations ; `EXECUTE` est accordé à `public` par défaut)

**Preuve**
```sql
20  create function public.add_credits(uid uuid, n int) returns void
21  language sql security definer as $$
22    update public.profiles set credits = credits + n where id = uid
23  $$;
```

**Impact concret**
`POST /rest/v1/rpc/add_credits {"uid":"…","n":100000}` avec la clé anon crédite n'importe quel compte. La fonction contourne la RLS (DEFINER) et n'a pas de `search_path` fixé.

**Correctif proposé**
```diff
-create function public.add_credits(uid uuid, n int) returns void
-language sql security definer as $$
+create function private.add_credits(uid uuid, n int) returns void
+language sql security definer set search_path = '' as $$
   update public.profiles set credits = credits + n where id = uid
 $$;
+revoke execute on function private.add_credits(uuid, int) from public, anon, authenticated;
```
(Créer le schéma `private`, non exposé par PostgREST ; appeler la fonction uniquement depuis le serveur, par exemple un webhook de paiement vérifié.)

---

### SEC-06 : `GET /api/invoices/[id]` sans authentification (IDOR)

- **Sévérité** : Critique
- **Catégorie OWASP** : A01
- **Emplacement** : `app/api/invoices/[id]/route.ts:5-8`
- **Statut** : Confirmé

**Preuve**
```ts
3  const admin = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);
5  export async function GET(_req: Request, { params }: { params: Promise<{ id: string }> }) {
6    const { id } = await params;
7    const { data } = await admin.from("invoices").select("*").eq("id", id).single();
8    return Response.json(data);
```

**Impact concret**
Aucun contrôle d'utilisateur, client `service_role` (RLS ignorée) : quiconque connaît ou devine un `id` lit la facture d'un autre client. Le middleware ne couvre pas `/api` (SEC-19).

**Correctif proposé**
```diff
-import { createClient } from "@supabase/supabase-js";
-
-const admin = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);
+import { createClient } from "@/lib/supabase/server"; // client lié aux cookies, clé anon + RLS
 
 export async function GET(_req: Request, { params }: { params: Promise<{ id: string }> }) {
   const { id } = await params;
-  const { data } = await admin.from("invoices").select("*").eq("id", id).single();
+  const supabase = await createClient();
+  const { data: { user } } = await supabase.auth.getUser();
+  if (!user) return new Response("Unauthorized", { status: 401 });
+  const { data } = await supabase.from("invoices").select("id, amount").eq("id", id).eq("user_id", user.id).single();
+  if (!data) return new Response("Not found", { status: 404 });
   return Response.json(data);
```

---

### SEC-07 : Server action `deleteInvoice` sans authentification

- **Sévérité** : Critique
- **Catégorie OWASP** : A01
- **Emplacement** : `app/actions.ts:6-8`
- **Statut** : Confirmé

**Preuve**
```ts
1  "use server";
4  const admin = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);
6  export async function deleteInvoice(id: string) {
7    await admin.from("invoices").delete().eq("id", id);
```

**Impact concret**
Une server action est un endpoint POST public. Un attaquant qui récupère l'ID d'action dans le bundle supprime n'importe quelle facture, sans compte.

**Correctif proposé**
```diff
 export async function deleteInvoice(id: string) {
-  await admin.from("invoices").delete().eq("id", id);
+  const supabase = await createClient(); // client serveur lié aux cookies
+  const { data: { user } } = await supabase.auth.getUser();
+  if (!user) throw new Error("Non authentifié");
+  await supabase.from("invoices").delete().eq("id", id).eq("user_id", user.id);
 }
```

---

### SEC-08 : Collection PocketBase `notes` lisible et supprimable par tous

- **Sévérité** : Critique
- **Catégorie OWASP** : A01
- **Emplacement** : `pb_migrations/1700000000_created_notes.js:6,7,10`
- **Statut** : Confirmé (seule migration touchant `notes`)

**Preuve**
```js
6      listRule: "",
7      viewRule: "",
10     deleteRule: "",
```

**Impact concret**
Une règle `""` signifie « public sans authentification ». `GET /api/collections/notes/records` liste toutes les notes de tous les utilisateurs, et `DELETE` les efface.

**Correctif proposé**
```diff
-    listRule: "",
-    viewRule: "",
+    listRule: "@request.auth.id != '' && owner = @request.auth.id",
+    viewRule: "@request.auth.id != '' && owner = @request.auth.id",
@@
-    deleteRule: "",
+    deleteRule: "owner = @request.auth.id",
```
(Nouvelle migration : ne pas réécrire une migration déjà appliquée.)

---

### SEC-09 : Injection SQL dans un hook PocketBase public

- **Sévérité** : Critique
- **Catégorie OWASP** : A03 Injection
- **Emplacement** : `pb_hooks/main.pb.js:2-5`
- **Statut** : Confirmé

**Preuve**
```js
2  routerAdd("GET", "/api/notes/search", (e) => {
3    const q = e.request.url.query().get("q");
5    $app.db().newQuery("SELECT id, content FROM notes WHERE content LIKE '%" + q + "%'").all(rows);
```

**Impact concret**
Route sans middleware d'auth. `?q=' UNION SELECT id, password FROM users --` extrait les hash de mots de passe et tokens de toute la base SQLite, en contournant toutes les API rules.

**Correctif proposé**
```diff
-routerAdd("GET", "/api/notes/search", (e) => {
+routerAdd("GET", "/api/notes/search", (e) => {
   const q = e.request.url.query().get("q");
   const rows = arrayOf(new DynamicModel({ id: "", content: "" }));
-  $app.db().newQuery("SELECT id, content FROM notes WHERE content LIKE '%" + q + "%'").all(rows);
+  $app.db().newQuery("SELECT id, content FROM notes WHERE owner = {:uid} AND content LIKE {:q}")
+    .bind({ uid: e.auth.id, q: "%" + q + "%" }).all(rows);
   return e.json(200, rows);
-});
+}, $apis.requireAuth());
```

---

### SEC-10 : Injection SQL sur le login PHP

- **Sévérité** : Critique
- **Catégorie OWASP** : A03
- **Emplacement** : `php/login.php:4-5`
- **Statut** : Confirmé

**Preuve**
```php
4  $email = $_POST['email'];
5  $res = $pdo->query("SELECT * FROM users WHERE email = '" . $email . "'");
```

**Impact concret**
`email=' UNION SELECT …` permet de lire toute la base `boutique`. Avec l'utilisateur `root` (SEC-23), éventuellement d'écrire des fichiers (`INTO OUTFILE`).

**Correctif proposé**
```diff
-$email = $_POST['email'];
-$res = $pdo->query("SELECT * FROM users WHERE email = '" . $email . "'");
-$user = $res->fetch();
+$stmt = $pdo->prepare('SELECT * FROM users WHERE email = ?');
+$stmt->execute([$_POST['email'] ?? '']);
+$user = $stmt->fetch();
```

---

### SEC-11 : Inclusion de fichier contrôlée par l'utilisateur (LFI)

- **Sévérité** : Critique
- **Catégorie OWASP** : A03
- **Emplacement** : `php/upload.php:6`
- **Statut** : Confirmé

**Preuve**
```php
6  include $_GET['page'] . '.php';
```

**Impact concret**
`?page=php://filter/convert.base64-encode/resource=config` renvoie le source de `config.php` (identifiants MySQL). Combiné à SEC-12, `?page=uploads/shell` exécute un fichier déposé.

**Correctif proposé**
```diff
-include $_GET['page'] . '.php';
+$pages = ['accueil', 'galerie'];
+$page = in_array($_GET['page'] ?? '', $pages, true) ? $_GET['page'] : 'accueil';
+include __DIR__ . "/pages/$page.php";
```

---

### SEC-12 : Upload non sécurisé permettant de déposer un `.php`

- **Sévérité** : Critique
- **Catégorie OWASP** : A04 Conception non sécurisée
- **Emplacement** : `php/upload.php:2-4`
- **Statut** : Confirmé (aucun contrôle d'auth ; aucun `uploads/.htaccess` dans le dépôt)

**Preuve**
```php
2  session_start();
3  if ($_FILES['photo']['type'] === 'image/jpeg') {
4      move_uploaded_file($_FILES['photo']['tmp_name'], __DIR__ . '/uploads/' . $_FILES['photo']['name']);
```

**Impact concret**
`$_FILES[...]['type']` est fourni par le client : envoyer `shell.php` avec `Content-Type: image/jpeg` suffit. Le nom d'origine est conservé dans un dossier du webroot, d'où exécution de code sur le serveur. Aucun utilisateur connecté n'est exigé.

**Correctif proposé**
```diff
 session_start();
-if ($_FILES['photo']['type'] === 'image/jpeg') {
-    move_uploaded_file($_FILES['photo']['tmp_name'], __DIR__ . '/uploads/' . $_FILES['photo']['name']);
-}
+if (empty($_SESSION['user_id'])) { http_response_code(401); exit; }
+$mime = (new finfo(FILEINFO_MIME_TYPE))->file($_FILES['photo']['tmp_name']);
+$ext = ['image/jpeg' => 'jpg', 'image/png' => 'png'][$mime] ?? null;
+if (!$ext || $_FILES['photo']['size'] > 5_000_000) { http_response_code(400); exit; }
+move_uploaded_file($_FILES['photo']['tmp_name'], __DIR__ . '/../storage/' . bin2hex(random_bytes(16)) . ".$ext");
```

---

### SEC-13 : SSTI via `render_template_string`

- **Sévérité** : Critique
- **Catégorie OWASP** : A03
- **Emplacement** : `flask/app.py:11`
- **Statut** : Confirmé

**Preuve**
```python
9   @app.route("/hello")
11      return render_template_string("<h1>Bonjour " + request.args.get("nom", "") + "</h1>")
```

**Impact concret**
`/hello?nom={{config.__class__.__init__.__globals__['os'].popen('id').read()}}` exécute une commande système : prise de contrôle du serveur.

**Correctif proposé**
```diff
-    return render_template_string("<h1>Bonjour " + request.args.get("nom", "") + "</h1>")
+    return render_template_string("<h1>Bonjour {{ nom }}</h1>", nom=request.args.get("nom", ""))
```

---

### SEC-14 : Injection SQL (f-string)

- **Sévérité** : Critique
- **Catégorie OWASP** : A03
- **Emplacement** : `flask/app.py:16`
- **Statut** : Confirmé

**Preuve**
```python
13  @app.route("/user")
16      cur.execute(f"SELECT * FROM users WHERE email = '{request.args['email']}'")
```

**Impact concret**
Route publique : `?email=' OR '1'='1` puis `UNION SELECT` permettent de lire toute la base `app.db`.

**Correctif proposé**
```diff
-    cur.execute(f"SELECT * FROM users WHERE email = '{request.args['email']}'")
+    cur.execute("SELECT id, email FROM users WHERE email = ?", (request.args.get("email", ""),))
```

---

### SEC-15 : Désérialisation `pickle` / `yaml.Loader` d'une entrée utilisateur

- **Sévérité** : Critique
- **Catégorie OWASP** : A08 Intégrité des données
- **Emplacement** : `flask/app.py:21`
- **Statut** : Confirmé

**Preuve**
```python
19  @app.post("/import")
21      return str(pickle.loads(request.data)) + str(yaml.load(request.form["cfg"], Loader=yaml.Loader))
```

**Impact concret**
Un objet pickle forgé (`__reduce__` → `os.system`) ou un YAML `!!python/object/apply:os.system` exécute du code arbitraire, sans authentification.

**Correctif proposé**
```diff
-    return str(pickle.loads(request.data)) + str(yaml.load(request.form["cfg"], Loader=yaml.Loader))
+    return str(json.loads(request.data)) + str(yaml.safe_load(request.form["cfg"]))
```

---

### SEC-16 : Débogueur Werkzeug exposé

- **Sévérité** : Critique
- **Catégorie OWASP** : A05 Mauvaise configuration
- **Emplacement** : `flask/app.py:24`
- **Statut** : À vérifier : aucun Dockerfile, Procfile ni unité systemd dans le dépôt n'indique comment l'app est lancée en production. Vérifier si `python app.py` est utilisé.

**Preuve**
```python
23  if __name__ == "__main__":
24      app.run(host="0.0.0.0", debug=True)
```

**Impact concret**
Si ce point d'entrée tourne en production, la console interactive Werkzeug est accessible sur le réseau : exécution de Python arbitraire.

**Correctif proposé**
```diff
-    app.run(host="0.0.0.0", debug=True)
+    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
```
En production : `gunicorn app:app`.

---

### SEC-17 : Vue `invoice_totals` sans `security_invoker`

- **Sévérité** : Haute
- **Catégorie OWASP** : A01
- **Emplacement** : `supabase/migrations/20250101000000_init.sql:26`
- **Statut** : Confirmé

**Preuve**
```sql
26  create view public.invoice_totals as select user_id, sum(amount) from public.invoices group by 1;
```

**Impact concret**
La vue s'exécute avec les droits de son créateur (`postgres`). Même après correction de SEC-03, `GET /rest/v1/invoice_totals` continuera d'exposer le chiffre d'affaires de chaque client.

**Correctif proposé**
```diff
-create view public.invoice_totals as select user_id, sum(amount) from public.invoices group by 1;
+create view public.invoice_totals with (security_invoker = true) as
+  select user_id, sum(amount) from public.invoices group by 1;
```

---

### SEC-18 : SSRF sur `/api/preview`

- **Sévérité** : Haute
- **Catégorie OWASP** : A10 SSRF
- **Emplacement** : `app/api/preview/route.ts:1-4`
- **Statut** : Confirmé

**Preuve**
```ts
1  export async function POST(request: Request) {
2    const body = await request.json();
3    const res = await fetch(body.url);
4    return new Response(await res.text());
```

**Impact concret**
Sans authentification, le serveur récupère n'importe quelle URL et renvoie la réponse : métadonnées cloud (`http://169.254.169.254/`), services internes (`http://127.0.0.1:8090/_/`, `http://127.0.0.1:54321`).

**Correctif proposé**
```diff
 export async function POST(request: Request) {
   const body = await request.json();
-  const res = await fetch(body.url);
+  const u = new URL(body.url);
+  if (u.protocol !== "https:" || !ALLOWED_HOSTS.has(u.hostname)) return new Response("URL refusée", { status: 400 });
+  const res = await fetch(u, { redirect: "error" });
   return new Response(await res.text());
```

---

### SEC-19 : Middleware contournable

- **Sévérité** : Haute
- **Catégorie OWASP** : A01
- **Emplacement** : `middleware.ts:9,14`
- **Statut** : Confirmé

**Preuve**
```ts
9   const { data } = await supabase.auth.getSession();
14  export const config = { matcher: ["/dashboard"] };
```

**Impact concret**
Seul le chemin exact `/dashboard` est protégé : `/dashboard/factures` et `/api/*` ne passent pas par le middleware. De plus, `getSession()` ne revalide pas le JWT côté serveur.

**Correctif proposé**
```diff
-  const { data } = await supabase.auth.getSession();
-  if (!data.session) return NextResponse.redirect(new URL("/login", req.url));
+  const { data: { user } } = await supabase.auth.getUser();
+  if (!user) return NextResponse.redirect(new URL("/login", req.url));
@@
-export const config = { matcher: ["/dashboard"] };
+export const config = { matcher: ["/dashboard/:path*"] };
```
L'autorisation doit quand même être refaite dans chaque route et action (SEC-06, SEC-07).

---

### SEC-20 : Next.js 15.1.0 affecté par CVE-2025-29927

- **Sévérité** : Haute
- **Catégorie OWASP** : A06 Composants vulnérables
- **Emplacement** : `package.json:4`
- **Statut** : À vérifier : aucun lockfile, la version réellement installée est inconnue. Vérifier avec `bun pm ls next` ou `npm ls next`.

**Preuve**
```json
4    "dependencies": { "next": "15.1.0", … }
```

**Impact concret**
Sur les versions < 15.2.3, l'en-tête `x-middleware-subrequest` permet de sauter le middleware entièrement (auto-hébergement).

**Correctif proposé**
```diff
-  "dependencies": { "next": "15.1.0",
+  "dependencies": { "next": "^15.2.3",
```
(au minimum 15.2.3 ; idéalement la dernière 15.x publiée)

---

### SEC-21 : Rules PocketBase create/update « connecté » au lieu de « propriétaire »

- **Sévérité** : Haute
- **Catégorie OWASP** : A01
- **Emplacement** : `pb_migrations/1700000000_created_notes.js:8-9`
- **Statut** : Confirmé

**Preuve**
```js
8      createRule: "@request.auth.id != ''",
9      updateRule: "@request.auth.id != ''",
```

**Impact concret**
Tout utilisateur inscrit modifie les notes des autres, et peut créer une note avec un `owner` arbitraire.

**Correctif proposé**
```diff
-    createRule: "@request.auth.id != ''",
-    updateRule: "@request.auth.id != ''",
+    createRule: "@request.auth.id != '' && @request.body.owner = @request.auth.id",
+    updateRule: "owner = @request.auth.id && @request.body.owner:isset = false",
```

---

### SEC-22 : Mots de passe hachés en MD5

- **Sévérité** : Haute
- **Catégorie OWASP** : A02
- **Emplacement** : `php/login.php:7`
- **Statut** : Confirmé

**Preuve**
```php
7  if ($user && $user['password'] === md5($_POST['password'])) {
```

**Impact concret**
En cas de fuite (SEC-10 la rend facile), les mots de passe MD5 sans sel se cassent en quelques secondes.

**Correctif proposé**
```diff
-if ($user && $user['password'] === md5($_POST['password'])) {
+if ($user && password_verify($_POST['password'] ?? '', $user['password'])) {
```
Migration : rehacher avec `password_hash()` à la prochaine connexion réussie.

---

### SEC-23 : Identifiants MySQL `root` en dur

- **Sévérité** : Haute
- **Catégorie OWASP** : A02
- **Emplacement** : `php/config.php:3`
- **Statut** : Confirmé

**Preuve**
```php
3  $pdo = new PDO('mysql:host=localhost;dbname=boutique', 'root', 'Boutiq…****');
```

**Impact concret**
Mot de passe `root` exposé à toute personne ayant accès au code (ou via SEC-11). L'application tourne avec tous les privilèges MySQL.

**Correctif proposé**
```diff
-$pdo = new PDO('mysql:host=localhost;dbname=boutique', 'root', '…');
+$pdo = new PDO(getenv('DB_DSN'), getenv('DB_USER'), getenv('DB_PASS'), [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
```
Créer un utilisateur MySQL dédié (SELECT/INSERT/UPDATE/DELETE sur `boutique` seulement) et changer le mot de passe root.

---

### SEC-24 : `SECRET_KEY` Flask en dur et triviale

- **Sévérité** : Haute
- **Catégorie OWASP** : A02
- **Emplacement** : `flask/app.py:6`
- **Statut** : Confirmé

**Preuve**
```python
6  app.config["SECRET_KEY"] = "dev"
```

**Impact concret**
Avec la clé connue, `flask-unsign` forge un cookie de session signé valide : usurpation de n'importe quel compte dès que l'app utilise `session`.

**Correctif proposé**
```diff
-app.config["SECRET_KEY"] = "dev"
+app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]
```

---

### SEC-25 : Insertion anonyme illimitée dans `comments`

- **Sévérité** : Moyenne
- **Catégorie OWASP** : A01
- **Emplacement** : `supabase/migrations/20250101000000_init.sql:18`
- **Statut** : Confirmé

**Preuve**
```sql
16  create table public.comments (id bigint generated always as identity primary key, body text);
18  create policy "commentaires" on public.comments for insert to anon with check (true);
```

**Impact concret**
Spam illimité et contenu de taille arbitraire, sans auteur traçable.

**Correctif proposé**
```diff
-create table public.comments (id bigint generated always as identity primary key, body text);
+create table public.comments (id bigint generated always as identity primary key,
+  author_id uuid not null references auth.users default auth.uid(),
+  body text not null check (length(body) between 1 and 2000));
@@
-create policy "commentaires" on public.comments for insert to anon with check (true);
+create policy "commentaires" on public.comments for insert to authenticated
+  with check ((select auth.uid()) = author_id);
```

---

### SEC-26 : XSS réfléchi sur l'email

- **Sévérité** : Moyenne
- **Catégorie OWASP** : A03
- **Emplacement** : `php/login.php:11`
- **Statut** : Confirmé

**Preuve**
```php
11 echo "Identifiants invalides pour " . $_POST['email'];
```

**Impact concret**
Un formulaire tiers auto-soumis avec `email=<script>…</script>` exécute du JS dans le domaine (vol de session, voir SEC-28).

**Correctif proposé**
```diff
-echo "Identifiants invalides pour " . $_POST['email'];
+echo 'Identifiants invalides pour ' . htmlspecialchars($_POST['email'] ?? '', ENT_QUOTES, 'UTF-8');
```

---

### SEC-27 : Redirection ouverte (et pas d'`exit`)

- **Sévérité** : Moyenne
- **Catégorie OWASP** : A01
- **Emplacement** : `php/login.php:9`
- **Statut** : Confirmé

**Preuve**
```php
9      header('Location: ' . $_GET['next']);
10 }
11 echo "Identifiants invalides pour " . $_POST['email'];
```

**Impact concret**
`login.php?next=https://site-pirate.example` redirige après connexion vers un faux site (phishing). Sans `exit`, la suite du script s'exécute aussi.

**Correctif proposé**
```diff
-    header('Location: ' . $_GET['next']);
+    $next = $_GET['next'] ?? '/';
+    header('Location: ' . (preg_match('#^/(?!/)#', $next) ? $next : '/'));
+    exit;
```

---

### SEC-28 : Fixation de session

- **Sévérité** : Moyenne
- **Catégorie OWASP** : A07 Authentification
- **Emplacement** : `php/login.php:3,8`
- **Statut** : Confirmé

**Preuve**
```php
3  session_start();
8      $_SESSION['user_id'] = $user['id'];
```

**Impact concret**
L'identifiant de session n'est pas renouvelé après connexion ; les paramètres `httponly`/`secure`/`samesite` ne sont fixés nulle part dans le dépôt.

**Correctif proposé**
```diff
-session_start();
+session_set_cookie_params(['httponly' => true, 'secure' => true, 'samesite' => 'Lax']);
+session_start();
@@
+    session_regenerate_id(true);
     $_SESSION['user_id'] = $user['id'];
```

---

### SEC-29 : `display_errors` activé

- **Sévérité** : Moyenne
- **Catégorie OWASP** : A05
- **Emplacement** : `php/config.php:2`
- **Statut** : Confirmé

**Preuve**
```php
2  ini_set('display_errors', 1);
```

**Impact concret**
Les erreurs PDO affichent requêtes, chemins et parfois le DSN, ce qui facilite l'exploitation de SEC-10.

**Correctif proposé**
```diff
-ini_set('display_errors', 1);
+ini_set('display_errors', '0');
+ini_set('log_errors', '1');
```

---

### SEC-30 : CORS toutes origines avec credentials

- **Sévérité** : Moyenne
- **Catégorie OWASP** : A05
- **Emplacement** : `flask/app.py:7`
- **Statut** : Confirmé

**Preuve**
```python
7  CORS(app, origins="*", supports_credentials=True)
```

**Impact concret**
Avec `supports_credentials=True`, flask-cors renvoie l'origine appelante : n'importe quel site peut lire les réponses authentifiées d'un visiteur connecté.

**Correctif proposé**
```diff
-CORS(app, origins="*", supports_credentials=True)
+CORS(app, origins=["https://app.example.ci"], supports_credentials=True)
```

---

### SEC-31 : `dangerouslySetInnerHTML` sans assainissement

- **Sévérité** : Moyenne
- **Catégorie OWASP** : A03
- **Emplacement** : `components/AdminPanel.tsx:10`
- **Statut** : À vérifier : aucun appelant de `AdminPanel` dans le dépôt, l'origine de `html` est inconnue. Si elle vient de la base ou d'un utilisateur → Haute.

**Preuve**
```tsx
9   export function AdminPanel({ html }: { html: string }) {
10    return <div dangerouslySetInnerHTML={{ __html: html }} />;
```

**Correctif proposé**
```diff
+import DOMPurify from "isomorphic-dompurify";
@@
-  return <div dangerouslySetInnerHTML={{ __html: html }} />;
+  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />;
```

---

### SEC-32 : Pas de rate limiting sur le login

- **Sévérité** : Moyenne
- **Catégorie OWASP** : A07
- **Emplacement** : `php/login.php:5`
- **Statut** : À vérifier : aucun limiteur dans le code ; vérifier la configuration du serveur web (nginx `limit_req`, fail2ban) qui n'est pas dans le dépôt.

**Impact concret**
Brute force illimité des mots de passe (d'autant plus efficace avec MD5, SEC-22).

**Correctif proposé** : compteur de tentatives par IP + email (table ou APCu/Redis), réponse 429 au-delà de 5 essais / 15 min.

---

### SEC-33 : Audit des dépendances impossible

- **Sévérité** : Info
- **Catégorie OWASP** : A06
- **Emplacement** : `package.json:1`, `flask/requirements.txt`
- **Statut** : À vérifier : `bun audit` échoue (« Lockfile not found ») ; `pip-audit` n'est pas installé.

**Correctif proposé** : committer `bun.lock`, puis lancer `bun audit` et `pip-audit -r flask/requirements.txt`.

---

## Points positifs

- RLS activée sur `profiles` et `comments` (`supabase/migrations/20250101000000_init.sql:7,17`) ; le problème vient des policies, pas d'un oubli d'activation.
- La clé `service_role` côté serveur (`app/actions.ts:4`, `app/api/invoices/[id]/route.ts:3`) est lue depuis `SUPABASE_SERVICE_ROLE_KEY`, variable non publique (le problème est l'absence de contrôle d'accès, pas la fuite).
- Requêtes Supabase via le query builder (`.eq(...)`), donc paramétrées : pas d'injection SQL côté Next.js.
- Collection `notes` dotée d'un champ relation `owner` (`pb_migrations/…:13`) : les règles par propriétaire sont directement applicables.
- Versions des dépendances Python figées (`flask/requirements.txt`), avec PyYAML 6.

## Priorités de correction

1. **SEC-01, SEC-02** : retirer la clé `service_role` du client, ignorer `.env`, **régénérer la clé service_role et la clé Stripe** (30 min).
2. **SEC-03, SEC-04, SEC-05, SEC-17** : migration Supabase corrective : RLS sur `invoices`, policy `profiles` par propriétaire avec droits par colonne, `add_credits` sortie de `public`, vue `security_invoker` (1 h).
3. **SEC-13, SEC-14, SEC-15, SEC-16** : Flask : supprimer `render_template_string` concaténé, requêtes paramétrées, `json`/`safe_load`, debug désactivé (1 h).
4. **SEC-10, SEC-11, SEC-12** : PHP : requête préparée au login, liste blanche pour `include`, upload refait hors webroot (2 h).
5. **SEC-06, SEC-07, SEC-08, SEC-09** : contrôle d'accès dans la route et l'action Next.js, rules et hook PocketBase par propriétaire (1 h).

## Annexes

### Commandes exécutées
```
bash scripts/detect_stack.sh .
bash scripts/find_secrets.sh .
bash scripts/grep_patterns.sh . nextjs,supabase,pocketbase,php-mysql,flask
bun audit                      → error: Lockfile not found
(scan_rls.sql non exécuté : aucune base fournie)
```

### Pistes écartées (faux positifs)
| Emplacement | Motif | Raison |
|---|---|---|
| `app/actions.ts:4`, `app/api/invoices/[id]/route.ts:3` | `service_role_serveur_a_verifier` | Fichiers serveur, variable non publique ; risque couvert par SEC-06/07 |
| `php/upload.php:6` | `include_variable` | Doublon de SEC-11 |
| `php/login.php:7` | `md5_sha1` | Doublon de SEC-22 |
| `.env:0` | `env_non_ignore_par_gitignore` | Regroupé dans SEC-02 |
| `middleware.ts:10` | `endpoint_auth_rate_limit` | Simple redirection vers `/login`, pas un endpoint d'auth |

### Non vérifié
- État réel de la base Supabase (policies créées depuis le dashboard, grants) : lancer `scripts/scan_rls.sql` sur la base locale (`supabase start`).
- Configuration PocketBase hors migrations (rate limits, superusers) et configuration Apache/nginx du dossier `php/`.
- Mode de lancement de Flask en production (SEC-16).
