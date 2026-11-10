# PocketBase checklist

Sources: `pb_migrations/*.js` (and `pb_schema.json` if present), `pb_hooks/*.pb.js`, client code (`new PocketBase(...)`), optionally `pb_data` **without opening it for writing**.
API rules semantics:
| Value | Meaning |
|---|---|
| `null` | superusers only (locked) |
| `""` (empty string) | **public: everyone, no authentication** |
| expression | allowed if the expression is true |

## PB1. Empty API rules (public access) — Critical to Info (A01)
```js
// ❌ pb_migrations/1700000000_created_invoices.js
listRule: "", viewRule: "", createRule: "", updateRule: "", deleteRule: "",
// ✅
listRule:   "@request.auth.id != '' && user = @request.auth.id",
viewRule:   "@request.auth.id != '' && user = @request.auth.id",
createRule: "@request.auth.id != '' && @request.body.user = @request.auth.id",
updateRule: "user = @request.auth.id && @request.body.user:isset = false",
deleteRule: null,
```
- `listRule/viewRule ""` on public data (published articles) = Info; on personal data = High.
- `create/update/deleteRule ""` = Critical (except create on an intentional public form → Medium, with field validation).
- Read the **latest** migration that touches the collection: successive migrations overwrite the rules.

## PB2. Overly broad `@request.auth.id != ""` rules — High (A01)
"Logged in" ≠ "owner": any registered user reads/modifies everyone's data.
```js
// ❌
updateRule: "@request.auth.id != ''"
// ✅
updateRule: "@request.auth.id != '' && owner = @request.auth.id"
```
- Open registration (`users.createRule = ""`) + rule `@request.auth.id != ""` ⇒ equivalent to public. Flag it.
- Roles: `@request.auth.role = 'admin'` is only safe if `role` cannot be modified by the user (PB3).

## PB3. Sensitive fields modifiable or exposed — High (A01)
- `users` collection with a `role`, `is_admin`, `credits`, `plan`, `verified` field and `updateRule: "id = @request.auth.id"` → the user self-promotes.
```js
// ✅ forbid modifying the field through the API
updateRule: "id = @request.auth.id && @request.body.role:isset = false && @request.body.credits:isset = false"
```
- Fields to hide: `hidden: true` option (PB ≥ 0.23) for `token`, `secret`, `api_key`, internal notes; otherwise they are returned in every `list`.
- `emailVisibility`: check that it is not forced to `true`.
- Expand relations: `?expand=user` can expose another user's record if `users.viewRule` is broad.

## PB4. Injectable filters in client code / hooks — High (A03)
```js
// ❌ (client or hook): concatenation in the filter
pb.collection("posts").getList(1, 20, { filter: `title ~ "${q}"` });
$app.findRecordsByFilter("posts", "owner = '" + id + "'");
// ✅
pb.collection("posts").getList(1, 20, { filter: pb.filter("title ~ {:q}", { q }) });
$app.findRecordsByFilter("posts", "owner = {:id}", "-created", 50, 0, { id });
```
- Raw SQL in a hook: `$app.db().newQuery("... " + x)` → use `.bind({ x })` with `{:x}`.

## PB5. Insecure JS hooks — High to Critical (A01)
- `routerAdd(...)` without an auth middleware: the route is public.
```js
// ❌
routerAdd("POST", "/api/admin/credit", (e) => { /* ... */ });
// ✅
routerAdd("POST", "/api/admin/credit", (e) => { /* ... */ }, $apis.requireSuperuserAuth());
// or $apis.requireAuth("users") + check e.auth.get("role") / owner
```
- Hook that saves fields taken as-is from the request (`record.load(e.requestInfo().body)`) → mass assignment.
- `$app.save()` in a hook bypasses API rules: the hook must do the ownership check itself.
- `$os.exec` / `$os.cmd` with user input → RCE (Critical).
- `$http.send({ url: body.url })` → SSRF.
- Hardcoded secrets in hooks (payment keys) → use `$os.getenv("...")`.

## PB6. Auth and admin — Medium to High (A07)
- `/_/` interface publicly exposed without IP restriction, superuser with a weak / default password in a committed init script.
- Permissive `authRule`, `passwordAuth.enabled` with `minPasswordLength` < 8, OTP without a limit.
- Rate limiting (Settings → Rate limits, PB ≥ 0.23): not visible in the repo → "to verify manually".
- Auth token stored in `localStorage` (SDK default) + XSS = session theft: mention if XSS is found.

## PB7. Files — Medium (A01)
- `file` field with `protected: false` on private documents: URLs accessible without a token.
- Empty `mimeTypes` and huge `maxSize` → upload of HTML/SVG served from the domain.
```js
// ✅
{ type: "file", name: "piece", protected: true, maxSize: 5242880, mimeTypes: ["application/pdf", "image/jpeg", "image/png"] }
```

## PB8. Deployment — Medium (A05)
`pocketbase serve --http 0.0.0.0:8090` without a TLS reverse proxy, `--dev` in production (verbose SQL logs), `pb_data/` committed.
