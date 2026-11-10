# Checklist PocketBase

Sources : `pb_migrations/*.js` (et `pb_schema.json` s'il existe), `pb_hooks/*.pb.js`, code client (`new PocketBase(...)`), éventuellement `pb_data` **sans l'ouvrir en écriture**.
Sémantique des API rules :
| Valeur | Signification |
|---|---|
| `null` | réservé aux superusers (verrouillé) |
| `""` (chaîne vide) | **public : tout le monde, sans authentification** |
| expression | autorisé si l'expression est vraie |

## PB1. API rules vides (accès public) — Critique à Info (A01)
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
- `listRule/viewRule ""` sur données publiques (articles publiés) = Info ; sur données personnelles = Haute.
- `create/update/deleteRule ""` = Critique (sauf create d'un formulaire public assumé → Moyenne, avec validation de champs).
- Lire la **dernière** migration qui touche la collection : les migrations successives écrasent les règles.

## PB2. Rules `@request.auth.id != ""` trop larges — Haute (A01)
« Connecté » ≠ « propriétaire » : tout utilisateur inscrit lit/modifie les données de tous.
```js
// ❌
updateRule: "@request.auth.id != ''"
// ✅
updateRule: "@request.auth.id != '' && owner = @request.auth.id"
```
- Inscription ouverte (`users.createRule = ""`) + rule `@request.auth.id != ""` ⇒ équivalent public. Le signaler.
- Rôles : `@request.auth.role = 'admin'` n'est sûr que si `role` n'est pas modifiable par l'utilisateur (PB3).

## PB3. Champs sensibles modifiables ou exposés — Haute (A01)
- Collection `users` avec champ `role`, `is_admin`, `credits`, `plan`, `verified` et `updateRule: "id = @request.auth.id"` → l'utilisateur s'auto-promeut.
```js
// ✅ interdire la modification du champ par l'API
updateRule: "id = @request.auth.id && @request.body.role:isset = false && @request.body.credits:isset = false"
```
- Champs à masquer : option `hidden: true` (PB ≥ 0.23) pour `token`, `secret`, `api_key`, notes internes ; sinon ils sortent dans chaque `list`.
- `emailVisibility` : vérifier qu'elle n'est pas forcée à `true`.
- Relations expand : `?expand=user` peut exposer la fiche d'un autre utilisateur si `users.viewRule` est large.

## PB4. Filtres injectables côté client / hooks — Haute (A03)
```js
// ❌ (client ou hook) : concaténation dans le filtre
pb.collection("posts").getList(1, 20, { filter: `title ~ "${q}"` });
$app.findRecordsByFilter("posts", "owner = '" + id + "'");
// ✅
pb.collection("posts").getList(1, 20, { filter: pb.filter("title ~ {:q}", { q }) });
$app.findRecordsByFilter("posts", "owner = {:id}", "-created", 50, 0, { id });
```
- SQL brut dans un hook : `$app.db().newQuery("... " + x)` → utiliser `.bind({ x })` avec `{:x}`.

## PB5. Hooks JS non sécurisés — Haute à Critique (A01)
- `routerAdd(...)` sans middleware d'auth : la route est publique.
```js
// ❌
routerAdd("POST", "/api/admin/credit", (e) => { /* ... */ });
// ✅
routerAdd("POST", "/api/admin/credit", (e) => { /* ... */ }, $apis.requireSuperuserAuth());
// ou $apis.requireAuth("users") + vérification e.auth.get("role") / propriétaire
```
- Hook qui sauvegarde avec des champs pris tels quels dans la requête (`record.load(e.requestInfo().body)`) → mass assignment.
- `$app.save()` dans un hook contourne les API rules : le hook doit faire lui-même le contrôle d'appartenance.
- `$os.exec` / `$os.cmd` avec une entrée utilisateur → RCE (Critique).
- `$http.send({ url: body.url })` → SSRF.
- Secrets en dur dans les hooks (clés de paiement) → utiliser `$os.getenv("...")`.

## PB6. Auth et admin — Moyenne à Haute (A07)
- Interface `/_/` exposée publiquement sans restriction IP, superuser au mot de passe faible / par défaut dans un script d'init commité.
- `authRule` permissive, `passwordAuth.enabled` avec `minPasswordLength` < 8, OTP sans limite.
- Rate limiting (Settings → Rate limits, PB ≥ 0.23) : non visible dans le dépôt → « à vérifier ».
- Token d'auth stocké dans `localStorage` (défaut du SDK) + XSS = vol de session : à mentionner si XSS trouvé.

## PB7. Fichiers — Moyenne (A01)
- Champ `file` avec `protected: false` sur des documents privés : URL accessibles sans token.
- `mimeTypes` vide et `maxSize` énorme → upload de HTML/SVG servi depuis le domaine.
```js
// ✅
{ type: "file", name: "piece", protected: true, maxSize: 5242880, mimeTypes: ["application/pdf", "image/jpeg", "image/png"] }
```

## PB8. Déploiement — Moyenne (A05)
`pocketbase serve --http 0.0.0.0:8090` sans reverse proxy TLS, `--dev` en production (logs SQL verbeux), `pb_data/` commité.
