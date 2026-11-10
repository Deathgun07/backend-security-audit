# Checklist Node.js (Express, Fastify, Koa, Hono, NestJS)

Pour les projets Node **hors Next.js** (Next.js : `nextjs.md`). Fichiers à lire : `server.js`/`app.js`/`index.ts`, `routes/`, `controllers/`, `middleware/`, `models/`, `db.js`, config.

## E1. Routes sans middleware d'auth / IDOR — Critique (A01)
```js
// ❌
router.get("/orders/:id", async (req, res) => res.json(await Order.findById(req.params.id)));
// ✅
router.get("/orders/:id", requireAuth, async (req, res) => {
  const order = await Order.findOne({ _id: req.params.id, userId: req.user.id });
  if (!order) return res.sendStatus(404);
  res.json(order);
});
```
- Ordre des `app.use` : une route déclarée **avant** `app.use(requireAuth)` n'est pas protégée.
- NestJS : contrôleur sans `@UseGuards(...)` ni guard global.

## E2. Injection SQL — Critique (A03)
```js
// ❌ mysql / mysql2 / pg / knex / sequelize
db.query("SELECT * FROM users WHERE email = '" + req.body.email + "'");
db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);
knex.raw(`... ${x}`); sequelize.query(`... ${x}`);
// ✅
db.query("SELECT * FROM users WHERE email = ?", [req.body.email]);          // mysql2
pool.query("SELECT * FROM users WHERE id = $1", [req.params.id]);           // pg
sequelize.query("... WHERE id = :id", { replacements: { id } });
```
- `mysql` avec `multipleStatements: true` aggrave toute injection.

## E3. Injection NoSQL (MongoDB) — Haute (A03)
```js
// ❌ body = { "email": "a@b.c", "password": { "$ne": null } }
User.findOne({ email: req.body.email, password: req.body.password });
// ✅
const { email, password } = z.object({ email: z.string().email(), password: z.string() }).parse(req.body);
const user = await User.findOne({ email: String(email) });
if (!user || !(await bcrypt.compare(password, user.passwordHash))) return res.sendStatus(401);
```
- `$where` avec une entrée utilisateur → Critique. `mongoose.set("sanitizeFilter", true)` ou `express-mongo-sanitize`.

## E4. Mass assignment — Haute (A01)
`User.create(req.body)`, `Object.assign(user, req.body)`, `User.findByIdAndUpdate(id, req.body)` → `role`, `isAdmin` modifiables. Valider avec zod/joi et choisir les champs.

## E5. JWT — Critique (A07)
- `jwt.verify(token, secret)` sans `{ algorithms: ["HS256"] }` avec une clé publique RSA → confusion d'algorithme.
- `jwt.decode()` utilisé pour authentifier (pas de vérification de signature) → Critique.
- Secret en dur / faible (`"secret"`, `"changeme"`) → Haute.
- Pas d'expiration (`expiresIn`) → Basse.

## E6. En-têtes, CORS, cookies — Moyenne (A05)
```js
// ❌
app.use(cors());                                   // toutes origines
app.use(cors({ origin: true, credentials: true })); // reflète toute origine avec cookies → Haute
// ✅
app.use(helmet());
app.use(cors({ origin: ["https://app.example.ci"], credentials: true }));
app.use(session({ secret: process.env.SESSION_SECRET, cookie: { httpOnly: true, secure: true, sameSite: "lax" } }));
```
- `app.disable("x-powered-by")` ou `helmet()`.

## E7. Path traversal / fichiers — Haute (A01)
`res.sendFile(path.join(__dirname, "uploads", req.query.f))` → `path.resolve` + vérification du préfixe, ou `res.sendFile(name, { root: UPLOAD_DIR })` avec `path.basename`.
- Multer : `fileFilter` (MIME + extension), `limits.fileSize`, noms générés, dossier non servi par `express.static` si contenus HTML/SVG.

## E8. Exécution de code / commandes — Critique (A03/A08)
`eval`, `new Function`, `vm.runInNewContext` (pas un bac à sable), `child_process.exec` avec interpolation, `node-serialize.unserialize` → utiliser `execFile` avec tableau d'arguments, `JSON.parse`.

## E9. Prototype pollution — Moyenne (A08)
Fusion récursive maison (`merge(target, req.body)`), `lodash.merge`/`_.set` avec chemins utilisateur, anciennes versions de `lodash` < 4.17.21.

## E10. SSRF — Haute (A10)
`axios.get(req.query.url)`, `fetch(req.body.webhook)` → liste blanche, refus des IP privées/metadata.

## E11. Erreurs — Basse (A09)
Handler d'erreur renvoyant `err.stack`/`err.message` ; `NODE_ENV` non défini à `production` (Express affiche la stack).

## E12. Rate limiting — Moyenne (A07)
Login/OTP/reset sans `express-rate-limit`, `@fastify/rate-limit`, `@nestjs/throttler`.

## E13. Dépendances — variable (A06)
`npm audit --omit=dev` / `bun audit` / `pnpm audit --prod`.
