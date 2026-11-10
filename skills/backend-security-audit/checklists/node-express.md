# Node.js checklist (Express, Fastify, Koa, Hono, NestJS)

For Node projects **other than Next.js** (Next.js: `nextjs.md`). Files to read: `server.js`/`app.js`/`index.ts`, `routes/`, `controllers/`, `middleware/`, `models/`, `db.js`, config.

## E1. Routes without auth middleware / IDOR — Critical (A01)
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
- Order of `app.use`: a route declared **before** `app.use(requireAuth)` is not protected.
- NestJS: controller without `@UseGuards(...)` and no global guard.

## E2. SQL injection — Critical (A03)
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
- `mysql` with `multipleStatements: true` makes any injection worse.

## E3. NoSQL injection (MongoDB) — High (A03)
```js
// ❌ body = { "email": "a@b.c", "password": { "$ne": null } }
User.findOne({ email: req.body.email, password: req.body.password });
// ✅
const { email, password } = z.object({ email: z.string().email(), password: z.string() }).parse(req.body);
const user = await User.findOne({ email: String(email) });
if (!user || !(await bcrypt.compare(password, user.passwordHash))) return res.sendStatus(401);
```
- `$where` with user input → Critical. `mongoose.set("sanitizeFilter", true)` or `express-mongo-sanitize`.

## E4. Mass assignment — High (A01)
`User.create(req.body)`, `Object.assign(user, req.body)`, `User.findByIdAndUpdate(id, req.body)` → `role`, `isAdmin` are writable. Validate with zod/joi and pick the fields explicitly.

## E5. JWT — Critical (A07)
- `jwt.verify(token, secret)` without `{ algorithms: ["HS256"] }` using an RSA public key → algorithm confusion.
- `jwt.decode()` used to authenticate (no signature verification) → Critical.
- Hardcoded / weak secret (`"secret"`, `"changeme"`) → High.
- No expiration (`expiresIn`) → Low.

## E6. Headers, CORS, cookies — Medium (A05)
```js
// ❌
app.use(cors());                                   // all origins
app.use(cors({ origin: true, credentials: true })); // reflects any origin with cookies → High
// ✅
app.use(helmet());
app.use(cors({ origin: ["https://app.example.ci"], credentials: true }));
app.use(session({ secret: process.env.SESSION_SECRET, cookie: { httpOnly: true, secure: true, sameSite: "lax" } }));
```
- `app.disable("x-powered-by")` or `helmet()`.

## E7. Path traversal / files — High (A01)
`res.sendFile(path.join(__dirname, "uploads", req.query.f))` → `path.resolve` + prefix check, or `res.sendFile(name, { root: UPLOAD_DIR })` with `path.basename`.
- Multer: `fileFilter` (MIME + extension), `limits.fileSize`, generated names, a folder not served by `express.static` if it holds HTML/SVG content.

## E8. Code / command execution — Critical (A03/A08)
`eval`, `new Function`, `vm.runInNewContext` (not a sandbox), `child_process.exec` with interpolation, `node-serialize.unserialize` → use `execFile` with an argument array, `JSON.parse`.

## E9. Prototype pollution — Medium (A08)
Homemade recursive merge (`merge(target, req.body)`), `lodash.merge`/`_.set` with user-controlled paths, older `lodash` versions < 4.17.21.

## E10. SSRF — High (A10)
`axios.get(req.query.url)`, `fetch(req.body.webhook)` → allowlist, reject private/metadata IPs.

## E11. Errors — Low (A09)
Error handler returning `err.stack`/`err.message`; `NODE_ENV` not set to `production` (Express shows the stack).

## E12. Rate limiting — Medium (A07)
Login/OTP/reset without `express-rate-limit`, `@fastify/rate-limit`, `@nestjs/throttler`.

## E13. Dependencies — variable (A06)
`npm audit --omit=dev` / `bun audit` / `pnpm audit --prod`.
