# Backend security audit: owasp-nodejs-goat

| | |
|---|---|
| **Date** | 2026-11-17 |
| **Audited commit** | `3732bde` (master) |
| **Detected stacks** | node-express (Express 4, MongoDB driver 2.x, swig templates) |
| **Scope** | Local repository code |
| **Out of scope** | Infrastructure, MongoDB server configuration, dynamic testing |

> Read-only static analysis: no project file was modified. Fixes are proposed as diffs.

## Summary

**Score: 0/100.** Remote code execution, server-side JS injection, plaintext passwords, missing authorization and several XSS paths are reachable by any user; do not deploy as is.

| Severity | Confirmed | To verify |
|---|---|---|
| Critical | 2 | 0 |
| High | 5 | 0 |
| Medium | 6 | 1 |
| Low | 2 | 1 |
| Info | 1 | 0 |

## Summary table

| ID | Severity | Title | OWASP | Location | Status |
|---|---|---|---|---|---|
| SEC-01 | Critical | `eval()` on request body (RCE) | A03 | `app/routes/contributions.js:32-34` | Confirmed |
| SEC-02 | Critical | MongoDB `$where` JS injection | A03 | `app/data/allocations-dao.js:78` | Confirmed |
| SEC-03 | High | Passwords stored and compared in plaintext | A02 | `app/data/user-dao.js:25,61,75` | Confirmed |
| SEC-04 | High | Admin pages only check login, not admin role | A01 | `app/routes/index.js:55-56`, `app/routes/session.js:25-34` | Confirmed |
| SEC-05 | High | IDOR on allocations (userId from URL) | A01 | `app/routes/index.js:63`, `app/routes/allocations.js:16-23` | Confirmed |
| SEC-06 | High | SSRF with reflected HTML on `/research` | A10 | `app/routes/research.js:15-27` | Confirmed |
| SEC-07 | High | Stored/reflected XSS (autoescape off, unsanitized markdown) | A03 | `server.js:126-128,137`, `app/views/memos.html:31`, `app/routes/profile.js:64`, `app/views/profile.html:41,78`, `app/views/error-template.html:11` | Confirmed |
| SEC-08 | Medium | No CSRF protection (csurf unused) | A01 | `server.js:71-102`, `app/views/login.html:117`, `app/views/profile.html:73` | Confirmed |
| SEC-09 | Medium | Session/crypto secrets hardcoded; weak session cookie config | A02/A07 | `config/env/all.js:8-9`, `server.js:78-85` | Confirmed |
| SEC-10 | Medium | Weak authentication flow (enumeration, no rate limit, weak policy, fixation) | A07 | `app/routes/session.js:63-98,116,144,171`, `app/routes/index.js:33-34` | Confirmed |
| SEC-11 | Medium | Open redirect on `/learn` | A01 | `app/routes/index.js:70-73` | Confirmed |
| SEC-12 | Medium | Sensitive PII (SSN, bank data) stored unencrypted | A02 | `app/data/profile-dao.js:55-66` | Confirmed |
| SEC-13 | Medium | ReDoS regex on bank routing | A04 | `app/routes/profile.js:59-61` | Confirmed |
| SEC-14 | Medium | Missing security headers (helmet installed, unused), no HTTPS enforcement | A05 | `server.js:68-129`, `package.json:16` | To verify |
| SEC-15 | Low | Stack traces and full config (incl. secrets) logged/exposed | A09 | `app/routes/error.js:7-11`, `config/config.js:12-13` | Confirmed |
| SEC-16 | Low | Hardcoded ZAP API key in env configs | A02 | `config/env/development.js:6`, `config/env/test.js:6` | Confirmed |
| SEC-17 | Low | Outdated/vulnerable dependencies and EOL runtime | A06 | `package.json:8-22`, `Dockerfile:1,7` | To verify |
| SEC-18 | Info | Missing `./tutorial` router module | A05 | `app/routes/index.js:8,79` | Confirmed |

## Findings

### SEC-01: `eval()` on request body (RCE)
- **Severity**: Critical | **OWASP**: A03 | **Status**: Confirmed
- **Location**: `app/routes/contributions.js:32-34` (route `POST /contributions`, `index.js:52`)
```js
32  const preTax = eval(req.body.preTax);
33  const afterTax = eval(req.body.afterTax);
34  const roth = eval(req.body.roth);
```
**Impact**: Any logged-in user (self sign-up is open) executes arbitrary JavaScript on the server (read env/DB, spawn processes).
**Fix**
```diff
-const preTax = eval(req.body.preTax);
+const preTax = parseInt(req.body.preTax, 10);
```
(same for the two other lines).

### SEC-02: MongoDB `$where` JS injection
- **Severity**: Critical | **OWASP**: A03 | **Status**: Confirmed
- **Location**: `app/data/allocations-dao.js:78`; source `app/routes/allocations.js:19-23`
```js
78  $where: `this.userId == ${parsedUserId} && this.stocks > '${threshold}'`
```
**Impact**: `threshold` (query string) is concatenated into server-side JS: `?threshold=0'; return true; var x='` returns every user's allocations; arbitrary JS runs in MongoDB (DoS, data exfiltration).
**Fix**
```diff
-$where: `this.userId == ${parsedUserId} && this.stocks > '${threshold}'`
+$and: [{ userId: parsedUserId }, { stocks: { $gt: parseInt(threshold, 10) } }]
```
Validate that `threshold` is numeric (and reject NaN).

### SEC-03: Passwords stored and compared in plaintext
- **Severity**: High | **OWASP**: A02 | **Status**: Confirmed
- **Location**: `app/data/user-dao.js:25,60-61,75`
```js
25  password
60  const comparePassword = (fromDB, fromUser) => {
61      return fromDB === fromUser;
```
**Impact**: Database leak (or the NoSQL/`$where` injection above) exposes every password; `bcrypt-nodejs` is a dependency but never used.
**Fix**
```diff
-password
+password: bcrypt.hashSync(password, bcrypt.genSaltSync())
...
-return fromDB === fromUser;
+return bcrypt.compareSync(fromUser, fromDB);
```
Prefer the maintained `bcrypt`/`argon2` package (`bcrypt-nodejs` is deprecated); migrate existing users.

### SEC-04: Admin pages only check login, not admin role
- **Severity**: High | **OWASP**: A01 | **Status**: Confirmed
- **Location**: `app/routes/index.js:55-56`; `isAdmin` defined at `index.js:27` / `session.js:25` but never used
```js
55  app.get("/benefits", isLoggedIn, benefitsHandler.displayBenefits);
56  app.post("/benefits", isLoggedIn, benefitsHandler.updateBenefits);
```
**Impact**: Any user lists all non-admin users and overwrites any user's `benefitStartDate` by posting `userId`. The handler also hardcodes `user: { isAdmin: true }` (`benefits.js:21,44`).
**Fix**
```diff
-app.get("/benefits", isLoggedIn, ...
+app.get("/benefits", isAdmin, ...
-app.post("/benefits", isLoggedIn, ...
+app.post("/benefits", isAdmin, ...
```

### SEC-05: IDOR on allocations
- **Severity**: High | **OWASP**: A01 | **Status**: Confirmed
- **Location**: `app/routes/index.js:63`, `app/routes/allocations.js:16-23`
```js
63  app.get("/allocations/:userId", isLoggedIn, allocationsHandler.displayAllocations);
16  const { userId } = req.params;
```
**Impact**: Any logged-in user reads another user's allocations (and name) by changing the ID in the URL.
**Fix**
```diff
-const { userId } = req.params;
+const { userId } = req.session;
```
(or reject if `req.params.userId !== String(req.session.userId)`).

### SEC-06: SSRF with reflected HTML on `/research`
- **Severity**: High | **OWASP**: A10 | **Status**: Confirmed
- **Location**: `app/routes/research.js:15-27`
```js
15  const url = req.query.url + req.query.symbol;
16  return needle.get(url, (error, newResponse, body) => {
...
25      res.write(body);
```
**Impact**: Authenticated users make the server request arbitrary URLs (internal services, cloud metadata, `file`-like schemes depending on library) and the response is written back as `text/html` (also reflected XSS).
**Fix**: Use a fixed base URL (`const url = STOCK_API + encodeURIComponent(symbol)`), never take the host from the client; escape or serve the body as `text/plain`.

### SEC-07: XSS (autoescape disabled, unsanitized markdown, unescaped fields)
- **Severity**: High | **OWASP**: A03 | **Status**: Confirmed
- **Location**: `server.js:126-128,135-137`, `app/views/memos.html:31`, `app/routes/memos.js:13`, `app/routes/profile.js:64`, `app/views/profile.html:41,45,78`, `app/views/error-template.html:11`
```js
126  marked.setOptions({ sanitize: true });
137  autoescape: false
```
```html
31  {{ marked(doc.memo) }}
41  value="{{firstNameSafeString}}"
```
**Impact**: Memos are shared by all users (`getAllMemos` returns all, `memos-dao.js:28`): a stored payload runs in every visitor's session (including admins). `marked@0.3.5` `sanitize` is known to be bypassable, and with swig `autoescape: false` every `{{ }}` (profile fields, error text, login `userName`) is emitted raw (reflected/stored XSS, attribute breakout).
**Fix**
```diff
-autoescape: false
+autoescape: true
```
Upgrade `marked` and pass output through DOMPurify (`sanitize` option is removed upstream); keep `|safe` only on sanitized HTML.

### SEC-08: No CSRF protection
- **Severity**: Medium | **OWASP**: A01 | **Status**: Confirmed
- **Location**: `server.js:71-102`; views carry `_csrf` fields (`login.html:117`, `profile.html:73`)
```html
<input type="hidden" name="_csrf" value="{{csrftoken}}" />
```
**Impact**: `csurf` is a dependency but no middleware is mounted and `csrftoken` is never provided; the token is empty and nothing is checked, so cross-site POSTs to `/profile`, `/contributions`, `/benefits`, `/memos` succeed with the victim's cookie.
**Fix**
```diff
+const csrf = require("csurf");
+app.use(csrf());
+app.use((req, res, next) => { res.locals.csrftoken = req.csrfToken(); next(); });
```
(after `session`, before `routes`). Also set `sameSite` on the cookie.

### SEC-09: Hardcoded secrets and weak session configuration
- **Severity**: Medium | **OWASP**: A02/A07 | **Status**: Confirmed
- **Location**: `config/env/all.js:8-9`, `server.js:78-85`
```js
8   cookieSecret: "session_cookie_secret_key_here",
9   cryptoKey: "a_secure_key_for_crypto_here",
84  saveUninitialized: true,
85  resave: true
```
**Impact**: The session secret is a public placeholder committed to the repo; anyone can forge signed session cookies if it is deployed unchanged. No `httpOnly`/`secure`/`sameSite`/`maxAge` options set; `express-session` default MemoryStore (leaks, not for production).
**Fix**
```diff
-cookieSecret: "session_cookie_secret_key_here",
+cookieSecret: process.env.COOKIE_SECRET,
```
```diff
 secret: cookieSecret,
-saveUninitialized: true,
-resave: true
+saveUninitialized: false,
+resave: false,
+cookie: { httpOnly: true, secure: true, sameSite: "lax", maxAge: 3600000 }
```
Use a persistent store (connect-mongo). Make the app fail if `COOKIE_SECRET` is unset in production.

### SEC-10: Weak authentication flow
- **Severity**: Medium | **OWASP**: A07 | **Status**: Confirmed
- **Location**: `session.js:63-98` (enumeration), `session.js:116` (no `regenerate` on login), `session.js:144,171` (weak policy), `index.js:33-34` (no limiter)
```js
82  loginError: invalidUserNameErrorMessage,   // "Invalid username"
91  loginError: invalidPasswordErrorMessage,   // "Invalid password"
116 req.session.userId = user._id;
144 const PASS_RE = /^.{1,20}$/;
```
**Impact**: Distinct errors reveal valid usernames; unlimited login attempts; passwords of 1 character accepted (message claims 8-18 with mixed case); session fixation since the ID is not regenerated at login (it is at signup, line 234).
**Fix**: single generic message; `express-rate-limit` on `/login` and `/signup`; enforce `^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}$`; call `req.session.regenerate()` before setting `userId` at login.

### SEC-11: Open redirect on `/learn`
- **Severity**: Medium | **OWASP**: A01 | **Status**: Confirmed
- **Location**: `app/routes/index.js:70-73`
```js
72  return res.redirect(req.query.url);
```
**Impact**: Phishing via a trusted domain link (`/learn?url=https://evil.example`).
**Fix**: allowlist target hosts or only accept relative paths (`url.startsWith("/") && !url.startsWith("//")`).

### SEC-12: Sensitive PII stored unencrypted
- **Severity**: Medium | **OWASP**: A02 | **Status**: Confirmed
- **Location**: `app/data/profile-dao.js:55-66`; unused `cryptoKey` at `config/env/all.js:9`
```js
61  if (ssn) { user.ssn = ssn; }
55  if (bankAcc) { user.bankAcc = bankAcc; }
```
**Impact**: SSN, date of birth and bank account/routing stored (and re-rendered into forms) in clear; a DB leak or injection (SEC-02) discloses them directly.
**Fix**: field-level encryption (AES-256-GCM with a key from the environment, not `aes256` CBC) or store only what is necessary; mask on display.

### SEC-13: ReDoS regex
- **Severity**: Medium | **OWASP**: A04 | **Status**: Confirmed
- **Location**: `app/routes/profile.js:59-61`
```js
59  const regexPattern = /([0-9]+)+\#/;
61  const testComplyWithRequirements = regexPattern.test(bankRouting);
```
**Impact**: Nested quantifier: `"0000000000000000000000000000x"` blocks the single Node event loop for a long time; any logged-in user can DoS the whole server.
**Fix**
```diff
-const regexPattern = /([0-9]+)+\#/;
+const regexPattern = /^[0-9]+#$/;
```

### SEC-14: Missing security headers
- **Severity**: Medium | **OWASP**: A05 | **Status**: To verify manually (reverse proxy or platform may add headers; check response headers of the deployed app: CSP, X-Frame-Options, HSTS, `X-Powered-By`)
- **Location**: `server.js:68-129`; `helmet` and `dont-sniff-mimetype` listed in `package.json:12,16` but never required
**Impact**: No CSP/X-Frame-Options/HSTS; `X-Powered-By: Express` disclosed; clickjacking and weaker XSS mitigation.
**Fix**
```diff
+const helmet = require("helmet");
+app.use(helmet());
```

### SEC-15: Stack traces and full config exposed
- **Severity**: Low | **OWASP**: A09 | **Status**: Confirmed
- **Location**: `app/routes/error.js:7-11`, `config/config.js:12-13`
```js
11  error: err
13  console.log(util.inspect(config, false, null));
```
**Impact**: The error template renders the error object to the client (`error-template.html:11`); the whole config (cookie secret, crypto key, DB URI with credentials if set in env) is written to logs at start-up.
**Fix**: render a generic message and log server-side only; remove the config dump.

### SEC-16: Hardcoded ZAP API key
- **Severity**: Low | **OWASP**: A02 | **Status**: Confirmed
- **Location**: `config/env/development.js:6`, `config/env/test.js:6`
```js
6   zapApiKey: "v9dn0b…****",
```
**Impact**: Credential for a ZAP scanner (private IP `192.168.56.20`) committed; limited exposure (dev/test only), but rotate if reused.
**Fix**: read from `process.env.ZAP_API_KEY`.

### SEC-17: Outdated dependencies and EOL runtime
- **Severity**: Low (weights halved) | **OWASP**: A06 | **Status**: To verify manually: `npm audit --omit=dev` failed (no network access); run it and `npm outdated`
- **Location**: `package.json:8-22`, `Dockerfile:1,7`
```json
"marked": "0.3.5", "needle": "2.2.4", "mongodb": "^2.1.18", "swig": "^1.4.2", "bcrypt-nodejs": "0.0.3"
```
**Impact**: `marked@0.3.5` (XSS/ReDoS advisories), `swig` and `bcrypt-nodejs` are unmaintained, `node:12-alpine` is end-of-life, `mongodb` 2.x is obsolete. Specific advisory reachability not confirmed offline.
**Fix**: upgrade to supported versions (Node 20+/22, `marked`, `mongodb` 6, replacement for swig/bcrypt-nodejs).

### SEC-18: Missing `./tutorial` router module
- **Severity**: Info | **OWASP**: A05 | **Status**: Confirmed
- **Location**: `app/routes/index.js:8,79`
```js
8   const tutorialRouter = require("./tutorial");
```
`app/routes/tutorial.js` does not exist in the repository: the application throws at start-up. Likely an incomplete export; confirm the file is not meant to be present (also `/tutorial` is mounted without `isLoggedIn`).

---

## Strengths

- Queries by ID go through `parseInt` and the MongoDB driver filter objects (`user-dao.js:99`, `profile-dao.js:79`), so classic operator injection on `_id` is avoided.
- Sign-up regenerates the session (`session.js:234`) and logout destroys it (`session.js:122`).
- Profile update copies only an explicit list of fields (no mass assignment) (`profile-dao.js:45-66`).
- Multi-stage Dockerfile runs as the non-root `node` user (`Dockerfile:8,17`); `.env` is git-ignored (`.gitignore:27-28`).
- No committed `.env` and no real-format keys in git history.

## Fix priorities

1. **SEC-01 and SEC-02**: remove `eval`, replace `$where` (30 min)
2. **SEC-03**: hash passwords with bcrypt/argon2 and migrate users (2 h)
3. **SEC-04 and SEC-05**: enforce `isAdmin` and ownership checks (30 min)
4. **SEC-07 and SEC-06**: enable autoescape, sanitize markdown, fix SSRF (2 h)
5. **SEC-08, SEC-09, SEC-10**: CSRF, secrets from env, cookie flags, rate limit (2 h)

## Appendices

### Commands run
```
bash scripts/detect_stack.sh TARGET
bash scripts/find_secrets.sh TARGET
bash scripts/grep_patterns.sh TARGET node-express
npm audit --omit=dev   # failed: registry unreachable
```

### Discarded leads (false positives)
| Location | Pattern | Reason |
|---|---|---|
| `Gruntfile.js:165` | shell_command | `exec` of a fixed command with `NODE_ENV` from the developer's environment; dev tooling, not reachable from requests |
| `config/env/all.js:8,9` (as hardcoded_password_or_key) | hardcoded_password_or_key | Reported as SEC-09 (placeholder secrets, but used as real session secret) rather than as a leak |
| `app/routes/index.js:30-76` | route_to_check / endpoint_auth_rate_limit | Inventory lines; reviewed, findings merged into SEC-04/05/10/11 |
| `Dockerfile:13` | dockerignore_missing_env | Not exploitable now: no `.env` file in the repo and `.env` is git-ignored; multi-stage build; noted only as hygiene |
| `app/routes/profile.js:28` | encodeForHTML on `website` | Correct output encoding (strength), not a finding |

### Not verified
- Dependency vulnerabilities (`npm audit` could not reach the registry).
- Deployed response headers, TLS, MongoDB authentication/network exposure, production environment variables.
- No dynamic testing.
