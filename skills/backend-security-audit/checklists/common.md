# Common checklist (always loaded)

Each item: what to look for → how to prove it → fix. Default severities, to be adjusted according to actual exposure.

## C1. Committed `.env` files — Critical (A02/A05)
- **Look for**: `find_secrets.sh` output, sections "`.env` tracked by git" and "`.env` not ignored".
- **Evidence**: `git ls-files | grep .env` + (masked) contents of a sensitive line.
- **Fix**:
```diff
# .gitignore
+.env
+.env.*
+!.env.example
```
then `git rm --cached .env` **and rotate all keys**: removing the file does not invalidate them.

## C2. Secrets in git history — Critical (A02)
- **Look for**: "Git history" section of `find_secrets.sh`. Verify with `git show <commit> --stat` then `git show <commit> -- <file> | grep -n <pattern>`.
- **Status**: "confirmed" only if the value is a real key (not a placeholder such as `xxx`, `your-key`, `changeme`).
- **Fix**: rotate the key (mandatory), then optionally `git filter-repo --path .env --invert-paths` (rewrites history, for the owner to decide).

## C3. Hardcoded secrets in code — High to Critical (A02/A07)
```ts
// ❌ vulnerable
const stripe = new Stripe("sk_live_51H...");
// ✅ fixed
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);
```
- Frequent false positives: Supabase `anon` key and Firebase web config `apiKey` (public by design → Info), test keys, test fixtures, example values in README.
- If a JWT is found: decode the payload (`echo <part2> | base64 -d`) to read `role`: `anon` = Info, `service_role` = Critical.

## C4. Vulnerable dependencies — variable (A06)
Run the appropriate tool if available (reads the lockfile, no modification):
| Stack | Command |
|---|---|
| Bun | `bun audit` |
| npm | `npm audit --omit=dev` |
| pnpm | `pnpm audit --prod` |
| PHP | `composer audit` |
| Python | `pip-audit -r requirements.txt` |
- Report only **High/Critical** vulnerabilities reachable in production, grouped into a single entry per package.
- If the tool is missing: a "to verify manually" line with the command to run.

## C5. No rate limiting on authentication — Medium to High (A07)
Affected endpoints: login, sign-up, OTP / SMS code, password reset, magic link, email verification.
- **Look for**: `endpoint_auth_rate_limit` output of `grep_patterns.sh`, then read the handler and the middleware.
- **Evidence of absence**: no call to a limiter (`@upstash/ratelimit`, `express-rate-limit`, `flask-limiter`, Redis counter/table, `throttle`) in the handler or upstream (middleware, reverse proxy configured in the repo: nginx `limit_req`, Caddy, Cloudflare).
- Supabase Auth / PocketBase have native limits: check the config (`supabase/config.toml` `[auth.rate_limit]`, PocketBase ≥ 0.23 Settings → Rate limits) before concluding. If not visible in the repo → "to verify".
```ts
// ✅ Next.js + Upstash
const { success } = await ratelimit.limit(`login:${ip}`);
if (!success) return new Response("Too many attempts", { status: 429 });
```
- A 4-6 digit OTP without a limit = High (enumerable).

## C6. Error messages and logs — Low to Medium (A09)
- Stack traces returned to the client, raw DB `error.message` in the HTTP response.
- Logs containing passwords, tokens, `Authorization` headers.
```ts
// ❌
return Response.json({ error: e.message }, { status: 500 });
// ✅
console.error(e); return Response.json({ error: "Internal error" }, { status: 500 });
```

## C7. Generic access control (IDOR) — High (A01)
Any route that receives an identifier (`id`, `userId`, `orderId`) from the client must verify that the resource belongs to the authenticated user **server-side** (or via RLS). The UI not showing the button is not a protection.

## C8. File upload — Medium to Critical (A04)
Check: extension allowlist **and** content check (magic bytes), max size, regenerated file name, storage outside the webroot or without execution, `Content-Disposition: attachment` for risky types (SVG/HTML = stored XSS).

## C9. Docker / deployment configuration — Medium (A05)
- DB ports publicly exposed in `docker-compose.yml` (`"5432:5432"`, `"3306:3306"`, `"8090:8090"` without a proxy) → prefer `127.0.0.1:5432:5432`.
- Default passwords (`POSTGRES_PASSWORD: postgres`, `root/root`).
- Container run as root without need.

## OWASP Top 10 (2021) mapping to use in the report
A01 Access control · A02 Crypto/secrets failures · A03 Injection (SQL, XSS, SSTI, command) · A04 Insecure design · A05 Misconfiguration · A06 Vulnerable components · A07 Authentication · A08 Integrity (deserialization) · A09 Logging · A10 SSRF
