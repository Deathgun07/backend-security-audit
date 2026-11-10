# Next.js checklist (App Router and Pages Router)

Files to read first: `middleware.ts` / `proxy.ts` (Next 16), `app/**/route.ts`, `pages/api/**`, `"use server"` files, `lib/auth*`, `lib/db*`, `next.config.*`, `.env*`.

## N1. Server actions without auth check — Critical (A01)
A server action is a public POST endpoint: anyone can call it with its action ID, even if the button is hidden.
```ts
// ❌
"use server";
export async function deletePost(id: string) {
  await db.post.delete({ where: { id } });
}
// ✅
"use server";
export async function deletePost(id: string) {
  const user = await getCurrentUser();            // reads and verifies the session server-side
  if (!user) throw new Error("Not authenticated");
  await db.post.delete({ where: { id, authorId: user.id } }); // ownership filter
}
```
- **Evidence**: cite the exported function and the absence of an auth call in its body and in the helpers it calls (follow the calls before concluding).

## N2. API routes without `auth.getUser()` / session — Critical (A01)
```ts
// ❌ app/api/admin/users/route.ts
export async function GET() { return Response.json(await db.user.findMany()); }
// ✅
export async function GET() {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return new Response("Unauthorized", { status: 401 });
  if (user.app_metadata.role !== "admin") return new Response("Forbidden", { status: 403 });
  return Response.json(await db.user.findMany());
}
```
- Do not rely on the middleware alone (see N4). `getSession()` on the server side is not enough (Supabase).

## N3. Secrets in `NEXT_PUBLIC_*` — Critical (A02)
Any `NEXT_PUBLIC_*` variable is inlined into the JS sent to the browser.
```diff
-NEXT_PUBLIC_STRIPE_SECRET_KEY=sk_live_...
-NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=eyJ...
+STRIPE_SECRET_KEY=sk_live_...
+SUPABASE_SERVICE_ROLE_KEY=eyJ...
```
- Also: a server module imported by a client component → add `import "server-only"` to modules that read secrets.

## N4. Bypassable middleware — High (A01)
- `matcher` that misses paths (`/api/*`, dynamic routes, `/_next/data`) or an overly broad regex exclusion.
- Check via `pathname.startsWith("/admin")` bypassable through casing or encoding if the route is case-insensitive.
- Next < 14.2.25 / 15.2.3: CVE-2025-29927 (the `x-middleware-subrequest` header bypasses the middleware) → check the version in the lockfile.
```ts
// ❌
export const config = { matcher: ["/dashboard"] };   // /dashboard/settings not covered, /api not covered
// ✅
export const config = { matcher: ["/((?!_next/static|_next/image|favicon.ico|login).*)"] };
```
Rule: the middleware is a convenience (redirect); authorization is redone in each route/action/server page.

## N5. IDOR — High (A01)
The identifier comes from the client (params, body, searchParams) and the query does not filter by owner.
```ts
// ❌ app/api/invoices/[id]/route.ts
const invoice = await db.invoice.findUnique({ where: { id: params.id } });
// ✅
const invoice = await db.invoice.findFirst({ where: { id: params.id, userId: user.id } });
if (!invoice) return new Response("Not found", { status: 404 });
```
- Variant: `userId` read from the body instead of the session (`const { userId } = await req.json()`) → Critical.
- With Supabase and correct RLS, the IDOR is blocked by the database: check the policy before rating.

## N6. No input validation — Medium (A03/A04)
```ts
// ❌
const body = await req.json();
await db.user.update({ where: { id: user.id }, data: body });   // mass assignment: role, isAdmin...
// ✅
const Schema = z.object({ name: z.string().min(1).max(80), bio: z.string().max(500).optional() });
const data = Schema.parse(await req.json());
await db.user.update({ where: { id: user.id }, data });
```
- Mass assignment of a privilege field = Critical; plain lack of validation = Medium.

## N7. Missing security headers — Low to Medium (A05)
Check `next.config.*` (`headers()`), middleware or reverse proxy.
```ts
// ✅ next.config.ts
async headers() { return [{ source: "/(.*)", headers: [
  { key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains; preload" },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
  { key: "Content-Security-Policy", value: "default-src 'self'; frame-ancestors 'none'" },
]}]; }
```
- Also `poweredByHeader: false`. Total absence of CSP = Low (Medium if `dangerouslySetInnerHTML` is present).

## N8. SSRF via fetch of a user URL — High (A10)
```ts
// ❌ app/api/preview/route.ts
const { url } = await req.json();
const res = await fetch(url);       // http://169.254.169.254/, http://localhost:8090/_/ ...
// ✅
const u = new URL(url);
if (u.protocol !== "https:" || !ALLOWED_HOSTS.has(u.hostname)) return new Response("URL rejected", { status: 400 });
const res = await fetch(u, { redirect: "error" });
```
- Also: `next.config` `images.remotePatterns` with `hostname: "**"` → Low (open image proxy).

## N9. XSS — Medium to High (A03)
`dangerouslySetInnerHTML` with user content without `DOMPurify`; Markdown rendered with `rehype-raw` without sanitize; `href={userUrl}` without a check (`javascript:`).

## N10. SQL / NoSQL injection — Critical (A03)
```ts
// ❌
await prisma.$queryRawUnsafe(`SELECT * FROM users WHERE email = '${email}'`);
await sql.unsafe(`... ${q}`);
// ✅
await prisma.$queryRaw`SELECT * FROM users WHERE email = ${email}`;
```

## N11. Cookies and sessions — Medium (A07)
Auth cookies without `httpOnly`, `secure`, `sameSite`. JWT stored in `localStorage`. `jwt.decode()` used instead of `jwt.verify()`.

## N12. Open redirect — Medium (A01)
`redirect(searchParams.get("next"))` without checking that the target is a relative path (`/^\/(?!\/)/`).

## N13. Webhooks — High (A08)
Stripe/payment webhook without signature verification (`stripe.webhooks.constructEvent(rawBody, sig, secret)`), or mobile money without HMAC check → anyone can validate a payment.

## N14. Data exposure in Server Components — Medium (A01)
Full object passed as props to a client component (`<Profile user={user} />` with `passwordHash`, `stripeCustomerId`) → serialized in the HTML. Select fields explicitly.
