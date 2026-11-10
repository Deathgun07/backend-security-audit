# Checklist Next.js (App Router et Pages Router)

Fichiers à lire en priorité : `middleware.ts` / `proxy.ts` (Next 16), `app/**/route.ts`, `pages/api/**`, fichiers `"use server"`, `lib/auth*`, `lib/db*`, `next.config.*`, `.env*`.

## N1. Server actions sans vérification d'auth — Critique (A01)
Une server action est un endpoint POST public : n'importe qui peut l'appeler avec son ID d'action, même si le bouton est caché.
```ts
// ❌
"use server";
export async function deletePost(id: string) {
  await db.post.delete({ where: { id } });
}
// ✅
"use server";
export async function deletePost(id: string) {
  const user = await getCurrentUser();            // lit et vérifie la session côté serveur
  if (!user) throw new Error("Non authentifié");
  await db.post.delete({ where: { id, authorId: user.id } }); // filtre d'appartenance
}
```
- **Preuve** : citer la fonction exportée et l'absence d'appel d'auth dans son corps et dans les helpers qu'elle appelle (suivre les appels avant de conclure).

## N2. Routes API sans `auth.getUser()` / session — Critique (A01)
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
- Ne pas compter sur le middleware seul (voir N4). `getSession()` côté serveur ne suffit pas (Supabase).

## N3. Secrets dans `NEXT_PUBLIC_*` — Critique (A02)
Toute variable `NEXT_PUBLIC_*` est inlinée dans le JS envoyé au navigateur.
```diff
-NEXT_PUBLIC_STRIPE_SECRET_KEY=sk_live_...
-NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=eyJ...
+STRIPE_SECRET_KEY=sk_live_...
+SUPABASE_SERVICE_ROLE_KEY=eyJ...
```
- Également : un module serveur importé par un composant client → ajouter `import "server-only"` dans les modules qui lisent des secrets.

## N4. Middleware contournable — Haute (A01)
- `matcher` qui oublie des chemins (`/api/*`, routes dynamiques, `/_next/data`) ou exclusion trop large par regex.
- Vérification par `pathname.startsWith("/admin")` contournable par la casse ou l'encodage si la route est insensible.
- Next < 14.2.25 / 15.2.3 : CVE-2025-29927 (en-tête `x-middleware-subrequest` contourne le middleware) → vérifier la version dans le lockfile.
```ts
// ❌
export const config = { matcher: ["/dashboard"] };   // /dashboard/settings non couvert, /api non couvert
// ✅
export const config = { matcher: ["/((?!_next/static|_next/image|favicon.ico|login).*)"] };
```
Règle : le middleware est une commodité (redirection), l'autorisation se refait dans chaque route/action/page serveur.

## N5. IDOR — Haute (A01)
L'identifiant vient du client (params, body, searchParams) et la requête ne filtre pas par propriétaire.
```ts
// ❌ app/api/invoices/[id]/route.ts
const invoice = await db.invoice.findUnique({ where: { id: params.id } });
// ✅
const invoice = await db.invoice.findFirst({ where: { id: params.id, userId: user.id } });
if (!invoice) return new Response("Not found", { status: 404 });
```
- Variante : `userId` lu depuis le body au lieu de la session (`const { userId } = await req.json()`) → Critique.
- Avec Supabase et RLS correcte, l'IDOR est bloqué par la base : vérifier la policy avant de classer.

## N6. Absence de validation des entrées — Moyenne (A03/A04)
```ts
// ❌
const body = await req.json();
await db.user.update({ where: { id: user.id }, data: body });   // mass assignment : role, isAdmin...
// ✅
const Schema = z.object({ name: z.string().min(1).max(80), bio: z.string().max(500).optional() });
const data = Schema.parse(await req.json());
await db.user.update({ where: { id: user.id }, data });
```
- Mass assignment d'un champ de privilège = Critique ; absence de validation simple = Moyenne.

## N7. En-têtes de sécurité manquants — Basse à Moyenne (A05)
Vérifier `next.config.*` (`headers()`), middleware ou reverse proxy.
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
- Également `poweredByHeader: false`. Absence totale de CSP = Basse (Moyenne si `dangerouslySetInnerHTML` présent).

## N8. SSRF via fetch d'URL utilisateur — Haute (A10)
```ts
// ❌ app/api/preview/route.ts
const { url } = await req.json();
const res = await fetch(url);       // http://169.254.169.254/, http://localhost:8090/_/ ...
// ✅
const u = new URL(url);
if (u.protocol !== "https:" || !ALLOWED_HOSTS.has(u.hostname)) return new Response("URL refusée", { status: 400 });
const res = await fetch(u, { redirect: "error" });
```
- Aussi : `next.config` `images.remotePatterns` avec `hostname: "**"` → Basse (proxy d'images ouvert).

## N9. XSS — Moyenne à Haute (A03)
`dangerouslySetInnerHTML` avec contenu utilisateur sans `DOMPurify` ; Markdown rendu avec `rehype-raw` sans sanitize ; `href={userUrl}` sans contrôle (`javascript:`).

## N10. Injection SQL / NoSQL — Critique (A03)
```ts
// ❌
await prisma.$queryRawUnsafe(`SELECT * FROM users WHERE email = '${email}'`);
await sql.unsafe(`... ${q}`);
// ✅
await prisma.$queryRaw`SELECT * FROM users WHERE email = ${email}`;
```

## N11. Cookies et sessions — Moyenne (A07)
Cookies d'auth sans `httpOnly`, `secure`, `sameSite`. JWT stocké en `localStorage`. `jwt.decode()` utilisé au lieu de `jwt.verify()`.

## N12. Redirection ouverte — Moyenne (A01)
`redirect(searchParams.get("next"))` sans vérifier que la cible est un chemin relatif (`/^\/(?!\/)/`).

## N13. Webhooks — Haute (A08)
Webhook Stripe/paiement sans vérification de signature (`stripe.webhooks.constructEvent(rawBody, sig, secret)`), ou mobile money sans contrôle HMAC → n'importe qui peut valider un paiement.

## N14. Exposition de données dans les Server Components — Moyenne (A01)
Objet complet passé en props à un composant client (`<Profile user={user} />` avec `passwordHash`, `stripeCustomerId`) → sérialisé dans le HTML. Sélectionner explicitement les champs.
