# Checklist commune (toujours chargée)

Chaque point : quoi chercher → comment le prouver → correctif. Sévérités par défaut, à ajuster selon l'exposition réelle.

## C1. Fichiers `.env` commités — Critique (A02/A05)
- **Chercher** : sortie `find_secrets.sh` sections « .env suivis par git » et « .env non ignoré ».
- **Preuve** : `git ls-files | grep .env` + contenu (masqué) d'une ligne sensible.
- **Correctif** :
```diff
# .gitignore
+.env
+.env.*
+!.env.example
```
puis `git rm --cached .env` **et rotation de toutes les clés** : retirer le fichier ne les invalide pas.

## C2. Secrets dans l'historique git — Critique (A02)
- **Chercher** : section « Historique git » de `find_secrets.sh`. Vérifier avec `git show <commit> --stat` puis `git show <commit> -- <fichier> | grep -n <motif>`.
- **Statut** : « confirmé » seulement si la valeur est une vraie clé (pas un placeholder `xxx`, `your-key`, `changeme`).
- **Correctif** : rotation de la clé (obligatoire), puis éventuellement `git filter-repo --path .env --invert-paths` (réécrit l'historique, à décider par le propriétaire).

## C3. Secrets en dur dans le code — Haute à Critique (A02/A07)
```ts
// ❌ vulnérable
const stripe = new Stripe("sk_live_51H...");
// ✅ corrigé
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);
```
- Faux positifs fréquents : clé `anon` Supabase et `apiKey` de la config web Firebase (publiques par conception → Info), clés de test, fixtures de tests, valeurs d'exemple dans README.
- Un JWT trouvé : décoder le payload (`echo <partie2> | base64 -d`) pour lire `role` : `anon` = Info, `service_role` = Critique.

## C4. Dépendances vulnérables — variable (A06)
Lancer l'outil adapté s'il est disponible (lecture du lockfile, aucune modification) :
| Stack | Commande |
|---|---|
| Bun | `bun audit` |
| npm | `npm audit --omit=dev` |
| pnpm | `pnpm audit --prod` |
| PHP | `composer audit` |
| Python | `pip-audit -r requirements.txt` |
- Reporter uniquement les vulnérabilités **High/Critical** atteignables en production, regroupées en une seule entrée par paquet.
- Si l'outil est absent : ligne « à vérifier manuellement » avec la commande à lancer.

## C5. Absence de rate limiting sur l'authentification — Moyenne à Haute (A07)
Endpoints concernés : login, inscription, OTP / code SMS, reset password, magic link, vérification d'email.
- **Chercher** : sortie `endpoint_auth_rate_limit` de `grep_patterns.sh`, puis lire le handler et le middleware.
- **Preuve d'absence** : aucun appel à un limiteur (`@upstash/ratelimit`, `express-rate-limit`, `flask-limiter`, compteur Redis/table, `throttle`) dans le handler ni en amont (middleware, reverse proxy configuré dans le dépôt : nginx `limit_req`, Caddy, Cloudflare).
- Supabase Auth / PocketBase ont des limites natives : vérifier la config (`supabase/config.toml` `[auth.rate_limit]`, PocketBase ≥ 0.23 Settings → Rate limits) avant de conclure. Si non visible dans le dépôt → « à vérifier ».
```ts
// ✅ Next.js + Upstash
const { success } = await ratelimit.limit(`login:${ip}`);
if (!success) return new Response("Trop de tentatives", { status: 429 });
```
- Un OTP à 4-6 chiffres sans limite = Haute (énumérable).

## C6. Messages d'erreur et logs — Basse à Moyenne (A09)
- Stack traces renvoyées au client, `error.message` brut de la BDD dans la réponse HTTP.
- Logs contenant mots de passe, tokens, en-têtes `Authorization`.
```ts
// ❌
return Response.json({ error: e.message }, { status: 500 });
// ✅
console.error(e); return Response.json({ error: "Erreur interne" }, { status: 500 });
```

## C7. Contrôle d'accès générique (IDOR) — Haute (A01)
Toute route qui reçoit un identifiant (`id`, `userId`, `orderId`) du client doit vérifier que la ressource appartient à l'utilisateur authentifié **côté serveur** (ou via RLS). Le fait que l'UI ne montre pas le bouton n'est pas une protection.

## C8. Upload de fichiers — Moyenne à Critique (A04)
Vérifier : liste blanche d'extensions **et** contrôle du contenu (magic bytes), taille max, nom de fichier régénéré, stockage hors webroot ou sans exécution, `Content-Disposition: attachment` pour les types risqués (SVG/HTML = XSS stocké).

## C9. Configuration Docker / déploiement — Moyenne (A05)
- Ports BDD exposés publiquement dans `docker-compose.yml` (`"5432:5432"`, `"3306:3306"`, `"8090:8090"` sans proxy) → préférer `127.0.0.1:5432:5432`.
- Mots de passe par défaut (`POSTGRES_PASSWORD: postgres`, `root/root`).
- Conteneur lancé en root sans nécessité.

## Mapping OWASP Top 10 (2021) à utiliser dans le rapport
A01 Contrôle d'accès · A02 Défaillances crypto/secrets · A03 Injection (SQL, XSS, SSTI, commande) · A04 Conception non sécurisée · A05 Mauvaise configuration · A06 Composants vulnérables · A07 Authentification · A08 Intégrité (désérialisation) · A09 Journalisation · A10 SSRF
