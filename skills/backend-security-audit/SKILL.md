---
name: backend-security-audit
description: Audit de sécurité backend en lecture seule d'un projet local (Supabase, Firebase, PocketBase, MySQL/MariaDB, Next.js, Node/Express, PHP, Laravel, Flask, FastAPI, Django, Go) qui produit SECURITY_AUDIT.md avec preuves et correctifs en diff. À utiliser quand l'utilisateur demande d'« auditer la sécurité », « vérifier les failles », « faire un audit de sécurité / pentest du code », vérifier la RLS, les policies, les Firebase Security Rules, les API rules, les comptes MySQL, les secrets exposés ou les injections SQL d'un projet, ou tape /backend-security-audit. Ne pas utiliser pour attaquer un système tiers ni pour une revue de diff (préférer security-review).
---

# Audit de sécurité backend

`SKILL_DIR` = dossier de ce fichier. `CIBLE` = racine du projet audité (dossier courant, sauf indication contraire).

## Règles absolues

1. **Lecture seule.** Ne jamais modifier, formater, installer ni committer quoi que ce soit dans le projet audité. Seule écriture autorisée : `CIBLE/SECURITY_AUDIT.md`. Les correctifs sont proposés en **diff minimal** dans le rapport.
2. **Preuve obligatoire.** Chaque faille cite `fichier:ligne` + un extrait exact relu avec Read. Pas de preuve → pas de faille. Une sortie de script n'est jamais une preuve à elle seule : relire le code.
3. **Deux statuts seulement** :
   - **Confirmé** : le chemin vulnérable est visible de bout en bout dans le code (source contrôlée par l'attaquant → sink, sans contrôle intermédiaire).
   - **À vérifier manuellement** : dépend d'un élément hors dépôt (config dashboard, variable d'env de prod, reverse proxy, version déployée). Dire précisément quoi vérifier et comment.
4. **Aucune action offensive.** Pas de requête vers un serveur, une API ou une URL de production, pas de scan réseau, pas d'exploitation. `scan_rls.sql` / `scan_mysql.sql` ne s'exécutent que sur **la base de l'utilisateur**, avec son accord explicite et la chaîne de connexion qu'il fournit (base locale de préférence).
5. **Secrets masqués** dans le rapport et dans les réponses : 6 premiers caractères puis `…****`.
6. Tout en français.

## Workflow

### 1. Détecter le stack
```bash
bash "$SKILL_DIR/scripts/detect_stack.sh" "$CIBLE"
```
Noter `stacks`, `lockfiles`, `outils_disponibles`, le commit courant (`git -C "$CIBLE" rev-parse --short HEAD`).
Si `racine_git` ≠ `CIBLE` (projet dans un dépôt parent), restreindre toutes les commandes git à `CIBLE`.
Si aucun stack n'est détecté : le dire, appliquer seulement la checklist commune.

### 2. Charger les checklists
Lire `checklists/commun.md` **toujours**, puis **uniquement** celles des stacks détectés :

| Stack détecté | Checklist |
|---|---|
| `supabase` | `supabase.md` |
| `firebase` | `firebase.md` |
| `pocketbase` | `pocketbase.md` |
| `mysql` | `mysql.md` (la base elle-même, quel que soit le langage) |
| `nextjs` | `nextjs.md` |
| `node-express` | `node-express.md` (Express, Fastify, Koa, Hono, NestJS) |
| `php-mysql` | `php-mysql.md` (tout code PHP) |
| `laravel` | `laravel.md` (en plus de `php-mysql.md`) |
| `flask`, `fastapi` | `flask.md` (sections Flask et FastAPI) |
| `django` | `django.md` |
| `go` | `go.md` |

Ne pas lire les autres. Stack non couvert (Rails, Spring, ASP.NET…) : appliquer `commun.md` + les principes OWASP des checklists proches, et le signaler dans « Non vérifié ».

### 3. Lancer les scripts de détection
```bash
bash "$SKILL_DIR/scripts/find_secrets.sh"  "$CIBLE"
bash "$SKILL_DIR/scripts/grep_patterns.sh" "$CIBLE" "<stacks séparés par des virgules>"
```
Format : `fichier:ligne:pattern:sévérité`. Ce sont des **pistes** : les trier une par une (faille / faux positif / à vérifier).
Les lignes `Info` (`route_api_a_verifier`, `server_action_a_verifier`…) servent d'inventaire pour l'étape 4.

Audit des dépendances, seulement si l'outil est disponible (lecture du lockfile) :
`bun audit` · `npm audit --omit=dev` · `composer audit` · `pip-audit -r requirements.txt` · `govulncheck ./...`.
Absent → entrée « à vérifier » avec la commande.

Bases de données (voir règle 4, toujours avec l'accord de l'utilisateur) :
- Supabase / Postgres : `scripts/scan_rls.sql`. Sans accès, analyser `supabase/migrations/*.sql` dans l'ordre chronologique.
- MySQL / MariaDB : `scripts/scan_mysql.sql` (`mysql -u root -p -t < scan_mysql.sql`). Sans accès, analyser `*.sql`, `docker-compose*.yml`, `*.cnf`.
- Firebase : les rules du dépôt peuvent différer de celles déployées → statut « à vérifier » si aucune preuve de déploiement.

### 4. Analyse manuelle des fichiers sensibles
Lister puis **lire** (pas seulement grep) :
```bash
cd "$CIBLE" && git ls-files 2>/dev/null | grep -iE 'auth|login|session|middleware|proxy\.ts|route\.(ts|js)$|/api/|actions?\.(ts|js)$|upload|admin|db|database|sql|query|config|hooks?/|pb_hooks|pb_migrations|policy|rls|\.rules(\.json)?$|functions/|settings\.py|urls\.py|serializers?\.py|\.go$|controllers?/|routes?/|docker-compose|\.cnf$|\.php$|app\.py|main\.py|views?\.py' | grep -v node_modules
```
Sans git : `find` équivalent en excluant `node_modules vendor .next dist venv`.
Pour chaque fichier, dérouler la checklist chargée. Priorités :
- **Auth** : comment la session est lue et vérifiée côté serveur ; qui peut appeler chaque route / action / RPC.
- **Autorisation** : chaque ID venant du client est-il filtré par propriétaire ? (IDOR)
- **Requêtes** : paramétrées ou concaténées ? Suivre la variable jusqu'à sa source.
- **Upload** : type, taille, nom, emplacement, exécution.
- **Middleware** : couverture réelle du matcher, contournements.
- **Règles d'accès BDD** : RLS, Firebase Security Rules, API rules PocketBase, comptes et GRANT MySQL : prendre la **dernière** migration qui touche chaque table/collection.
- **Rate limiting** sur login, OTP, reset password.

Suivre les appels entre fichiers avant de conclure à une absence de contrôle (un helper peut faire la vérification).
Pour les grosses bases de code, déléguer la lecture par zone à des sous-agents `Explore`, puis vérifier soi-même chaque faille remontée.

### 5. Évaluer
- Sévérité : partir de la valeur par défaut de la checklist, ajuster selon l'exposition réelle (route publique vs admin, données personnelles vs publiques). Justifier tout écart dans « Impact ».
- Une même cause racine répétée dans N fichiers = **une** faille listant les emplacements.
- Score = 100 − (25×Critique + 10×Haute + 4×Moyenne + 1×Basse) pour les confirmées, moitié des poids pour « à vérifier », plancher 0.

### 6. Rédiger le rapport
Copier la structure de `templates/rapport.md` dans `CIBLE/SECURITY_AUDIT.md` et la remplir :
résumé et score, tableau récapitulatif, détail de chaque faille (ID `SEC-NN` trié par sévérité), points positifs (avec preuves), top 5 des priorités, annexes (commandes, faux positifs écartés, non vérifié).
Si `SECURITY_AUDIT.md` existe déjà : demander avant d'écraser (ou écrire `SECURITY_AUDIT-AAAA-MM-JJ.md`).

### 7. Restituer
Dans la réponse : score, nombre de failles par sévérité, les 3 plus graves en une ligne chacune, lien vers le rapport, ce qui reste « à vérifier ». Proposer d'appliquer les correctifs **seulement si l'utilisateur le demande** (hors de ce skill).

## Faux positifs fréquents (à écarter avec justification)
- Clé `anon` / `publishable` Supabase et config web Firebase (`apiKey: "AIza…"`) côté client : publiques par conception (Info).
- Valeurs d'exemple : `.env.example`, `your-api-key`, `changeme`, `xxx`, fixtures de tests, documentation.
- `listRule: ""` PocketBase / `using (true)` en SELECT sur des données réellement publiques.
- `render_template_string` avec chaîne constante ; `md5` utilisé pour un ETag ou un cache, pas un mot de passe.
- Code dans `tests/`, `scripts/` de dev, `seed` : sévérité réduite sauf secret réel.
