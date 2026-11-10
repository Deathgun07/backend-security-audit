# backend-security-audit

Skill pour assistants IA de code ([Claude Code](https://claude.com/claude-code), Cursor, Codex, Gemini CLI, GitHub Copilot, Windsurf, Kiro…) qui audite la sécurité backend d'un projet **en lecture seule** et produit un rapport `SECURITY_AUDIT.md` : score /100, failles classées par sévérité et catégorie OWASP, preuve `fichier:ligne` pour chacune, correctif sous forme de diff.

Stacks couverts :
- **Bases de données / BaaS** : Supabase (Postgres + RLS), Firebase (Firestore, Realtime Database, Storage, Cloud Functions), PocketBase, MySQL / MariaDB
- **Backends** : PHP natif, Laravel, Node.js (Express, Fastify, Koa, Hono, NestJS), Next.js, Flask, FastAPI, Django, Go (net/http, Gin, Echo, Fiber, Chi)
- **Contrôles communs** : secrets, `.env` commités, historique git, dépendances, rate limiting

> 📄 Exemple de rapport généré : [exemples/SECURITY_AUDIT.md](exemples/SECURITY_AUDIT.md)

## Ce que fait le skill

1. Détecte le stack (`package.json`, `composer.json`, `requirements.txt`, `supabase/`, `pb_migrations/`…)
2. Charge **uniquement** les checklists correspondantes (un projet Laravel + MySQL ne charge que `commun`, `php-mysql`, `laravel` et `mysql`)
3. Lance les scripts de détection (secrets, motifs dangereux par langage)
4. Relit à la main les fichiers sensibles : auth, routes, server actions, middleware, requêtes SQL, upload, policies RLS, API rules
5. Écrit `SECURITY_AUDIT.md` à la racine du projet audité

Règles appliquées par le skill :
- **ne modifie jamais le code audité** ; les correctifs sont proposés en diff ;
- **pas de faille sans preuve** (fichier, ligne, extrait relu) ;
- chaque faille est marquée **Confirmé** ou **À vérifier manuellement** (avec la vérification à faire) ;
- secrets masqués dans le rapport ;
- **aucune action offensive** : uniquement le code local et, si vous le fournissez, votre propre base de données.

## Installation

### Avec la CLI (tous les assistants IA)

Une seule commande, sans installation préalable (Node ≥ 18) :

```bash
npx github:Deathgun07/backend-security-audit init --ai claude
```

Remplacez `claude` par votre assistant :

| `--ai` | Assistant | Dossier créé |
|---|---|---|
| `claude` | Claude Code | `.claude/skills/backend-security-audit/` |
| `cursor` | Cursor | `.cursor/skills/backend-security-audit/` |
| `codex` | Codex CLI | `.agents/skills/backend-security-audit/` |
| `gemini` | Gemini CLI | `.gemini/skills/backend-security-audit/` |
| `copilot` | GitHub Copilot | `.github/prompts/backend-security-audit.prompt.md` |
| `windsurf` | Windsurf | `.windsurf/skills/backend-security-audit/` |
| `kiro` | Kiro | `.kiro/steering/backend-security-audit/` |
| `antigravity` | Antigravity | `.agents/skills/backend-security-audit/` |
| `opencode` | OpenCode | `.opencode/skills/backend-security-audit/` |
| `roocode` | Roo Code | `.roo/skills/backend-security-audit/` |
| `kilocode` | Kilo Code | `.kilocode/skills/backend-security-audit/` |
| `continue` | Continue | `.continue/skills/backend-security-audit/` |
| `trae` | Trae | `.trae/skills/backend-security-audit/` |
| `qoder` | Qoder | `.qoder/skills/backend-security-audit/` |
| `codebuddy` | CodeBuddy | `.codebuddy/skills/backend-security-audit/` |
| `droid` | Droid (Factory) | `.factory/skills/backend-security-audit/` |
| `augment` | Augment | `.augment/skills/backend-security-audit/` |
| `warp` | Warp | `.warp/skills/backend-security-audit/` |
| `amazonq` | Amazon Q Developer | `.amazonq/rules/backend-security-audit.md` |
| `universal` | Standard Agent Skills | `.agents/skills/backend-security-audit/` |
| `all` | tous | — |

Autres commandes :
```bash
npx github:Deathgun07/backend-security-audit init                      # détecte les assistants présents dans le projet
npx github:Deathgun07/backend-security-audit init --ai cursor,codex    # plusieurs assistants
npx github:Deathgun07/backend-security-audit init --ai claude --global # pour tous vos projets (~/.claude/skills/)
npx github:Deathgun07/backend-security-audit init --ai all --dry-run   # aperçu sans rien écrire
npx github:Deathgun07/backend-security-audit list                      # où est-il installé ?
npx github:Deathgun07/backend-security-audit uninstall --ai cursor
```
Pour mettre à jour : relancer `init` avec `--force`.

### Avec le gestionnaire de plugins de Claude Code

```
/plugin marketplace add Deathgun07/backend-security-audit
/plugin install backend-security-audit@backend-security-audit
```

### Sans Node

```bash
git clone https://github.com/Deathgun07/backend-security-audit.git
cd backend-security-audit
./install.sh            # → ~/.claude/skills/
./install.sh --projet   # → ./.claude/skills/ du dossier courant
```
Ou copiez `skills/backend-security-audit/` dans le dossier de skills de votre assistant.

Relancez votre assistant après l'installation.

## Utilisation

Depuis la racine du projet à auditer :
```
/backend-security-audit
```
(Claude Code) ou, dans n'importe quel assistant, en langage naturel : *« audite la sécurité de ce projet »*, *« vérifie les policies RLS »*, *« cherche des failles dans mon backend »*.

### Audit de la base de données (optionnel)

Les policies créées depuis le dashboard n'apparaissent pas dans le code. Pour les auditer, exécutez `scan_rls.sql` sur **votre** base (lecture seule, transaction annulée à la fin) :
```bash
supabase start
psql "postgresql://postgres:postgres@127.0.0.1:54322/postgres" -f ~/.claude/skills/backend-security-audit/scripts/scan_rls.sql
```
ou collez-le section par section dans le SQL Editor de votre projet.

Pour MySQL / MariaDB, `scan_mysql.sql` liste les comptes sans mot de passe, les accès distants, les privilèges dangereux et les réglages risqués :
```bash
mysql -u root -p -t < ~/.claude/skills/backend-security-audit/scripts/scan_mysql.sql
```
Le skill vous proposera ces scripts ; il ne se connecte jamais à une base sans votre accord.

### Utiliser les scripts sans Claude

```bash
S=~/.claude/skills/backend-security-audit/scripts
bash $S/detect_stack.sh  /chemin/projet          # JSON des stacks détectés
bash $S/find_secrets.sh  /chemin/projet          # fichier:ligne:type:sévérité
bash $S/grep_patterns.sh /chemin/projet nextjs,supabase
```

## Ce qui est vérifié

| Stack | Points clés |
|---|---|
| Supabase | tables sans RLS, `USING (true)`, écriture `anon`, `SECURITY DEFINER` sans `search_path`, vues sans `security_invoker`, buckets publics, RPC exposées, `service_role` côté client, colonnes `role`/`is_admin` modifiables, `user_metadata` dans les policies |
| Firebase | rules `if true` / sans condition, mode test à date, `request.auth != null` seul, champs de rôle modifiables, Realtime Database ouverte, Storage rules, Cloud Functions sans contrôle, compte de service commité |
| PocketBase | API rules vides, rules `@request.auth.id != ""` trop larges, champs sensibles, filtres injectables, hooks sans auth |
| MySQL / MariaDB | comptes sans mot de passe, root distant, `GRANT ALL ON *.*`, port 3306 publié, `local_infile`, mots de passe MD5 en base, SQL dynamique dans les procédures, phpMyAdmin/Adminer exposés, versions obsolètes |
| Next.js | server actions et routes API sans auth, secrets `NEXT_PUBLIC_*`, middleware contournable, IDOR, validation (zod), en-têtes de sécurité, SSRF, XSS, webhooks non signés |
| Node / Express | routes sans auth, injection SQL et NoSQL, mass assignment, JWT, CORS, path traversal, prototype pollution, désérialisation |
| PHP | injection SQL, XSS, CSRF, sessions, upload, include/require, md5/sha1, identifiants en dur, `display_errors` |
| Laravel | `APP_DEBUG`, `APP_KEY` commité, requêtes `*Raw`, mass assignment, policies, `{!! !!}`, exclusions CSRF, upload |
| Flask / FastAPI | `debug=True`, `SECRET_KEY`, SQL f-string, SSTI, pickle/yaml, CORS `*`, dépendances d'auth, JWT non vérifié, modèles Pydantic |
| Django | `DEBUG`, `SECRET_KEY`, `ALLOWED_HOSTS`, `raw()`/`extra()`, IDOR, `fields = "__all__"`, `AllowAny`, `csrf_exempt`, `mark_safe`, hachage faible |
| Go | SQL `fmt.Sprintf`, middleware sans `return`/`Abort`, JWT, `exec.Command("sh")`, path traversal, SSRF, TLS, timeouts serveur, CORS |
| Commun | `.env` commités, secrets dans l'historique git, dépendances (`bun audit`, `npm audit`, `composer audit`, `pip-audit`, `govulncheck`), rate limiting |

Le détail, avec exemples vulnérables et corrigés, est dans [`skills/backend-security-audit/checklists/`](skills/backend-security-audit/checklists/).

## Structure

```
skills/backend-security-audit/
├── SKILL.md              # workflow et règles (lu par Claude)
├── checklists/           # commun + une checklist par stack
├── scripts/              # detect_stack.sh, find_secrets.sh, grep_patterns.sh, scan_rls.sql, scan_mysql.sql
└── templates/rapport.md  # modèle du rapport
tests/
├── fixtures/app-vulnerable/   # application volontairement vulnérable
├── run_tests.sh               # vérifie que les scripts détectent les failles attendues
└── test_cli.sh                # vérifie la CLI d'installation
bin/cli.mjs                    # CLI npx (init / list / uninstall), sans dépendance
```

## Prérequis

- Linux (Ubuntu/Debian testés) ou WSL ; bash ≥ 4, `grep`, `find`, `git`
- Optionnels : `ripgrep` (plus rapide), `psql`, `mysql`, `bun`/`npm`/`composer`/`pip-audit`/`govulncheck` pour l'audit des dépendances
- macOS : installer un bash récent (`brew install bash`), le bash 3.2 système n'est pas supporté

## Tests

```bash
bash tests/run_tests.sh          # scripts de détection (VERBOSE=1 pour voir la sortie)
bash tests/test_cli.sh           # CLI d'installation (npm pack + init/list/uninstall)
```

## Limites

C'est une analyse statique assistée, pas un pentest : elle ne remplace ni des tests dynamiques ni une revue humaine. Les scripts produisent des **pistes** que Claude doit relire ; des faux négatifs restent possibles, surtout sur la logique métier.

## Contribuer

Les PR sont bienvenues : nouveaux motifs (avec un cas ajouté à la fixture et au test), nouvelles checklists (Rails, Spring, ASP.NET, MongoDB…), réduction des faux positifs. Lancez `bash tests/run_tests.sh` avant d'ouvrir une PR.

## Licence

[MIT](LICENSE)
