<div align="center">

# backend-security-audit

**Un skill d'audit de sécurité backend, en lecture seule, pour les assistants IA de code.**
Une preuve pour chaque faille, des correctifs en diff, un rapport priorisé : en quelques minutes, sans quitter votre éditeur.

[English](README.md) · **Français** · [Español](README.es.md) · [Português (BR)](README.pt-BR.md) · [简体中文](README.zh-CN.md)

[![Licence : MIT](https://img.shields.io/badge/Licence-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/Deathgun07/backend-security-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/Deathgun07/backend-security-audit/actions/workflows/ci.yml)
![Assistants](https://img.shields.io/badge/assistants-20-informational)
![Stacks](https://img.shields.io/badge/stacks-12-informational)

</div>

Fonctionne avec **Claude Code, Cursor, Codex CLI, Gemini CLI, GitHub Copilot, Windsurf, Kiro** et 13 autres assistants. Demandez *« audite la sécurité de ce projet »* et vous obtenez un `SECURITY_AUDIT.md` : score sur 100, failles classées par sévérité et catégorie OWASP, preuve `fichier:ligne` pour chacune, correctif prêt à appliquer.

> 📄 Exemple de rapport, généré par le skill sur une application volontairement vulnérable couvrant les 12 stacks : [examples/SECURITY_AUDIT.md](examples/SECURITY_AUDIT.md) (en anglais ; vos rapports sont rédigés dans la langue de votre demande).

## Ce que le skill vous apporte

- **Il voit ce que les scanners génériques ratent.** Policies RLS Supabase, Security Rules Firebase, API rules PocketBase, comptes MySQL, server actions Next.js : les failles propres à chaque plateforme, à l'origine de la plupart des fuites de données réelles.
- **Pas de faille inventée.** Chaque faille cite `fichier:ligne` et un extrait exact relu par l'IA. Chacune est marquée **Confirmé** ou **À vérifier manuellement**, avec ce qu'il faut vérifier et comment.
- **Des correctifs, pas seulement des alertes.** Chaque faille est accompagnée d'un diff minimal et, si besoin, de l'action hors code : rotation de clé, migration à appliquer, réglage à changer.
- **Des priorités claires.** Score sur 100, nombre de failles par sévérité, tableau récapitulatif et **top 5** à corriger en premier, avec une estimation d'effort.
- **Sans risque.** Strictement en lecture seule : le code audité n'est jamais modifié, rien n'est envoyé à des systèmes tiers, les secrets sont masqués dans le rapport. Les scans de base ne s'exécutent que sur *votre* base, avec votre accord.
- **Il trouve les secrets qui ont fuité.** `.env` commités, clés d'API, JWT, clés privées, comptes de service Firebase, et les secrets restés dans l'**historique git**.
- **Il audite votre vraie base, pas seulement les migrations.** `scan_rls.sql` (Postgres/Supabase) et `scan_mysql.sql` (MySQL/MariaDB) listent les tables sans RLS, les policies permissives, les RPC exposées, les comptes sans mot de passe, root accessible à distance, les droits dangereux.
- **Il vous apprend en même temps.** 12 checklists avec du code *vulnérable puis corrigé* pour chaque problème : pour apprendre, former une équipe ou enseigner.
- **Utilisable sans IA.** Les scripts de détection sont du bash simple : lancez-les en CI ou en hook pre-commit.
- **Gratuit et open source** (MIT), sans compte, sans service externe, fonctionne hors ligne une fois installé.

**Pour qui ?** Développeurs solo et « vibe coders » avant la mise en ligne · freelances qui livrent à un client · équipes avant une release · étudiants et enseignants · toute personne qui reprend un projet et veut savoir où sont les trous.

## Stacks couverts

| Type | Stacks |
|---|---|
| Bases de données / BaaS | Supabase (Postgres + RLS), Firebase (Firestore, Realtime Database, Storage, Cloud Functions), PocketBase, MySQL / MariaDB |
| Backends | PHP natif, Laravel, Node.js (Express, Fastify, Koa, Hono, NestJS), Next.js, Flask, FastAPI, Django, Go (net/http, Gin, Echo, Fiber, Chi) |
| Partout | secrets et `.env` commités, historique git, dépendances vulnérables (`bun audit`, `npm audit`, `composer audit`, `pip-audit`, `govulncheck`), absence de rate limiting |

Le stack est détecté automatiquement et **seules les checklists utiles sont chargées** (un projet Laravel + MySQL charge `common`, `php-mysql`, `laravel` et `mysql`).

<details>
<summary><b>Ce qui est vérifié en détail</b></summary>

| Stack | Points clés |
|---|---|
| Supabase | tables sans RLS, `USING (true)`, écriture `anon`, `SECURITY DEFINER` sans `search_path`, vues sans `security_invoker`, buckets publics, RPC exposées, `service_role` côté client, colonnes `role`/`is_admin` modifiables, `user_metadata` dans les policies |
| Firebase | rules `if true` / sans condition, mode test à date, `request.auth != null` seul, champs de rôle modifiables, Realtime Database ouverte, Storage rules, Cloud Functions sans contrôle, compte de service commité |
| PocketBase | API rules vides (publiques), rules `@request.auth.id != ""` trop larges, champs sensibles exposés, filtres injectables, hooks sans auth |
| MySQL / MariaDB | comptes sans mot de passe, root distant, `GRANT ALL ON *.*`, port 3306 publié, `local_infile`, mots de passe MD5 en base, SQL dynamique dans les procédures, phpMyAdmin/Adminer exposés, versions obsolètes |
| Next.js | server actions et routes API sans auth, secrets `NEXT_PUBLIC_*`, middleware contournable, IDOR, validation absente, en-têtes de sécurité, SSRF, XSS, webhooks non signés |
| Node / Express | routes sans auth, injection SQL et NoSQL, mass assignment, JWT, CORS, path traversal, prototype pollution, désérialisation |
| PHP | injection SQL, XSS, CSRF, sessions, upload, `include`/`require` avec entrée utilisateur, md5/sha1, identifiants en dur, `display_errors` |
| Laravel | `APP_DEBUG`, `APP_KEY` commité, requêtes `*Raw`, mass assignment, policies, `{!! !!}`, exclusions CSRF, upload |
| Flask / FastAPI | `debug=True`, `SECRET_KEY`, SQL en f-string, SSTI, pickle/yaml, CORS `*`, dépendances d'auth, JWT non vérifié, modèles Pydantic |
| Django | `DEBUG`, `SECRET_KEY`, `ALLOWED_HOSTS`, `raw()`/`extra()`, IDOR, `fields = "__all__"`, `AllowAny`, `csrf_exempt`, `mark_safe`, hachage faible |
| Go | SQL `fmt.Sprintf`, middleware sans `return`/`Abort`, JWT, `exec.Command("sh")`, path traversal, SSRF, TLS, timeouts serveur, CORS |

</details>

## Installation

Choisissez votre assistant avec `--ai` (ou `--ai all`). Sans `--ai`, l'installeur détecte les assistants déjà utilisés dans le projet.

**npm / Node ≥ 18**
```bash
npx github:Deathgun07/backend-security-audit init --ai claude
```

**Bun**
```bash
bunx github:Deathgun07/backend-security-audit init --ai claude
```

**pnpm**
```bash
pnpm dlx github:Deathgun07/backend-security-audit init --ai claude
```

**Yarn (Berry)**
```bash
yarn dlx -p backend-security-audit@github:Deathgun07/backend-security-audit backend-security-audit init --ai claude
```

**curl (sans Node : bash + curl ou wget)**
```bash
curl -fsSL https://raw.githubusercontent.com/Deathgun07/backend-security-audit/main/install.sh | bash -s -- --ai claude
```

**Gestionnaire de plugins de Claude Code**
```
/plugin marketplace add Deathgun07/backend-security-audit
/plugin install backend-security-audit@backend-security-audit
```

**git clone**
```bash
git clone https://github.com/Deathgun07/backend-security-audit.git
./backend-security-audit/install.sh --ai claude
```

| `--ai` | Assistant | Installé dans |
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

Options (identiques pour tous les installeurs) : `--global` (dossier personnel, tous les projets) · `--force` (mise à jour) · `--dry-run` · `list` / `--list` · `uninstall` (CLI Node). Les messages sont en français si la langue du système est le français, en anglais sinon.

Relancez votre assistant après l'installation.

## Utilisation

Depuis la racine du projet à auditer, demandez à votre assistant :

> *« Audite la sécurité de ce projet »*, *« Vérifie mes policies RLS Supabase »*, *« Mes règles Firebase sont-elles sûres ? »*, *« Cherche des failles dans mon backend »*

Dans Claude Code, vous pouvez aussi taper `/backend-security-audit`. Le rapport `SECURITY_AUDIT.md` est écrit à la racine du projet, dans la langue de votre demande.

### Auditer votre base de données (optionnel)

Les policies créées depuis un dashboard n'apparaissent pas dans le code. Pour les auditer, lancez les scans en lecture seule sur **votre propre** base :
```bash
# Supabase / Postgres (transaction annulée à la fin)
psql "postgresql://postgres:postgres@127.0.0.1:54322/postgres" -f .claude/skills/backend-security-audit/scripts/scan_rls.sql
# MySQL / MariaDB (uniquement des SELECT)
mysql -u root -p -t < .claude/skills/backend-security-audit/scripts/scan_mysql.sql
```
L'assistant vous proposera ces scans ; il ne se connecte jamais à une base sans votre accord.

### Utiliser les scripts sans IA (CI, pre-commit)

```bash
S=.claude/skills/backend-security-audit/scripts
bash $S/detect_stack.sh  .                    # stacks détectés en JSON
bash $S/find_secrets.sh  .                    # fichier:ligne:type:sévérité (valeurs jamais affichées)
bash $S/grep_patterns.sh . nextjs,supabase    # fichier:ligne:pattern:sévérité
```

## Les règles suivies par le skill

1. **Lecture seule** : le code audité n'est jamais modifié ; les correctifs sont proposés en diff.
2. **Pas de faille sans preuve** : `fichier:ligne` + un extrait réellement relu par l'IA.
3. **Deux statuts seulement** : *Confirmé* (visible de bout en bout dans le code) ou *À vérifier manuellement* (dépend d'un élément hors dépôt, expliqué).
4. **Aucune action offensive** : uniquement le code local, et votre propre base si vous la fournissez.
5. **Secrets masqués** dans le rapport.

## Structure du projet

```
skills/backend-security-audit/
├── SKILL.md              # workflow et règles (lu par l'assistant)
├── checklists/           # common + une checklist par stack (12)
├── scripts/              # detect_stack.sh, find_secrets.sh, grep_patterns.sh, scan_rls.sql, scan_mysql.sql
└── templates/report.md  # modèle de rapport
bin/cli.mjs               # installeur npx / bunx / pnpm dlx (sans dépendance)
install.sh                # installeur bash (curl | bash)
tests/
├── fixtures/app-vulnerable/   # application volontairement vulnérable couvrant les 12 stacks
├── run_tests.sh               # scripts de détection (81 vérifications)
└── test_cli.sh                # installeurs (23 vérifications)
```

## Prérequis

- Linux, macOS (avec bash ≥ 4 : `brew install bash`) ou Windows via WSL / Git Bash ; `grep`, `find`, `git`
- Optionnels : `ripgrep` (plus rapide), `psql`, `mysql`, `bun` / `npm` / `composer` / `pip-audit` / `govulncheck` pour l'audit des dépendances

## Limites

C'est une analyse statique assistée par IA, pas un test d'intrusion. Elle ne remplace ni des tests dynamiques ni une revue humaine. Les scripts produisent des **pistes** que l'assistant doit relire ; des faux négatifs restent possibles, surtout dans la logique métier.

## Contribuer

Les PR sont bienvenues : nouveaux motifs (avec un cas dans la fixture et le test), nouvelles checklists (Rails, Spring, ASP.NET, MongoDB…), moins de faux positifs, **traductions**. Voir [CONTRIBUTING.md](CONTRIBUTING.md) (en anglais). Pour signaler une faille dans le skill lui-même : [SECURITY.md](SECURITY.md).

## Licence

[MIT](LICENSE) © Deathgun07
