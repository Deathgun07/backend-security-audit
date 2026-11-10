---
name: backend-security-audit
description: Read-only backend security audit of a local project (Supabase, Firebase, PocketBase, MySQL/MariaDB, Next.js, Node/Express, PHP, Laravel, Flask, FastAPI, Django, Go) producing SECURITY_AUDIT.md with evidence (file:line) and fixes as diffs. Use when the user asks to audit security, find vulnerabilities, check RLS / policies / Firebase Security Rules / PocketBase API rules / MySQL accounts, look for exposed secrets or SQL injections, or types /backend-security-audit. Also triggers in other languages, e.g. French « audite la sécurité », « cherche les failles », Spanish « audita la seguridad », Portuguese « audite a segurança ». Not for attacking third-party systems nor for reviewing a diff.
---

# Backend security audit

`SKILL_DIR` = directory of this file. `TARGET` = root of the audited project (current directory unless told otherwise).

## Absolute rules

1. **Read-only.** Never modify, format, install or commit anything in the audited project. The only allowed write is `TARGET/SECURITY_AUDIT.md`. Fixes are proposed as **minimal diffs** in the report.
2. **Evidence required.** Every finding cites `file:line` plus an exact excerpt re-read with your file-reading tool. No evidence → no finding. Script output alone is never evidence: re-read the code.
3. **Two statuses only**:
   - **Confirmed**: the vulnerable path is visible end to end in the code (attacker-controlled source → sink, with no check in between).
   - **To verify manually**: depends on something outside the repository (dashboard settings, production env vars, reverse proxy, deployed version). State exactly what to check and how.
4. **No offensive action.** No requests to production servers, APIs or URLs, no network scanning, no exploitation. `scan_rls.sql` / `scan_mysql.sql` run only against **the user's own database**, with their explicit consent and a connection string they provide (local database preferred).
5. **Mask secrets** in the report and in replies: first 6 characters then `…****`.
6. **Language**: write the report and replies in the language of the user's request (translate the headings of `templates/report.md`; keep the file name `SECURITY_AUDIT.md`). Severity and status names are translated too.

## Workflow

### 1. Detect the stack
```bash
bash "$SKILL_DIR/scripts/detect_stack.sh" "$TARGET"
```
Note `stacks`, `lockfiles`, `available_tools`, and the current commit (`git -C "$TARGET" rev-parse --short HEAD`).
If `git_root` ≠ `TARGET` (project inside a parent repository), restrict every git command to `TARGET`.
If no stack is detected: say so and apply only the common checklist.

### 2. Load the checklists
Always read `checklists/common.md`, then **only** those of the detected stacks:

| Detected stack | Checklist |
|---|---|
| `supabase` | `supabase.md` |
| `firebase` | `firebase.md` |
| `pocketbase` | `pocketbase.md` |
| `mysql` | `mysql.md` (the database itself, whatever the language) |
| `nextjs` | `nextjs.md` |
| `node-express` | `node-express.md` (Express, Fastify, Koa, Hono, NestJS) |
| `php-mysql` | `php-mysql.md` (any PHP code) |
| `laravel` | `laravel.md` (in addition to `php-mysql.md`) |
| `flask`, `fastapi` | `flask.md` (Flask and FastAPI sections) |
| `django` | `django.md` |
| `go` | `go.md` |

Do not read the others. Uncovered stack (Rails, Spring, ASP.NET…): apply `common.md` plus the OWASP principles of the closest checklists, and say so under "Not verified".

### 3. Run the detection scripts
```bash
bash "$SKILL_DIR/scripts/find_secrets.sh"  "$TARGET"
bash "$SKILL_DIR/scripts/grep_patterns.sh" "$TARGET" "<comma-separated stacks>"
```
Format: `file:line:pattern:severity`. These are **leads**: triage them one by one (finding / false positive / to verify).
`Info` lines (`api_route_to_check`, `server_action_to_check`…) are an inventory for step 4.

Dependency audit, only if the tool is available (reads the lockfile):
`bun audit` · `npm audit --omit=dev` · `composer audit` · `pip-audit -r requirements.txt` · `govulncheck ./...`.
Tool missing → "to verify" entry with the command.

Databases (see rule 4, always with the user's consent):
- Supabase / Postgres: `scripts/scan_rls.sql`. Without access, analyze `supabase/migrations/*.sql` in chronological order.
- MySQL / MariaDB: `scripts/scan_mysql.sql` (`mysql -u root -p -t < scan_mysql.sql`). Without access, analyze `*.sql`, `docker-compose*.yml`, `*.cnf`.
- Firebase: rule files referenced by `firebase.json` are what `firebase deploy` ships → findings in them are **Confirmed** (add a note that the console may hold newer rules); rule files not referenced anywhere → "to verify". Cloud Functions code follows the normal rules.

### 4. Manual review of sensitive files
List, then **read** (not just grep):
```bash
cd "$TARGET" && git ls-files 2>/dev/null | grep -iE 'auth|login|session|middleware|proxy\.ts|route\.(ts|js)$|/api/|actions?\.(ts|js)$|upload|admin|db|database|sql|query|config|hooks?/|pb_hooks|pb_migrations|policy|rls|\.rules(\.json)?$|functions/|settings\.py|urls\.py|serializers?\.py|\.go$|controllers?/|routes?/|docker-compose|\.cnf$|\.php$|\.pb\.js$|views?/|app\.py|main\.py|views?\.py|package\.json$|next\.config' | grep -v node_modules
```
Without git: equivalent `find`, excluding `node_modules vendor .next dist venv`.
For each file, walk through the loaded checklist. Priorities:
- **Authentication**: how the session is read and verified server-side; who can call each route / action / RPC.
- **Authorization**: is every client-supplied ID filtered by owner? (IDOR)
- **Queries**: parameterized or concatenated? Follow the variable back to its source.
- **Uploads**: type, size, name, location, execution.
- **Middleware**: actual matcher coverage, bypasses.
- **Database access rules**: RLS, Firebase Security Rules, PocketBase API rules, MySQL accounts and GRANTs: use the **latest** migration touching each table/collection.
- **Rate limiting** on login, OTP, password reset.

Follow calls across files before concluding that a check is missing (a helper may do it).
For large codebases, delegate reading by area to sub-agents if your environment supports them, then verify every reported finding yourself.

### 5. Assess
- Severity: start from the checklist default, adjust to the real exposure (public vs admin route, personal vs public data). Justify any deviation in "Impact".
- The same root cause repeated in N files of the **same stack/component** = **one** finding listing all locations (e.g. one SQL injection finding for the PHP code, another for the Go service).
- Secrets: a value matching a real key format (`sk_live_…`, `AKIA…`, `sb_secret_…`, a JWT with `role: service_role`) in a tracked file is **Confirmed** and requires rotation, even if it might be a test value; only obvious placeholders (`xxx`, `your-key`, `changeme`) are discarded.
- Score = 100 − (25×Critical + 10×High + 4×Medium + 1×Low) for confirmed findings, half the weights for "to verify", floor 0.

### 6. Write the report
Copy the structure of `templates/report.md` into `TARGET/SECURITY_AUDIT.md` and fill it in:
summary and score, summary table, details of each finding (ID `SEC-NN`, sorted by severity), strengths (with evidence), top 5 priorities, appendices (commands, discarded false positives, not verified).
If `SECURITY_AUDIT.md` already exists: ask before overwriting (or write `SECURITY_AUDIT-YYYY-MM-DD.md`).

### 7. Report back
In your reply: score, number of findings per severity, the 3 most severe in one line each, a link to the report, and what remains "to verify". Offer to apply the fixes **only if the user asks** (outside this skill).

## Common false positives (discard with a justification)
- Supabase `anon` / `publishable` key and Firebase web config (`apiKey: "AIza…"`) on the client: public by design (Info).
- Example values: `.env.example`, `your-api-key`, `changeme`, `xxx`, test fixtures, documentation.
- PocketBase `listRule: ""` / `using (true)` on SELECT for genuinely public data.
- `render_template_string` with a constant string; `md5` used for an ETag or cache key, not a password.
- Code in `tests/`, dev `scripts/`, `seed`: lower severity unless it holds a real secret.
