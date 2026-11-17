# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [2.2.0] - 2026-11-17

Field feedback from two real audits (a large PHP/MySQL project without a framework, and a Next.js + PocketBase project).

### Added
- `php_write_endpoint_without_auth` (block check): PHP scripts that read the request and run `INSERT`/`UPDATE`/`DELETE` with no session check in the file nor in the files it includes (2 levels, loop-safe). Files are pre-selected with `grep -rl` to stay fast on large projects.
- `cors_wildcard_origin` for PHP (`header('Access-Control-Allow-Origin: *')` or reflected `$_SERVER` origin).
- Docker build context checks: `docker_context_without_dockerignore`, `dockerignore_missing_env`, and an Info line naming each `.env*` file in the context (never its value).
- `detect_stack.sh`: `"web_root": true|false` (project served as is, e.g. `htdocs/`). The skill then warns that the report must not be written or deployed inside the site.
- `EXCLUDE_DIRS` (extra directories to skip, read by the 3 scripts) and `NO_RG=1` (force the grep fallback).
- Checklists: PHP AJAX/API scripts without a session (P13), PHP CORS (P16), Docker build context (C9), client-side rate-limit guards bypassable for PocketBase and Supabase, PocketBase `exportToCookie({ httpOnly: false })` trade-off.

### Changed
- `grep_patterns.sh` no longer truncates silently: Critical and High leads are never cut; other patterns print `# truncated: <label> (<sev>) <max> of <total> shown`. `MAX_PER_PATTERN=0` disables the limit.
- `find_secrets.sh`: secrets in local files that are untracked **and** ignored by git are listed under `### Secrets in local files ignored by git (not committed)`, one level lower (Critical → Medium, High → Low). Generic `password = "…"` findings in test/fixture/benchmark paths are Low.
- `shell_command` (Next.js, Node): only actual shell calls (`exec(`, `execSync(`, `spawn(… { shell: true })`), not the word `child_process` nor `execFile*`; one level lower in test files.
- `hook_sql_concat`: concatenation of an UPPER_CASE constant with bound parameters is ignored; Medium in `pb_migrations/`.
- PHP `endpoint_auth_rate_limit`: based on `password_verify(` and login/reset/OTP file names instead of the word "connexion" (which also means a database connection in French).
- Supabase is detected only with `supabase/config.toml`, `supabase/migrations/` or a Supabase client dependency (not an empty `lib/supabase/` folder).
- `.php` files are counted without a depth limit.

### Fixed
- `hardcoded_password_or_key` missed every value containing an `s` with GNU grep (`\s` inside a bracket expression); now uses `[:space:]`.
- `rule_auth_too_broad` flagged owner-scoped rules such as `@request.auth.id != '' && user = @request.auth.id`.
- SQL comment lines (`-- …`) are ignored by the `*.sql` patterns (e.g. `security_definer` in a comment).

## [2.1.0] - 2026-11-10

### Added
- Block-level checks (portable awk) for missing authorization that a single-line pattern cannot see:
  - `go_auth_response_without_return`: Go handler or middleware that writes a 401/403 but neither returns nor aborts, so the request keeps going.
  - `jwt_parse_error_ignored`: `token, _ := jwt.Parse(...)` in Go.
  - `write_endpoint_without_auth` / `endpoint_without_auth`: FastAPI endpoints without an auth `Depends`/`Security`, Flask routes without `@login_required` (or similar); files with a global dependency or `before_request` are skipped.
  - `cloud_function_without_auth`: Firebase `onCall` / `onRequest` whose body never checks `request.auth`, `verifyIdToken` or a webhook signature.
  - `write_route_without_middleware`: Express write routes whose handler is passed directly (public routes such as `/login`, `/webhook` excluded).
- `tests/fixtures/app-safe/`: correct versions of those patterns; the test suite asserts that none of the new checks fire on it.

## [2.0.0] - 2026-11-10

### Changed
- The skill content is now in English: `SKILL.md`, the 12 checklists, the report template and the script output. Reports are still written in the language of the user's request.
- **Breaking** for anyone parsing script output: severities are `Critical`, `High`, `Medium`, `Low`, `Info`, and pattern labels are in English (e.g. `secret_in_public_env`, `sql_concatenated`). JSON keys of `detect_stack.sh` are `root`, `git_root`, `evidence`, `available_tools`.
- `checklists/commun.md` renamed to `checklists/common.md`, `templates/rapport.md` to `templates/report.md`, `exemples/` to `examples/`.
- New example report covering all 12 stacks.

### Added
- GitHub Actions CI (Linux, Linux + ripgrep, macOS, ShellCheck).
- `CONTRIBUTING.md`, `SECURITY.md`, issue and pull request templates.

## [1.3.0] - 2026-11-10

### Added
- Installation with Bun (`bunx`), pnpm (`pnpm dlx`), Yarn (`yarn dlx`) and `curl | bash` (no Node required).
- Installer messages in English or French depending on the system locale.
- README in English, French, Spanish, Brazilian Portuguese and Simplified Chinese.

## [1.2.0] - 2026-11-10

### Added
- `npx` installer for 20 AI assistants (Claude Code, Cursor, Codex CLI, Gemini CLI, GitHub Copilot, Windsurf, Kiro, …), with project or global install, auto-detection, `list` and `uninstall`.

## [1.1.0] - 2026-11-10

### Added
- Firebase, MySQL / MariaDB (database), Django, Go, Node.js / Express, Laravel and FastAPI support.
- `scan_mysql.sql` read-only MySQL audit.

## [1.0.0] - 2026-11-10

### Added
- First release: Supabase, Next.js, PHP / MySQL, Flask and PocketBase checklists, detection scripts, `scan_rls.sql`, Claude Code plugin.
