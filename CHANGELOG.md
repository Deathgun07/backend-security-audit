# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

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
