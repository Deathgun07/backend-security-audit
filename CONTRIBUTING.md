# Contributing

Thanks for helping make backend code safer. Contributions of any size are welcome: a new detection pattern, a false-positive fix, a new stack, a translation.

## Ground rules

- **Read-only and defensive.** The skill only analyzes local code and the user's own database. Contributions that add offensive capabilities (exploitation, scanning third-party systems) will not be accepted.
- **Evidence over guesses.** Checks must lead to a `file:line` proof; prefer precise patterns over noisy ones.
- **No real secrets.** Never commit a string that looks like a real key (`sk_live_…`, `AKIA…`, private keys). In tests, build fake secrets by concatenation, as `tests/run_tests.sh` does.

## Repository layout

| Path | Content |
|---|---|
| `skills/backend-security-audit/SKILL.md` | workflow and rules read by the assistant (keep it under 200 lines) |
| `skills/backend-security-audit/checklists/` | one checklist per stack: vulnerable vs. fixed code, severity, OWASP category |
| `skills/backend-security-audit/scripts/` | detection scripts (bash, grep/ripgrep, git) and read-only SQL scans |
| `bin/cli.mjs` | Node installer (`npx`, `bunx`, `pnpm dlx`), zero dependencies |
| `install.sh` | bash installer (`curl \| bash`) |
| `tests/` | vulnerable fixture app and test suites |

## Adding a detection pattern

1. Add a `chk` line in `scripts/grep_patterns.sh` (stack, severity, `snake_case` label, ERE regex, globs, optional exclusion).
2. Add a vulnerable case to `tests/fixtures/app-vulnerable/`.
3. Add the expected `file:line:label` regex to `EXPECTED` in `tests/run_tests.sh`.
4. Document the check in the stack checklist, with a vulnerable and a fixed example.

Regexes must work with both GNU grep `-E` and ripgrep: avoid lookarounds and backreferences.

## Adding a stack

1. Detection in `scripts/detect_stack.sh`.
2. A new `checklists/<stack>.md`, and a row in the table of step 2 in `SKILL.md`.
3. Patterns, fixture cases and tests as above.
4. A row in the "Supported stacks" tables of the READMEs.

## Adding an assistant to the installers

Add the platform to `PLATFORMS` in `bin/cli.mjs` **and** in `install.sh` (same folder layout), then a check in `tests/test_cli.sh`.

## Translations

`README.md` (English) is the reference. When you change it, update `README.fr.md`, `README.es.md`, `README.pt-BR.md` and `README.zh-CN.md`, or mention in the PR which ones are left to translate. New translations are welcome (`README.<lang>.md` + a link in the language bar of every README).

## Before opening a PR

```bash
bash tests/run_tests.sh
bash tests/test_cli.sh
```
Keep the versions of `package.json`, `.claude-plugin/plugin.json` and `.claude-plugin/marketplace.json` identical, and add an entry to `CHANGELOG.md`.
