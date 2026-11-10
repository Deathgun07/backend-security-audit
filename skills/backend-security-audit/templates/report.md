# Backend security audit: {{PROJECT_NAME}}

<!-- Translate every heading and label into the language of the user's request. -->

| | |
|---|---|
| **Date** | {{YYYY-MM-DD}} |
| **Audited commit** | `{{SHORT_HASH}}` ({{BRANCH}}) |
| **Detected stacks** | {{STACKS}} |
| **Scope** | Local repository code{{+ local Postgres / user's Supabase project / MySQL server, if a database scan was run}} |
| **Out of scope** | {{e.g. infrastructure, unexported dashboard settings, dynamic testing}} |

> Read-only static analysis: no project file was modified. Fixes are proposed as diffs.

## Summary

**Score: {{SCORE}}/100.** {{one-sentence verdict}}

| Severity | Confirmed | To verify |
|---|---|---|
| 🔴 Critical | {{n}} | {{n}} |
| 🟠 High | {{n}} | {{n}} |
| 🟡 Medium | {{n}} | {{n}} |
| 🔵 Low | {{n}} | {{n}} |
| ⚪ Info | {{n}} | {{n}} |

<!-- Score = 100 − (25×Critical + 10×High + 4×Medium + 1×Low) for confirmed findings,
     half the weights for "to verify", Info = 0. Floor 0. -->

## Summary table

| ID | Severity | Title | OWASP | Location | Status |
|---|---|---|---|---|---|
| SEC-01 | Critical | {{short title}} | A01 | `{{file}}:{{line}}` | Confirmed |

## Findings

### SEC-01: {{Title}}

- **Severity**: {{Critical / High / Medium / Low / Info}}
- **OWASP category**: {{A0x — name}}
- **Location**: `{{file}}:{{line}}`
- **Status**: {{Confirmed | To verify manually: what to check and how}}

**Evidence**
```{{language}}
{{exact excerpt, 3 to 10 lines, line numbers as a prefix; secrets masked: sk_liv…****}}
```

**Concrete impact**
{{Who can do what, from where, with what consequences. E.g. "Any anonymous visitor can read all 2,000 invoices via GET /rest/v1/invoices with the public anon key."}}

**Proposed fix**
```diff
--- a/{{file}}
+++ b/{{file}}
@@ {{line}} @@
-{{vulnerable line}}
+{{fixed line}}
```
{{Out-of-code actions if needed: key rotation, migration to apply, dashboard setting.}}

---

## Strengths

- {{Good practice observed, with the file as evidence. E.g. "PocketBase queries are parameterized with pb.filter() (lib/data.ts:42)."}}

## Fix priorities

1. **SEC-0x**: {{concrete action}} ({{estimated effort: 5 min / 1 h / 1 day}})
2. …
3. …
4. …
5. …

## Appendices

### Commands run
```
{{detect_stack.sh, find_secrets.sh, grep_patterns.sh, dependency audit, scan_rls.sql / scan_mysql.sql}}
```

### Discarded leads (false positives)
| Location | Pattern | Reason |
|---|---|---|
| `{{file}}:{{line}}` | {{pattern}} | {{e.g. public anon key, test file, example value}} |

### Not verified
- {{What could not be checked and why: missing tool, no database access, configuration outside the repository.}}
