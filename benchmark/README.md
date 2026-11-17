# Benchmark

How well does `backend-security-audit` find **known** vulnerabilities, and how many false alarms does it raise? We ran it on three well-known intentionally vulnerable applications and on one small Supabase app we wrote, then compared each report with the list of vulnerabilities documented by the application itself.

**Measured on 2026-11-17 with skill v2.2.0 (pre-release), Claude Sonnet as the assistant, one run per application.**

## Results

| Application | Stack | Known vulnerabilities (backend) | Found | Missed | False positives | Extra valid findings¹ |
|---|---|---|---|---|---|---|
| [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) `266448a` | Node.js / Express / TypeScript | 15 | **11** | 4 | 1 | 10+ |
| [OWASP NodeGoat](https://github.com/OWASP/NodeGoat) `c5cb68a` | Node.js / Express / MongoDB | 18 | **16** | 2 | 0 | 4 |
| [DVWA](https://github.com/digininja/DVWA) `502ac15` | PHP / MySQL | 16 | **15** | 1 | 1² | 5 |
| Supabase shop (ours, [source](apps/supabase-shop)) | Next.js / Supabase | 9 | **9** | 0 | 0 | 3 |
| **Total** | | **58** | **51 (88 %)** | **7** | **2 of 73 findings (2.7 %)** | |

¹ Real vulnerabilities reported by the tool that are not in the application's own list (e.g. XXE, zip slip, SSRF and a hardcoded RSA key in Juice Shop, which does not annotate all of its flaws).
² Caused by a bug in the new `prompt_injection_attempt` pattern (`ai` matched inside "cont**ai**ns"). Fixed before release, with a regression test.

### What was missed

| Application | Missed vulnerability | Follow-up |
|---|---|---|
| Juice Shop | Passkey signature not verified (`routes/passkey.ts:222`) | WebAuthn/passkey check added to `checklists/node-express.md` |
| Juice Shop | Passkey credential overwrite (`routes/passkey.ts:142`) | same |
| Juice Shop | Chatbot lets the LLM choose the coupon discount, no server-side bound (`routes/chat.ts:180-185`) | "LLM features" check added to `checklists/common.md` |
| Juice Shop | `/metrics` exposed without authentication (`server.ts:771`) | added to `checklists/node-express.md` |
| NodeGoat | Log injection / CRLF (`app/routes/session.js:64`) | added to `checklists/common.md` |
| NodeGoat | Plain HTTP server, no TLS (`server.js:145`) | added to `checklists/node-express.md` |
| DVWA | Old API version (v1) still routed and leaking user data (`vulnerabilities/api`) | "old API versions" check added to `checklists/common.md` |

The numbers above were measured **before** these checklist additions.

### False positives

| Application | Finding | Why it is a false positive |
|---|---|---|
| Juice Shop | `prompt_injection_attempt` (Medium) on `AGENTS.md` | A genuine maintainers' policy asking AI agents not to send unsolicited bug-hunting PRs. The assistant correctly did **not** obey it, but should have reported it as Info. `SKILL.md` now reserves Medium for text that tries to suppress findings, change the score or trigger actions. |
| DVWA | `prompt_injection_attempt` (Medium) on `security.txt` | Pattern bug, see ² above. |

## Method

1. **Pinned versions.** Each application is cloned at the commit shown in the table.
2. **Ground truth from the applications themselves**, never from the tool's output ([ground-truth/](ground-truth)):
   - Juice Shop: the lines annotated `vuln-code-snippet vuln-line` (server side only; 7 frontend-only coding challenges excluded), grouped by root cause (e.g. the 3 login SQL injection challenges count as one).
   - NodeGoat: the vulnerabilities of its OWASP Top 10 tutorial and its `Fix for …` comments.
   - DVWA: each server-side module's `source/low.php` is vulnerable; `source/impossible.php` is the secure version used to count false positives (`csp`, `javascript`, `xss_d` excluded: browser-only).
   - Supabase shop: written by us with 9 seeded vulnerabilities and 6 secure parts. **Not independent**: read it as a sanity check, not as evidence.
3. **Blinded copies** ([tools/prepare.py](tools/prepare.py)): annotations, "Fix for" comments, tutorials, help pages and exploit tests are removed, and Juice Shop's challenge identifiers are renamed (`challenges.loginAdminChallenge` → `challenges.ch_63`), so the code does not give the answers away. Line numbers are preserved, and a line-by-line check confirms that only comments and identifiers changed.
4. **Audit.** A fresh Claude Sonnet agent ran the skill on each copy with the same neutral prompt ("Audit the security of this project using the backend-security-audit skill"), without knowing the ground truth. Raw reports: [reports/](reports).
5. **Scoring** by hand: a known vulnerability counts as found when a finding points to the same location and describes the same flaw (a finding about the same file but a different flaw does not count). A false positive is a reported finding that is not a real vulnerability.

## Limits

- **These applications are famous.** The model may know them from training, which can only help it. DVWA's name and module names (`sqli`, `exec`…) cannot be hidden. The Supabase app is unknown to the model but written by us.
- **One run per application.** LLM output varies between runs; expect a few points of difference.
- **Manual matching.** Ambiguous cases are listed in the reports and in this page, so anyone can recount.
- Ground truths list what each project documents, not every vulnerability it contains: "extra valid findings" are real issues outside those lists.

## Reproduce

```bash
git clone https://github.com/juice-shop/juice-shop.git src/juice-shop && git -C src/juice-shop checkout 266448a
git clone https://github.com/OWASP/NodeGoat.git    src/NodeGoat    && git -C src/NodeGoat checkout c5cb68a
git clone https://github.com/digininja/DVWA.git    src/DVWA        && git -C src/DVWA checkout 502ac15
python3 -I benchmark/tools/prepare.py src out      # → out/app-a (Juice Shop), out/app-b (NodeGoat), out/app-c (DVWA)
cp -r benchmark/apps/supabase-shop out/app-d
# then, in your assistant, for each out/app-*: "Audit the security of this project using the backend-security-audit skill"
```
Never deploy these applications: they are vulnerable on purpose. The audit only reads their code.
