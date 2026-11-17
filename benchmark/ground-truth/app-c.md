# app-c = DVWA @ 502ac15 — ground truth: each server-side module's `source/low.php` is vulnerable, `source/impossible.php` is the secure version
Excluded (browser-only): csp, javascript, xss_d.
| ID | Module (low.php) | Vulnerability |
|---|---|---|
| C1 | api | API versioning / broken object exposure (old API version leaks data) |
| C2 | authbypass | Authorization bypass (admin page / API not enforcing role) |
| C3 | bac | Broken access control |
| C4 | brute | Brute force (no rate limit) + SQL built from user input |
| C5 | captcha | Insecure CAPTCHA (step bypass, client-controlled state) |
| C6 | cryptography | Weak cryptography |
| C7 | csrf | CSRF on password change |
| C8 | exec | OS command injection |
| C9 | fi | File inclusion (LFI/RFI) |
| C10 | open_redirect | Open redirect |
| C11 | sqli | SQL injection |
| C12 | sqli_blind | Blind SQL injection |
| C13 | upload | Unrestricted file upload |
| C14 | weak_id | Predictable session ID |
| C15 | xss_r | Reflected XSS |
| C16 | xss_s | Stored XSS |
False-positive check: findings reported in `source/impossible.php` of these 16 modules.
