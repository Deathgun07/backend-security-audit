# app-b = OWASP NodeGoat @ c5cb68a — ground truth from its OWASP tutorial and "Fix for …" comments
| ID | Vulnerability | Location |
|---|---|---|
| B1 | Server-side JS injection via eval() | app/routes/contributions.js:32-34 |
| B2 | NoSQL injection ($where with user input) | app/data/allocations-dao.js:78 |
| B3 | Log injection (CRLF) | app/routes/session.js:64 |
| B4 | Passwords stored in plain text | app/data/user-dao.js:25 |
| B5 | User enumeration (distinct login errors) | app/routes/session.js:60-61 |
| B6 | Weak password policy | app/routes/session.js:144 |
| B7 | Session fixation (no session regeneration on login) | app/routes/session.js:117 |
| B8 | XSS: template autoescape disabled | server.js:137 |
| B9 | IDOR: allocations by userId from the URL | app/routes/allocations.js, app/routes/index.js:63 |
| B10 | Security misconfiguration: no security headers (helmet disabled), session cookie without httpOnly/secure | server.js:10, server.js:95 |
| B11 | Sensitive data (SSN, DOB) stored unencrypted | app/data/profile-dao.js:61 |
| B12 | No TLS (plain HTTP server) | server.js:145 |
| B13 | Missing function-level access control (/benefits without isAdmin) | app/routes/index.js:57-58 |
| B14 | No CSRF protection | server.js:7, server.js:106 |
| B15 | Vulnerable component (marked 0.3.5, memos rendered unsanitized) | package.json:17 |
| B16 | Open redirect (/learn?url=) | app/routes/index.js:73 |
| B17 | SSRF (research url + symbol) | app/routes/research.js:15-16 |
| B18 | ReDoS (bank routing regex) | app/routes/profile.js:59 |
