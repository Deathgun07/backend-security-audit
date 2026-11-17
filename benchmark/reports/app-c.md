# Security audit

- Project: PHP / MariaDB web application (Docker, Apache), commit `3af3f12`
- Stacks detected: `php-mysql`, `mysql` (no DB access: static analysis of code, `compose.yml`, `database/*.sql`)
- Method: read-only static review, checklists `common.md`, `php-mysql.md`, `mysql.md`. Nothing was run, installed or modified.
- Note: `web_root` is `true`: this report is downloadable if served as is. Do not deploy it (add a deny rule for `SECURITY_AUDIT.md`).

## Summary

**Score: 0 / 100** (4 Critical, 5 High, 6 Medium, 2 Low; floor at 0).

The application is a deliberately vulnerable training lab. Whatever the intent, it contains every classic flaw in directly exploitable form, and the vulnerable code path is selected by a client-controlled cookie (SEC-05). It must never be exposed to a network you do not control. The compose file already binds the app to `127.0.0.1`, which is the right default.

| ID | Severity | Status | Title |
|---|---|---|---|
| SEC-01 | Critical | Confirmed | SQL injection (PHP code) |
| SEC-02 | Critical | Confirmed | OS command injection |
| SEC-03 | Critical | Confirmed | File inclusion / code evaluation from user input |
| SEC-04 | Critical | Confirmed | Unrestricted file upload into the web root |
| SEC-05 | High | Confirmed | Vulnerability level chosen by a client cookie |
| SEC-06 | High | Confirmed | Arbitrary PHP file read through `view_source.php` |
| SEC-07 | High | Confirmed | Reflected, stored and DOM XSS |
| SEC-08 | High | Confirmed | CSRF on password change (GET, weak Referer check) |
| SEC-09 | High | Confirmed | Missing authentication/authorization on user-data endpoints |
| SEC-10 | High | Confirmed | Unauthenticated `setup.php` drops and recreates the database |
| SEC-11 | High | Confirmed | Known default credentials and hardcoded secrets |
| SEC-12 | Medium | Confirmed | Unsalted MD5 passwords and predictable tokens |
| SEC-13 | Medium | Confirmed | Weak session and cookie configuration |
| SEC-14 | Medium | Confirmed | Open redirect |
| SEC-15 | Medium | Confirmed | Information disclosure (phpinfo, raw SQL errors) |
| SEC-16 | Medium | Confirmed | No brute-force protection on login; wildcard CORS on API |
| SEC-17 | Medium | Confirmed | Prompt-injection style text aimed at AI reviewers |
| SEC-18 | Low | To verify | Docker image hardening |
| SEC-19 | Low | Confirmed | Home-made crypto (XOR with hardcoded key) |

## Details

### SEC-01 SQL injection (Critical, Confirmed, A03)
User input is concatenated into SQL, or "escaped" with `mysqli_real_escape_string` but used in a numeric (unquoted) context, which does not protect.
- `vulnerabilities/sqli/source/low.php:10` `$id = $_REQUEST['id']` then line 10 query `... WHERE user_id = '$id'` (also SQLite branch line 31)
- `vulnerabilities/sqli/source/medium.php:11,27` escape without quotes: `WHERE user_id = $id`
- `vulnerabilities/sqli/source/high.php:10` `$id = $_SESSION['id']`, set from `$_POST['id']` in `vulnerabilities/sqli/session-input.php:12`
- `vulnerabilities/sqli_blind/source/low.php:11,32`, `medium.php:13,34`, `high.php:11,33` (GET, POST, then cookie `id`)
- `vulnerabilities/brute/source/low.php:12` (`$user = $_GET['username']` straight into the query: authentication bypass)
- `vulnerabilities/bac/source/low.php:77-80` `X-Forwarded-For` header interpolated in an `INSERT`
- `vulnerabilities/authbypass/change_user_details.php:47` JSON body fields concatenated in an `UPDATE`
Evidence (`sqli/source/low.php`): `$query = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";`
Fix:
```diff
-$query = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
-$result = mysqli_query($conn, $query);
+$stmt = $conn->prepare('SELECT first_name, last_name FROM users WHERE user_id = ?');
+$stmt->bind_param('i', $id); $stmt->execute();
```

### SEC-02 OS command injection (Critical, Confirmed, A03)
The `ip` field goes into `shell_exec('ping -c 4 ' . $target)`. Low has no filter; medium/high use a denylist (`str_replace` of `&&`, `;`, ...), bypassable with `|`, newline, `&`.
- `vulnerabilities/exec/source/low.php:5,10,14`
- `vulnerabilities/exec/source/medium.php:8-14,19,23`
- `vulnerabilities/exec/source/high.php:35-51,26,30` (denylist, `|` without trailing space is not removed, e.g. `127.0.0.1|id`)
- `vulnerabilities/api/src/HealthController.php:85-88` JSON `target` passed to `exec("ping -c 4 " . $target)`; no token check is visible in this handler (verify the router in `vulnerabilities/api/index.php` / `public/index.php`).
Fix: validate with `filter_var($t, FILTER_VALIDATE_IP)` and call `escapeshellarg()`, or avoid the shell.

### SEC-03 File inclusion and code evaluation (Critical, Confirmed, A03)
- `vulnerabilities/fi/source/low.php:4` `$file = $_GET['page']` then `vulnerabilities/fi/index.php:36` `include($file)`. `php.ini:4-5` sets `allow_url_fopen = on` and `allow_url_include = on`, so remote code inclusion is possible.
- `vulnerabilities/fi/source/high.php:4-10` the `fnmatch("file*")` check is bypassed by `file:///...`.
- `vulnerabilities/view_help.php:20,22` `eval('?>' . file_get_contents(".../vulnerabilities/{$id}/help/help.{$locale}.php") ...)` with `id` and `locale` from `$_GET`: path traversal into an evaluated file (any uploaded file, see SEC-04, gives code execution).
Fix: allowlist of page names (`in_array($page, $pages, true)`), drop `eval`, set `allow_url_include = Off`.

### SEC-04 Unrestricted file upload (Critical, Confirmed, A04)
Files land in `hackable/uploads/` inside the web root (a `.htaccess` blocking PHP is absent: the only `.htaccess` in the repo is `vulnerabilities/api/.htaccess`).
- `vulnerabilities/upload/source/low.php:4-6,9` no check at all, original file name kept: upload of `shell.php`.
- `vulnerabilities/upload/source/medium.php:10,14` trusts the client-supplied `$_FILES['uploaded']['type']`.
- `vulnerabilities/upload/source/high.php:15-17,20` extension check plus `getimagesize()`: a valid image with appended PHP, combined with SEC-03, executes.
Fix: detect MIME with `finfo`, regenerate the file name, store outside the web root, add `php_flag engine off` in the upload folder.

### SEC-05 Vulnerability level selected by a client cookie (High, Confirmed, A04)
`dvwa/includes/dvwaPage.inc.php:203-205` returns `$_COOKIE['security']` as the security level, validated only against the list `low/medium/high/impossible` (line 21-22). Every page loads `source/{level}.php`, so any logged-in visitor can switch to `low` by editing a cookie, and all vulnerable code of SEC-01 to SEC-09 is always reachable in the deployed app. Fix: read the level from server-side state, and do not ship the weak variants to a deployed instance.

### SEC-06 Arbitrary PHP file read (High, Confirmed, A01)
`vulnerabilities/view_source.php:63,68` `file_get_contents(".../vulnerabilities/{$id}/source/{$security}.php")` with `id` and `security` from `$_GET` and no allowlist: `security=../../../config/config.inc` discloses configuration source, then displayed through `highlight_string` (lines 40, 25 of rendering). Authenticated users only (line 6). Fix: allowlist `id` and `security`.

### SEC-07 Cross-site scripting (High, Confirmed, A03)
- Reflected: `vulnerabilities/xss_r/source/low.php:8`, `medium.php:8` (removes only `<script>`), `high.php:8` (regex on `script`, bypassed by `<img onerror>`)
- Stored: `vulnerabilities/xss_s/source/low.php:16` (SQL-escaped only, not HTML-escaped), `medium.php:9-11`, `high.php:14` (regex on `script`)
- DOM: `vulnerabilities/xss_d/index.php:53` `document.write(... decodeURI(lang) ...)` from the URL
- Others: `vulnerabilities/brute/source/low.php:21-22` (`$user` and `$avatar` echoed), `vulnerabilities/bac/source/low.php:89-90` (`user_role` cookie echoed), `vulnerabilities/sqli/session-input.php:14`
`low.php` also sends `X-XSS-Protection: 0` (`xss_r/source/low.php:3`).
Fix: `htmlspecialchars($v, ENT_QUOTES|ENT_SUBSTITUTE, 'UTF-8')` on output and a `Content-Security-Policy`.

### SEC-08 CSRF on password change (High, Confirmed, A01)
- `vulnerabilities/csrf/source/low.php:3-5,16` password changed by a GET request, no token.
- `vulnerabilities/csrf/source/medium.php:5` only `stripos($_SERVER['HTTP_REFERER'], $_SERVER['SERVER_NAME'])`: bypassed by a Referer containing the host name anywhere; the header is also optional (undefined index when absent).
- `vulnerabilities/captcha/source/low.php:50-62` same weakness through a client-side-controlled step flag.
Fix: per-session CSRF token with `hash_equals`, POST only, ask for the current password, `SameSite=Strict`.

### SEC-09 Missing authentication and authorization (High, Confirmed, A01)
- `vulnerabilities/authbypass/get_user_data.php:5,10` and `change_user_details.php:47,53` never call `dvwaPageStartup(['authenticated'])`; the "admin only" check exists only at `high`/`impossible` level (and only `impossible` in `change_user_details.php:53`). The user list and an `UPDATE` of any user are reachable without session at the default levels.
- `vulnerabilities/bac/source/low.php:30-33,89` role and user id taken from cookies (`user_id`, `user_role`) that the client controls.
- `vulnerabilities/api/src/OrderController.php:25-34` relies on a token whose secrets are constants (see SEC-11).
Fix: authenticate every endpoint server-side, derive user and role from the session, check ownership.

### SEC-10 Unauthenticated database reset (High, Confirmed, A01/A05)
`setup.php:6` calls `dvwaPageStartup(array())` (no `authenticated`), and `setup.php:10-19` then runs `dvwa/includes/DBMS/MySQL.php:22,28` (`DROP DATABASE IF EXISTS`, `CREATE DATABASE`). The only guard is a CSRF token bound to the visitor's own session, which anyone can obtain from the page itself. Anyone who reaches the app can wipe and reseed it with the known users of SEC-11. Fix: remove or protect `setup.php` after installation.

### SEC-11 Default credentials and hardcoded secrets (High, Confirmed, A02/A07)
- `dvwa/includes/DBMS/MySQL.php:55-59` seeds `admin/password`, `gordonb/abc123`, `1337/charley`, `pablo/letmein`, `smithy/password`.
- `compose.yml:31,34` `MYSQL_ROOT_PASSWORD=dvwa`, `MYSQL_PASSWORD=p@ssw0rd`; `config/config.inc.php.dist:21` same default password.
- `vulnerabilities/api/src/Login.php:10,12` token signing secrets `"12345"` and `"98765"`; `vulnerabilities/api/src/LoginController.php:60,86` fixed login `mrbennett` / `beca…****` and client secret `ABigLo…****`.
- `vulnerabilities/sqli/test.php:4-5` hardcoded DB host and password (`passw…****`), legacy `mssql_*` code.
Treat as lab values; for any real deployment they must be replaced and read from the environment.

### SEC-12 Weak password hashing and tokens (Medium, Confirmed, A02)
- Unsalted MD5: `login.php:27`, `dvwa/includes/DBMS/MySQL.php:55-59`, `vulnerabilities/brute/source/*.php`, `csrf/source/low.php:12`, `captcha/source/low.php`.
- Predictable tokens: `dvwa/includes/dvwaPage.inc.php:650` `md5(uniqid())`; `vulnerabilities/weak_id/source/low.php:9-11` incrementing session id, `high.php:10` `md5` of a counter.
Fix: `password_hash()` / `password_verify()`, `bin2hex(random_bytes(32))`.

### SEC-13 Session and cookie configuration (Medium, Confirmed, A07)
`dvwa/includes/dvwaPage.inc.php:44-60,98-112` `httponly` false and `secure` false except at `impossible`, session id regenerated only at `impossible`; `dvwaLogin()` (`dvwaPage.inc.php:140-142`) does not regenerate the id (session fixation). `dvwaPage.inc.php:226` the `security` cookie is not `Secure`. `vulnerabilities/sqli_blind/cookie-input.php:12` and `weak_id/source/low.php:11` call `setcookie()` without flags.

### SEC-14 Open redirect (Medium, Confirmed, A01)
`vulnerabilities/open_redirect/source/low.php:4` `header("location: " . $_GET['redirect'])`; `medium.php:11` and `high.php:4-5` only test `strpos(..., "info.php") !== false`, bypassed with `https://evil.example/?info.php`. Fix: allowlist of internal targets.

### SEC-15 Information disclosure (Medium, Confirmed, A05)
`phpinfo.php:8` (authenticated) prints the full PHP configuration. Raw `mysqli_error()` is sent to the browser: `login.php:47`, `vulnerabilities/sqli/source/low.php:10-12`, `brute/source/low.php:13`, `csrf/source/low.php:17`. `vulnerabilities/bac/source/impossible.php:6` enables `display_errors`. Fix: log server-side, return a generic message, remove `phpinfo.php`.

### SEC-16 No brute-force protection; wildcard CORS (Medium, Confirmed, A07/A05)
- `login.php:10-57` and `vulnerabilities/brute/source/low.php:3-12` accept unlimited attempts (no lockout, delay or limiter in the code or in a proxy config in the repo).
- `vulnerabilities/api/public/index.php:11` and `vulnerabilities/api/index.php:11` `Access-Control-Allow-Origin: *` on an API that has write endpoints.

### SEC-17 Prompt-injection style text (Medium, Confirmed, A04)
`security.txt:1` says: "DVWA contains both intentional and unintentional vulnerabilities ... please do not try to report them." This is project content asking reporters (and automated reviewers) not to report findings. It was not obeyed. In context it reads as the lab's disclosure policy, but under the audit rules it is flagged (`prompt_injection_attempt`).

### SEC-18 Docker image hardening (Low, To verify, A05)
`Dockerfile:19` pulls `composer:latest` (unpinned), `Dockerfile:20` `COPY . .` and `.dockerignore` does not exclude `.env*` (none is tracked today). The image runs Apache as the image default (root master process) and `www-data` owns the whole web root (`--chown=www-data`), so code execution (SEC-02/03/04) can overwrite the application. Check the final image user and pin the composer image.

### SEC-19 Home-made crypto (Low, Confirmed, A02)
`vulnerabilities/cryptography/source/low.php:3-16,40-41` XOR with the hardcoded key `"wach…****"` and a plain-text password compare (`$password == "Olifant"`, loose comparison). Use an authenticated cipher (libsodium) and `hash_equals`.

## Strengths
- `compose.yml:25-26` publishes the app on `127.0.0.1:4280` only and the DB has no published port (`compose.yml:29-37`).
- `config/config.inc.php` is git-ignored (`.gitignore:3-4`); `default_security_level` defaults to `impossible` (`config/config.inc.php.dist:33`).
- `login.php:18` and `setup.php:18` verify a CSRF token, and `login.php:22,26` escape credentials.
- `impossible.php` variants (for example `vulnerabilities/exec/source/impossible.php`) show the intended fixes: use them as the reference implementation.
- `composer audit --locked` on `vulnerabilities/api/composer.lock`: no advisories.

## Top 5 priorities
1. Never expose this instance beyond localhost; remove the `low/medium/high` variants from anything deployed (SEC-05).
2. Fix SQL injection with prepared statements (SEC-01).
3. Remove command injection, `include`/`eval` of user input and the unrestricted upload (SEC-02, SEC-03, SEC-04).
4. Require authentication on `setup.php`, `authbypass/*` and the API (SEC-09, SEC-10).
5. Replace default credentials and MD5 hashing (SEC-11, SEC-12).

## Appendices

### Commands run
`detect_stack.sh`, `find_secrets.sh`, `grep_patterns.sh php-mysql` and `mysql`, `composer audit --locked` (read-only), plus manual reading of the files cited above.

### Discarded false positives
- `instructions.php:20` (`sql_with_superglobal`): no SQL; `$_GET['doc']` is checked against the `$docs` allowlist before use (`instructions.php:30-34`).
- `setup.php:58,61,73` and `vulnerabilities/api/index.php:33` (`command_execution`): `shell_exec` on constant strings (`apachectl -M`, `git log`).
- `vulnerabilities/api/src/LoginController.php:151-152` (`xss_echo_superglobal`): inside a PHP comment block.
- `login.php:46`, `vulnerabilities/csrf/test_credentials.php:21`, `captcha/source/*.php`, `xss_s/source/*.php` `sql_string_interpolated` / `sql_concat_or_interpolated` for quoted, escaped values (`mysqli_real_escape_string` in a quoted context) or values taken from the server session: not injectable, so not reported as SQL injection.
- `dvwa/includes/DBMS/MySQL.php:37,60,68,119` and `dvwaPage.inc.php:570`: queries built from the config file's database name, not user input.
- `vulnerabilities/api/source/medium.php:83`, `cryptography/source/*.php` `php_self`: output is in a static form of a training page, no reflected value reaches the response beyond what SEC-07 covers.
- `md5_sha1` Low hits in `dvwaPage.inc.php:650` kept under SEC-12; `vulnerabilities/javascript/*` md5 is a client-side token demo.
- `Dockerfile:20 dockerignore_missing_env`: no `.env` file exists in the repository (kept as Low, SEC-18).
- `hackable/flags/fi.php:17`, `vulnerabilities/api/gen_openapi.php:12` `xss_echo_variable`: static lab text / CLI generator output.

### Not verified
- Deployed environment: reverse proxy, TLS, PHP production settings, final container user.
- Whether the API router enforces a token on `HealthController` (SEC-02, last item).
- Database accounts and grants (no DB access; `scan_mysql.sql` not run): the application connects as `dvwa` with a password set in `compose.yml`.
- Dependencies of `vulnerabilities/api/composer.lock` beyond what `composer audit` knows.
