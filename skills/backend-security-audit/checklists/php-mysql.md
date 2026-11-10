# PHP / MySQL checklist

Files to read first: `config*.php`, `db*.php`, `connexion*.php`, `login*.php`, `register*.php`, `upload*.php`, `admin/`, `.htaccess`, `php.ini`, `index.php` (router).

## P1. SQL injection — Critical (A03)
Concatenation or interpolation of variables in the query, even "already filtered" ones (`addslashes`, `mysqli_real_escape_string` without quotes, forgotten `intval`).
```php
// ❌
$id = $_GET['id'];
$res = mysqli_query($conn, "SELECT * FROM users WHERE id = $id");
$res = $pdo->query("SELECT * FROM users WHERE email = '" . $_POST['email'] . "'");
// ✅ PDO
$stmt = $pdo->prepare('SELECT * FROM users WHERE email = ?');
$stmt->execute([$_POST['email']]);
// ✅ mysqli
$stmt = $conn->prepare('SELECT * FROM users WHERE id = ?');
$stmt->bind_param('i', $_GET['id']); $stmt->execute();
```
- `prepare()` with an interpolated variable inside = always vulnerable.
- Dynamic column names / `ORDER BY`: allowlist (`in_array($col, ['nom','date'], true)`).
- Check `PDO::ATTR_EMULATE_PREPARES => false` and `charset=utf8mb4` in the DSN.
- **Evidence**: trace the variable back to its source (`$_GET`, `$_POST`, `$_COOKIE`, `$_SERVER['HTTP_*']`).

## P2. XSS — High (A03)
```php
// ❌
echo "Hello " . $_GET['nom'];
<?= $commentaire['texte'] ?>
// ✅
function e(string $s): string { return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
echo 'Hello ' . e($_GET['nom']);
<?= e($commentaire['texte']) ?>
```
- Stored XSS (DB data displayed) = High; reflected = Medium to High.
- `$_SERVER['PHP_SELF']` in `action=""` without escaping = reflected XSS.
- JS / attribute contexts: `json_encode($v, JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_QUOT|JSON_HEX_AMP)`.

## P3. CSRF — Medium to High (A01)
POST forms that change state (password, deletion, payment, admin) without a token.
```php
// ✅ generation
if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(32));
echo '<input type="hidden" name="csrf" value="' . e($_SESSION['csrf']) . '">';
// ✅ verification
if (!hash_equals($_SESSION['csrf'] ?? '', $_POST['csrf'] ?? '')) { http_response_code(403); exit; }
```
- Sensitive actions via GET (`supprimer.php?id=3`) = High.
- `SameSite=Lax` reduces the risk but does not replace the token.

## P4. Sessions — Medium (A07)
```php
// ❌ login without regeneration → session fixation
$_SESSION['user_id'] = $user['id'];
// ✅
session_set_cookie_params(['httponly' => true, 'secure' => true, 'samesite' => 'Lax']);
session_start();
// ... after verifying the password:
session_regenerate_id(true);
$_SESSION['user_id'] = $user['id'];
```
- Logout: `session_unset(); session_destroy();` + cookie deletion.
- `session.use_strict_mode = 1`, `session.use_only_cookies = 1`.
- Role stored in a cookie (`$_COOKIE['role'] == 'admin'`) = Critical.

## P5. File upload — High to Critical (A04)
```php
// ❌
move_uploaded_file($_FILES['f']['tmp_name'], 'uploads/' . $_FILES['f']['name']);
// ✅
$finfo = new finfo(FILEINFO_MIME_TYPE);
$mime  = $finfo->file($_FILES['f']['tmp_name']);           // not $_FILES['f']['type'] (client-supplied)
$ext   = ['image/jpeg' => 'jpg', 'image/png' => 'png', 'application/pdf' => 'pdf'][$mime] ?? null;
if (!$ext || $_FILES['f']['size'] > 5_000_000) { http_response_code(400); exit; }
$nom = bin2hex(random_bytes(16)) . '.' . $ext;             // regenerated name
move_uploaded_file($_FILES['f']['tmp_name'], __DIR__ . '/../storage/' . $nom); // outside webroot
```
- Upload folder in the webroot without a `.htaccess` blocking PHP → upload of `shell.php` = Critical.
```apache
# uploads/.htaccess
php_flag engine off
<FilesMatch "\.(php|phtml|phar|php\d)$">
  Require all denied
</FilesMatch>
```
- Extension denylist (`!= 'php'`) bypassable (`.phtml`, `.php5`, `.PhP`, double extension).

## P6. include/require with user input — Critical (A03)
```php
// ❌
include $_GET['page'] . '.php';             // ../../etc/passwd%00, php://filter, ...
// ✅
$pages = ['accueil', 'contact', 'produits'];
$page = in_array($_GET['page'] ?? '', $pages, true) ? $_GET['page'] : 'accueil';
include __DIR__ . "/pages/$page.php";
```
- Same for `file_get_contents`, `readfile`, `fopen` with a user path → arbitrary file read.

## P7. Passwords in md5/sha1 — High (A02)
```php
// ❌
$hash = md5($_POST['password']);
if (sha1($pwd) === $row['password']) ...
// ✅
$hash = password_hash($_POST['password'], PASSWORD_DEFAULT);
if (password_verify($_POST['password'], $row['password'])) { /* + password_needs_rehash */ }
```
- `==` comparison between hashes ("magic hashes" `0e...`) → use `hash_equals` or `password_verify`.

## P8. Hardcoded DB credentials — High (A02)
```php
// ❌ committed config.php
$pdo = new PDO('mysql:host=localhost;dbname=app', 'root', 'MyPassword');
// ✅
$pdo = new PDO($_ENV['DB_DSN'], $_ENV['DB_USER'], $_ENV['DB_PASS'], [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
```
- `root` without a password locally: Low; real production password in the repo: Critical.
- Application DB user = `root` / all privileges → Medium.

## P9. `display_errors` enabled — Medium (A05)
`ini_set('display_errors', 1)` or `display_errors = On` outside a dev environment: leaks paths, SQL queries, credentials.
```php
// ✅
ini_set('display_errors', '0'); ini_set('log_errors', '1');
```
- `die(mysqli_error($conn))` / `echo $e->getMessage()` on a PDO exception → same problem.

## P10. Code / command execution — Critical (A03)
`eval`, `assert` (PHP < 8), `system`, `exec`, `shell_exec`, `passthru`, backticks, `preg_replace` with `/e`: user input → RCE. Fix: remove, or `escapeshellarg` + allowlist.

## P11. Deserialization — Critical (A08)
`unserialize($_COOKIE[...])` → object injection. Use `json_decode`.

## P12. `extract($_POST)` / emulated register_globals — High (A01)
Overwrites `$is_admin`, `$user_id`… Remove and read the fields explicitly.

## P13. Access control — High (A01)
`admin/*.php` pages without a session check at the top; `header('Location: login.php')` **without `exit;`** afterwards → the rest of the page still executes.
```php
// ❌
if (!isset($_SESSION['admin'])) header('Location: login.php');
// ✅
if (empty($_SESSION['admin'])) { header('Location: login.php'); exit; }
```

## P14. Open redirect and headers — Low to Medium
`header('Location: ' . $_GET['url'])`; missing `X-Frame-Options`, `X-Content-Type-Options`; `expose_php = On`.

## P15. Exposed files — Medium to High (A05)
Accessible `phpinfo()`, `.git/` served by Apache, backups `*.sql`, `*.bak`, `config.php~` in the webroot, accessible `composer.json`/`vendor/`.
