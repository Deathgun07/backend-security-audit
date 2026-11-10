# Checklist PHP / MySQL

Fichiers à lire en priorité : `config*.php`, `db*.php`, `connexion*.php`, `login*.php`, `register*.php`, `upload*.php`, `admin/`, `.htaccess`, `php.ini`, `index.php` (routeur).

## P1. Injection SQL — Critique (A03)
Concaténation ou interpolation de variables dans la requête, même « déjà filtrées » (`addslashes`, `mysqli_real_escape_string` sans quotes, `intval` oublié).
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
- `prepare()` avec variable interpolée dedans = toujours vulnérable.
- Noms de colonnes / `ORDER BY` dynamiques : liste blanche (`in_array($col, ['nom','date'], true)`).
- Vérifier `PDO::ATTR_EMULATE_PREPARES => false` et `charset=utf8mb4` dans le DSN.
- **Preuve** : remonter la variable jusqu'à sa source (`$_GET`, `$_POST`, `$_COOKIE`, `$_SERVER['HTTP_*']`).

## P2. XSS — Haute (A03)
```php
// ❌
echo "Bonjour " . $_GET['nom'];
<?= $commentaire['texte'] ?>
// ✅
function e(string $s): string { return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
echo 'Bonjour ' . e($_GET['nom']);
<?= e($commentaire['texte']) ?>
```
- XSS stocké (donnée BDD affichée) = Haute ; réfléchi = Moyenne à Haute.
- `$_SERVER['PHP_SELF']` dans `action=""` sans échappement = XSS réfléchi.
- Contextes JS / attribut : `json_encode($v, JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_QUOT|JSON_HEX_AMP)`.

## P3. CSRF — Moyenne à Haute (A01)
Formulaires POST qui modifient l'état (mot de passe, suppression, paiement, admin) sans jeton.
```php
// ✅ génération
if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(32));
echo '<input type="hidden" name="csrf" value="' . e($_SESSION['csrf']) . '">';
// ✅ vérification
if (!hash_equals($_SESSION['csrf'] ?? '', $_POST['csrf'] ?? '')) { http_response_code(403); exit; }
```
- Actions sensibles en GET (`supprimer.php?id=3`) = Haute.
- `SameSite=Lax` réduit le risque mais ne remplace pas le jeton.

## P4. Sessions — Moyenne (A07)
```php
// ❌ login sans régénération → fixation de session
$_SESSION['user_id'] = $user['id'];
// ✅
session_set_cookie_params(['httponly' => true, 'secure' => true, 'samesite' => 'Lax']);
session_start();
// ... après vérification du mot de passe :
session_regenerate_id(true);
$_SESSION['user_id'] = $user['id'];
```
- Logout : `session_unset(); session_destroy();` + suppression du cookie.
- `session.use_strict_mode = 1`, `session.use_only_cookies = 1`.
- Rôle stocké dans un cookie (`$_COOKIE['role'] == 'admin'`) = Critique.

## P5. Upload de fichiers — Haute à Critique (A04)
```php
// ❌
move_uploaded_file($_FILES['f']['tmp_name'], 'uploads/' . $_FILES['f']['name']);
// ✅
$finfo = new finfo(FILEINFO_MIME_TYPE);
$mime  = $finfo->file($_FILES['f']['tmp_name']);           // pas $_FILES['f']['type'] (fourni par le client)
$ext   = ['image/jpeg' => 'jpg', 'image/png' => 'png', 'application/pdf' => 'pdf'][$mime] ?? null;
if (!$ext || $_FILES['f']['size'] > 5_000_000) { http_response_code(400); exit; }
$nom = bin2hex(random_bytes(16)) . '.' . $ext;             // nom régénéré
move_uploaded_file($_FILES['f']['tmp_name'], __DIR__ . '/../storage/' . $nom); // hors webroot
```
- Dossier d'upload dans le webroot sans `.htaccess` bloquant PHP → upload de `shell.php` = Critique.
```apache
# uploads/.htaccess
php_flag engine off
<FilesMatch "\.(php|phtml|phar|php\d)$">
  Require all denied
</FilesMatch>
```
- Liste noire d'extensions (`!= 'php'`) contournable (`.phtml`, `.php5`, `.PhP`, double extension).

## P6. include/require avec entrée utilisateur — Critique (A03)
```php
// ❌
include $_GET['page'] . '.php';             // ../../etc/passwd%00, php://filter, ...
// ✅
$pages = ['accueil', 'contact', 'produits'];
$page = in_array($_GET['page'] ?? '', $pages, true) ? $_GET['page'] : 'accueil';
include __DIR__ . "/pages/$page.php";
```
- Idem `file_get_contents`, `readfile`, `fopen` avec chemin utilisateur → lecture de fichiers arbitraires.

## P7. Mots de passe en md5/sha1 — Haute (A02)
```php
// ❌
$hash = md5($_POST['password']);
if (sha1($pwd) === $row['password']) ...
// ✅
$hash = password_hash($_POST['password'], PASSWORD_DEFAULT);
if (password_verify($_POST['password'], $row['password'])) { /* + password_needs_rehash */ }
```
- Comparaison `==` entre hash (« magic hashes » `0e...`) → utiliser `hash_equals` ou `password_verify`.

## P8. Identifiants BDD en dur — Haute (A02)
```php
// ❌ config.php commité
$pdo = new PDO('mysql:host=localhost;dbname=app', 'root', 'MonMotDePasse');
// ✅
$pdo = new PDO($_ENV['DB_DSN'], $_ENV['DB_USER'], $_ENV['DB_PASS'], [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
```
- `root` sans mot de passe en local : Basse ; vrai mot de passe de prod dans le dépôt : Critique.
- Utilisateur BDD de l'application = `root` / tous privilèges → Moyenne.

## P9. `display_errors` actif — Moyenne (A05)
`ini_set('display_errors', 1)` ou `display_errors = On` hors environnement de dev : fuite de chemins, requêtes SQL, identifiants.
```php
// ✅
ini_set('display_errors', '0'); ini_set('log_errors', '1');
```
- `die(mysqli_error($conn))` / `echo $e->getMessage()` sur une exception PDO → même problème.

## P10. Exécution de code / commandes — Critique (A03)
`eval`, `assert` (PHP < 8), `system`, `exec`, `shell_exec`, `passthru`, backticks, `preg_replace` avec `/e` : entrée utilisateur → RCE. Correctif : supprimer ou `escapeshellarg` + liste blanche.

## P11. Désérialisation — Critique (A08)
`unserialize($_COOKIE[...])` → injection d'objets. Utiliser `json_decode`.

## P12. `extract($_POST)` / register_globals simulés — Haute (A01)
Écrase `$is_admin`, `$user_id`… Supprimer et lire explicitement les champs.

## P13. Contrôle d'accès — Haute (A01)
Pages `admin/*.php` sans vérification de session en tête ; `header('Location: login.php')` **sans `exit;`** après → le reste de la page s'exécute quand même.
```php
// ❌
if (!isset($_SESSION['admin'])) header('Location: login.php');
// ✅
if (empty($_SESSION['admin'])) { header('Location: login.php'); exit; }
```

## P14. Redirection ouverte et en-têtes — Basse à Moyenne
`header('Location: ' . $_GET['url'])` ; absence de `X-Frame-Options`, `X-Content-Type-Options` ; `expose_php = On`.

## P15. Fichiers exposés — Moyenne à Haute (A05)
`phpinfo()` accessible, `.git/` servi par Apache, sauvegardes `*.sql`, `*.bak`, `config.php~` dans le webroot, `composer.json`/`vendor/` accessibles.
