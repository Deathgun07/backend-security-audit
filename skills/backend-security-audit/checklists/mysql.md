# Checklist MySQL / MariaDB (base de données)

Concerne la base elle-même, quel que soit le langage de l'application (PHP, Node, Python, Go…). L'injection SQL côté code est traitée dans la checklist du langage.
Sources : `*.sql` (schéma, dumps, init), `docker-compose*.yml`, `my.cnf` / `*.cnf`, `.env`, chaînes de connexion, et si l'utilisateur fournit l'accès à **sa** base : sortie de `scripts/scan_mysql.sql`.

## M1. Compte sans mot de passe ou mot de passe faible — Critique (A07)
```yaml
# ❌ docker-compose.yml
environment:
  MYSQL_ALLOW_EMPTY_PASSWORD: "yes"
  MYSQL_ROOT_PASSWORD: root
# ✅
environment:
  MYSQL_ROOT_PASSWORD_FILE: /run/secrets/mysql_root
  MYSQL_PASSWORD_FILE: /run/secrets/mysql_app
```
```sql
-- ❌
CREATE USER 'app'@'%' IDENTIFIED BY '';
-- ✅
CREATE USER 'app'@'10.0.0.%' IDENTIFIED BY '<généré, 24+ caractères>';
```
- Utilisateurs anonymes (`''@'localhost'`) présents après une installation sans `mysql_secure_installation` → Haute.

## M2. L'application se connecte en `root` / avec ALL PRIVILEGES — Haute (A01)
```sql
-- ❌
GRANT ALL PRIVILEGES ON *.* TO 'app'@'%';
-- ✅ moindre privilège
GRANT SELECT, INSERT, UPDATE, DELETE ON boutique.* TO 'app'@'10.0.0.%';
```
- `FILE`, `SUPER`, `PROCESS`, `GRANT OPTION` pour le compte applicatif → Haute (une injection SQL devient lecture/écriture de fichiers).

## M3. Accès réseau trop ouvert — Haute (A05)
- `bind-address = 0.0.0.0` + port publié (`"3306:3306"` dans docker-compose) + hôte `'%'` = base joignable depuis Internet.
```yaml
# ❌
ports: ["3306:3306"]
# ✅ (accès local uniquement, ou aucun port publié si seule l'app y accède via le réseau Docker)
ports: ["127.0.0.1:3306:3306"]
```
- `root@'%'` → Critique.

## M4. Données sensibles en clair — Haute (A02)
- Mots de passe stockés en clair ou en `MD5()`/`SHA1()`/`PASSWORD()` dans le schéma ou les dumps (`INSERT INTO users … MD5('…')`).
- Dumps (`*.sql`) commités contenant de vraies données personnelles ou des hash → Haute.
- Colonnes de numéros de carte, pièces d'identité sans chiffrement applicatif → Moyenne.

## M5. Configuration serveur — Moyenne (A05)
| Paramètre | Valeur sûre |
|---|---|
| `local_infile` | `0` (sinon `LOAD DATA LOCAL INFILE` lit des fichiers du client) |
| `secure_file_priv` | dossier dédié ou `NULL`, jamais vide `""` |
| `require_secure_transport` | `ON` si la base est accédée hors machine |
| `skip-grant-tables` | **jamais** (désactive toute authentification → Critique) |
| `sql_mode` | inclure `STRICT_TRANS_TABLES` |
| `general_log` | `OFF` en prod (journalise les requêtes, donc les données) |

## M6. Connexion depuis l'application — Moyenne (A02/A03)
- TLS désactivé vers une base distante (`ssl: false`, `sslmode=disable`, `tls=false` dans le DSN) → Moyenne.
- Node `mysql`/`mysql2` avec `multipleStatements: true` → une injection SQL permet d'empiler des requêtes (Haute si injection présente).
- PHP PDO : `PDO::ATTR_EMULATE_PREPARES` à `true` + charset non défini → préférer `false` et `charset=utf8mb4`.
- Go : `interpolateParams=true` dans le DSN avec un charset non UTF-8 → Basse.

## M7. Procédures stockées et SQL dynamique — Haute (A03)
```sql
-- ❌
SET @q = CONCAT('SELECT * FROM users WHERE name = ''', p_name, '''');
PREPARE s FROM @q; EXECUTE s;
-- ✅
PREPARE s FROM 'SELECT * FROM users WHERE name = ?';
SET @n = p_name; EXECUTE s USING @n;
```
- Procédures `SQL SECURITY DEFINER` dont le definer est `root` → exécutées avec ses droits (Moyenne).

## M8. Sauvegardes et outils d'admin exposés — Haute (A05)
phpMyAdmin / Adminer accessibles publiquement (service dans docker-compose avec port publié, `adminer.php` dans le webroot), sauvegardes `.sql` servies par le serveur web.

## M9. Version obsolète — variable (A06)
Image `mysql:5.6`/`5.7`, `mariadb:10.3` ou plus ancienne : fin de support → Moyenne ; vérifier les CVE de la version exacte.
