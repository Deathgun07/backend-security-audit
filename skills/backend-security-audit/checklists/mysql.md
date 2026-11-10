# MySQL / MariaDB checklist (database)

Concerns the database itself, regardless of the application language (PHP, Node, Python, Go…). SQL injection in code is covered in the language checklist.
Sources: `*.sql` (schema, dumps, init), `docker-compose*.yml`, `my.cnf` / `*.cnf`, `.env`, connection strings, and, if the user provides access to **their** database: output of `scripts/scan_mysql.sql`.

## M1. Account with no password or a weak password — Critical (A07)
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
CREATE USER 'app'@'10.0.0.%' IDENTIFIED BY '<generated, 24+ characters>';
```
- Anonymous users (`''@'localhost'`) present after an install without `mysql_secure_installation` → High.

## M2. Application connects as `root` / with ALL PRIVILEGES — High (A01)
```sql
-- ❌
GRANT ALL PRIVILEGES ON *.* TO 'app'@'%';
-- ✅ least privilege
GRANT SELECT, INSERT, UPDATE, DELETE ON boutique.* TO 'app'@'10.0.0.%';
```
- `FILE`, `SUPER`, `PROCESS`, `GRANT OPTION` on the application account → High (an SQL injection becomes file read/write).

## M3. Network access too open — High (A05)
- `bind-address = 0.0.0.0` + published port (`"3306:3306"` in docker-compose) + host `'%'` = database reachable from the Internet.
```yaml
# ❌
ports: ["3306:3306"]
# ✅ (local access only, or no published port if only the app reaches it through the Docker network)
ports: ["127.0.0.1:3306:3306"]
```
- `root@'%'` → Critical.

## M4. Sensitive data in clear text — High (A02)
- Passwords stored in clear text or with `MD5()`/`SHA1()`/`PASSWORD()` in the schema or dumps (`INSERT INTO users … MD5('…')`).
- Committed dumps (`*.sql`) containing real personal data or hashes → High.
- Card number or ID document columns without application-level encryption → Medium.

## M5. Server configuration — Medium (A05)
| Setting | Safe value |
|---|---|
| `local_infile` | `0` (otherwise `LOAD DATA LOCAL INFILE` reads client files) |
| `secure_file_priv` | dedicated directory or `NULL`, never empty `""` |
| `require_secure_transport` | `ON` if the database is accessed from outside the machine |
| `skip-grant-tables` | **never** (disables all authentication → Critical) |
| `sql_mode` | include `STRICT_TRANS_TABLES` |
| `general_log` | `OFF` in prod (logs queries, hence data) |

## M6. Connection from the application — Medium (A02/A03)
- TLS disabled to a remote database (`ssl: false`, `sslmode=disable`, `tls=false` in the DSN) → Medium.
- Node `mysql`/`mysql2` with `multipleStatements: true` → an SQL injection allows stacking queries (High if an injection is present).
- PHP PDO: `PDO::ATTR_EMULATE_PREPARES` set to `true` + charset not defined → prefer `false` and `charset=utf8mb4`.
- Go: `interpolateParams=true` in the DSN with a non-UTF-8 charset → Low.

## M7. Stored procedures and dynamic SQL — High (A03)
```sql
-- ❌
SET @q = CONCAT('SELECT * FROM users WHERE name = ''', p_name, '''');
PREPARE s FROM @q; EXECUTE s;
-- ✅
PREPARE s FROM 'SELECT * FROM users WHERE name = ?';
SET @n = p_name; EXECUTE s USING @n;
```
- `SQL SECURITY DEFINER` procedures whose definer is `root` → run with its privileges (Medium).

## M8. Exposed backups and admin tools — High (A05)
phpMyAdmin / Adminer publicly accessible (service in docker-compose with a published port, `adminer.php` in the webroot), `.sql` backups served by the web server.

## M9. Outdated version — varies (A06)
Image `mysql:5.6`/`5.7`, `mariadb:10.3` or older: end of support → Medium; check the CVEs for the exact version.
