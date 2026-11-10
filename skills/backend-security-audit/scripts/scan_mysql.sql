-- scan_mysql.sql — audits accounts, privileges and settings of a MySQL / MariaDB server. READ-ONLY.
-- Run ONLY on your own server (preferably local), with an account that can read the `mysql` database:
--   mysql -u root -p -t < scan_mysql.sql
--   docker exec -i <conteneur> mysql -uroot -p<mdp> -t < scan_mysql.sql
-- No query writes anything: only SELECTs on mysql.* and information_schema.

SELECT '=== 1. Accounts without a password (Critical) ===' AS section;
SELECT user, host, plugin FROM mysql.user
WHERE (authentication_string IS NULL OR authentication_string = '')
  AND plugin NOT IN ('auth_socket', 'unix_socket', 'mysql_no_login')
ORDER BY user, host;

SELECT '=== 2. Anonymous accounts (High) ===' AS section;
SELECT user, host FROM mysql.user WHERE user = '';

SELECT '=== 3. root or global-privilege accounts reachable remotely (Critical if host = %) ===' AS section;
SELECT user, host, Super_priv, File_priv, Grant_priv, Process_priv
FROM mysql.user
WHERE host NOT IN ('localhost', '127.0.0.1', '::1')
  AND (user = 'root' OR Super_priv = 'Y' OR File_priv = 'Y' OR Grant_priv = 'Y' OR (Select_priv = 'Y' AND Insert_priv = 'Y' AND Delete_priv = 'Y'))
ORDER BY user, host;

SELECT '=== 4. Accounts with dangerous FILE / SUPER / PROCESS / GRANT privileges (system accounts excluded) ===' AS section;
SELECT user, host, File_priv, Super_priv, Process_priv, Grant_priv, Shutdown_priv
FROM mysql.user
WHERE (File_priv = 'Y' OR Super_priv = 'Y' OR Process_priv = 'Y' OR Grant_priv = 'Y')
  AND user NOT IN ('root', 'mysql.sys', 'mysql.session', 'mysql.infoschema', 'mariadb.sys')
ORDER BY user;

SELECT '=== 5. Accounts accepting any host (host = %) ===' AS section;
SELECT user, host FROM mysql.user WHERE host = '%' ORDER BY user;

SELECT '=== 6. ALL privileges at database level (check least privilege of the app account) ===' AS section;
SELECT grantee, table_schema, COUNT(*) AS nb_privileges
FROM information_schema.schema_privileges
GROUP BY grantee, table_schema
HAVING COUNT(*) >= 10
ORDER BY grantee;

SELECT '=== 7. Sensitive server settings ===' AS section;
SELECT variable_name, variable_value,
  CASE
    WHEN variable_name = 'local_infile'              AND variable_value IN ('ON','1') THEN 'Medium: disable it'
    WHEN variable_name = 'secure_file_priv'          AND variable_value = ''          THEN 'High: file read/write anywhere'
    WHEN variable_name = 'require_secure_transport'  AND variable_value IN ('OFF','0') THEN 'Info: TLS not enforced (Medium if remote access)'
    WHEN variable_name = 'skip_networking'           AND variable_value IN ('OFF','0') THEN 'Info: network listening enabled'
    WHEN variable_name = 'bind_address'              AND variable_value IN ('*','0.0.0.0','::') THEN 'Medium: listening on all interfaces'
    WHEN variable_name = 'general_log'               AND variable_value IN ('ON','1') THEN 'Medium: queries logged in clear text'
    WHEN variable_name = 'skip_grant_tables'         AND variable_value IN ('ON','1') THEN 'Critical: authentication disabled'
    WHEN variable_name = 'sql_mode'                  AND variable_value NOT LIKE '%STRICT_TRANS_TABLES%' THEN 'Low: non-strict mode'
    WHEN variable_name = 'default_password_lifetime' THEN 'Info'
    ELSE ''
  END AS alert
FROM performance_schema.global_variables
WHERE variable_name IN ('local_infile','secure_file_priv','require_secure_transport','skip_networking','bind_address',
                        'general_log','skip_grant_tables','sql_mode','have_ssl','tls_version','version','default_password_lifetime')
ORDER BY variable_name;

SELECT '=== 8. SQL SECURITY DEFINER procedures / functions (run with the definer privileges) ===' AS section;
SELECT routine_schema, routine_name, routine_type, definer
FROM information_schema.routines
WHERE security_type = 'DEFINER'
  AND routine_schema NOT IN ('mysql','sys','information_schema','performance_schema')
ORDER BY routine_schema, routine_name;

SELECT '=== 9. Password columns probably MD5/SHA1 (length 32/40, to confirm) ===' AS section;
SELECT table_schema, table_name, column_name, data_type, character_maximum_length
FROM information_schema.columns
WHERE column_name REGEXP '^(pass|password|passwd|pwd|mdp|mot_de_passe)'
  AND character_maximum_length IN (32, 40)
  AND table_schema NOT IN ('mysql','sys','information_schema','performance_schema');
