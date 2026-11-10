-- scan_mysql.sql — audit des comptes, privilèges et réglages d'un serveur MySQL / MariaDB. LECTURE SEULE.
-- À exécuter UNIQUEMENT sur votre propre serveur (local de préférence), avec un compte pouvant lire la base `mysql` :
--   mysql -u root -p -t < scan_mysql.sql
--   docker exec -i <conteneur> mysql -uroot -p<mdp> -t < scan_mysql.sql
-- Aucune requête n'écrit : uniquement des SELECT sur mysql.* et information_schema.

SELECT '=== 1. Comptes sans mot de passe (Critique) ===' AS section;
SELECT user, host, plugin FROM mysql.user
WHERE (authentication_string IS NULL OR authentication_string = '')
  AND plugin NOT IN ('auth_socket', 'unix_socket', 'mysql_no_login')
ORDER BY user, host;

SELECT '=== 2. Comptes anonymes (Haute) ===' AS section;
SELECT user, host FROM mysql.user WHERE user = '';

SELECT '=== 3. root ou comptes à privilèges globaux accessibles à distance (Critique si host = %) ===' AS section;
SELECT user, host, Super_priv, File_priv, Grant_priv, Process_priv
FROM mysql.user
WHERE host NOT IN ('localhost', '127.0.0.1', '::1')
  AND (user = 'root' OR Super_priv = 'Y' OR File_priv = 'Y' OR Grant_priv = 'Y' OR (Select_priv = 'Y' AND Insert_priv = 'Y' AND Delete_priv = 'Y'))
ORDER BY user, host;

SELECT '=== 4. Comptes avec privilèges dangereux FILE / SUPER / PROCESS / GRANT (hors comptes système) ===' AS section;
SELECT user, host, File_priv, Super_priv, Process_priv, Grant_priv, Shutdown_priv
FROM mysql.user
WHERE (File_priv = 'Y' OR Super_priv = 'Y' OR Process_priv = 'Y' OR Grant_priv = 'Y')
  AND user NOT IN ('root', 'mysql.sys', 'mysql.session', 'mysql.infoschema', 'mariadb.sys')
ORDER BY user;

SELECT '=== 5. Comptes acceptant n''importe quel hôte (host = %) ===' AS section;
SELECT user, host FROM mysql.user WHERE host = '%' ORDER BY user;

SELECT '=== 6. Privilèges ALL au niveau base (vérifier le moindre privilège du compte applicatif) ===' AS section;
SELECT grantee, table_schema, COUNT(*) AS nb_privileges
FROM information_schema.schema_privileges
GROUP BY grantee, table_schema
HAVING COUNT(*) >= 10
ORDER BY grantee;

SELECT '=== 7. Réglages serveur sensibles ===' AS section;
SELECT variable_name, variable_value,
  CASE
    WHEN variable_name = 'local_infile'              AND variable_value IN ('ON','1') THEN 'Moyenne: désactiver'
    WHEN variable_name = 'secure_file_priv'          AND variable_value = ''          THEN 'Haute: lecture/écriture de fichiers partout'
    WHEN variable_name = 'require_secure_transport'  AND variable_value IN ('OFF','0') THEN 'Info: TLS non imposé (Moyenne si accès distant)'
    WHEN variable_name = 'skip_networking'           AND variable_value IN ('OFF','0') THEN 'Info: écoute réseau active'
    WHEN variable_name = 'bind_address'              AND variable_value IN ('*','0.0.0.0','::') THEN 'Moyenne: écoute sur toutes les interfaces'
    WHEN variable_name = 'general_log'               AND variable_value IN ('ON','1') THEN 'Moyenne: requêtes journalisées en clair'
    WHEN variable_name = 'skip_grant_tables'         AND variable_value IN ('ON','1') THEN 'Critique: authentification désactivée'
    WHEN variable_name = 'sql_mode'                  AND variable_value NOT LIKE '%STRICT_TRANS_TABLES%' THEN 'Basse: mode non strict'
    WHEN variable_name = 'default_password_lifetime' THEN 'Info'
    ELSE ''
  END AS alerte
FROM performance_schema.global_variables
WHERE variable_name IN ('local_infile','secure_file_priv','require_secure_transport','skip_networking','bind_address',
                        'general_log','skip_grant_tables','sql_mode','have_ssl','tls_version','version','default_password_lifetime')
ORDER BY variable_name;

SELECT '=== 8. Procédures / fonctions SQL SECURITY DEFINER (s''exécutent avec les droits du definer) ===' AS section;
SELECT routine_schema, routine_name, routine_type, definer
FROM information_schema.routines
WHERE security_type = 'DEFINER'
  AND routine_schema NOT IN ('mysql','sys','information_schema','performance_schema')
ORDER BY routine_schema, routine_name;

SELECT '=== 9. Colonnes de mots de passe probablement en MD5/SHA1 (longueur 32/40, à confirmer) ===' AS section;
SELECT table_schema, table_name, column_name, data_type, character_maximum_length
FROM information_schema.columns
WHERE column_name REGEXP '^(pass|password|passwd|pwd|mdp|mot_de_passe)'
  AND character_maximum_length IN (32, 40)
  AND table_schema NOT IN ('mysql','sys','information_schema','performance_schema');
