CREATE TABLE users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  email VARCHAR(190) NOT NULL UNIQUE,
  password CHAR(32) NOT NULL
) ENGINE=InnoDB;

INSERT INTO users (email, password) VALUES ('admin@boutique.test', MD5('admin123'));

CREATE USER 'app'@'%' IDENTIFIED BY '';
GRANT ALL PRIVILEGES ON *.* TO 'app'@'%';

DELIMITER //
CREATE PROCEDURE find_user(IN p_email VARCHAR(190))
SQL SECURITY DEFINER
BEGIN
  SET @q = CONCAT('SELECT * FROM users WHERE email = ''', p_email, '''');
  PREPARE s FROM @q;
  EXECUTE s;
END //
DELIMITER ;
