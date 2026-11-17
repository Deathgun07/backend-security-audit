<?php
require __DIR__ . '/../auth.php';
$pdo = new PDO(getenv('DB_DSN'), getenv('DB_USER'), getenv('DB_PASS'));
