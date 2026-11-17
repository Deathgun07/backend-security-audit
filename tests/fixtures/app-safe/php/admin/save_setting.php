<?php
require dirname(__DIR__) . '/lib/bootstrap.php';
$stmt = $pdo->prepare('INSERT INTO settings (name, value) VALUES (?, ?)');
$stmt->execute([$_POST['name'], $_POST['value']]);
