<?php
require __DIR__ . '/config.php';
$id = (int) $_POST['id'];
$stmt = $pdo->prepare('DELETE FROM users WHERE id = ?');
$stmt->execute([$id]);
echo json_encode(['ok' => true]);
