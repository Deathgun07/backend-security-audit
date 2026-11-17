<?php require_once __DIR__ . '/auth.php'; ?>
<?php
$stmt = $pdo->prepare('UPDATE users SET name = ? WHERE id = ?');
$stmt->execute([$_POST['name'], $_SESSION['user_id']]);
