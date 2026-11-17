<?php
session_start();
if (!isset($_SESSION['user_id'])) {
    header('Location: /login.php');
    exit;
}
$stmt = $pdo->prepare('DELETE FROM posts WHERE id = ? AND author_id = ?');
$stmt->execute([$_POST['id'], $_SESSION['user_id']]);
