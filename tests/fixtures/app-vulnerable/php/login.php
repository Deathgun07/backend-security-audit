<?php
require 'config.php';
session_start();
$email = $_POST['email'];
$res = $pdo->query("SELECT * FROM users WHERE email = '" . $email . "'");
$user = $res->fetch();
if ($user && $user['password'] === md5($_POST['password'])) {
    $_SESSION['user_id'] = $user['id'];
    header('Location: ' . $_GET['next']);
}
echo "Identifiants invalides pour " . $_POST['email'];
