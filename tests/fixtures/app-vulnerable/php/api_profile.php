<?php
header('Access-Control-Allow-Origin: *');
session_start();
echo json_encode(['user' => $_SESSION['user_id'] ?? null]);
