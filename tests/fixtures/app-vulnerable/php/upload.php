<?php
session_start();
if ($_FILES['photo']['type'] === 'image/jpeg') {
    move_uploaded_file($_FILES['photo']['tmp_name'], __DIR__ . '/uploads/' . $_FILES['photo']['name']);
}
include $_GET['page'] . '.php';
