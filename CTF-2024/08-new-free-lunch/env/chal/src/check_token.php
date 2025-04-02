<?php
session_start();

header('Content-Type: application/json');

if (isset($_SESSION['token'])) {
    echo json_encode(['success' => true, 'token' => $_SESSION['token']]);
} else {
    echo json_encode(['success' => false]);
}
?>
