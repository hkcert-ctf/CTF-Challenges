<?php
session_start();

$servername = "db";
$username = "root";
$password = "P@ssw0rdP@";
$dbname = "game_scores";
$secretKey = '3636f69fcc3760cb130c1558ffef5e24';

$conn = new mysqli($servername, $username, $password, $dbname);

if ($conn->connect_error) {
    die(json_encode(['success' => false, 'message' => 'Connection failed']));
}

$headers = apache_request_headers();
$authHeader = isset($headers['Authorization']) ? $headers['Authorization'] : '';

if (!preg_match('/Bearer\s(\S+)/', $authHeader, $matches)) {
    die(json_encode(['success' => false, 'message' => 'Unauthorized']));
}

$token = $matches[1];

$data = json_decode(file_get_contents('php://input'), true);
$score = $data['score'];
$hash = $data['hash'];

$stmt = $conn->prepare("SELECT username FROM users WHERE token = ?");
$stmt->bind_param("s", $token);
$stmt->execute();
$stmt->store_result();
$stmt->bind_result($username);
$stmt->fetch();

if ($stmt->num_rows > 0) {
    $calculatedHash = hash('sha256', $secretKey . $username . $score);

    if ($hash === $calculatedHash) {
        $updateStmt = $conn->prepare("UPDATE users SET highscore = GREATEST(highscore, ?) WHERE username = ?");
        $updateStmt->bind_param("is", $score, $username);
        $updateStmt->execute();
        $updateStmt->close();

        echo json_encode(['success' => true, 'message' => 'Score updated']);
    } else {
        echo json_encode(['success' => false, 'message' => 'Invalid hash']);
    }
} else {
    echo json_encode(['success' => false, 'message' => 'Invalid token']);
}

$stmt->close();
$conn->close();
?>
