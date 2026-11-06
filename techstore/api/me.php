<?php
if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    header('Allow: GET');
    http_response_code(405);

    echo json_encode([
        'error' => 'Method not allowed'
    ]);
    exit;
}

if (!isset($_SESSION['user_id'])) {
    http_response_code(401);

    echo json_encode([
        'error' => 'Authentication required'
    ]);
    exit;
}

require_once __DIR__ . '/../includes/db.php';

$stmt = $pdo->prepare(
    'SELECT id, username, email, created_at
     FROM users
     WHERE id = :id'
);

$stmt->execute(['id' => $_SESSION['user_id']]);
$user = $stmt->fetch();

if (!$user) {
    http_response_code(401);

    echo json_encode([
        'error' => 'Invalid session'
    ]);
    exit;
}

echo json_encode(
    ['data' => $user],
    JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT
);
