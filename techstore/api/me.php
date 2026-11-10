
<?php

require_once __DIR__ . '/../includes/security.php';
require_once __DIR__ . '/../includes/db.php';

// Odpowiedź API w formacie JSON.
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');

// API obsługuje wyłącznie metodę GET.
if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    http_response_code(405);
    header('Allow: GET');

    echo json_encode([
        'success' => false,
        'message' => 'Niedozwolona metoda żądania.'
    ], JSON_UNESCAPED_UNICODE);

    exit;
}

// Sprawdzamy, czy użytkownik jest zalogowany.
if (!isset($_SESSION['user_id'])) {
    http_response_code(401);

    echo json_encode([
        'success' => false,
        'message' => 'Użytkownik nie jest zalogowany.'
    ], JSON_UNESCAPED_UNICODE);

    exit;
}

// Pobieramy dane zalogowanego użytkownika.
$stmt = $pdo->prepare(
    'SELECT id, username, email
     FROM users
     WHERE id = :id
     LIMIT 1'
);

$stmt->execute([
    'id' => $_SESSION['user_id']
]);

$user = $stmt->fetch();

// Sprawdzamy, czy użytkownik nadal istnieje w bazie.
if (!$user) {
    http_response_code(401);

    echo json_encode([
        'success' => false,
        'message' => 'Nie znaleziono użytkownika.'
    ], JSON_UNESCAPED_UNICODE);

    exit;
}

// Zwracamy dane użytkownika.
http_response_code(200);

echo json_encode([
    'success' => true,
    'data' => [
        'id' => (int) $user['id'],
        'username' => $user['username'],
        'email' => $user['email']
    ]
], JSON_UNESCAPED_UNICODE);
