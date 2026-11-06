<?php
require_once __DIR__ . '/../../includes/db.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

$id = $_GET['id'] ?? null;

if ($id === null || !ctype_digit((string) $id)) {
    http_response_code(400);

    echo json_encode([
        'error' => 'Podaj prawidłowe ID produktu.'
    ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);

    exit;
}

$stmt = $pdo->prepare(
    'SELECT id, name, description, price
     FROM products
     WHERE id = :id'
);

$stmt->execute(['id' => (int) $id]);
$product = $stmt->fetch();

if (!$product) {
    http_response_code(404);

    echo json_encode([
        'error' => 'Nie znaleziono produktu.'
    ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);

    exit;
}

echo json_encode([
    'data' => $product
], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
