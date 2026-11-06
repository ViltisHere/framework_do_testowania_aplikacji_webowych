
<?php
require_once __DIR__ . '/../includes/security.php';
require_once __DIR__ . '/../includes/db.php';

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

$stmt = $pdo->query(
    'SELECT id, name, description, price, category, stock
     FROM products
     ORDER BY id'
);

$products = $stmt->fetchAll();

echo json_encode(
    [
        'count' => count($products),
        'data' => $products
    ],
    JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT
);
