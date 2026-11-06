<?php
require_once __DIR__ . '/../../includes/db.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

// CELOWO PODATNY KOD — wyłącznie do lokalnych testów.
$id = $_GET['id'] ?? '1';

// Niebezpieczne: dane użytkownika są bezpośrednio
// wstawiane do zapytania SQL.
$sql = "SELECT id, name, description, price
        FROM products
        WHERE id = $id";

try {
    $stmt = $pdo->query($sql);
    $products = $stmt->fetchAll();

    echo json_encode([
        'count' => count($products),
        'data' => $products
    ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);

} catch (PDOException $e) {
    http_response_code(400);

    echo json_encode([
        'error' => 'Zapytanie SQL nie powiodło się.'
    ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
}
