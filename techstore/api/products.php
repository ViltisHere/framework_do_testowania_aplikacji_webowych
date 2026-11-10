
<?php

require_once __DIR__ . '/../includes/security.php';
require_once __DIR__ . '/../includes/db.php';

// Odpowiedź API w formacie JSON.
header('Content-Type: application/json; charset=utf-8');

// Zapobiegamy przechowywaniu odpowiedzi w pamięci podręcznej.
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');

// API obsługuje wyłącznie metodę GET.
if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    http_response_code(405);
    header('Allow: GET');

    echo json_encode([
        'error' => 'Method not allowed'
    ], JSON_UNESCAPED_UNICODE);

    exit;
}

try {
    // Jeżeli podano parametr id, pobieramy jeden produkt.
    if (array_key_exists('id', $_GET)) {
        $rawId = $_GET['id'];

        // Parametr musi być pojedynczą dodatnią liczbą całkowitą.
        if (
            !is_string($rawId)
            || filter_var(
                $rawId,
                FILTER_VALIDATE_INT,
                ['options' => ['min_range' => 1]]
            ) === false
        ) {
            http_response_code(400);

            echo json_encode([
                'error' => 'Invalid product ID'
            ], JSON_UNESCAPED_UNICODE);

            exit;
        }

        $productId = (int) $rawId;

        // Zapytanie parametryzowane zabezpiecza wartość id.
        $stmt = $pdo->prepare(
            'SELECT id, name, description, price, category, stock
             FROM products
             WHERE id = :id'
        );

        $stmt->bindValue(':id', $productId, PDO::PARAM_INT);
        $stmt->execute();

        $products = $stmt->fetchAll();
    } else {
        // Bez parametru id zwracamy wszystkie produkty.
        $stmt = $pdo->query(
            'SELECT id, name, description, price, category, stock
             FROM products
             ORDER BY id'
        );

        $products = $stmt->fetchAll();
    }

    http_response_code(200);

    echo json_encode(
        [
            'count' => count($products),
            'data' => $products
        ],
        JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT
    );

} catch (PDOException $e) {
    // Szczegóły błędu zapisujemy w logu serwera.
    error_log($e->getMessage());

    http_response_code(500);

    echo json_encode([
        'error' => 'Internal server error'
    ], JSON_UNESCAPED_UNICODE);
}
