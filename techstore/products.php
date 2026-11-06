<?php
require_once __DIR__ . '/includes/db.php';

$stmt = $pdo->query(
    'SELECT id, name, description, price, category, stock
     FROM products
     ORDER BY id'
);

$products = $stmt->fetchAll();

require_once __DIR__ . '/includes/header.php';
?>

<section class="page-intro">
    <span class="eyebrow">NASZA OFERTA</span>
    <h1>Produkty</h1>
    <p>Sprawdź produkty dostępne w naszym sklepie.</p>
</section>

<section class="product-section">
    <div class="product-toolbar">
        <span>Liczba produktów: <?= count($products) ?></span>
    </div>

    <div class="product-grid">
        <?php foreach ($products as $product): ?>
            <article class="product-card">
                <div class="product-visual">
                    <span class="product-symbol">
                        <?= htmlspecialchars(
                            mb_substr($product['name'], 0, 1),
                            ENT_QUOTES,
                            'UTF-8'
                        ) ?>
                    </span>
                </div>

                <div class="product-info">
                    <span class="product-category">
                        <?= htmlspecialchars($product['category'] ?? '', ENT_QUOTES, 'UTF-8') ?>
                    </span>

                    <h2>
                        <?= htmlspecialchars($product['name'], ENT_QUOTES, 'UTF-8') ?>
                    </h2>

                    <p>
                        <?= htmlspecialchars($product['description'] ?? '', ENT_QUOTES, 'UTF-8') ?>
                    </p>

                    <div class="product-bottom">
                        <strong>
                            <?= number_format((float) $product['price'], 2, ',', ' ') ?> zł
                        </strong>

                        <?php if ((int) $product['stock'] > 0): ?>
                            <a class="button"
                               href="checkout.php?product_id=<?= (int) $product['id'] ?>">
                                Kup teraz
                            </a>
                        <?php else: ?>
                            <span>Brak w magazynie</span>
                        <?php endif; ?>
                    </div>
                </div>
            </article>
        <?php endforeach; ?>
    </div>
</section>

<?php require_once __DIR__ . '/includes/footer.php'; ?>
