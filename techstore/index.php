<?php
$pageTitle = 'TechStore — elektronika dla Ciebie';
$currentPage = 'home';
require __DIR__ . '/includes/header.php';
?>

<section class="hero">
    <div class="hero-content">
        <span class="eyebrow">TECHSTORE / SKLEP ELEKTRONICZNY</span>

        <h1>Technologia, która<br>pracuje dla <span>Ciebie.</span></h1>

        <p>
            Odkryj elektronikę do pracy, nauki i rozrywki.
            Wybierz sprzęt, który pasuje do Twojego stylu.
        </p>

        <div class="hero-actions">
            <a class="button" href="products.php">
                Odkryj produkty <span aria-hidden="true">→</span>
            </a>

            <a class="text-link" href="register.php">
                Utwórz konto
            </a>
        </div>

        <div class="hero-stats">
            <div>
                <strong>Jakość</strong>
                <span>Sprawdzony sprzęt</span>
            </div>
            <div>
                <strong>Wygoda</strong>
                <span>Proste zakupy</span>
            </div>
            <div>
                <strong>TechStore</strong>
                <span>Technologia na co dzień</span>
            </div>
        </div>
    </div>

    <div class="hero-visual" aria-label="Ilustracja elektroniki">
        <div class="visual-glow"></div>

        <div class="device-card laptop">
            <div class="device-screen">
                <div class="screen-top"></div>
                <div class="screen-art">
                    <span></span>
                    <span></span>
                    <span></span>
                </div>
            </div>
            <div class="laptop-base"></div>
        </div>

        <div class="floating-card">
            <span class="floating-icon">✦</span>
            <div>
                <strong>Nowa technologia</strong>
                <small>Odkryj możliwości</small>
            </div>
        </div>

        <span class="visual-label">TECHNOLOGY / 2026</span>
    </div>
</section>

<section class="categories">
    <div class="section-heading">
        <div>
            <span class="eyebrow">POZNAJ NASZĄ OFERTĘ</span>
            <h2>Technologia na każdą okazję.</h2>
        </div>

        <a class="text-link" href="products.php">
            Wszystkie produkty →
        </a>
    </div>

    <div class="category-grid">
        <a class="category-card" href="products.php">
            <span class="category-number">01 / KOMPUTERY</span>
            <span class="category-symbol">▰</span>
            <h3>Laptopy i komputery</h3>
            <p>Sprzęt do pracy i rozrywki.</p>
        </a>

        <a class="category-card" href="products.php">
            <span class="category-number">02 / AUDIO</span>
            <span class="category-symbol">◖))</span>
            <h3>Audio</h3>
            <p>Dźwięk, który robi różnicę.</p>
        </a>

        <a class="category-card" href="products.php">
            <span class="category-number">03 / AKCESORIA</span>
            <span class="category-symbol">⌘</span>
            <h3>Akcesoria</h3>
            <p>Dopracuj swoje stanowisko.</p>
        </a>
    </div>
</section>

<?php require __DIR__ . '/includes/footer.php'; ?>
