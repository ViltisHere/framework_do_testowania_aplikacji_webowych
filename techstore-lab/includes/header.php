
<?php

require_once __DIR__ . '/security.php';

$currentPage = basename($_SERVER['PHP_SELF']);

?>

<!DOCTYPE html>
<html lang="pl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TechStore</title>
    <link rel="stylesheet" href="assets/style.css">
</head>
<body>

<header class="site-header">
    <a href="index.php" class="logo">Tech<span>Store</span></a>

    <nav class="main-nav">
        <a href="index.php"
           class="<?= $currentPage === 'index.php' ? 'active' : '' ?>">
            Strona główna
        </a>

        <a href="products.php"
           class="<?= $currentPage === 'products.php' ? 'active' : '' ?>">
            Produkty
        </a>

        <?php if (isset($_SESSION['user_id'])): ?>

            <a href="account.php"
               class="<?= $currentPage === 'account.php' ? 'active' : '' ?>">
                Moje konto
            </a>

            <span>
                Cześć,
                <?= htmlspecialchars(
                    $_SESSION['username'] ?? '',
                    ENT_QUOTES,
                    'UTF-8'
                ) ?>
            </span>

            <a href="logout.php">Wyloguj się</a>

        <?php else: ?>

            <a href="login.php"
               class="<?= $currentPage === 'login.php' ? 'active' : '' ?>">
                Zaloguj się
            </a>

            <a href="register.php" class="nav-cta">Rejestracja</a>

        <?php endif; ?>
    </nav>
</header>

<main>
