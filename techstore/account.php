<?php
require_once __DIR__ . '/includes/auth.php';
requireLogin();

require_once __DIR__ . '/includes/db.php';

$stmt = $pdo->prepare(
    'SELECT username, email, created_at
     FROM users
     WHERE id = :id'
);

$stmt->execute(['id' => $_SESSION['user_id']]);
$user = $stmt->fetch();

if (!$user) {
    $_SESSION = [];
    session_destroy();
    header('Location: login.php');
    exit;
}

require_once __DIR__ . '/includes/header.php';
?>

<section class="form-page">
    <div class="form-container">
        <span class="eyebrow">TWOJE KONTO</span>
        <h1>Witaj, <?= htmlspecialchars($user['username'], ENT_QUOTES, 'UTF-8') ?>!</h1>

        <p class="form-description">
            To jest Twój panel użytkownika TechStore.
        </p>

        <h2>Dane konta</h2>

        <p>
            <strong>Nazwa użytkownika:</strong>
            <?= htmlspecialchars($user['username'], ENT_QUOTES, 'UTF-8') ?>
        </p>

        <p>
            <strong>E-mail:</strong>
            <?= htmlspecialchars($user['email'], ENT_QUOTES, 'UTF-8') ?>
        </p>

        <p>
            <strong>Data rejestracji:</strong>
            <?= htmlspecialchars($user['created_at'], ENT_QUOTES, 'UTF-8') ?>
        </p>

        <p class="form-alternative">
            <a href="products.php">Przejdź do produktów</a>
        </p>
    </div>
</section>

<?php require_once __DIR__ . '/includes/footer.php'; ?>
