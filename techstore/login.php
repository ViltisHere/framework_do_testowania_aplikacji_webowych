<?php
if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}

require_once __DIR__ . '/includes/db.php';

$errors = [];
$email = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';

    $stmt = $pdo->prepare(
        'SELECT id, username, email, password
         FROM users
         WHERE email = :email'
    );
    $stmt->execute(['email' => $email]);
    $user = $stmt->fetch();

    if ($user && password_verify($password, $user['password'])) {
        session_regenerate_id(true);

        $_SESSION['user_id'] = (int) $user['id'];
        $_SESSION['username'] = $user['username'];

        header('Location: index.php');
        exit;
    }

    $errors[] = 'Nieprawidłowy adres e-mail lub hasło.';
}

require_once __DIR__ . '/includes/header.php';
?>

<section class="form-page">
    <div class="form-container">
        <div class="form-icon">↪</div>
        <h1>Zaloguj się</h1>
        <p class="form-description">
            Zaloguj się na swoje konto TechStore.
        </p>

        <?php if (isset($_GET['registered'])): ?>
            <p class="form-note" style="color: #15803d">
                Konto utworzone. Możesz się zalogować.
            </p>
        <?php endif; ?>

        <?php foreach ($errors as $error): ?>
            <p class="form-note" style="color: #dc2626">
                <?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?>
            </p>
        <?php endforeach; ?>

        <form method="POST" action="login.php">
            <label for="email">Adres e-mail</label>
            <input
                id="email"
                name="email"
                type="email"
                maxlength="100"
                required
                value="<?= htmlspecialchars($email, ENT_QUOTES, 'UTF-8') ?>"
            >

            <label for="password">Hasło</label>
            <input
                id="password"
                name="password"
                type="password"
                required
            >

            <button type="submit">Zaloguj się</button>
        </form>

        <p class="form-alternative">
            Nie masz konta? <a href="register.php">Zarejestruj się</a>
        </p>
    </div>
</section>

<?php require_once __DIR__ . '/includes/footer.php'; ?>
