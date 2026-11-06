
<?php

require_once __DIR__ . '/includes/security.php';
require_once __DIR__ . '/includes/db.php';

$errors = [];
$email = '';

// Utworzenie tokenu CSRF dla formularza logowania.
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    $csrfToken = $_POST['csrf_token'] ?? '';

    // Weryfikacja tokenu CSRF przed przetwarzaniem logowania.
    if (
        !is_string($csrfToken)
        || !hash_equals($_SESSION['csrf_token'], $csrfToken)
    ) {
        http_response_code(403);
        $errors[] = 'Sesja formularza wygasła lub token jest nieprawidłowy. Odśwież stronę i spróbuj ponownie.';
    } else {
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

            // Nowy token po pomyślnym zalogowaniu.
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));

            header('Location: index.php');
            exit;
        }

        $errors[] = 'Nieprawidłowy adres e-mail lub hasło.';
    }
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
            <input
                type="hidden"
                name="csrf_token"
                value="<?= htmlspecialchars(
                    $_SESSION['csrf_token'],
                    ENT_QUOTES,
                    'UTF-8'
                ) ?>"
            >

            <label for="email">Adres e-mail</label>
            <input
                id="email"
                name="email"
                type="email"
                maxlength="100"
                autocomplete="email"
                required
                value="<?= htmlspecialchars($email, ENT_QUOTES, 'UTF-8') ?>"
            >

            <label for="password">Hasło</label>
            <input
                id="password"
                name="password"
                type="password"
                autocomplete="current-password"
                required
            >

            <button type="submit">Zaloguj się</button>
        </form>

        <p class="form-alternative">
            Nie masz konta?
            <a href="register.php">Zarejestruj się</a>
        </p>
    </div>
</section>

<?php require_once __DIR__ . '/includes/footer.php'; ?>
