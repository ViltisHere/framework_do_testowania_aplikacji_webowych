
<?php

require_once __DIR__ . '/includes/security.php';
require_once __DIR__ . '/includes/db.php';

$errors = [];
$username = '';
$email = '';

// Utworzenie tokenu CSRF.
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username'] ?? '');
    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    $passwordConfirm = $_POST['password_confirm'] ?? '';
    $csrfToken = $_POST['csrf_token'] ?? '';

    // Weryfikacja tokenu CSRF.
    if (
        !is_string($csrfToken)
        || !hash_equals($_SESSION['csrf_token'], $csrfToken)
    ) {
        http_response_code(403);
        $errors[] = 'Sesja formularza wygasła lub token jest nieprawidłowy. Odśwież stronę i spróbuj ponownie.';
    } else {
        // Walidacja danych.
        if (strlen($username) < 3 || strlen($username) > 50) {
            $errors[] = 'Nazwa użytkownika musi mieć od 3 do 50 znaków.';
        }

        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $errors[] = 'Podaj poprawny adres e-mail.';
        }

        if (strlen($password) < 8) {
            $errors[] = 'Hasło musi mieć co najmniej 8 znaków.';
        }

        if ($password !== $passwordConfirm) {
            $errors[] = 'Podane hasła nie są identyczne.';
        }

        if (!$errors) {
            $stmt = $pdo->prepare(
                'SELECT id FROM users WHERE email = :email'
            );
            $stmt->execute(['email' => $email]);

            if ($stmt->fetch()) {
                $errors[] = 'Konto z tym adresem e-mail już istnieje.';
            } else {
                $stmt = $pdo->prepare(
                    'INSERT INTO users (username, email, password)
                     VALUES (:username, :email, :password)'
                );

                $stmt->execute([
                    'username' => $username,
                    'email' => $email,
                    'password' => password_hash($password, PASSWORD_DEFAULT)
                ]);

                header('Location: login.php?registered=1');
                exit;
            }
        }
    }
}

require_once __DIR__ . '/includes/header.php';
?>

<section class="form-page">
    <div class="form-container">
        <div class="form-icon">＋</div>
        <h1>Utwórz konto</h1>

        <p class="form-description">
            Zarejestruj się, aby korzystać ze sklepu TechStore.
        </p>

        <?php foreach ($errors as $error): ?>
            <p class="form-note" style="color: #dc2626">
                <?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?>
            </p>
        <?php endforeach; ?>

        <form method="POST" action="register.php">
            <input
                type="hidden"
                name="csrf_token"
                value="<?= htmlspecialchars(
                    $_SESSION['csrf_token'],
                    ENT_QUOTES,
                    'UTF-8'
                ) ?>"
            >

            <label for="username">Nazwa użytkownika</label>
            <input
                id="username"
                name="username"
                type="text"
                minlength="3"
                maxlength="50"
                required
                value="<?= htmlspecialchars($username, ENT_QUOTES, 'UTF-8') ?>"
            >

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
                minlength="8"
                autocomplete="new-password"
                required
            >

            <label for="password_confirm">Powtórz hasło</label>
            <input
                id="password_confirm"
                name="password_confirm"
                type="password"
                minlength="8"
                autocomplete="new-password"
                required
            >

            <button type="submit">Zarejestruj się</button>
        </form>

        <p class="form-alternative">
            Masz już konto? <a href="login.php">Zaloguj się</a>
        </p>
    </div>
</section>

<?php require_once __DIR__ . '/includes/footer.php'; ?>
