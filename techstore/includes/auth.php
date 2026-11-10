
<?php

// Wspólna konfiguracja zabezpieczeń i sesji.
require_once __DIR__ . '/security.php';

/**
 * Sprawdza, czy użytkownik jest zalogowany.
 * Jeśli nie, przekierowuje go do strony logowania.
 */
function requireLogin(): void
{
    if (!isset($_SESSION['user_id'])) {
        header('Location: login.php');
        exit;
    }
}
