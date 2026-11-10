
<?php

// Wspólna konfiguracja zabezpieczeń i sesji.
require_once __DIR__ . '/includes/security.php';

// Usuwamy wszystkie dane sesji.
$_SESSION = [];

// Usuwamy ciasteczko sesyjne z przeglądarki.
if (ini_get('session.use_cookies')) {
    $params = session_get_cookie_params();

    setcookie(
        session_name(),
        '',
        [
            'expires' => time() - 42000,
            'path' => $params['path'],
            'domain' => $params['domain'],
            'secure' => $params['secure'],
            'httponly' => $params['httponly'],
            'samesite' => $params['samesite'] ?? 'Lax'
        ]
    );
}

// Niszczenie sesji po stronie serwera.
session_destroy();

// Przekierowanie do logowania.
header('Location: login.php');
exit;
