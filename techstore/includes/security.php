
<?php
/*
 * Wspólna konfiguracja zabezpieczeń HTTP
 * dla zabezpieczonej wersji aplikacji TechStore.
 */

$isHttps = (
    (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
    || (
        isset($_SERVER['SERVER_PORT'])
        && (int) $_SERVER['SERVER_PORT'] === 443
    )
);

// Nagłówki bezpieczeństwa HTTP.
if (!headers_sent()) {
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: strict-origin-when-cross-origin');
    header('Permissions-Policy: camera=(), microphone=(), geolocation=()');

    header(
        "Content-Security-Policy: "
        . "default-src 'self'; "
        . "base-uri 'self'; "
        . "object-src 'none'; "
        . "frame-ancestors 'none'; "
        . "form-action 'self'; "
        . "img-src 'self' data:; "
        . "style-src 'self' 'unsafe-inline'; "
        . "script-src 'self'"
    );

    // HSTS włączamy wyłącznie przy HTTPS.
    if ($isHttps) {
        header('Strict-Transport-Security: max-age=31536000');
    }
}

// Bezpieczna konfiguracja sesji.
if (session_status() !== PHP_SESSION_ACTIVE) {
    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'secure' => $isHttps,
        'httponly' => true,
        'samesite' => 'Lax'
    ]);

    session_start();
}

// Token CSRF.
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

/**
 * Sprawdza token CSRF przesłany metodą POST.
 */
function verifyCsrfToken(): bool
{
    $submittedToken = $_POST['csrf_token'] ?? '';
    $sessionToken = $_SESSION['csrf_token'] ?? '';

    return (
        is_string($submittedToken)
        && is_string($sessionToken)
        && $sessionToken !== ''
        && hash_equals($sessionToken, $submittedToken)
    );
}

/**
 * Generuje nowy token CSRF.
 */
function regenerateCsrfToken(): void
{
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
