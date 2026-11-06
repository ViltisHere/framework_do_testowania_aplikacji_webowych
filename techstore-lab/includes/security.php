
<?php

/*
 * Wspólna konfiguracja zabezpieczeń HTTP
 * dla aplikacji TechStore.
 */

// Sprawdzenie, czy aplikacja działa przez HTTPS.
$isHttps = (
    (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
    || (
        isset($_SERVER['SERVER_PORT'])
        && (int) $_SERVER['SERVER_PORT'] === 443
    )
);

// Podstawowe nagłówki bezpieczeństwa.
if (!headers_sent()) {
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');

    header(
        'Referrer-Policy: strict-origin-when-cross-origin'
    );

    header(
        'Permissions-Policy: camera=(), microphone=(), geolocation=()'
    );

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

    // HSTS włączamy tylko przy HTTPS.
    if ($isHttps) {
        header(
            'Strict-Transport-Security: max-age=31536000'
        );
    }
}

// Ustawienia ciasteczka sesyjnego muszą być
// skonfigurowane przed uruchomieniem sesji.
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
