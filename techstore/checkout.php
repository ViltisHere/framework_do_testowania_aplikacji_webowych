
<?php
require_once __DIR__ . '/includes/security.php';
require_once __DIR__ . '/includes/db.php';

$pageTitle = 'Zamówienie — TechStore';
$currentPage = '';

$errors = [];
$orderSuccess = false;
$product = null;
$orderId = null;

// Wyświetlenie potwierdzenia zamówienia po przekierowaniu.
// Nie usuwamy numeru zamówienia z sesji, dzięki czemu
// potwierdzenie pozostaje widoczne również po odświeżeniu.
if (
    $_SERVER['REQUEST_METHOD'] === 'GET'
    && isset($_GET['success'])
    && $_GET['success'] === '1'
    && isset($_SESSION['completed_order_id'])
) {
    $orderSuccess = true;
    $orderId = (int) $_SESSION['completed_order_id'];
}

$firstName = '';
$lastName = '';
$email = '';
$phone = '';
$street = '';
$postalCode = '';
$city = '';
$quantity = 1;
$delivery = '';
$payment = '';
$notes = '';

$selectedProductId = filter_input(
    INPUT_GET,
    'product_id',
    FILTER_VALIDATE_INT
);

$isPost = $_SERVER['REQUEST_METHOD'] === 'POST';
$validCsrf = !$isPost || verifyCsrfToken();

if ($isPost) {
    $selectedProductId = filter_input(
        INPUT_POST,
        'product_id',
        FILTER_VALIDATE_INT
    );

    // Pobieramy dane formularza.
    $firstName = trim($_POST['first_name'] ?? '');
    $lastName = trim($_POST['last_name'] ?? '');
    $email = trim($_POST['email'] ?? '');
    $phone = trim($_POST['phone'] ?? '');
    $street = trim($_POST['street'] ?? '');
    $postalCode = trim($_POST['postal_code'] ?? '');
    $city = trim($_POST['city'] ?? '');
    $quantityInput = $_POST['quantity'] ?? '';
    $delivery = $_POST['delivery'] ?? '';
    $payment = $_POST['payment'] ?? '';
    $notes = trim($_POST['notes'] ?? '');

    if (!$validCsrf) {
        http_response_code(403);
        $errors[] = 'Nieprawidłowy token bezpieczeństwa. Odśwież stronę i spróbuj ponownie.';
    } else {
        // Walidacja danych klienta.
        if ($firstName === '' || $lastName === '') {
            $errors[] = 'Podaj imię i nazwisko.';
        }

        if (mb_strlen($firstName) > 50 || mb_strlen($lastName) > 50) {
            $errors[] = 'Imię lub nazwisko jest zbyt długie.';
        }

        if (
            !filter_var($email, FILTER_VALIDATE_EMAIL)
            || mb_strlen($email) > 100
        ) {
            $errors[] = 'Podaj prawidłowy adres e-mail.';
        }

        if ($phone === '' || mb_strlen($phone) > 30) {
            $errors[] = 'Podaj prawidłowy numer telefonu.';
        }

        if ($street === '' || mb_strlen($street) > 150) {
            $errors[] = 'Podaj ulicę i numer domu.';
        }

        if (!preg_match('/^\d{2}-\d{3}$/', $postalCode)) {
            $errors[] = 'Kod pocztowy musi mieć format 00-000.';
        }

        if ($city === '' || mb_strlen($city) > 80) {
            $errors[] = 'Podaj prawidłową nazwę miasta.';
        }

        // Walidacja liczby produktów.
        $quantity = filter_var(
            $quantityInput,
            FILTER_VALIDATE_INT,
            ['options' => ['min_range' => 1, 'max_range' => 10]]
        );

        if ($quantity === false) {
            $errors[] = 'Liczba sztuk musi wynosić od 1 do 10.';
            $quantity = 1;
        }

        // Walidacja dostawy i płatności.
        if (!in_array($delivery, ['courier', 'parcel_machine'], true)) {
            $errors[] = 'Wybierz prawidłową metodę dostawy.';
        }

        if (!in_array($payment, ['card', 'blik', 'transfer'], true)) {
            $errors[] = 'Wybierz prawidłową metodę płatności.';
        }

        if (mb_strlen($notes) > 1000) {
            $errors[] = 'Uwagi mogą mieć maksymalnie 1000 znaków.';
        }

        if (!isset($_POST['terms'])) {
            $errors[] = 'Zaakceptuj regulamin sklepu.';
        }

        if (!$selectedProductId || $selectedProductId < 1) {
            $errors[] = 'Wybierz prawidłowy produkt.';
        }

        // Sprawdzamy, czy produkt istnieje i czy jest dostępny.
        if (!$errors) {
            $stmt = $pdo->prepare(
                'SELECT id, name, price, stock
                 FROM products
                 WHERE id = :id'
            );

            $stmt->execute(['id' => $selectedProductId]);
            $product = $stmt->fetch();

            if (!$product) {
                $errors[] = 'Wybrany produkt nie istnieje.';
            } elseif ((int) $product['stock'] < $quantity) {
                $errors[] = 'Niewystarczająca liczba produktów w magazynie.';
            }
        }

        // Zapisujemy zamówienie, jeśli walidacja przebiegła poprawnie.
        if (!$errors && $product) {
            $total = (float) $product['price'] * $quantity;
            $customerName = $firstName . ' ' . $lastName;

            $addressParts = [
                'Ulica: ' . $street,
                'Kod pocztowy: ' . $postalCode,
                'Miasto: ' . $city,
                'Telefon: ' . $phone,
                'Produkt: ' . $product['name'],
                'ID produktu: ' . $product['id'],
                'Liczba sztuk: ' . $quantity,
                'Uwagi: ' . ($notes !== '' ? $notes : 'Brak')
            ];

            $address = implode("\n", $addressParts);

            try {
                $pdo->beginTransaction();

                // Blokujemy wiersz produktu na czas transakcji.
                // Ponownie sprawdzamy stan magazynowy.
                $stmt = $pdo->prepare(
                    'SELECT id, name, price, stock
                     FROM products
                     WHERE id = :id
                     FOR UPDATE'
                );

                $stmt->execute(['id' => $selectedProductId]);
                $product = $stmt->fetch();

                if (!$product || (int) $product['stock'] < $quantity) {
                    throw new RuntimeException(
                        'Produkt jest niedostępny w wybranej liczbie sztuk.'
                    );
                }

                $total = (float) $product['price'] * $quantity;

                // Dodajemy zamówienie do bazy danych.
                $stmt = $pdo->prepare(
                    'INSERT INTO orders
                        (user_id, customer_name, email, address,
                         delivery_method, payment_method, total)
                     VALUES
                        (:user_id, :customer_name, :email, :address,
                         :delivery_method, :payment_method, :total)'
                );

                $stmt->execute([
                    'user_id' => $_SESSION['user_id'] ?? null,
                    'customer_name' => $customerName,
                    'email' => $email,
                    'address' => $address,
                    'delivery_method' => $delivery,
                    'payment_method' => $payment,
                    'total' => number_format($total, 2, '.', '')
                ]);

                $orderId = (int) $pdo->lastInsertId();

                // Zmniejszamy stan magazynowy.
                $stmt = $pdo->prepare(
                    'UPDATE products
                     SET stock = stock - :quantity
                     WHERE id = :id'
                );

                $stmt->execute([
                    'quantity' => $quantity,
                    'id' => $selectedProductId
                ]);

                // Zatwierdzamy transakcję.
                $pdo->commit();

                // Zapamiętujemy numer zamówienia w sesji.
                $_SESSION['completed_order_id'] = $orderId;

                // Generujemy nowy token CSRF.
                regenerateCsrfToken();

                // Przekierowanie zapobiega ponownemu wysłaniu formularza.
                header('Location: checkout.php?success=1');
                exit;

            } catch (Throwable $e) {
                if ($pdo->inTransaction()) {
                    $pdo->rollBack();
                }

                error_log($e->getMessage());

                $errors[] = $e instanceof RuntimeException
                    ? $e->getMessage()
                    : 'Nie udało się zapisać zamówienia. Spróbuj ponownie.';
            }
        }
    }
}

if (!$selectedProductId || $selectedProductId < 1) {
    $selectedProductId = '';
}

require __DIR__ . '/includes/header.php';
?>

<section class="form-page">
    <div class="form-container wide">

        <span class="eyebrow">OSTATNI KROK</span>

        <h1>Finalizacja zamówienia.</h1>

        <?php if ($orderSuccess): ?>

            <h2>Dziękujemy za zamówienie!</h2>

            <p class="form-description">
                Zamówienie zostało zapisane w systemie.
            </p>

            <p>
                Numer zamówienia:
                <strong><?= (int) $orderId ?></strong>
            </p>

            <a class="button" href="products.php">
                Wróć do produktów
            </a>

        <?php else: ?>

            <p class="form-description">
                Uzupełnij dane potrzebne do przygotowania zamówienia.
            </p>

            <?php foreach ($errors as $error): ?>
                <p class="form-note" style="color: #dc2626">
                    <?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?>
                </p>
            <?php endforeach; ?>

            <form method="POST" action="checkout.php">

                <input
                    type="hidden"
                    name="csrf_token"
                    value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>"
                >

                <h2>Dane klienta</h2>

                <div class="form-row">
                    <div class="field">
                        <label for="first_name">Imię</label>

                        <input
                            type="text"
                            id="first_name"
                            name="first_name"
                            maxlength="50"
                            autocomplete="given-name"
                            value="<?= htmlspecialchars($firstName, ENT_QUOTES, 'UTF-8') ?>"
                            required
                        >
                    </div>

                    <div class="field">
                        <label for="last_name">Nazwisko</label>

                        <input
                            type="text"
                            id="last_name"
                            name="last_name"
                            maxlength="50"
                            autocomplete="family-name"
                            value="<?= htmlspecialchars($lastName, ENT_QUOTES, 'UTF-8') ?>"
                            required
                        >
                    </div>
                </div>

                <label for="email">Adres e-mail</label>

                <input
                    type="email"
                    id="email"
                    name="email"
                    maxlength="100"
                    autocomplete="email"
                    value="<?= htmlspecialchars($email, ENT_QUOTES, 'UTF-8') ?>"
                    required
                >

                <label for="phone">Telefon</label>

                <input
                    type="tel"
                    id="phone"
                    name="phone"
                    maxlength="30"
                    autocomplete="tel"
                    value="<?= htmlspecialchars($phone, ENT_QUOTES, 'UTF-8') ?>"
                    required
                >

                <h2>Adres dostawy</h2>

                <label for="street">Ulica i numer domu</label>

                <input
                    type="text"
                    id="street"
                    name="street"
                    maxlength="150"
                    autocomplete="street-address"
                    value="<?= htmlspecialchars($street, ENT_QUOTES, 'UTF-8') ?>"
                    required
                >

                <div class="form-row">
                    <div class="field">
                        <label for="postal_code">Kod pocztowy</label>

                        <input
                            type="text"
                            id="postal_code"
                            name="postal_code"
                            placeholder="00-000"
                            pattern="[0-9]{2}-[0-9]{3}"
                            autocomplete="postal-code"
                            value="<?= htmlspecialchars($postalCode, ENT_QUOTES, 'UTF-8') ?>"
                            required
                        >
                    </div>

                    <div class="field">
                        <label for="city">Miasto</label>

                        <input
                            type="text"
                            id="city"
                            name="city"
                            maxlength="80"
                            autocomplete="address-level2"
                            value="<?= htmlspecialchars($city, ENT_QUOTES, 'UTF-8') ?>"
                            required
                        >
                    </div>
                </div>

                <h2>Szczegóły zamówienia</h2>

                <label for="product_id">ID produktu</label>

                <input
                    type="number"
                    id="product_id"
                    name="product_id"
                    min="1"
                    value="<?= htmlspecialchars((string) $selectedProductId, ENT_QUOTES, 'UTF-8') ?>"
                    required
                >

                <label for="quantity">Liczba sztuk</label>

                <input
                    type="number"
                    id="quantity"
                    name="quantity"
                    min="1"
                    max="10"
                    value="<?= (int) $quantity ?>"
                    required
                >

                <h2>Metoda dostawy</h2>

                <div class="choice-list">

                    <label class="choice">
                        <input
                            type="radio"
                            name="delivery"
                            value="courier"
                            <?= $delivery === 'courier' ? 'checked' : '' ?>
                            required
                        >
                        <span>Kurier</span>
                    </label>

                    <label class="choice">
                        <input
                            type="radio"
                            name="delivery"
                            value="parcel_machine"
                            <?= $delivery === 'parcel_machine' ? 'checked' : '' ?>
                        >
                        <span>Paczkomat</span>
                    </label>

                </div>

                <h2>Metoda płatności</h2>

                <label for="payment">Wybierz płatność</label>

                <select id="payment" name="payment" required>
                    <option value="">Wybierz metodę płatności</option>

                    <option
                        value="card"
                        <?= $payment === 'card' ? 'selected' : '' ?>
                    >
                        Karta — demonstracyjnie
                    </option>

                    <option
                        value="blik"
                        <?= $payment === 'blik' ? 'selected' : '' ?>
                    >
                        BLIK — demonstracyjnie
                    </option>

                    <option
                        value="transfer"
                        <?= $payment === 'transfer' ? 'selected' : '' ?>
                    >
                        Przelew — demonstracyjnie
                    </option>
                </select>

                <label for="notes">
                    Uwagi do zamówienia (opcjonalnie)
                </label>

                <textarea
                    id="notes"
                    name="notes"
                    rows="4"
                    maxlength="1000"
                    placeholder="Dodatkowe informacje..."
                ><?= htmlspecialchars($notes, ENT_QUOTES, 'UTF-8') ?></textarea>

                <label class="choice terms-choice">
                    <input
                        type="checkbox"
                        name="terms"
                        value="1"
                        <?= isset($_POST['terms']) ? 'checked' : '' ?>
                        required
                    >
                    <span>Akceptuję regulamin sklepu.</span>
                </label>

                <button class="button form-submit" type="submit">
                    Złóż zamówienie →
                </button>

                <p class="form-note">
                    To środowisko demonstracyjne. Nie podawaj prawdziwych
                    danych płatniczych.
                </p>

            </form>

        <?php endif; ?>

    </div>
</section>

<?php require __DIR__ . '/includes/footer.php'; ?>
