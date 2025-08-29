<?php
// bootstrap.php
session_start();

/* ───────────────────────────── Config ───────────────────────────── */

$config = parse_ini_file(__DIR__ . '/config.ini', true);
if (!$config) {
    die('Configuration file not found or invalid');
}

define('MATRIX_SERVER',              rtrim($config['matrix']['server'] ?? '', '/'));
define('MATRIX_DOMAIN',              $config['matrix']['domain'] ?? 'localhost');

define('LOG_FILE',                   $config['security']['log_file'] ?? __DIR__ . '/admin.log');
define('MAX_FAILED_ATTEMPTS',   (int)($config['security']['max_failed_attempts'] ?? 5));
define('LOGIN_DELAY_MICROSECONDS', (int)($config['security']['login_delay_microseconds'] ?? 300000)); // 0.3s

/* ───────────────────────────── CSRF ───────────────────────────── */

if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

function csrf_token(): string {
    return $_SESSION['csrf_token'] ?? '';
}

function verifyCsrf(string $token): bool {
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

/* ───────────────────────────── Auth helpers ───────────────────────────── */

function isLoggedIn(): bool {
    return isset($_SESSION['admin_token']) && $_SESSION['admin_token'] !== '';
}

function currentUser(): string {
    return $_SESSION['admin_user'] ?? 'unknown';
}

function require_login(): void {
    if (!isLoggedIn()) {
        header('Location: index.php?page=login');
        exit;
    }
}

/* ───────────────────────────── Logging & archiving ───────────────────────────── */

function logAction(string $action): void {
    $ts = date('Y-m-d H:i:s');
    $user = currentUser();
    @file_put_contents(LOG_FILE, "[$ts] $user → $action\n", FILE_APPEND | LOCK_EX);
}

function archiveLogsIfNeeded(): void {
    if (!is_file(LOG_FILE)) return;

    $logDir = dirname(LOG_FILE);
    $marker = $logDir . '/.last_archive';
    $last   = is_file($marker) ? (int)@file_get_contents($marker) : 0;
    $weekAgo = time() - 7*24*60*60;

    if ($last < $weekAgo) {
        $archiveDate = date('Y-m-d', $weekAgo);
        $archiveFile = $logDir . '/admin-actions-' . $archiveDate . '.log';
        if (@copy(LOG_FILE, $archiveFile)) {
            @file_put_contents(LOG_FILE, '');
            @file_put_contents($marker, (string)time());
            logAction('archived logs to ' . basename($archiveFile));
        }
    }
}

/* ───────────────────────────── Rate limit ───────────────────────────── */

function incFail(): void {
    $_SESSION['failed_attempts'] = (int)($_SESSION['failed_attempts'] ?? 0) + 1;
}

function resetFail(): void {
    $_SESSION['failed_attempts'] = 0;
}

function checkRate(): bool {
    return (int)($_SESSION['failed_attempts'] ?? 0) < MAX_FAILED_ATTEMPTS;
}

/* ───────────────────────────── Validators ───────────────────────────── */

function validateUsername(string $u): bool {
    return (bool)preg_match('/^[a-zA-Z0-9_.\-]+$/', $u);
}

/* ───────────────────────────── HTTP helper ───────────────────────────── */

function makeMatrixRequest(string $url, string $method='GET', $data=null, array $headers=[]): array {
    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL            => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 30,
    ]);

    $m = strtoupper($method);
    if ($m === 'POST') {
        curl_setopt($ch, CURLOPT_POST, true);
        if ($data !== null) curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
    } elseif (in_array($m, ['PUT','DELETE','PATCH'], true)) {
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $m);
        if ($data !== null) curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
    }
    if ($headers) curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

    $response  = curl_exec($ch);
    $httpCode  = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curlError = curl_error($ch);
    curl_close($ch);

    if ($response === false || $curlError) {
        logAction('curl error: ' . $curlError . ' for ' . $url);
        return ['success' => false, 'error' => $curlError, 'http_code' => 0];
    }
    return ['success' => true, 'response' => $response, 'http_code' => $httpCode];
}

/* ───────────────────────────── Roles / action guard ───────────────────────────── */

function isSeniorAdmin(string $userId): bool {
    return true; // заглушка
}

function isActionAllowed(string $action, ?string $targetUserId = null): bool {
    $me = $_SESSION['admin_user'] ?? '';
    if ($action === 'deactivate'   && $targetUserId === $me) return false;
    if ($action === 'remove_admin' && $targetUserId === $me) return false;
    return true;
}
