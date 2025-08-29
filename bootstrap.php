<?php
// bootstrap.php
session_start();

// ── Config
$config = parse_ini_file(__DIR__ . '/config.ini', true);
if (!$config) { die('Configuration file not found or invalid'); }

define('MATRIX_SERVER', $config['matrix']['server']);
define('MATRIX_DOMAIN', $config['matrix']['domain']);
define('LOG_FILE', $config['security']['log_file'] ?? __DIR__.'/admin.log');
define('MAX_FAILED_ATTEMPTS', (int)($config['security']['max_failed_attempts'] ?? 5));
define('LOGIN_DELAY_MICROSECONDS', (int)($config['security']['login_delay_microseconds'] ?? 300000));

// ── CSRF
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
function csrf_token() { return $_SESSION['csrf_token'] ?? ''; }
function verifyCsrf($t) { return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $t); }

// ── Auth helpers
function isLoggedIn() { return isset($_SESSION['admin_token']) && $_SESSION['admin_token'] !== ''; }
function currentUser() { return $_SESSION['admin_user'] ?? 'unknown'; }

// ── Logging
function logAction($action) {
    $ts = date('Y-m-d H:i:s');
    $user = currentUser();
    @file_put_contents(LOG_FILE, "[$ts] $user → $action\n", FILE_APPEND | LOCK_EX);
}

// ── HTTP helper with DELETE support
function makeMatrixRequest($url, $method='GET', $data=null, $headers=[]) {
    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 30,
    ]);

    switch (strtoupper($method)) {
        case 'POST':
            curl_setopt($ch, CURLOPT_POST, true);
            if ($data) curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
            break;
        case 'PUT':
        case 'DELETE':
        case 'PATCH':
            curl_setopt($ch, CURLOPT_CUSTOMREQUEST, strtoupper($method));
            if ($data) curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
            break;
    }

    if ($headers) curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

    $response = curl_exec($ch);
    $httpCode = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curlError = curl_error($ch);
    curl_close($ch);

    if ($response === false || $curlError) {
        logAction("curl error: $curlError for $url");
        return ['success'=>false, 'error'=>$curlError, 'http_code'=>0];
    }
    return ['success'=>true, 'response'=>$response, 'http_code'=>$httpCode];
}

// ── Small helpers
function validateUsername($u){ return (bool)preg_match('/^[a-zA-Z0-9_.-]+$/', $u); }
function incFail(){ $_SESSION['failed_attempts'] = (int)($_SESSION['failed_attempts']??0) + 1; }
function resetFail(){ $_SESSION['failed_attempts'] = 0; }
function checkRate(){ return (int)($_SESSION['failed_attempts']??0) < MAX_FAILED_ATTEMPTS; }

// ── Simple guard
function require_login() {
    if (!isLoggedIn()) { header('Location: index.php?page=users'); exit; }
}
