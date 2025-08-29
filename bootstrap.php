<?php

session_start();

error_reporting(E_ALL);
ini_set('display_errors', '1');
ini_set('log_errors', '1');
ini_set('error_log', __DIR__ . '/php_errors.log');

/* ===== Config ===== */
$config = parse_ini_file(__DIR__ . '/config.ini', true);
if (!$config) { die('Configuration file not found or invalid'); }

define('MATRIX_SERVER', rtrim($config['matrix']['server'] ?? '', '/'));
define('MATRIX_DOMAIN', $config['matrix']['domain'] ?? '');
define('LOG_FILE', $config['security']['log_file'] ?? __DIR__.'/admin.log');
define('MAX_FAILED_ATTEMPTS', (int)($config['security']['max_failed_attempts'] ?? 5));
define('LOGIN_DELAY_MICROSECONDS', (int)($config['security']['login_delay_microseconds'] ?? 300000));

/* ===== CSRF ===== */
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
function csrf_token() { return $_SESSION['csrf_token'] ?? ''; }
function verifyCsrf($t) { return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $t); }

/* ===== Auth helpers ===== */
function isLoggedIn() { return isset($_SESSION['admin_token']) && $_SESSION['admin_token'] !== ''; }
function currentUser() { return $_SESSION['admin_user'] ?? 'unknown'; }

/* ===== Logging ===== */
function logAction($action) {
    $ts = date('Y-m-d H:i:s');
    $user = currentUser();
    @file_put_contents(LOG_FILE, "[$ts] $user → $action\n", FILE_APPEND | LOCK_EX);
}

/* ===== HTTP helper with DELETE/PUT/PATCH support ===== */
function makeMatrixRequest($url, $method='GET', $data=null, $headers=[]) {
    $ch = curl_init();
    curl_s_
