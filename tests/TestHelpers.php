<?php
/**
 * Test Helpers for Paranoia Matrix Admin Panel
 * 
 * Extracts and isolates functions from main files for unit testing
 */

// Extract utility functions from admin.php for testing
// These are copies of the functions to avoid including the full admin.php file

function test_validateUsername($username) {
    return preg_match('/^[a-zA-Z0-9_\-\.]+$/', $username) === 1;
}

function test_verifyCsrf($token) {
    if (!isset($_SESSION['csrf_token']) || $token === null) {
        return false;
    }
    return hash_equals($_SESSION['csrf_token'], (string)$token);
}

function test_isActionAllowed($action, $targetUserId = null) {
    $currentUser = $_SESSION['admin_user'] ?? '';
    
    // Prevent self-deactivation
    if ($action === 'deactivate' && $targetUserId === $currentUser) {
        return false;
    }
    
    // Prevent removing own admin privileges
    if ($action === 'remove_admin' && $targetUserId === $currentUser) {
        return false;
    }
    
    return true;
}

function test_checkRateLimit() {
    if (!isset($_SESSION['failed_attempts'])) {
        $_SESSION['failed_attempts'] = 0;
    }
    return $_SESSION['failed_attempts'] < MAX_FAILED_ATTEMPTS;
}

function test_incrementFailedAttempts() {
    if (!isset($_SESSION['failed_attempts'])) {
        $_SESSION['failed_attempts'] = 0;
    }
    $_SESSION['failed_attempts']++;
}

function test_resetFailedAttempts() {
    $_SESSION['failed_attempts'] = 0;
}

function test_logAction($action) {
    $timestamp = date('Y-m-d H:i:s');
    $user = $_SESSION['admin_user'] ?? 'unknown';
    $logEntry = "[$timestamp] $user → $action\n";
    return file_put_contents(LOG_FILE, $logEntry, FILE_APPEND | LOCK_EX);
}

// Mock HTTP request for testing
function test_makeMatrixRequest($url, $method = 'GET', $data = null, $headers = []) {
    // Mock successful response for testing - order matters!
    
    // Login endpoint
    if (strpos($url, '/_matrix/client/r0/login') !== false) {
        return [
            'success' => true,
            'response' => json_encode(['access_token' => 'test_token_123']),
            'http_code' => 200
        ];
    }
    
    // Admin verification endpoint (more specific first)
    if (strpos($url, '/admin') !== false && strpos($url, '/users/') !== false) {
        return [
            'success' => true,
            'response' => json_encode(['admin' => true]),
            'http_code' => 200
        ];
    }
    
    // Users management endpoints
    if (strpos($url, '/_synapse/admin/v2/users') !== false || strpos($url, '/users') !== false) {
        return [
            'success' => true,
            'response' => json_encode(['result' => 'success']),
            'http_code' => 200
        ];
    }
    
    // Default response for any other endpoints
    return [
        'success' => true,
        'response' => json_encode(['result' => 'success']),
        'http_code' => 200
    ];
} 