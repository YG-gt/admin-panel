<?php
/**
 * PHPUnit Bootstrap for Paranoia Matrix Admin Panel
 * 
 * Sets up testing environment for old-school PHP project
 */

// Prevent actual session start in tests
if (!defined('TESTING')) {
    define('TESTING', true);
}

// Mock session functions for testing
if (!function_exists('session_start')) {
    function session_start() {
        return true;
    }
}

// Initialize test session
$_SESSION = [];

// Set up test configuration
if (!defined('MATRIX_SERVER')) {
    define('MATRIX_SERVER', 'https://test-matrix.example.com');
}
if (!defined('MATRIX_DOMAIN')) {
    define('MATRIX_DOMAIN', 'test.example.com');
}
if (!defined('LOG_FILE')) {
    define('LOG_FILE', '/tmp/test-paranoia.log');
}
if (!defined('MAX_FAILED_ATTEMPTS')) {
    define('MAX_FAILED_ATTEMPTS', 5);
}
if (!defined('LOGIN_DELAY_MICROSECONDS')) {
    define('LOGIN_DELAY_MICROSECONDS', 100000);
}

// Clean up test log file
if (file_exists(LOG_FILE)) {
    unlink(LOG_FILE);
}

// Include utility functions for testing
require_once __DIR__ . '/TestHelpers.php';

echo "🔒 Paranoia Test Suite Bootstrap - Ready for testing!\n"; 