<?php
session_start();

// Load configuration
$config = parse_ini_file(__DIR__ . '/config.ini', true);
if (!$config) {
    die('Configuration file not found or invalid');
}

define('MATRIX_SERVER', $config['matrix']['server']);
define('MATRIX_DOMAIN', $config['matrix']['domain']);
define('LOG_FILE', $config['security']['log_file']);
define('MAX_FAILED_ATTEMPTS', $config['security']['max_failed_attempts']);
define('LOGIN_DELAY_MICROSECONDS', $config['security']['login_delay_microseconds']);

// Generate CSRF token
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Function to log actions
function logAction($action) {
    $timestamp = date('Y-m-d H:i:s');
    $user = $_SESSION['admin_user'] ?? 'unknown';
    $logEntry = "[$timestamp] $user → $action\n";
    file_put_contents(LOG_FILE, $logEntry, FILE_APPEND | LOCK_EX);
}

// Function to verify CSRF token
function verifyCsrf($token) {
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

// Function to validate username
function validateUsername($username) {
    return preg_match('/^[a-zA-Z0-9_\-\.]+$/', $username);
}

// Function to check rate limit
function checkRateLimit() {
    if (!isset($_SESSION['failed_attempts'])) {
        $_SESSION['failed_attempts'] = 0;
    }
    return $_SESSION['failed_attempts'] < MAX_FAILED_ATTEMPTS;
}

// Function to increment failed attempts
function incrementFailedAttempts() {
    if (!isset($_SESSION['failed_attempts'])) {
        $_SESSION['failed_attempts'] = 0;
    }
    $_SESSION['failed_attempts']++;
}

// Function to reset failed attempts
function resetFailedAttempts() {
    $_SESSION['failed_attempts'] = 0;
}

// Function to check if user is senior admin (first admin created or specifically designated)
function isSeniorAdmin($userId) {
    // Senior admin is determined by being the first admin or having specific designation
    // For simplicity, we'll consider the current logged-in user as senior if they're the first in alphabetical order
    // In production, this should be stored in a separate config or database
    return true; // For now, all logged-in admins are considered senior
}

// Function to check if action is allowed based on role
function isActionAllowed($action, $targetUserId = null) {
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

// Function to archive old logs weekly
function archiveLogsIfNeeded() {
    if (!file_exists(LOG_FILE)) return;
    
    $logDir = dirname(LOG_FILE);
    $lastArchiveFile = $logDir . '/.last_archive';
    $lastArchive = file_exists($lastArchiveFile) ? (int)file_get_contents($lastArchiveFile) : 0;
    $weekAgo = time() - (7 * 24 * 60 * 60);
    
    if ($lastArchive < $weekAgo) {
        $archiveDate = date('Y-m-d', $weekAgo);
        $archiveFile = $logDir . '/admin-actions-' . $archiveDate . '.log';
        
        // Copy current log to archive
        if (copy(LOG_FILE, $archiveFile)) {
            // Clear current log but keep the file
            file_put_contents(LOG_FILE, '');
            // Update last archive timestamp
            file_put_contents($lastArchiveFile, time());
            logAction('archived logs to ' . basename($archiveFile));
        }
    }
}

// Function to make secure HTTP request with error logging
function makeMatrixRequest($url, $method = 'GET', $data = null, $headers = []) {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 30);
    
    if ($method === 'POST') {
        curl_setopt($ch, CURLOPT_POST, true);
        if ($data) curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
    } elseif ($method === 'PUT') {
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'PUT');
        if ($data) curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
    }
    
    if (!empty($headers)) {
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    }
    
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curlError = curl_error($ch);
    curl_close($ch);
    
    // Log curl errors
    if ($response === false || !empty($curlError)) {
        logAction('curl error: ' . $curlError . ' for URL: ' . $url);
        return ['success' => false, 'error' => 'Network error: ' . $curlError, 'http_code' => 0];
    }
    
    return ['success' => true, 'response' => $response, 'http_code' => $httpCode];
}

// Check if admin is logged in
$isLoggedIn = isset($_SESSION['admin_token']);

// Archive logs if needed (weekly)
if ($isLoggedIn) {
    archiveLogsIfNeeded();
}

// Handle logout
if (isset($_GET['logout'])) {
    if ($isLoggedIn) {
        logAction('logout');
    }
    session_destroy();
    header('Location: admin.php');
    exit;
}

// Handle login
if (($_POST['action'] ?? '') === 'login' && !$isLoggedIn) {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    $csrfToken = $_POST['csrf_token'] ?? '';
    
    if (!verifyCsrf($csrfToken)) {
        $error = 'Invalid CSRF token';
        logAction('login failed: invalid CSRF token from IP ' . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
        usleep(LOGIN_DELAY_MICROSECONDS);
    } elseif (!checkRateLimit()) {
        $error = 'Too many failed login attempts. Please try again later.';
        logAction('login blocked: rate limit exceeded from IP ' . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
        usleep(LOGIN_DELAY_MICROSECONDS);
    } elseif (!$username || !$password) {
        $error = 'Please enter username and password';
        incrementFailedAttempts();
        usleep(LOGIN_DELAY_MICROSECONDS);
    } elseif (!validateUsername($username)) {
        $error = 'Invalid username format';
        incrementFailedAttempts();
        logAction('login failed: invalid username format "' . $username . '" from IP ' . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
        usleep(LOGIN_DELAY_MICROSECONDS);
    } else {
        $loginData = [
            'type' => 'm.login.password',
            'user' => $username,
            'password' => $password
        ];
        
        $loginResult = makeMatrixRequest(
            MATRIX_SERVER . '/_matrix/client/r0/login',
            'POST',
            json_encode($loginData),
            ['Content-Type: application/json']
        );
        
        if (!$loginResult['success']) {
            $error = 'Network error during login';
            incrementFailedAttempts();
            usleep(LOGIN_DELAY_MICROSECONDS);
        } elseif ($loginResult['http_code'] === 200) {
            $data = json_decode($loginResult['response'], true);
            $token = $data['access_token'] ?? '';
            
            if ($token) {
                // Check if user is admin
                $adminResult = makeMatrixRequest(
                    MATRIX_SERVER . '/_synapse/admin/v1/users/@' . $username . ':' . MATRIX_DOMAIN . '/admin',
                    'GET',
                    null,
                    ['Authorization: Bearer ' . $token]
                );
                
                if (!$adminResult['success']) {
                    $error = 'Network error during admin verification';
                    incrementFailedAttempts();
                    usleep(LOGIN_DELAY_MICROSECONDS);
                } elseif ($adminResult['http_code'] === 200) {
                    $adminData = json_decode($adminResult['response'], true);
                    if ($adminData['admin'] === true) {
                        $_SESSION['admin_token'] = $token;
                        $_SESSION['admin_user'] = '@' . $username . ':' . MATRIX_DOMAIN;
                        resetFailedAttempts();
                        logAction('login successful from IP ' . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
                        header('Location: admin.php');
                        exit;
                    } else {
                        $error = 'Access denied: Admin privileges required';
                        incrementFailedAttempts();
                        logAction('login failed: user "' . $username . '" not admin from IP ' . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
                        usleep(LOGIN_DELAY_MICROSECONDS);
                    }
                } else {
                    $error = 'Failed to verify admin status';
                    incrementFailedAttempts();
                    logAction('login failed: admin verification failed for "' . $username . '" from IP ' . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
                    usleep(LOGIN_DELAY_MICROSECONDS);
                }
            } else {
                $error = 'Invalid server response';
                incrementFailedAttempts();
                usleep(LOGIN_DELAY_MICROSECONDS);
            }
        } else {
            $error = 'Invalid username or password';
            incrementFailedAttempts();
            logAction('login failed: invalid credentials for "' . $username . '" from IP ' . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
            usleep(LOGIN_DELAY_MICROSECONDS);
        }
    }
}
// ===== Rooms: bulk actions (delete via admin v2, async) =====
if (($_POST['action'] ?? '') === 'bulk_rooms' && $isLoggedIn) {
    $csrfToken = $_POST['csrf_token'] ?? '';
    $op = $_POST['bulk_op'] ?? '';
    $ids = array_filter((array)($_POST['room_ids'] ?? []), 'strlen');

    // сохранить параметры пагинации/поиска для возврата
    $r_page = (int)($_POST['r_page'] ?? 1);
    $r_per_page = (int)($_POST['r_per_page'] ?? 50);
    $r_search = trim($_POST['r_search'] ?? '');

    if (!verifyCsrf($csrfToken)) {
        $error = 'Invalid CSRF token';
    } elseif (empty($ids)) {
        $error = 'No rooms selected';
    } elseif ($op !== 'delete') {
        $error = 'Unknown bulk operation';
    } else {
        $ok = 0; $fail = 0; $errors = [];
        foreach ($ids as $rid) {
            $res = makeMatrixRequest(
                MATRIX_SERVER . '/_synapse/admin/v2/rooms/' . rawurlencode($rid),
                'DELETE',
                null,
                [
                    'Authorization: Bearer ' . $_SESSION['admin_token'],
                    'Content-Type: application/json'
                ]
            );
            if ($res['success'] && $res['http_code'] >= 200 && $res['http_code'] < 300) {
                $ok++;
                logAction('bulk delete room requested ' . $rid);
            } else {
                $fail++;
                $msg = $res['response'] ?? $res['error'] ?? 'unknown';
                $errors[] = $rid . ' => ' . $msg;
                logAction('bulk delete room FAILED ' . $rid . ' - ' . $msg);
            }
        }
        if ($fail === 0) {
            $success = "Deletion requested for $ok room(s) (async).";
        } else {
            $error = "Requested deletion: OK $ok, failed $fail.";
        }
    }

    // Возврат на список комнат с сохранением фильтров/пагинации
    $redir = 'admin.php?r_page=' . max(1, $r_page) . '&r_per_page=' . max(10, $r_per_page);
    if ($r_search !== '') $redir .= '&r_search=' . urlencode($r_search);
    if (isset($_POST['page'])) $redir .= '&page=' . (int)$_POST['page'];
    if (isset($_POST['per_page'])) $redir .= '&per_page=' . (int)$_POST['per_page'];
    if (!empty($_POST['search'])) $redir .= '&search=' . urlencode($_POST['search']);
    if (!empty($_POST['show_deactivated'])) $redir .= '&show_deactivated=1';
    if (isset($success)) $redir .= '&success=' . urlencode($success);
    if (isset($error))   $redir .= '&error='   . urlencode($error);
    header('Location: ' . $redir);
    exit;
}
// Handle user creation
if (($_POST['action'] ?? '') === 'create_user' && $isLoggedIn) {
    $newUsername = trim($_POST['new_username'] ?? '');
    $newPassword = $_POST['new_password'] ?? '';
    $isAdmin = isset($_POST['is_admin']) ? true : false;
    $csrfToken = $_POST['csrf_token'] ?? '';
    
    if (!verifyCsrf($csrfToken)) {
        $error = 'Invalid CSRF token';
    } elseif (!$newUsername || !$newPassword) {
        $error = 'Please enter username and password';
    } elseif (!validateUsername($newUsername)) {
        $error = 'Invalid username format. Use only letters, numbers, dots, hyphens and underscores.';
    } elseif (strlen($newPassword) < 6) {
        $error = 'Password must be at least 6 characters long';
    } else {
        $userData = [
            'password' => $newPassword,
            'admin' => $isAdmin
        ];
        
        $createResult = makeMatrixRequest(
            MATRIX_SERVER . '/_synapse/admin/v2/users/@' . $newUsername . ':' . MATRIX_DOMAIN,
            'PUT',
            json_encode($userData),
            [
                'Content-Type: application/json',
                'Authorization: Bearer ' . $_SESSION['admin_token']
            ]
        );
        
        if (!$createResult['success']) {
            $error = 'Network error during user creation';
            logAction('failed to create user @' . $newUsername . ':' . MATRIX_DOMAIN . ' - network error');
        } elseif ($createResult['http_code'] === 200 || $createResult['http_code'] === 201) {
            $success = 'User @' . $newUsername . ':' . MATRIX_DOMAIN . ' created successfully';
            logAction('create user @' . $newUsername . ':' . MATRIX_DOMAIN . ($isAdmin ? ' (admin)' : ''));
        } else {
            $error = 'Failed to create user: ' . $createResult['response'];
            logAction('failed to create user @' . $newUsername . ':' . MATRIX_DOMAIN . ' - ' . $createResult['response']);
        }
    }
}

// Handle user deactivation
if (($_POST['action'] ?? '') === 'deactivate_user' && $isLoggedIn) {
    $userId = $_POST['user_id'] ?? '';
    $csrfToken = $_POST['csrf_token'] ?? '';
    
    if (!verifyCsrf($csrfToken)) {
        $error = 'Invalid CSRF token';
    } elseif (!isActionAllowed('deactivate', $userId)) {
        $error = 'Cannot deactivate yourself or perform this action';
    } elseif ($userId) {
        $deactivateData = ['deactivated' => true];
        
        $deactivateResult = makeMatrixRequest(
            MATRIX_SERVER . '/_synapse/admin/v2/users/' . urlencode($userId),
            'PUT',
            json_encode($deactivateData),
            [
                'Content-Type: application/json',
                'Authorization: Bearer ' . $_SESSION['admin_token']
            ]
        );
        
        if (!$deactivateResult['success']) {
            $error = 'Network error during user deactivation';
            logAction('failed to deactivate user ' . $userId . ' - network error');
        } elseif ($deactivateResult['http_code'] === 200) {
            $success = 'User ' . $userId . ' deactivated successfully';
            logAction('deactivate user ' . $userId);
            // Redirect to preserve pagination and search
            $redirectUrl = 'admin.php?';
            if (!empty($_POST['page'])) $redirectUrl .= 'page=' . $_POST['page'] . '&';
            if (!empty($_POST['per_page'])) $redirectUrl .= 'per_page=' . $_POST['per_page'] . '&';
            if (!empty($_POST['search'])) $redirectUrl .= 'search=' . urlencode($_POST['search']) . '&';
            $redirectUrl .= 'success=' . urlencode($success);
            header('Location: ' . $redirectUrl);
            exit;
        } else {
            $error = 'Failed to deactivate user: ' . $deactivateResult['response'];
            logAction('failed to deactivate user ' . $userId . ' - ' . $deactivateResult['response']);
        }
    }
}

// Handle user reactivation
if (($_POST['action'] ?? '') === 'reactivate_user' && $isLoggedIn) {
    $userId = $_POST['user_id'] ?? '';
    $csrfToken = $_POST['csrf_token'] ?? '';
    
    if (!verifyCsrf($csrfToken)) {
        $error = 'Invalid CSRF token';
    } elseif ($userId) {
        $reactivateData = ['deactivated' => false];
        
        $reactivateResult = makeMatrixRequest(
            MATRIX_SERVER . '/_synapse/admin/v2/users/' . urlencode($userId),
            'PUT',
            json_encode($reactivateData),
            [
                'Content-Type: application/json',
                'Authorization: Bearer ' . $_SESSION['admin_token']
            ]
        );
        
        if (!$reactivateResult['success']) {
            $error = 'Network error during user reactivation';
            logAction('failed to reactivate user ' . $userId . ' - network error');
        } elseif ($reactivateResult['http_code'] === 200) {
            $success = 'User ' . $userId . ' reactivated successfully';
            logAction('reactivate user ' . $userId);
            // Redirect to preserve pagination and search
            $redirectUrl = 'admin.php?';
            if (!empty($_POST['page'])) $redirectUrl .= 'page=' . $_POST['page'] . '&';
            if (!empty($_POST['per_page'])) $redirectUrl .= 'per_page=' . $_POST['per_page'] . '&';
            if (!empty($_POST['search'])) $redirectUrl .= 'search=' . urlencode($_POST['search']) . '&';
            $redirectUrl .= 'success=' . urlencode($success);
            header('Location: ' . $redirectUrl);
            exit;
        } else {
            $error = 'Failed to reactivate user: ' . $reactivateResult['response'];
            logAction('failed to reactivate user ' . $userId . ' - ' . $reactivateResult['response']);
        }
    }
}

// Handle admin toggle
if (($_POST['action'] ?? '') === 'toggle_admin' && $isLoggedIn) {
    $userId = $_POST['user_id'] ?? '';
    $makeAdmin = isset($_POST['make_admin']) ? true : false;
    $csrfToken = $_POST['csrf_token'] ?? '';
    
    if (!verifyCsrf($csrfToken)) {
        $error = 'Invalid CSRF token';
    } elseif (!$makeAdmin && !isActionAllowed('remove_admin', $userId)) {
        $error = 'Cannot remove your own admin privileges';
    } elseif ($userId) {
        $adminData = ['admin' => $makeAdmin];
        
        $adminResult = makeMatrixRequest(
            MATRIX_SERVER . '/_synapse/admin/v2/users/' . urlencode($userId),
            'PUT',
            json_encode($adminData),
            [
                'Content-Type: application/json',
                'Authorization: Bearer ' . $_SESSION['admin_token']
            ]
        );
        
        if (!$adminResult['success']) {
            $error = 'Network error during admin status change';
            logAction('failed to change admin status for user ' . $userId . ' - network error');
        } elseif ($adminResult['http_code'] === 200) {
            $action = $makeAdmin ? 'granted' : 'revoked';
            $success = 'Admin privileges ' . $action . ' for user ' . $userId;
            logAction($action . ' admin privileges for user ' . $userId);
            // Redirect to preserve pagination and search
            $redirectUrl = 'admin.php?';
            if (!empty($_POST['page'])) $redirectUrl .= 'page=' . $_POST['page'] . '&';
            if (!empty($_POST['per_page'])) $redirectUrl .= 'per_page=' . $_POST['per_page'] . '&';
            if (!empty($_POST['search'])) $redirectUrl .= 'search=' . urlencode($_POST['search']) . '&';
            $redirectUrl .= 'success=' . urlencode($success);
            header('Location: ' . $redirectUrl);
            exit;
        } else {
            $error = 'Failed to change admin status: ' . $adminResult['response'];
            logAction('failed to change admin status for user ' . $userId . ' - ' . $adminResult['response']);
        }
    }
}

// Handle audit export
if (($_POST['action'] ?? '') === 'export_audit' && $isLoggedIn) {
    $csrfToken = $_POST['csrf_token'] ?? '';
    
    if (!verifyCsrf($csrfToken)) {
        $error = 'Invalid CSRF token';
    } else {
        logAction('exported audit log');
        
        // Read log file
        $logData = [];
        if (file_exists(LOG_FILE)) {
            $logContent = file_get_contents(LOG_FILE);
            if ($logContent !== false) {
                $lines = explode("\n", trim($logContent));
                foreach ($lines as $line) {
                    if (trim($line) !== '') {
                        // Parse log format: [2025-06-25 16:24:44] user → action
                        if (preg_match('/^\[(.*?)\]\s+(.*?)\s+→\s+(.*)$/', $line, $matches)) {
                            $logData[] = [
                                'timestamp' => $matches[1],
                                'user' => $matches[2],
                                'action' => $matches[3]
                            ];
                        }
                    }
                }
            }
        }
        
        // Generate CSV
        $filename = 'matrix-audit-' . date('Y-m-d-H-i-s') . '.csv';
        header('Content-Type: text/csv');
        header('Content-Disposition: attachment; filename="' . $filename . '"');
        header('Cache-Control: no-cache, must-revalidate');
        
        $output = fopen('php://output', 'w');
        fputcsv($output, ['Timestamp', 'User', 'Action']);
        
        foreach ($logData as $row) {
            fputcsv($output, [$row['timestamp'], $row['user'], $row['action']]);
        }
        
        fclose($output);
        exit;
    }
}

// Handle password change
if (($_POST['action'] ?? '') === 'change_password' && $isLoggedIn) {
    $userId = $_POST['user_id'] ?? '';
    $newPassword = $_POST['new_password'] ?? '';
    $csrfToken = $_POST['csrf_token'] ?? '';
    
    if (!verifyCsrf($csrfToken)) {
        $error = 'Invalid CSRF token';
    } elseif (!$userId || !$newPassword) {
        $error = 'Please enter user ID and new password';
    } elseif (strlen($newPassword) < 6) {
        $error = 'Password must be at least 6 characters long';
    } else {
        $passwordData = ['new_password' => $newPassword];
        
        $passwordResult = makeMatrixRequest(
            MATRIX_SERVER . '/_synapse/admin/v1/users/' . urlencode($userId) . '/password',
            'POST',
            json_encode($passwordData),
            [
                'Content-Type: application/json',
                'Authorization: Bearer ' . $_SESSION['admin_token']
            ]
        );
        
        if (!$passwordResult['success']) {
            $error = 'Network error during password change';
            logAction('failed to change password for user ' . $userId . ' - network error');
        } elseif ($passwordResult['http_code'] === 200) {
            $success = 'Password changed successfully for user ' . $userId;
            logAction('change password for user ' . $userId);
            // Redirect to preserve pagination and search
            $redirectUrl = 'admin.php?';
            if (!empty($_POST['page'])) $redirectUrl .= 'page=' . $_POST['page'] . '&';
            if (!empty($_POST['per_page'])) $redirectUrl .= 'per_page=' . $_POST['per_page'] . '&';
            if (!empty($_POST['search'])) $redirectUrl .= 'search=' . urlencode($_POST['search']) . '&';
            $redirectUrl .= 'success=' . urlencode($success);
            header('Location: ' . $redirectUrl);
            exit;
        } else {
            $error = 'Failed to change password: ' . $passwordResult['response'];
            logAction('failed to change password for user ' . $userId . ' - ' . $passwordResult['response']);
        }
    }
}

// Handle room creation
if (($_POST['action'] ?? '') === 'create_room' && $isLoggedIn) {
    $roomName = trim($_POST['room_name'] ?? '');
    $roomType = $_POST['room_type'] ?? 'private';
    $csrfToken = $_POST['csrf_token'] ?? '';
    if (!verifyCsrf($csrfToken)) {
        $error = 'Invalid CSRF token';
    } elseif (!$roomName) {
        $error = 'Please enter room name';
    } else {
        $roomData = [
            'name' => $roomName,
            'preset' => $roomType === 'public' ? 'public_chat' : 'private_chat',
            'visibility' => $roomType,
        ];
        $roomResult = makeMatrixRequest(
            MATRIX_SERVER . '/_matrix/client/r0/createRoom',
            'POST',
            json_encode($roomData),
            [
                'Content-Type: application/json',
                'Authorization: Bearer ' . $_SESSION['admin_token']
            ]
        );
        if (!$roomResult['success']) {
            $error = 'Network error during room creation';
            logAction('failed to create room "' . $roomName . '" - network error');
        } elseif ($roomResult['http_code'] === 200) {
            $roomResp = json_decode($roomResult['response'], true);
            $success = 'Room created successfully. Room ID: ' . htmlspecialchars($roomResp['room_id'] ?? 'unknown');
            logAction('create room "' . $roomName . '" (' . ($roomResp['room_id'] ?? 'unknown') . ')');
        } else {
            $error = 'Failed to create room: ' . $roomResult['response'];
            logAction('failed to create room "' . $roomName . '" - ' . $roomResult['response']);
        }
    }
}

// Handle inviting user to room
if (($_POST['action'] ?? '') === 'invite_to_room' && $isLoggedIn) {
    $inviteRoomId = trim($_POST['invite_room_id'] ?? '');
    $inviteUserId = trim($_POST['invite_user_id'] ?? '');
    $csrfToken = $_POST['csrf_token'] ?? '';
    if (!verifyCsrf($csrfToken)) {
        $error = 'Invalid CSRF token';
    } elseif (!$inviteRoomId || !$inviteUserId) {
        $error = 'Please enter both Room ID and User ID';
    } else {
        $inviteData = [ 'user_id' => $inviteUserId ];
        $inviteResult = makeMatrixRequest(
            MATRIX_SERVER . '/_matrix/client/r0/rooms/' . urlencode($inviteRoomId) . '/invite',
            'POST',
            json_encode($inviteData),
            [
                'Content-Type: application/json',
                'Authorization: Bearer ' . $_SESSION['admin_token']
            ]
        );
        if (!$inviteResult['success']) {
            $error = 'Network error during invite';
            logAction('failed to invite ' . $inviteUserId . ' to room ' . $inviteRoomId . ' - network error');
        } elseif ($inviteResult['http_code'] === 200) {
            $success = 'User ' . htmlspecialchars($inviteUserId) . ' invited to room ' . htmlspecialchars($inviteRoomId);
            logAction('invite ' . $inviteUserId . ' to room ' . $inviteRoomId);
        } else {
            $error = 'Failed to invite user: ' . $inviteResult['response'];
            logAction('failed to invite ' . $inviteUserId . ' to room ' . $inviteRoomId . ' - ' . $inviteResult['response']);
        }
    }
}

// Get users list if logged in
$users = [];
$totalUsers = 0;
$page = 1;
$perPage = 50;
$search = '';

if ($isLoggedIn) {
    // Get pagination and search parameters
    $page = max(1, (int)($_GET['page'] ?? 1));
    $perPage = in_array($_GET['per_page'] ?? 50, [10, 50, 100]) ? (int)$_GET['per_page'] : 50;
    $search = trim($_GET['search'] ?? '');
    $showDeactivated = isset($_GET['show_deactivated']);
    
    // Build API URL with pagination
    $apiUrl = MATRIX_SERVER . '/_synapse/admin/v2/users?limit=' . $perPage . '&from=' . (($page - 1) * $perPage);
    if ($search) {
        $apiUrl .= '&name=' . urlencode($search);
    }
    if ($showDeactivated) {
        $apiUrl .= '&deactivated=true';
    }
    
    $usersResult = makeMatrixRequest(
        $apiUrl,
        'GET',
        null,
        ['Authorization: Bearer ' . $_SESSION['admin_token']]
    );
    
    if ($usersResult['success'] && $usersResult['http_code'] === 200) {
        $data = json_decode($usersResult['response'], true);
        $users = $data['users'] ?? [];
        $totalUsers = $data['total'] ?? count($users);
    } else {
        logAction('failed to fetch users list - ' . ($usersResult['error'] ?? 'unknown error'));
    }
}

$totalPages = ($totalUsers > 0 && $perPage > 0) ? ceil($totalUsers / $perPage) : 1;
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Matrix Admin Panel - <?= MATRIX_DOMAIN ?></title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', 'Menlo', monospace;
            background: #181A20;
            color: #C9D1D9;
            min-height: 100vh;
        }
        .container { max-width: 800px; margin: 0 auto; padding: 50px; }
        .header {
            position: relative;
            text-align: center;
            margin-bottom: 30px;
            padding: 20px;
            background: #23272E;
            border-radius: 10px;
            border: 1px solid #30363D;
        }
        .nav-links {
            position: absolute;
            top: 20px;
            left: 20px;
        }
        .nav-links a,
        .nav-links .btn {
            color: #58A6FF;
            text-decoration: none;
            padding: 8px 16px;
            border: 1px solid #30363D;
            border-radius: 5px;
            margin-right: 10px;
            transition: all 0.3s ease;
            background: #23272E;
            display: inline-block;
            font-size: 14px;
            font-weight: normal;
        }
        .nav-links a:hover,
        .nav-links .btn:hover {
            background: #21262C;
            color: #79C0FF;
        }
        .header h1 {
            font-size: 2.5rem;
            color: #58A6FF;
            text-shadow: 0 0 10px #30363D;
            margin-bottom: 10px;
        }
        .card {
            background: #23272E;
            border: 1px solid #30363D;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 0 20px rgba(40, 50, 60, 0.2);
        }
        .form-group { margin-bottom: 15px; }
        .form-group label {
            display: block;
            margin-bottom: 5px;
            color: #8B949E;
        }
        .form-group input[type="text"],
        .form-group input[type="password"] {
            width: 100%;
            padding: 10px;
            background: #181A20;
            border: 1px solid #30363D;
            border-radius: 5px;
            color: #C9D1D9;
            font-size: 14px;
            margin: 10px 0;
        }
        .checkbox-group {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .btn {
            background: linear-gradient(90deg, #30363D 0%, #21262C 100%);
            color: #58A6FF;
            border: none;
            padding: 12px 24px;
            border-radius: 5px;
            cursor: pointer;
            font-weight: bold;
            transition: all 0.3s ease;
        }
        .btn:hover {
            background: #21262C;
            color: #79C0FF;
            box-shadow: 0 5px 15px rgba(88, 166, 255, 0.1);
        }
        .btn-danger {
            background: linear-gradient(45deg, #ff4444, #cc0000);
            color: #fff;
        }
        .btn-warning {
            background: linear-gradient(45deg, #ffaa00, #cc8800);
            color: #000;
        }
        .btn-info {
            background: linear-gradient(45deg, #0088ff, #0066cc);
            color: #fff;
        }
        .login-form-actions {
            display: flex;
            justify-content: center;
            margin-top: 15px;
        }
        .action-buttons {
            display: flex;
            gap: 5px;
            flex-wrap: wrap;
            align-items: center;
        }
        .action-buttons .btn {
            min-width: 90px;
            text-align: center;
            white-space: nowrap;
        }
        .action-buttons button,
        .action-buttons span {
            padding: 6px 12px;
            font-size: 12px;
            min-width: 80px;
            text-align: center;
            display: inline-block;
        }
        .search-form {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
            align-items: center;
        }
        .search-form input[type="text"] {
            flex: 1;
            padding: 10px;
            background: #181A20;
            border: 1px solid #30363D;
            border-radius: 5px;
            color: #C9D1D9;
        }
        .search-form select {
            padding: 10px;
            background: #181A20;
            border: 1px solid #30363D;
            border-radius: 5px;
            color: #C9D1D9;
        }
        .pagination {
            display: flex;
            justify-content: center;
            align-items: center;
            gap: 10px;
            margin: 20px 0;
        }
        .pagination a, .pagination span {
            padding: 8px 12px;
            border: 1px solid #30363D;
            border-radius: 5px;
            text-decoration: none;
            color: #58A6FF;
        }
        .pagination a:hover {
            background: #21262C;
            color: #79C0FF;
        }
        .pagination .current {
            background: #23272E;
            font-weight: bold;
        }
        .stats {
            text-align: center;
            margin: 10px 0;
            opacity: 0.7;
            font-size: 14px;
        }
        .alert {
            font-size: 12px; 
            padding: 5px;
            border-radius: 5px;
            margin-bottom: 10px;
            margin-top: 10px;
        }
        .alert-success {
            background: #23272E;
            border: 1px solid #30363D;
            color: #58A6FF;
        }
        .alert-error {
            background: #23272E;
            color: #ff4444;
        }
        .users-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        .users-table th,
        .users-table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #30363D;
        }
        .users-table th {
            background: #23272E;
            color: #58A6FF;
            font-weight: bold;
        }
        .users-table tr:hover {
            background: #21262C;
        }
        .status-active { color: #58A6FF; }
        .status-inactive { color: #ff4444; }
        .logout-link {
            position: absolute;
            top: 20px;
            right: 20px;
            color: #ff4444;
            text-decoration: none;
            padding: 8px 16px;
            border: 1px solid #ff4444;
            border-radius: 5px;
            transition: all 0.3s ease;
            font-size: 14px;
            background: #23272E;
        }
        .logout-link:hover {
            background: #21262C;
            color: #ff6666;
        }
        @media (max-width: 768px) {
            .header {
                padding: 15px;
            }
            .header h1 {
                font-size: 2rem;
                margin-bottom: 15px;
            }
            .logout-link {
                position: static;
                display: inline-block;
                margin-top: 15px;
                font-size: 12px;
                padding: 8px 16px;
            }
            .container {
                padding: 10px;
            }
            .users-table {
                font-size: 12px;
            }
            .users-table th,
            .users-table td {
                padding: 8px;
            }
        }
        /* Modal styles */
        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(24, 26, 32, 0.95);
        }
        .modal-content {
            background: #23272E;
            margin: 15% auto;
            padding: 20px;
            border: 1px solid #30363D;
            border-radius: 10px;
            width: 80%;
            max-width: 500px;
            color: #C9D1D9;
        }
        .close {
            color: #ff4444;
            float: right;
            font-size: 28px;
            font-weight: bold;
            cursor: pointer;
        }
        .close:hover {
            color: #ff6666;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <?php if ($isLoggedIn): ?>
                <div class="nav-links">
                    <a href="logs.php">📊 View Logs</a>
                    <form method="POST" style="display: inline-block; margin-left: 10px;">
                        <input type="hidden" name="action" value="export_audit">
                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                        <button type="submit" class="btn">📥 Export CSV</button>
                    </form>
                </div>
            <?php endif; ?>
            <h1>Matrix Admin Panel</h1>
            <p><?= MATRIX_DOMAIN ?> - User Management System</p>
            <?php if ($isLoggedIn): ?>
                <a href="?logout=1" class="logout-link">Logout (<?= htmlspecialchars($_SESSION['admin_user']) ?>)</a>
            <?php endif; ?>
        </div>

        <?php if (isset($error)): ?>
            <div class="alert alert-error"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>

        <?php if (isset($success)): ?>
            <div class="alert alert-success"><?= htmlspecialchars($success) ?></div>
        <?php endif; ?>

        <?php if (isset($_GET['success'])): ?>
            <div class="alert alert-success"><?= htmlspecialchars($_GET['success']) ?></div>
        <?php endif; ?>

        <?php if (!$isLoggedIn): ?>
            <div class="card">
                <h2>Admin Login</h2>
                <?php if (isset($_SESSION['failed_attempts']) && $_SESSION['failed_attempts'] > 0): ?>
                    <div class="alert alert-error">
                        Warning: <?= $_SESSION['failed_attempts'] ?>/<?= MAX_FAILED_ATTEMPTS ?> failed attempts. 
                        <?= (MAX_FAILED_ATTEMPTS - $_SESSION['failed_attempts']) ?> attempts remaining.
                    </div>
                <?php endif; ?>
                <form method="POST">
                    <input type="hidden" name="action" value="login">
                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                    <div class="form-group">
                        <label for="username">Username:</label>
                        <input type="text" id="username" name="username" required>
                    </div>
                    <div class="form-group">
                        <label for="password">Password:</label>
                        <input type="password" id="password" name="password" required>
                    </div>
                    <div class="login-form-actions">
                        <button type="submit" class="btn">Login</button>
                    </div>
                </form>
            </div>
        <?php else: ?>
            <div class="card">
                <h2>Create New User</h2>
                <form method="POST">
                    <input type="hidden" name="action" value="create_user">
                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                    <div class="form-group">
                        <label for="new_username">Username:</label>
                        <input type="text" id="new_username" name="new_username" required placeholder="Enter username (without @domain)">
                    </div>
                    <div class="form-group">
                        <label for="new_password">Password:</label>
                        <input type="password" id="new_password" name="new_password" required>
                    </div>
                    <div class="form-group">
                        <div class="checkbox-group">
                            <input type="checkbox" id="is_admin" name="is_admin">
                            <label for="is_admin">Admin privileges</label>
                        </div>
                    </div>
                    <button type="submit" class="btn">Create User</button>
                </form>
            </div>

            <div class="card">
    <h2>Rooms</h2>

    <form method="GET" class="search-form" style="margin-top:10px;">
        <input type="text" name="r_search" placeholder="Search rooms by name..." value="<?= htmlspecialchars($roomsSearch) ?>">
        <select name="r_per_page">
            <option value="10"  <?= $roomsPerPage == 10  ? 'selected' : '' ?>>10 per page</option>
            <option value="50"  <?= $roomsPerPage == 50  ? 'selected' : '' ?>>50 per page</option>
            <option value="100" <?= $roomsPerPage == 100 ? 'selected' : '' ?>>100 per page</option>
        </select>
        <button type="submit" class="btn">Search</button>
        <?php if ($roomsSearch !== '' || $roomsPerPage != 50): ?>
            <a href="admin.php" class="btn" style="background:#666;">Clear</a>
        <?php endif; ?>
        <!-- сохраняем состояние Users -->
        <input type="hidden" name="page" value="<?= $page ?>">
        <input type="hidden" name="per_page" value="<?= $perPage ?>">
        <?php if (!empty($search)): ?>
            <input type="hidden" name="search" value="<?= htmlspecialchars($search) ?>">
        <?php endif; ?>
        <?php if (!empty($showDeactivated)): ?>
            <input type="hidden" name="show_deactivated" value="1">
        <?php endif; ?>
    </form>

    <div class="stats">
        Showing <?= count($rooms) ?> of <?= $roomsTotal ?> rooms
        <?php if ($roomsSearch !== ''): ?>
            (filtered by "<?= htmlspecialchars($roomsSearch) ?>")
        <?php endif; ?>
    </div>

    <!-- Bulk actions toolbar -->
    <form method="POST" id="roomsBulkForm" onsubmit="return roomsConfirm();">
        <input type="hidden" name="action" value="bulk_rooms">
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
        <!-- вернуть фильтры/пагинацию -->
        <input type="hidden" name="r_page" value="<?= $roomsPage ?>">
        <input type="hidden" name="r_per_page" value="<?= $roomsPerPage ?>">
        <input type="hidden" name="r_search" value="<?= htmlspecialchars($roomsSearch) ?>">
        <input type="hidden" name="page" value="<?= $page ?>">
        <input type="hidden" name="per_page" value="<?= $perPage ?>">
        <?php if (!empty($search)): ?>
            <input type="hidden" name="search" value="<?= htmlspecialchars($search) ?>">
        <?php endif; ?>
        <?php if (!empty($showDeactivated)): ?>
            <input type="hidden" name="show_deactivated" value="1">
        <?php endif; ?>

        <div style="display:flex; gap:10px; align-items:center; margin:10px 0;">
            <select name="bulk_op" id="roomsBulkOp" style="padding:10px; background:#181A20; border:1px solid #30363D; color:#C9D1D9; border-radius:5px;">
                <option value="delete">Delete selected (async)</option>
            </select>
            <button type="submit" class="btn" id="roomsBulkBtn" disabled>Apply to selected</button>
            <div style="font-size:12px; color:#8B949E;">Tip: deletion via v2 is asynchronous.</div>
        </div>

        <table class="users-table">
            <thead>
                <tr>
                    <th style="width:36px; text-align:center;">
                        <input type="checkbox" id="rooms_select_all" onclick="roomsToggleAll(this)">
                    </th>
                    <th>Name</th>
                    <th>Room ID</th>
                    <th>Type</th>
                    <th>Visibility</th>
                    <th>Members</th>
                    <th>Encrypted</th>
                    <th>Creator</th>
                </tr>
            </thead>
            <tbody>
            <?php if (empty($rooms)): ?>
                <tr><td colspan="8" style="text-align:center; color:#8B949E;">No rooms found</td></tr>
            <?php else: ?>
                <?php foreach ($rooms as $room): 
                    $name = $room['name'] ?? '(no name)';
                    $rid  = $room['room_id'] ?? '';
                    $rtype = $room['room_type'] ?? 'room';
                    $vis = ($room['public'] ?? false) ? 'public' : ($room['join_rules'] ?? 'invite');
                    $members = (int)($room['joined_members'] ?? 0);
                    $enc = !empty($room['encryption']) ? 'yes' : 'no';
                    $creator = $room['creator'] ?? 'unknown';
                ?>
                <tr>
                    <td style="text-align:center;">
                        <input type="checkbox" class="room-chk" name="room_ids[]" value="<?= htmlspecialchars($rid) ?>">
                    </td>
                    <td><?= htmlspecialchars($name) ?></td>
                    <td style="font-family:monospace;"><?= htmlspecialchars($rid) ?></td>
                    <td><?= htmlspecialchars($rtype) ?></td>
                    <td><?= htmlspecialchars($vis) ?></td>
                    <td><?= $members ?></td>
                    <td><?= $enc ?></td>
                    <td><?= htmlspecialchars($creator) ?></td>
                </tr>
                <?php endforeach; ?>
            <?php endif; ?>
            </tbody>
        </table>
    </form>

    <?php if ($roomsTotalPages > 1): ?>
        <div class="pagination">
            <?php 
                $rParams = 'r_per_page=' . $roomsPerPage . '&r_search=' . urlencode($roomsSearch);
                $rParams .= '&page=' . $page . '&per_page=' . $perPage;
                if (!empty($search)) $rParams .= '&search=' . urlencode($search);
                if (!empty($showDeactivated)) $rParams .= '&show_deactivated=1';
            ?>
            <?php if ($roomsPage > 1): ?>
                <a href="?r_page=1&<?= $rParams ?>">First</a>
                <a href="?r_page=<?= $roomsPage - 1 ?>&<?= $rParams ?>">Previous</a>
            <?php endif; ?>

            <?php
                $rStart = max(1, $roomsPage - 2);
                $rEnd = min($roomsTotalPages, $roomsPage + 2);
                for ($i = $rStart; $i <= $rEnd; $i++):
            ?>
                <?php if ($i == $roomsPage): ?>
                    <span class="current"><?= $i ?></span>
                <?php else: ?>
                    <a href="?r_page=<?= $i ?>&<?= $rParams ?>"><?= $i ?></a>
                <?php endif; ?>
            <?php endfor; ?>

            <?php if ($roomsPage < $roomsTotalPages): ?>
                <a href="?r_page=<?= $roomsPage + 1 ?>&<?= $rParams ?>">Next</a>
                <a href="?r_page=<?= $roomsTotalPages ?>&<?= $rParams ?>">Last</a>
            <?php endif; ?>
        </div>
    <?php endif; ?>
</div>

                <div class="card">
                    <h2>Create Room</h2>
                    <form method="POST">
                        <input type="hidden" name="action" value="create_room">
                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                        <div class="form-group">
                            <label for="room_name">Room Name:</label>
                            <input type="text" id="room_name" name="room_name" required>
                        </div>
                        <div class="form-group">
                            <label for="room_type">Room Type:</label>
                            <select id="room_type" name="room_type">
                                <option value="private">Private</option>
                                <option value="public">Public</option>
                            </select>
                        </div>
                        <button type="submit" class="btn">Create Room</button>
                    </form>
                </div>

                <div class="card">
                    <h2>Invite User to Room</h2>
                    <form method="POST">
                        <input type="hidden" name="action" value="invite_to_room">
                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                        <div class="form-group">
                            <label for="invite_room_id">Room ID:</label>
                            <input type="text" id="invite_room_id" name="invite_room_id" required>
                        </div>
                        <div class="form-group">
                            <label for="invite_user_id">User ID (@user:domain):</label>
                            <input type="text" id="invite_user_id" name="invite_user_id" required>
                        </div>
                        <button type="submit" class="btn">Invite User</button>
                    </form>
                </div>

            <div class="card">
                <h2>Search Users</h2>
                <form method="GET" class="search-form">
                    <input type="text" name="search" placeholder="Search users by name..." value="<?= htmlspecialchars($search) ?>">
                    <select name="per_page">
                        <option value="10" <?= $perPage == 10 ? 'selected' : '' ?>>10 per page</option>
                        <option value="50" <?= $perPage == 50 ? 'selected' : '' ?>>50 per page</option>
                        <option value="100" <?= $perPage == 100 ? 'selected' : '' ?>>100 per page</option>
                    </select>
                    <div class="checkbox-group">
                        <input type="checkbox" id="show_deactivated" name="show_deactivated" <?= $showDeactivated ? 'checked' : '' ?>>
                        <label for="show_deactivated">Show deactivated users</label>
                    </div>
                    <button type="submit" class="btn">Search</button>
                    <?php if (!empty($search) || $showDeactivated): ?>
                        <a href="admin.php" class="btn" style="background: #666;">Clear</a>
                    <?php endif; ?>
                </form>
            </div>

            <div class="card">
                <h2>Users Management</h2>
                <div class="stats">
                    Showing <?= count($users) ?> of <?= $totalUsers ?> users
                    <?php if (!empty($search)): ?>
                        (filtered by "<?= htmlspecialchars($search) ?>")
                    <?php endif; ?>
                </div>
                <table class="users-table">
                    <thead>
                        <tr>
                            <th>User ID</th>
                            <th>Display Name</th>
                            <th>Admin</th>
                            <th>Status</th>
                            <th>Created</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($users as $user): ?>
                            <tr>
                                <td><?= htmlspecialchars($user['name']) ?></td>
                                <td><?= htmlspecialchars($user['displayname'] ?? 'N/A') ?></td>
                                <td>
                                    <?php if ($user['admin']): ?>
                                        <span style="color: #00ff00;">Admin</span>
                                        <?php if (isSeniorAdmin($user['name'])): ?>
                                            <span style="color: #ffaa00; font-size: 10px;"> (Senior)</span>
                                        <?php endif; ?>
                                    <?php else: ?>
                                        <span style="color: #888;">User</span>
                                    <?php endif; ?>
                                </td>
                                <td class="<?= $user['deactivated'] ? 'status-inactive' : 'status-active' ?>">
                                    <?= $user['deactivated'] ? 'Inactive' : 'Active' ?>
                                </td>
                                <td><?= date('Y-m-d H:i', $user['creation_ts'] / 1000) ?></td>
                                <td>
                                    <div class="action-buttons">
                                        <?php if (!$user['deactivated']): ?>
                                            <?php if (isActionAllowed('deactivate', $user['name'])): ?>
                                                <form method="POST" style="display: inline;">
                                                    <input type="hidden" name="action" value="deactivate_user">
                                                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                                                    <input type="hidden" name="user_id" value="<?= htmlspecialchars($user['name']) ?>">
                                                    <input type="hidden" name="page" value="<?= $page ?>">
                                                    <input type="hidden" name="per_page" value="<?= $perPage ?>">
                                                    <input type="hidden" name="search" value="<?= htmlspecialchars($search) ?>">
                                                    <?php if ($showDeactivated): ?>
                                                        <input type="hidden" name="show_deactivated" value="1">
                                                    <?php endif; ?>
                                                    <button type="submit" class="btn btn-danger" onclick="return confirm('Are you sure you want to deactivate this user?')">Deactivate</button>
                                                </form>
                                            <?php else: ?>
                                                <span class="btn btn-danger" style="background: #666; cursor: not-allowed; opacity: 0.6;" title="Cannot deactivate yourself">Deactivate</span>
                                            <?php endif; ?>
                                        <?php else: ?>
                                            <form method="POST" style="display: inline;">
                                                <input type="hidden" name="action" value="reactivate_user">
                                                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                                                <input type="hidden" name="user_id" value="<?= htmlspecialchars($user['name']) ?>">
                                                <input type="hidden" name="page" value="<?= $page ?>">
                                                <input type="hidden" name="per_page" value="<?= $perPage ?>">
                                                <input type="hidden" name="search" value="<?= htmlspecialchars($search) ?>">
                                                <?php if ($showDeactivated): ?>
                                                    <input type="hidden" name="show_deactivated" value="1">
                                                <?php endif; ?>
                                                <button type="submit" class="btn btn-warning" onclick="return confirm('Are you sure you want to reactivate this user?')">Reactivate</button>
                                            </form>
                                        <?php endif; ?>
                                        
                                        <button type="button" class="btn btn-info" onclick="changePassword('<?= htmlspecialchars($user['name']) ?>')">Change Password</button>
                                        
                                        <?php if (!$user['admin']): ?>
                                            <form method="POST" style="display: inline;">
                                                <input type="hidden" name="action" value="toggle_admin">
                                                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                                                <input type="hidden" name="user_id" value="<?= htmlspecialchars($user['name']) ?>">
                                                <input type="hidden" name="make_admin" value="1">
                                                <input type="hidden" name="page" value="<?= $page ?>">
                                                                                                 <input type="hidden" name="per_page" value="<?= $perPage ?>">
                                                 <input type="hidden" name="search" value="<?= htmlspecialchars($search) ?>">
                                                 <?php if ($showDeactivated): ?>
                                                     <input type="hidden" name="show_deactivated" value="1">
                                                 <?php endif; ?>
                                                 <button type="submit" class="btn" style="background: linear-gradient(45deg, #8800ff, #6600cc);" onclick="return confirm('Are you sure you want to grant admin privileges to this user?')">Make Admin</button>
                                            </form>
                                                                                <?php else: ?>
                                            <?php if (isActionAllowed('remove_admin', $user['name'])): ?>
                                                <form method="POST" style="display: inline;">
                                                    <input type="hidden" name="action" value="toggle_admin">
                                                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                                                    <input type="hidden" name="user_id" value="<?= htmlspecialchars($user['name']) ?>">
                                                    <input type="hidden" name="page" value="<?= $page ?>">
                                                    <input type="hidden" name="per_page" value="<?= $perPage ?>">
                                                    <input type="hidden" name="search" value="<?= htmlspecialchars($search) ?>">
                                                    <?php if ($showDeactivated): ?>
                                                        <input type="hidden" name="show_deactivated" value="1">
                                                    <?php endif; ?>
                                                    <button type="submit" class="btn btn-warning" onclick="return confirm('Are you sure you want to revoke admin privileges from this user?')">Remove Admin</button>
                                                </form>
                                            <?php else: ?>
                                                <span class="btn btn-warning" style="background: #666; cursor: not-allowed; opacity: 0.6;" title="Cannot remove your own admin privileges">Remove Admin</span>
                                            <?php endif; ?>
                                        <?php endif; ?>
                                    </div>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
                
                <?php if ($totalPages > 1): ?>
                    <div class="pagination">
                        <?php 
                        $paginationParams = 'per_page=' . $perPage . '&search=' . urlencode($search);
                        if ($showDeactivated) $paginationParams .= '&show_deactivated=1';
                        ?>
                        <?php if ($page > 1): ?>
                            <a href="?page=1&<?= $paginationParams ?>">First</a>
                            <a href="?page=<?= $page - 1 ?>&<?= $paginationParams ?>">Previous</a>
                        <?php endif; ?>
                        
                        <?php
                        $start = max(1, $page - 2);
                        $end = min($totalPages, $page + 2);
                        for ($i = $start; $i <= $end; $i++):
                        ?>
                            <?php if ($i == $page): ?>
                                <span class="current"><?= $i ?></span>
                            <?php else: ?>
                                <a href="?page=<?= $i ?>&<?= $paginationParams ?>"><?= $i ?></a>
                            <?php endif; ?>
                        <?php endfor; ?>
                        
                        <?php if ($page < $totalPages): ?>
                            <a href="?page=<?= $page + 1 ?>&<?= $paginationParams ?>">Next</a>
                            <a href="?page=<?= $totalPages ?>&<?= $paginationParams ?>">Last</a>
                        <?php endif; ?>
                    </div>
                <?php endif; ?>
            </div>
        <?php endif; ?>
    </div>

    <!-- Password Change Modal -->
    <div id="passwordModal" class="modal">
        <div class="modal-content">
            <span class="close" onclick="closePasswordModal()">&times;</span>
            <h2>Change Password</h2>
            <form method="POST" id="passwordForm">
                <input type="hidden" name="action" value="change_password">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'] ?? '') ?>">
                <input type="hidden" name="user_id" id="modalUserId" value="">
                <input type="hidden" name="page" value="<?= $page ?>">
                <input type="hidden" name="per_page" value="<?= $perPage ?>">
                <input type="hidden" name="search" value="<?= htmlspecialchars($search) ?>">
                <?php if ($showDeactivated): ?>
                    <input type="hidden" name="show_deactivated" value="1">
                <?php endif; ?>
                
                <div class="form-group">
                    <label for="modalNewPassword">New Password:</label>
                    <input type="password" id="modalNewPassword" name="new_password" required minlength="6" placeholder="Minimum 6 characters">
                </div>
                
                <div style="text-align: center; margin-top: 20px;">
                    <button type="submit" class="btn">Change Password</button>
                    <button type="button" class="btn" style="background: #666; margin-left: 10px;" onclick="closePasswordModal()">Cancel</button>
                </div>
            </form>
        </div>
    </div>

    <script>
        function changePassword(userId) {
            document.getElementById('modalUserId').value = userId;
            document.getElementById('modalNewPassword').value = '';
            document.getElementById('passwordModal').style.display = 'block';
            document.getElementById('modalNewPassword').focus();
        }
        
        function closePasswordModal() {
            document.getElementById('passwordModal').style.display = 'none';
        }
        
        // Close modal when clicking outside
        window.onclick = function(event) {
            var modal = document.getElementById('passwordModal');
            if (event.target == modal) {
                closePasswordModal();
            }
        }
        
        // Close modal with Escape key
        document.addEventListener('keydown', function(event) {
            if (event.key === 'Escape') {
                closePasswordModal();
            }
        });
    </script>
    <script>
function roomsToggleAll(cb){
    document.querySelectorAll('.room-chk').forEach(ch => ch.checked = cb.checked);
    roomsUpdateBulkBtn();
}
function roomsUpdateBulkBtn(){
    const any = document.querySelectorAll('.room-chk:checked').length > 0;
    const btn = document.getElementById('roomsBulkBtn');
    if (btn) btn.disabled = !any;
}
function roomsConfirm(){
    const op = document.getElementById('roomsBulkOp')?.value || '';
    const count = document.querySelectorAll('.room-chk:checked').length;
    if (!count) return false;
    if (op === 'delete') {
        return confirm('Request deletion for ' + count + ' room(s)? (async)');
    }
    return true;
}
document.addEventListener('change', function(e){
    if (e.target.classList.contains('room-chk')) roomsUpdateBulkBtn();
});
</script>

</body>
</html> 