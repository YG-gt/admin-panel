<?php
session_start();

// Load configuration
$config = parse_ini_file(__DIR__ . '/config.ini', true);
if (!$config) {
    die('Configuration file not found or invalid');
}

define('MATRIX_SERVER', $config['matrix']['server']);
define('MATRIX_DOMAIN', $config['matrix']['domain']);

// Check if admin is logged in
$isLoggedIn = isset($_SESSION['admin_token']) && !empty($_SESSION['admin_token']);

// Handle logout
if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: index.php');
    exit;
}

// Handle login
if (($_POST['action'] ?? '') === 'login' && !$isLoggedIn) {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    
    if ($username && $password) {
        $loginData = [
            'type' => 'm.login.password',
            'user' => $username,
            'password' => $password
        ];
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, MATRIX_SERVER . '/_matrix/client/r0/login');
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($loginData));
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        if ($httpCode === 200) {
            $data = json_decode($response, true);
            $token = $data['access_token'] ?? '';
            
            // Check if user is admin
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, MATRIX_SERVER . '/_synapse/admin/v1/users/@' . $username . ':' . MATRIX_DOMAIN . '/admin');
            curl_setopt($ch, CURLOPT_HTTPHEADER, ['Authorization: Bearer ' . $token]);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            
            $adminResponse = curl_exec($ch);
            $adminHttpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);
            
            if ($adminHttpCode === 200) {
                $adminData = json_decode($adminResponse, true);
                if ($adminData['admin'] === true) {
                    $_SESSION['admin_token'] = $token;
                    $_SESSION['admin_user'] = '@' . $username . ':' . MATRIX_DOMAIN;
                    header('Location: index.php');
                    exit;
                } else {
                    $error = 'Access denied: Admin privileges required';
                }
            } else {
                $error = 'Failed to verify admin status';
            }
        } else {
            $error = 'Invalid username or password';
        }
    } else {
        $error = 'Please enter username and password';
    }
}

// Handle user creation
if (($_POST['action'] ?? '') === 'create_user' && $isLoggedIn) {
    $newUsername = $_POST['new_username'] ?? '';
    $newPassword = $_POST['new_password'] ?? '';
    $isAdmin = isset($_POST['is_admin']) ? true : false;
    
    if ($newUsername && $newPassword) {
        $userData = [
            'password' => $newPassword,
            'admin' => $isAdmin
        ];
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, MATRIX_SERVER . '/_synapse/admin/v2/users/@' . $newUsername . ':' . MATRIX_DOMAIN);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'PUT');
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($userData));
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Content-Type: application/json',
            'Authorization: Bearer ' . $_SESSION['admin_token']
        ]);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        if ($httpCode === 200 || $httpCode === 201) {
            $success = 'User created successfully';
        } else {
            $error = 'Failed to create user: ' . $response;
        }
    } else {
        $error = 'Please enter username and password';
    }
}

// Handle user deactivation
if (($_POST['action'] ?? '') === 'deactivate_user' && $isLoggedIn) {
    $userId = $_POST['user_id'] ?? '';
    
    if ($userId) {
        $deactivateData = ['deactivated' => true];
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, MATRIX_SERVER . '/_synapse/admin/v2/users/' . urlencode($userId));
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'PUT');
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($deactivateData));
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Content-Type: application/json',
            'Authorization: Bearer ' . $_SESSION['admin_token']
        ]);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        if ($httpCode === 200) {
            $success = 'User deactivated successfully';
        } else {
            $error = 'Failed to deactivate user: ' . $response;
        }
    }
}

// Get users list if logged in
$users = [];
if ($isLoggedIn) {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, MATRIX_SERVER . '/_synapse/admin/v2/users');
    curl_setopt($ch, CURLOPT_HTTPHEADER, ['Authorization: Bearer ' . $_SESSION['admin_token']]);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    if ($httpCode === 200) {
        $data = json_decode($response, true);
        $users = $data['users'] ?? [];
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Matrix Admin Panel - <?= MATRIX_DOMAIN ?></title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #0f0f0f 0%, #1a1a1a 100%);
            color: #00ff00;
            min-height: 100vh;
            margin: 0;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        
        .header {
            text-align: center;
            margin-bottom: 30px;
            padding: 20px;
            background: rgba(0, 255, 0, 0.1);
            border-radius: 10px;
            border: 1px solid #00ff00;
        }
        
        .header h1 {
            font-size: 2.5rem;
            text-shadow: 0 0 10px #00ff00;
            margin-bottom: 10px;
        }
        
        .card {
            background: rgba(0, 0, 0, 0.8);
            border: 1px solid #00ff00;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 0 20px rgba(0, 255, 0, 0.2);
        }
        
        .btn {
            background: linear-gradient(45deg, #00ff00, #00cc00);
            color: #000;
            border: none;
            padding: 12px 24px;
            border-radius: 5px;
            cursor: pointer;
            font-weight: bold;
            transition: all 0.3s ease;
        }
        
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0, 255, 0, 0.3);
        }
        
        input[type="text"], input[type="password"] {
            width: 100%;
            padding: 10px;
            background: rgba(0, 0, 0, 0.7);
            border: 1px solid #00ff00;
            border-radius: 5px;
            color: #00ff00;
            margin: 10px 0;
        }
        
        label {
            color: #00cc00;
            display: block;
            margin-top: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Matrix Admin Panel</h1>
            <p><?= MATRIX_DOMAIN ?> - User Management System</p>
        </div>

        <div class="card">
            <h2>Welcome to Matrix Admin Panel</h2>
            <p>This application allows authorized administrators to manage Matrix users on <?= MATRIX_DOMAIN ?> server.</p>
            <p>Features:</p>
            <ul>
                <li>Create new users</li>
                <li>Deactivate existing users</li>
                <li>View user statistics</li>
                <li>Admin authentication required</li>
            </ul>
            <br>
            <a href="admin.php" class="btn">Access Admin Panel</a>
        </div>
        
        <div style="text-align: center; margin-top: 30px; opacity: 0.7;">
            <p>Created with ❤️ by <a href="https://www.easypro.tech" style="color: #00aa00;">www.easypro.tech</a></p>
        </div>
    </div>
</body>
</html> 