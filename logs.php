<?php
session_start();

// Load configuration
$config = parse_ini_file(__DIR__ . '/config.ini', true);
if (!$config) {
    die('Configuration file not found or invalid');
}

define('MATRIX_DOMAIN', $config['matrix']['domain']);
define('LOG_FILE', $config['security']['log_file']);

// Check if admin is logged in
$isLoggedIn = isset($_SESSION['admin_token']);

if (!$isLoggedIn) {
    header('Location: admin.php');
    exit;
}

// Get pagination parameters
$page = max(1, (int)($_GET['page'] ?? 1));
$perPageParam = $_GET['per_page'] ?? 10;
$perPage = in_array($perPageParam, [10, 50, 100]) ? (int)$perPageParam : 10;
$search = trim($_GET['search'] ?? '');



// Read and process log file
$logs = [];
$totalLogs = 0;

if (file_exists(LOG_FILE)) {
    $logContent = file_get_contents(LOG_FILE);
    if ($logContent !== false) {
        $allLogs = array_reverse(explode("\n", trim($logContent)));
        
        // Remove empty lines
        $allLogs = array_filter($allLogs, function($log) {
            return trim($log) !== '';
        });
        
        // Reset array keys after filtering
        $allLogs = array_values($allLogs);
        
        // Filter logs by search term
        if ($search) {
            $allLogs = array_filter($allLogs, function($log) use ($search) {
                return stripos($log, $search) !== false;
            });
            // Reset keys again after search filtering
            $allLogs = array_values($allLogs);
        }
        
        $totalLogs = count($allLogs);
        $offset = ($page - 1) * $perPage;
        $logs = array_slice($allLogs, $offset, $perPage);
    }
}

$totalPages = ($totalLogs > 0 && $perPage > 0) ? ceil($totalLogs / $perPage) : 1;
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Action Logs - <?= MATRIX_DOMAIN ?></title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #0f0f0f 0%, #1a1a1a 100%);
            color: #00ff00;
            min-height: 100vh;
        }
        
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        
        .header {
            position: relative;
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
        
        .nav-links {
            position: absolute;
            top: 20px;
            left: 20px;
        }
        
        .nav-links a {
            color: #00ff00;
            text-decoration: none;
            padding: 8px 16px;
            border: 1px solid #00ff00;
            border-radius: 5px;
            margin-right: 10px;
            transition: all 0.3s ease;
        }
        
        .nav-links a:hover {
            background: rgba(0, 255, 0, 0.2);
        }
        
        .logout-link {
            position: absolute;
            top: 20px;
            right: 20px;
            color: #ff4444;
            text-decoration: none;
            padding: 10px 20px;
            border: 1px solid #ff4444;
            border-radius: 5px;
            font-size: 14px;
        }
        
        .logout-link:hover {
            background: rgba(255, 68, 68, 0.2);
        }
        
        .card {
            background: rgba(0, 0, 0, 0.8);
            border: 1px solid #00ff00;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 0 20px rgba(0, 255, 0, 0.2);
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
            background: rgba(0, 0, 0, 0.7);
            border: 1px solid #00ff00;
            border-radius: 5px;
            color: #00ff00;
        }
        
        .search-form select {
            padding: 10px;
            background: rgba(0, 0, 0, 0.7);
            border: 1px solid #00ff00;
            border-radius: 5px;
            color: #00ff00;
        }
        
        .btn {
            background: linear-gradient(45deg, #00ff00, #00cc00);
            color: #000;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            font-weight: bold;
            text-decoration: none;
            display: inline-block;
        }
        
        .log-container {
            background: rgba(0, 0, 0, 0.5);
            border: 1px solid #00ff00;
            border-radius: 5px;
            padding: 15px;
            max-height: 600px;
            overflow-y: auto;
            font-family: monospace;
            font-size: 12px;
            white-space: pre-line;
            margin-bottom: 20px;
        }
        
        .log-entry {
            padding: 5px 0;
            border-bottom: 1px solid rgba(0, 255, 0, 0.1);
        }
        
        .log-entry:last-child {
            border-bottom: none;
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
            border: 1px solid #00ff00;
            border-radius: 5px;
            text-decoration: none;
            color: #00ff00;
        }
        
        .pagination a:hover {
            background: rgba(0, 255, 0, 0.2);
        }
        
        .pagination .current {
            background: rgba(0, 255, 0, 0.3);
            font-weight: bold;
        }
        
        .stats {
            text-align: center;
            margin: 10px 0;
            opacity: 0.7;
            font-size: 14px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="nav-links">
                <a href="admin.php">← Back to Admin</a>
            </div>
            <h1>Action Logs</h1>
            <p><?= MATRIX_DOMAIN ?> - Activity Monitor</p>
            <a href="admin.php?logout=1" class="logout-link">Logout (<?= htmlspecialchars($_SESSION['admin_user']) ?>)</a>
        </div>

        <div class="card">
            <h2>Search & Filter</h2>
            <form method="GET" class="search-form">
                <input type="text" name="search" placeholder="Search logs..." value="<?= htmlspecialchars($search) ?>">
                <select name="per_page">
                    <option value="10" <?= $perPage == 10 ? 'selected' : '' ?>>10 per page</option>
                    <option value="50" <?= $perPage == 50 ? 'selected' : '' ?>>50 per page</option>
                    <option value="100" <?= $perPage == 100 ? 'selected' : '' ?>>100 per page</option>
                </select>
                <button type="submit" class="btn">Search</button>
                <?php if ($search): ?>
                    <a href="logs.php" class="btn" style="background: #666;">Clear</a>
                <?php endif; ?>
            </form>
        </div>

        <div class="card">
            <h2>Activity Log</h2>
            <div class="stats">
                Showing <?= count($logs) ?> of <?= $totalLogs ?> entries
                <?php if ($search): ?>
                    (filtered by "<?= htmlspecialchars($search) ?>")
                <?php endif; ?>
            </div>
            
            <?php if (empty($logs) && $totalLogs == 0): ?>
                <p style="text-align: center; opacity: 0.7; padding: 50px;">
                    <?= $search ? 'No logs found matching your search.' : 'No logs available.' ?>
                </p>
            <?php elseif (empty($logs) && $totalLogs > 0): ?>
                <p style="text-align: center; opacity: 0.7; padding: 50px;">
                    No logs on this page. Try page 1.
                </p>
            <?php else: ?>
                <div class="log-container">
                    <?php foreach ($logs as $log): ?>
                        <div class="log-entry"><?= htmlspecialchars($log) ?></div>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>
            
            <?php if ($totalPages > 1): ?>
                <div class="pagination">
                    <?php if ($page > 1): ?>
                        <a href="?page=1&per_page=<?= $perPage ?>&search=<?= urlencode($search) ?>">First</a>
                        <a href="?page=<?= $page - 1 ?>&per_page=<?= $perPage ?>&search=<?= urlencode($search) ?>">Previous</a>
                    <?php endif; ?>
                    
                    <?php
                    $start = max(1, $page - 2);
                    $end = min($totalPages, $page + 2);
                    for ($i = $start; $i <= $end; $i++):
                    ?>
                        <?php if ($i == $page): ?>
                            <span class="current"><?= $i ?></span>
                        <?php else: ?>
                            <a href="?page=<?= $i ?>&per_page=<?= $perPage ?>&search=<?= urlencode($search) ?>"><?= $i ?></a>
                        <?php endif; ?>
                    <?php endfor; ?>
                    
                    <?php if ($page < $totalPages): ?>
                        <a href="?page=<?= $page + 1 ?>&per_page=<?= $perPage ?>&search=<?= urlencode($search) ?>">Next</a>
                        <a href="?page=<?= $totalPages ?>&per_page=<?= $perPage ?>&search=<?= urlencode($search) ?>">Last</a>
                    <?php endif; ?>
                </div>
            <?php endif; ?>
        </div>
        
        <div style="text-align: center; margin-top: 30px; opacity: 0.7;">
            <p>Created with ❤️ by <a href="https://www.easypro.tech" style="color: #00aa00;">www.easypro.tech</a></p>
        </div>
    </div>
</body>
</html> 