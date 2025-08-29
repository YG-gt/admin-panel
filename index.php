<?php
require __DIR__ . '/bootstrap.php';

// router: ?page=users|rooms (по умолчанию users)
$view = $_GET['page'] ?? 'users';
$allowed = ['users','rooms'];
if (!in_array($view, $allowed, true)) $view = 'users';
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Matrix Admin Panel - <?= htmlspecialchars(MATRIX_DOMAIN) ?></title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link rel="stylesheet" href="style.css">
</head>
<body>
<div class="layout">
  <aside class="sidebar">
    <div class="brand">Matrix Admin</div>

    <div class="menu">
      <a href="index.php?page=users" class="<?= $view==='users'?'active':'' ?>">👤 Users</a>
      <a href="index.php?page=rooms" class="<?= $view==='rooms'?'active':'' ?>"># Rooms</a>
    </div>

    <div style="margin-top:auto">
      <?php if (isLoggedIn()): ?>
        <div style="font-size:12px; opacity:.8; margin-bottom:10px;">
          <?= htmlspecialchars(currentUser()) ?>
        </div>
        <a class="logout" href="index.php?page=users&logout=1">Logout</a>
      <?php endif; ?>
    </div>
  </aside>

  <main class="content">
    <div class="card row">
      <h1 style="color:#58A6FF;margin:0;">Matrix Admin Panel — <?= htmlspecialchars(MATRIX_DOMAIN) ?></h1>
      <?php if (!isLoggedIn()): ?>
        <div style="font-size:12px;opacity:.8">please login</div>
      <?php endif; ?>
    </div>

    <?php
      // Подключаем выбранную страницу
      if ($view === 'users') {
          include __DIR__ . '/users.php';
      } else {
          include __DIR__ . '/rooms.php';
      }
    ?>
  </main>
</div>
</body>
</html>
