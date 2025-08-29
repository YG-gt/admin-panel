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
<style>
  *{box-sizing:border-box}
  body{margin:0; font-family:'JetBrains Mono','Fira Code',monospace; background:#181A20; color:#C9D1D9}
  .layout{display:flex; min-height:100vh}
  .sidebar{
    width:240px; background:#23272E; border-right:1px solid #30363D; padding:20px; position:sticky; top:0; height:100vh;
  }
  .brand{color:#58A6FF; font-size:20px; margin-bottom:20px;}
  .menu a{
    display:block; padding:10px 12px; margin-bottom:8px; text-decoration:none; color:#C9D1D9; border:1px solid #30363D; border-radius:8px;
    background:#1f2229;
  }
  .menu a.active{ background:#2a3038; color:#79C0FF; border-color:#3b4450;}
  .content{flex:1; padding:28px; max-width:1200px; margin:0 auto;}
  .card{background:#23272E; border:1px solid #30363D; border-radius:10px; padding:20px; margin-bottom:20px;}
  .row{display:flex; align-items:center; justify-content:space-between;}
  .btn{background:linear-gradient(90deg,#30363D 0%,#21262C 100%); color:#58A6FF; padding:10px 18px; border:none; border-radius:6px; cursor:pointer}
  .logout{color:#ff6666; text-decoration:none; border:1px solid #ff4444; padding:8px 12px; border-radius:6px}
</style>
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
