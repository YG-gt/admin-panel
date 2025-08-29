<?php
// users.php
// Логин/логаут
if (isset($_GET['logout'])) {
    if (isLoggedIn()) logAction('logout');
    session_destroy();
    header('Location: index.php?page=users');
    exit;
}

$error = $success = null;

// LOGIN
if (($_POST['action'] ?? '') === 'login' && !isLoggedIn()) {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    if (!verifyCsrf($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid CSRF token';
        usleep(LOGIN_DELAY_MICROSECONDS);
    } elseif (!checkRate()) {
        $error = 'Too many failed attempts';
        usleep(LOGIN_DELAY_MICROSECONDS);
    } elseif (!$username || !$password) {
        $error = 'Enter username and password';
        incFail(); usleep(LOGIN_DELAY_MICROSECONDS);
    } elseif (!validateUsername($username)) {
        $error = 'Invalid username format';
        incFail(); usleep(LOGIN_DELAY_MICROSECONDS);
    } else {
        // 1) login
        $loginData = json_encode(['type'=>'m.login.password','user'=>$username,'password'=>$password]);
        $res = makeMatrixRequest(MATRIX_SERVER.'/_matrix/client/r0/login','POST',$loginData,['Content-Type: application/json']);
        if (!$res['success'] || $res['http_code'] !== 200) { $error='Invalid username or password'; incFail(); }
        else {
            $data = json_decode($res['response'], true);
            $token = $data['access_token'] ?? '';
            if (!$token) { $error='Invalid server response'; incFail(); }
            else {
                // 2) check admin
                $adm = makeMatrixRequest(
                    MATRIX_SERVER.'/_synapse/admin/v1/users/@'.$username.':'.MATRIX_DOMAIN.'/admin',
                    'GET', null, ['Authorization: Bearer '.$token]
                );
                if ($adm['success'] && $adm['http_code']===200 && (json_decode($adm['response'],true)['admin']??false)) {
                    $_SESSION['admin_token'] = $token;
                    $_SESSION['admin_user']  = '@'.$username.':'.MATRIX_DOMAIN;
                    resetFail();
                    logAction('login ok');
                    header('Location: index.php?page=users');
                    exit;
                } else { $error='Access denied: admin only'; incFail(); }
            }
        }
    }
}

// Дальше — весь CRUD пользователей показываем только авторизованным
if (!isLoggedIn()):
?>
<div class="card">
  <h2>Admin Login</h2>
  <?php if ($error): ?><div style="color:#ff6666; margin:10px 0;"><?= htmlspecialchars($error) ?></div><?php endif; ?>
  <?php if (($fa = (int)($_SESSION['failed_attempts']??0))>0): ?>
    <div style="color:#ff6666; margin:10px 0; font-size:12px;">
      Warning: <?= $fa ?>/<?= MAX_FAILED_ATTEMPTS ?> failed attempts. <?= (MAX_FAILED_ATTEMPTS-$fa) ?> left.
    </div>
  <?php endif; ?>
  <form method="POST" style="max-width:420px">
    <input type="hidden" name="action" value="login">
    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrf_token()) ?>">
    <div style="margin:10px 0">
      <label>Username</label>
      <input name="username" required style="width:100%;padding:10px;background:#181A20;border:1px solid #30363D;border-radius:6px;color:#C9D1D9">
    </div>
    <div style="margin:10px 0">
      <label>Password</label>
      <input type="password" name="password" required style="width:100%;padding:10px;background:#181A20;border:1px solid #30363D;border-radius:6px;color:#C9D1D9">
    </div>
    <div style="display:flex;justify-content:center;margin-top:12px;">
      <button class="btn" type="submit">Login</button>
    </div>
  </form>
</div>
<?php
return; // не показываем нижее
endif;

// ===== Ниже: действия с пользователями (создание, deactivate/reactivate, toggle admin, change password)
$error = $_GET['error']  ?? $error;
$success = $_GET['success'] ?? $success;

// CREATE user
if (($_POST['action'] ?? '') === 'create_user') {
    if (!verifyCsrf($_POST['csrf_token'] ?? '')) $error='Invalid CSRF token';
    else {
        $u = trim($_POST['new_username'] ?? ''); $p = $_POST['new_password'] ?? ''; $isAdmin = isset($_POST['is_admin']);
        if (!$u || !$p) $error='Enter username & password';
        elseif (!validateUsername($u)) $error='Invalid username format';
        elseif (strlen($p) < 6) $error='Password too short';
        else {
            $data = json_encode(['password'=>$p,'admin'=>$isAdmin]);
            $r = makeMatrixRequest(MATRIX_SERVER.'/_synapse/admin/v2/users/@'.$u.':'.MATRIX_DOMAIN,'PUT',$data,[
                'Content-Type: application/json','Authorization: Bearer '.$_SESSION['admin_token']
            ]);
            if ($r['success'] && in_array($r['http_code'],[200,201],true)) { $success='User created'; logAction('create user @'.$u.':'.MATRIX_DOMAIN.($isAdmin?' (admin)':'')); }
            else $error='Create failed: '.($r['response']??$r['error']??'');
        }
    }
}

// Deactivate/Reactivate/Toggle admin/Change password — как у тебя было.
// (Чтобы не раздувать ответ, оставляю ту же логику, которую ты уже использовал — можешь перенести блоки 1:1.)

// Получение списка пользователей (пагинация + поиск)
$page = max(1,(int)($_GET['page']??1));
$perPage = in_array((int)($_GET['per_page']??50),[10,50,100]) ? (int)($_GET['per_page']) : 50;
$search = trim($_GET['search'] ?? '');
$showDeactivated = isset($_GET['show_deactivated']);
$apiUrl = MATRIX_SERVER.'/_synapse/admin/v2/users?limit='.$perPage.'&from='.(($page-1)*$perPage);
if ($search) $apiUrl .= '&name='.urlencode($search);
if ($showDeactivated) $apiUrl .= '&deactivated=true';
$r = makeMatrixRequest($apiUrl,'GET',null,['Authorization: Bearer '.$_SESSION['admin_token']]);
$users=[]; $total=0;
if ($r['success'] && $r['http_code']===200) {
  $d = json_decode($r['response'],true);
  $users = $d['users'] ?? [];
  $total = (int)($d['total'] ?? count($users));
}
$totalPages = max(1, (int)ceil($total/$perPage));
?>

<?php if ($error): ?><div class="card" style="border-color:#ff4444;color:#ff6666;"><?= htmlspecialchars($error) ?></div><?php endif; ?>
<?php if ($success): ?><div class="card" style="border-color:#30363D;color:#79C0FF;"><?= htmlspecialchars($success) ?></div><?php endif; ?>

<div class="card">
  <h2>Create New User</h2>
  <form method="POST">
    <input type="hidden" name="action" value="create_user">
    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrf_token()) ?>">
    <div style="display:grid; grid-template-columns:1fr 1fr auto; gap:10px;">
      <input name="new_username" placeholder="username (without @domain)" required
             style="padding:10px;background:#181A20;border:1px solid #30363D;border-radius:6px;color:#C9D1D9">
      <input type="password" name="new_password" placeholder="password" required
             style="padding:10px;background:#181A20;border:1px solid #30363D;border-radius:6px;color:#C9D1D9">
      <label style="display:flex;align-items:center;gap:8px;">
        <input type="checkbox" name="is_admin"> Admin
      </label>
    </div>
    <div style="margin-top:10px"><button class="btn">Create</button></div>
  </form>
</div>

<div class="card">
  <h2>Users Management</h2>

  <form method="GET" style="display:flex; gap:10px; margin:10px 0;">
    <input type="hidden" name="page" value="users">
    <input name="search" placeholder="Search…" value="<?= htmlspecialchars($search) ?>"
           style="flex:1;padding:10px;background:#181A20;border:1px solid #30363D;border-radius:6px;color:#C9D1D9">
    <select name="per_page" style="padding:10px;background:#181A20;border:1px solid #30363D;border-radius:6px;color:#C9D1D9">
      <option <?= $perPage==10?'selected':'' ?> value="10">10</option>
      <option <?= $perPage==50?'selected':'' ?> value="50">50</option>
      <option <?= $perPage==100?'selected':'' ?> value="100">100</option>
    </select>
    <label style="display:flex;align-items:center;gap:6px;">
      <input type="checkbox" name="show_deactivated" <?= $showDeactivated?'checked':'' ?>> show deactivated
    </label>
    <button class="btn">Search</button>
    <?php if ($search || $showDeactivated || $perPage!=50): ?>
      <a class="btn" href="index.php?page=users" style="background:#666">Clear</a>
    <?php endif; ?>
  </form>

  <div style="opacity:.7;margin:8px 0;">Showing <?= count($users) ?> of <?= $total ?> users</div>

  <table style="width:100%;border-collapse:collapse">
    <thead>
      <tr style="border-bottom:1px solid #30363D;color:#58A6FF">
        <th style="text-align:left;padding:10px">User ID</th>
        <th style="text-align:left;padding:10px">Display Name</th>
        <th style="text-align:left;padding:10px">Admin</th>
        <th style="text-align:left;padding:10px">Status</th>
        <th style="text-align:left;padding:10px">Created</th>
        <th style="text-align:left;padding:10px">Actions</th>
      </tr>
    </thead>
    <tbody>
      <?php if (!$users): ?>
        <tr><td colspan="6" style="padding:14px;opacity:.7;text-align:center">No users</td></tr>
      <?php else: foreach ($users as $u):
        $uid = $u['name']; $isAdm = !empty($u['admin']); $dead = !empty($u['deactivated']);
        $created = !empty($u['creation_ts']) ? date('Y-m-d H:i', $u['creation_ts']/1000) : '—';
      ?>
      <tr style="border-bottom:1px solid #30363D">
        <td style="padding:10px"><?= htmlspecialchars($uid) ?></td>
        <td style="padding:10px"><?= htmlspecialchars($u['displayname'] ?? 'N/A') ?></td>
        <td style="padding:10px"><?= $isAdm ? '<span style="color:#00ff88">Admin</span>' : '<span style="color:#888">User</span>' ?></td>
        <td style="padding:10px"><?= $dead ? '<span style="color:#ff6666">Inactive</span>' : '<span style="color:#58A6FF">Active</span>' ?></td>
        <td style="padding:10px"><?= $created ?></td>
        <td style="padding:10px">
          <!-- сюда перенеси твои формы Deactivate/Reactivate/Change password/Toggle admin как в прежнем коде -->
          <!-- я опустил их ради компактности ответа -->
        </td>
      </tr>
      <?php endforeach; endif; ?>
    </tbody>
  </table>

  <?php if ($totalPages>1): ?>
    <div style="display:flex;gap:8px;justify-content:center;margin-top:14px">
      <?php
        $base = 'index.php?page=users&per_page='.$perPage.'&search='.urlencode($search).($showDeactivated?'&show_deactivated=1':'');
        if ($page>1) echo '<a class="btn" href="'.$base.'&page=1">First</a><a class="btn" href="'.$base.'&page='.($page-1).'">Prev</a>';
        for ($i=max(1,$page-2);$i<=min($totalPages,$page+2);$i++){
          if ($i==$page) echo '<span class="btn" style="background:#2a3038;cursor:default">'.$i.'</span>';
          else echo '<a class="btn" href="'.$base.'&page='.$i.'">'.$i.'</a>';
        }
        if ($page<$totalPages) echo '<a class="btn" href="'.$base.'&page='.($page+1).'">Next</a><a class="btn" href="'.$base.'&page='.$totalPages.'">Last</a>';
      ?>
    </div>
  <?php endif; ?>
</div>
