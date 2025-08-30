<?php

if (!function_exists('isLoggedIn')) { require __DIR__ . '/bootstrap.php'; }
require_login();

$error   = isset($_GET['error'])   ? $_GET['error']   : null;
$success = isset($_GET['success']) ? $_GET['success'] : null;

/* ---------- helpers ---------- */
function users_redirect_with_state($extra = array()) {
    $params = array(
        'page'             => 'users',
        'page_num'         => isset($_GET['page_num']) ? $_GET['page_num'] : 1,
        'per_page'         => isset($_GET['per_page']) ? $_GET['per_page'] : 50,
        'search'           => isset($_GET['search']) ? $_GET['search'] : '',
        'show_deactivated' => isset($_GET['show_deactivated']) ? '1' : null,
    );
    foreach ($extra as $k => $v) { $params[$k] = $v; }
    // remove nulls
    $clean = array();
    foreach ($params as $k => $v) { if ($v !== null) $clean[$k] = $v; }
    header('Location: index.php?' . http_build_query($clean));
    exit;
}

function http_fail_msg($res, $fallback) {
    $code = isset($res['http_code']) ? (int)$res['http_code'] : 0;
    $body = isset($res['response']) ? (string)$res['response'] : (isset($res['error']) ? (string)$res['error'] : '');
    if ($body !== '') { $body = substr($body, 0, 300); }
    $tail = ($code ? 'HTTP '.$code : '') . ($body !== '' ? ' / '.$body : '');
    return $fallback . ($tail ? ' — '.$tail : '');
}

/* ---------- actions ---------- */
// Create
if (isset($_POST['action']) && $_POST['action'] === 'create_user') {
    if (!verifyCsrf(isset($_POST['csrf_token']) ? $_POST['csrf_token'] : '')) {
        $error = 'Invalid CSRF token';
    } else {
        $u = trim(isset($_POST['new_username']) ? $_POST['new_username'] : '');
        $p = (string)(isset($_POST['new_password']) ? $_POST['new_password'] : '');
        $isAdmin = !empty($_POST['is_admin']);

        if ($u === '' || $p === '') {
            $error = 'Please enter username and password';
        } elseif (!validateUsername($u)) {
            $error = 'Invalid username format';
        } elseif (strlen($p) < 6) {
            $error = 'Password must be at least 6 characters';
        } else {
            $payload = json_encode(array('password'=>$p,'admin'=>$isAdmin));
            $res = makeMatrixRequest(
                MATRIX_SERVER.'/_synapse/admin/v2/users/@'.$u.':'.MATRIX_DOMAIN,
                'PUT',
                $payload,
                array('Content-Type: application/json','Authorization: Bearer '.$_SESSION['admin_token'])
            );
            if (!empty($res['success']) && in_array((int)$res['http_code'], array(200,201), true)) {
                logAction('create user @'.$u.':'.MATRIX_DOMAIN.($isAdmin?' (admin)':''));
                users_redirect_with_state(array('success'=>'User created'));
            } else {
                $error = http_fail_msg($res, 'Failed to create user');
            }
        }
    }
}

// Deactivate
if (isset($_POST['action']) && $_POST['action'] === 'deactivate_user') {
    if (!verifyCsrf(isset($_POST['csrf_token']) ? $_POST['csrf_token'] : '')) {
        $error='Invalid CSRF token';
    } else {
        $uid = (string)(isset($_POST['user_id']) ? $_POST['user_id'] : '');
        if ($uid === (isset($_SESSION['admin_user']) ? $_SESSION['admin_user'] : '')) {
            $error='Cannot deactivate yourself';
        } elseif ($uid !== '') {
            $res = makeMatrixRequest(
                MATRIX_SERVER.'/_synapse/admin/v2/users/'.rawurlencode($uid),
                'PUT',
                json_encode(array('deactivated'=>true)),
                array('Content-Type: application/json','Authorization: Bearer '.$_SESSION['admin_token'])
            );
            if (!empty($res['success']) && (int)$res['http_code']===200) {
                logAction('deactivate '.$uid);
                users_redirect_with_state(array('success'=>'User deactivated'));
            } else {
                $error = http_fail_msg($res,'Failed to deactivate');
            }
        }
    }
}

// Reactivate
if (isset($_POST['action']) && $_POST['action'] === 'reactivate_user') {
    if (!verifyCsrf(isset($_POST['csrf_token']) ? $_POST['csrf_token'] : '')) {
        $error='Invalid CSRF token';
    } else {
        $uid = (string)(isset($_POST['user_id']) ? $_POST['user_id'] : '');
        if ($uid !== '') {
            $res = makeMatrixRequest(
                MATRIX_SERVER.'/_synapse/admin/v2/users/'.rawurlencode($uid),
                'PUT',
                json_encode(array('deactivated'=>false)),
                array('Content-Type: application/json','Authorization: Bearer '.$_SESSION['admin_token'])
            );
            if (!empty($res['success']) && (int)$res['http_code']===200) {
                logAction('reactivate '.$uid);
                users_redirect_with_state(array('success'=>'User reactivated'));
            } else {
                $error = http_fail_msg($res,'Failed to reactivate');
            }
        }
    }
}

// Toggle admin
if (isset($_POST['action']) && $_POST['action'] === 'toggle_admin') {
    if (!verifyCsrf(isset($_POST['csrf_token']) ? $_POST['csrf_token'] : '')) {
        $error='Invalid CSRF token';
    } else {
        $uid  = (string)(isset($_POST['user_id']) ? $_POST['user_id'] : '');
        $make = !empty($_POST['make_admin']);
        if (!$make && $uid === (isset($_SESSION['admin_user']) ? $_SESSION['admin_user'] : '')) {
            $error='Cannot remove your own admin privileges';
        } elseif ($uid !== '') {
            $res = makeMatrixRequest(
                MATRIX_SERVER.'/_synapse/admin/v2/users/'.rawurlencode($uid),
                'PUT',
                json_encode(array('admin'=>$make)),
                array('Content-Type: application/json','Authorization: Bearer '.$_SESSION['admin_token'])
            );
            if (!empty($res['success']) && (int)$res['http_code']===200) {
                logAction(($make?'grant':'revoke').' admin '.$uid);
                users_redirect_with_state(array('success'=>$make?'Admin granted':'Admin revoked'));
            } else {
                $error = http_fail_msg($res,'Failed to change admin');
            }
        }
    }
}

// Change password
// Change password (v2 preferred, fallback to v1)
if (isset($_POST['action']) && $_POST['action'] === 'change_password') {
    if (!verifyCsrf(isset($_POST['csrf_token']) ? $_POST['csrf_token'] : '')) {
        $error = 'Invalid CSRF token';
    } else {
        $uid = (string)(isset($_POST['user_id']) ? $_POST['user_id'] : '');
        $npw = (string)(isset($_POST['new_password']) ? $_POST['new_password'] : '');
        if (strlen($npw) < 6) {
            $error = 'Password must be at least 6 characters';
        } elseif ($uid !== '') {

            // 1) v2 modify user
            $payloadV2 = json_encode(array('password' => $npw, 'logout_devices' => true));
            $res = makeMatrixRequest(
                MATRIX_SERVER.'/_synapse/admin/v2/users/'.rawurlencode($uid),
                'PUT',
                $payloadV2,
                array('Content-Type: application/json', 'Authorization: Bearer '.$_SESSION['admin_token'])
            );

            $ok = !empty($res['success']) && (int)$res['http_code'] === 200;

            // 2) fallback: v1 reset_password (old API)
            if (!$ok && in_array((int)$res['http_code'], array(404,405,501), true)) {
                $payloadV1 = json_encode(array('new_password' => $npw, 'logout_devices' => true));
                $res = makeMatrixRequest(
                    MATRIX_SERVER.'/_synapse/admin/v1/reset_password/'.rawurlencode($uid),
                    'POST',
                    $payloadV1,
                    array('Content-Type: application/json', 'Authorization: Bearer '.$_SESSION['admin_token'])
                );
                $ok = !empty($res['success']) && (int)$res['http_code'] === 200;
            }

            if ($ok) {
                logAction('change password '.$uid);
                users_redirect_with_state(array('success' => 'Password changed'));
            } else {
                $error = http_fail_msg($res, 'Failed to change password');
            }
        }
    }
}

/* ---------- fetch list ---------- */
$page    = max(1, (int)(isset($_GET['page_num']) ? $_GET['page_num'] : 1)); 
$perPage = (int)(isset($_GET['per_page']) ? $_GET['per_page'] : 50);
if (!in_array($perPage, array(10,50,100), true)) $perPage = 50;
$search  = trim((string)(isset($_GET['search']) ? $_GET['search'] : ''));
$showDeactivated = isset($_GET['show_deactivated']);

$apiUrl = MATRIX_SERVER.'/_synapse/admin/v2/users?limit='.$perPage.'&from='.(($page-1)*$perPage);
if ($search !== '')   $apiUrl .= '&name='.urlencode($search);
if ($showDeactivated) $apiUrl .= '&deactivated=true';

$listRes = makeMatrixRequest($apiUrl,'GET',null,array('Authorization: Bearer '.$_SESSION['admin_token']));
$users = array(); $total = 0;
if (!empty($listRes['success']) && (int)$listRes['http_code']===200) {
    $data = json_decode($listRes['response'], true);
    if (!is_array($data)) $data = array();

    if (isset($data['users']) && is_array($data['users'])) {
        $users = $data['users'];
        $total = isset($data['total']) ? (int)$data['total'] : count($users);
    } elseif (isset($data['results']) && is_array($data['results'])) {
        $users = $data['results'];
        $total = isset($data['count']) ? (int)$data['count'] : count($users);
    } else {
        $error = 'Unexpected users payload';
    }
} else {
    $error = $error ?: http_fail_msg($listRes, 'Failed to load users list');
}
$totalPages = max(1, (int)ceil(max(1, $total) / $perPage));
?>

<?php if ($error): ?>
  <div class="card alert alert-error"><?= htmlspecialchars($error) ?></div>
<?php endif; ?>
<?php if ($success): ?>
  <div class="card alert alert-success"><?= htmlspecialchars($success) ?></div>
<?php endif; ?>

<!-- Create user -->
<div class="card">
  <h2>Create New User</h2>
  <form method="post" style="margin-top:10px;">
    <input type="hidden" name="action" value="create_user">
    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrf_token()) ?>">
    <div style="display:grid;grid-template-columns:1fr 1fr auto;gap:10px;">
      <input class="input" name="new_username" placeholder="username (without @domain)" required
             style="padding:10px;background:#181A20;border:1px solid #30363D;border-radius:6px;color:#C9D1D9">
      <input class="input" type="password" name="new_password" placeholder="password" required
             style="padding:10px;background:#181A20;border:1px solid #30363D;border-radius:6px;color:#C9D1D9">
      <label style="display:flex;align-items:center;gap:8px;">
        <input type="checkbox" name="is_admin"> Admin
      </label>
    </div>
    <div style="margin-top:10px;"><button class="btn" type="submit">Create</button></div>
  </form>
</div>

<!-- Search / filters + list -->
<div class="card">
  <h2>Users</h2>
  <form method="get" style="display:flex;gap:10px;margin:12px 0;align-items:center;">
    <input type="hidden" name="page" value="users">
    <input class="input" name="search" placeholder="Search users…" value="<?= htmlspecialchars($search) ?>"
           style="flex:1;padding:10px;background:#181A20;border:1px solid #30363D;border-radius:6px;color:#C9D1D9">
    <select class="input" name="per_page"
            style="padding:10px;background:#181A20;border:1px solid #30363D;border-radius:6px;color:#C9D1D9">
      <option value="10"  <?= $perPage===10?'selected':'' ?>>10</option>
      <option value="50"  <?= $perPage===50?'selected':'' ?>>50</option>
      <option value="100" <?= $perPage===100?'selected':'' ?>>100</option>
    </select>
    <label style="display:flex;align-items:center;gap:6px;">
      <input type="checkbox" name="show_deactivated" <?= $showDeactivated?'checked':'' ?>> show deactivated
    </label>
    <button class="btn" type="submit">Search</button>
    <?php if ($search !== '' || $showDeactivated || $perPage !== 50): ?>
      <a class="btn" href="index.php?page=users" style="background:#666">Clear</a>
    <?php endif; ?>
  </form>

  <div class="stats" style="opacity:.7;margin:6px 0;">
    Showing <?= is_array($users)?count($users):0 ?> of <?= (int)$total ?> users <?= $search!=='' ? '(filtered)' : '' ?>
  </div>

  <table class="table">
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
    <?php if (!$users): ?>
      <tr><td colspan="6" style="text-align:center;opacity:.7;padding:14px;">No users</td></tr>
    <?php else: foreach ($users as $u):
        $uid     = isset($u['name']) ? (string)$u['name'] : (isset($u['user_id']) ? (string)$u['user_id'] : '');
        $isAdm   = !empty($u['admin']);
        $dead    = !empty($u['deactivated']);
        $created = !empty($u['creation_ts']) ? date('Y-m-d H:i', $u['creation_ts']/1000) : '—';
    ?>
      <tr>
        <td><?= htmlspecialchars($uid) ?></td>
        <td><?= htmlspecialchars(isset($u['displayname']) ? $u['displayname'] : 'N/A') ?></td>
        <td><?= $isAdm ? '<span style="color:#00ff88">Admin</span>' : '<span style="color:#888">User</span>' ?></td>
        <td><?= $dead ? '<span style="color:#ff6666">Inactive</span>' : '<span style="color:#58A6FF">Active</span>' ?></td>
        <td><?= $created ?></td>
        <td>
          <div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center;">
            <?php if (!$dead): ?>
              <?php if ($uid !== (isset($_SESSION['admin_user']) ? $_SESSION['admin_user'] : '')): ?>
                <form method="post" class="js-confirm-form" data-confirm="Deactivate this user?">
                  <input type="hidden" name="action" value="deactivate_user">
                  <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrf_token()) ?>">
                  <input type="hidden" name="user_id" value="<?= htmlspecialchars($uid) ?>">
                  <button class="btn btn-danger btn-sm" type="submit">Deactivate</button>
                </form>
              <?php else: ?>
                <span class="btn btn-sm" style="background:#555;cursor:not-allowed;opacity:.6;">Deactivate</span>
              <?php endif; ?>
            <?php else: ?>
              <form method="post" class="js-confirm-form" data-confirm="Reactivate this user?">
                <input type="hidden" name="action" value="reactivate_user">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrf_token()) ?>">
                <input type="hidden" name="user_id" value="<?= htmlspecialchars($uid) ?>">
                <button class="btn btn-warning btn-sm" type="submit">Reactivate</button>
              </form>
            <?php endif; ?>

            <button class="btn btn-info btn-sm js-open-pwd" type="button" data-uid="<?= htmlspecialchars($uid, ENT_QUOTES) ?>">Change Password</button>

            <?php if (!$isAdm): ?>
              <form method="post" class="js-confirm-form" data-confirm="Grant admin to this user?">
                <input type="hidden" name="action" value="toggle_admin">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrf_token()) ?>">
                <input type="hidden" name="user_id" value="<?= htmlspecialchars($uid) ?>">
                <input type="hidden" name="make_admin" value="1">
                <button class="btn btn-warning btn-sm" type="submit">Make Admin</button>
              </form>
            <?php else: ?>
              <?php if ($uid !== (isset($_SESSION['admin_user']) ? $_SESSION['admin_user'] : '')): ?>
                <form method="post" class="js-confirm-form" data-confirm="Revoke admin from this user?">
                  <input type="hidden" name="action" value="toggle_admin">
                  <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrf_token()) ?>">
                  <input type="hidden" name="user_id" value="<?= htmlspecialchars($uid) ?>">
                  <button class="btn btn-danger btn-sm" type="submit">Remove Admin</button>
                </form>
              <?php else: ?>
                <span class="btn btn-sm" style="background:#555;cursor:not-allowed;opacity:.6;">Remove Admin</span>
              <?php endif; ?>
            <?php endif; ?>
          </div>
        </td>
      </tr>
    <?php endforeach; endif; ?>
    </tbody>
  </table>
</div>

<!-- Password modal -->
<div id="pwdModal" class="modal" style="display:none;position:fixed;inset:0;background:rgba(24,26,32,.95);z-index:1000;">
  <div class="modal-content" style="background:#23272E;border:1px solid #30363D;border-radius:10px;max-width:480px;margin:10% auto;padding:20px;">
    <div style="display:flex;justify-content:space-between;align-items:center;">
      <h3>Change Password</h3>
      <button class="btn js-close-pwd" type="button">✕</button>
    </div>
    <form method="post" id="pwdForm" style="margin-top:10px;">
      <input type="hidden" name="action" value="change_password">
      <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrf_token()) ?>">
      <input type="hidden" name="user_id" id="pwdUid" value="">
      <div style="margin:10px 0;">
        <label>New password</label>
        <input type="password" name="new_password" id="pwdNew"
               placeholder="Minimum 6 characters" required minlength="6"
               style="width:100%;padding:10px;background:#181A20;border:1px solid #30363D;border-radius:6px;color:#C9D1D9">
      </div>
      <div style="display:flex;gap:8px;justify-content:center;margin-top:10px;">
        <button class="btn btn-info btn-sm" type="submit">Change</button>
        <button class="btn btn-sm js-close-pwd" type="button" style="background:#666;">Cancel</button>
      </div>
    </form>
  </div>
</div>

<script src="app.js" defer></script>
