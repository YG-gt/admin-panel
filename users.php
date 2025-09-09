<?php

if (!function_exists('isLoggedIn')) { require __DIR__ . '/bootstrap.php'; }
require_login();

$error   = $_GET['error']   ?? null;
$success = $_GET['success'] ?? null;

/* ---------- helpers ---------- */
function users_redirect_with_state($extra = []) {
    $params = [
        'page'             => 'users',
        'page_num'         => $_GET['page_num'] ?? 1,
        'per_page'         => $_GET['per_page'] ?? 50,
        'search'           => $_GET['search'] ?? '',
        'show_deactivated' => isset($_GET['show_deactivated']) ? '1' : null,
    ];
    foreach ($extra as $k => $v) { $params[$k] = $v; }
    $params = array_filter($params, fn($v) => $v !== null);
    header('Location: index.php?' . http_build_query($params));
    exit;
}

function http_fail_msg($res, $fallback) {
    $code = $res['http_code'] ?? 0;
    $body = $res['response'] ?? ($res['error'] ?? '');
    if ($body !== '') { $body = substr($body, 0, 300); }
    $tail = ($code ? 'HTTP '.$code : '') . ($body !== '' ? ' / '.$body : '');
    return $fallback . ($tail ? ' — '.$tail : '');
}

/* ---------- actions ---------- */
// Create user
if (($_POST['action'] ?? '') === 'create_user') {
    if (!verifyCsrf($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid CSRF token';
    } else {
        $u = trim($_POST['new_username'] ?? '');
        $p = $_POST['new_password'] ?? '';
        $isAdmin = !empty($_POST['is_admin']);
        $displayname = trim($_POST['displayname'] ?? '');
        $userType = trim($_POST['user_type'] ?? '');

        if ($u === '' || $p === '') {
            $error = 'Please enter username and password';
        } elseif (!validateUsername($u)) {
            $error = 'Invalid username format';
        } elseif (strlen($p) < 6) {
            $error = 'Password must be at least 6 characters';
        } else {
            $payloadArr = [
                'password' => $p,
                'admin'    => $isAdmin,
            ];
            if ($displayname !== '') {
                $payloadArr['displayname'] = $displayname;
            }
            if ($userType !== '') {
                $payloadArr['user_type'] = $userType; // '', 'moderator', 'teamlead'
            }

            $res = makeMatrixRequest(
                MATRIX_SERVER.'/_synapse/admin/v2/users/@'.$u.':'.MATRIX_DOMAIN,
                'PUT',
                json_encode($payloadArr),
                ['Content-Type: application/json','Authorization: Bearer '.$_SESSION['admin_token']]
            );
            if (!empty($res['success']) && in_array((int)$res['http_code'], [200,201], true)) {
                logAction('create user @'.$u.':'.MATRIX_DOMAIN.($isAdmin?' (admin)':'').($userType ? ' ('.$userType.')' : ''));
                users_redirect_with_state(['success'=>'User created']);
            } else {
                $error = http_fail_msg($res, 'Failed to create user');
            }
        }
    }
}

// Deactivate
if (isset($_POST['action']) && $_POST['action'] === 'deactivate_user') {
    if (!verifyCsrf($_POST['csrf_token'] ?? '')) {
        $error='Invalid CSRF token';
    } else {
        $uid = (string)($_POST['user_id'] ?? '');
        if ($uid === ($_SESSION['admin_user'] ?? '')) {
            $error='Cannot deactivate yourself';
        } elseif ($uid !== '') {
            $res = makeMatrixRequest(
                MATRIX_SERVER.'/_synapse/admin/v2/users/'.rawurlencode($uid),
                'PUT',
                json_encode(['deactivated'=>true]),
                ['Content-Type: application/json','Authorization: Bearer '.$_SESSION['admin_token']]
            );
            if (!empty($res['success']) && (int)$res['http_code']===200) {
                logAction('deactivate '.$uid);
                users_redirect_with_state(['success'=>'User deactivated']);
            } else {
                $error = http_fail_msg($res,'Failed to deactivate');
            }
        }
    }
}

// Reactivate
if (isset($_POST['action']) && $_POST['action'] === 'reactivate_user') {
    if (!verifyCsrf($_POST['csrf_token'] ?? '')) {
        $error='Invalid CSRF token';
    } else {
        $uid = (string)($_POST['user_id'] ?? '');
        if ($uid !== '') {
            $res = makeMatrixRequest(
                MATRIX_SERVER.'/_synapse/admin/v2/users/'.rawurlencode($uid),
                'PUT',
                json_encode(['deactivated'=>false]),
                ['Content-Type: application/json','Authorization: Bearer '.$_SESSION['admin_token']]
            );
            if (!empty($res['success']) && (int)$res['http_code']===200) {
                logAction('reactivate '.$uid);
                users_redirect_with_state(['success'=>'User reactivated']);
            } else {
                $error = http_fail_msg($res,'Failed to reactivate');
            }
        }
    }
}

// Toggle admin
if (isset($_POST['action']) && $_POST['action'] === 'toggle_admin') {
    if (!verifyCsrf($_POST['csrf_token'] ?? '')) {
        $error='Invalid CSRF token';
    } else {
        $uid  = (string)($_POST['user_id'] ?? '');
        $make = !empty($_POST['make_admin']);
        if (!$make && $uid === ($_SESSION['admin_user'] ?? '')) {
            $error='Cannot remove your own admin privileges';
        } elseif ($uid !== '') {
            $res = makeMatrixRequest(
                MATRIX_SERVER.'/_synapse/admin/v2/users/'.rawurlencode($uid),
                'PUT',
                json_encode(['admin'=>$make]),
                ['Content-Type: application/json','Authorization: Bearer '.$_SESSION['admin_token']]
            );
            if (!empty($res['success']) && (int)$res['http_code']===200) {
                logAction(($make?'grant':'revoke').' admin '.$uid);
                users_redirect_with_state(['success'=>$make?'Admin granted':'Admin revoked']);
            } else {
                $error = http_fail_msg($res,'Failed to change admin');
            }
        }
    }
}

// Change password (v2 preferred, fallback to v1)
if (isset($_POST['action']) && $_POST['action'] === 'change_password') {
    if (!verifyCsrf($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid CSRF token';
    } else {
        $uid = (string)($_POST['user_id'] ?? '');
        $npw = (string)($_POST['new_password'] ?? '');
        if (strlen($npw) < 6) {
            $error = 'Password must be at least 6 characters';
        } elseif ($uid !== '') {

            // v2
            $payloadV2 = json_encode(['password' => $npw, 'logout_devices' => true]);
            $res = makeMatrixRequest(
                MATRIX_SERVER.'/_synapse/admin/v2/users/'.rawurlencode($uid),
                'PUT',
                $payloadV2,
                ['Content-Type: application/json', 'Authorization: Bearer '.$_SESSION['admin_token']]
            );

            $ok = !empty($res['success']) && (int)$res['http_code'] === 200;

            // fallback v1
            if (!$ok && in_array((int)$res['http_code'], [404,405,501], true)) {
                $payloadV1 = json_encode(['new_password' => $npw, 'logout_devices' => true]);
                $res = makeMatrixRequest(
                    MATRIX_SERVER.'/_synapse/admin/v1/reset_password/'.rawurlencode($uid),
                    'POST',
                    $payloadV1,
                    ['Content-Type: application/json', 'Authorization: Bearer '.$_SESSION['admin_token']]
                );
                $ok = !empty($res['success']) && (int)$res['http_code'] === 200;
            }

            if ($ok) {
                logAction('change password '.$uid);
                users_redirect_with_state(['success' => 'Password changed']);
            } else {
                $error = http_fail_msg($res, 'Failed to change password');
            }
        }
    }
}

// NEW: change user type
if (isset($_POST['action']) && $_POST['action'] === 'change_user_type') {
    if (!verifyCsrf($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid CSRF token';
    } else {
        $uid = (string)($_POST['user_id'] ?? '');
        $new = trim((string)($_POST['new_user_type'] ?? '')); // '' | 'moderator' | 'teamlead'
        if ($uid !== '') {
            // '' -> null (сброс к дефолтному типу)
            $payload = ['user_type' => ($new === '' ? null : $new)];
            $res = makeMatrixRequest(
                MATRIX_SERVER.'/_synapse/admin/v2/users/'.rawurlencode($uid),
                'PUT',
                json_encode($payload),
                ['Content-Type: application/json','Authorization: Bearer '.$_SESSION['admin_token']]
            );
            if (!empty($res['success']) && (int)$res['http_code']===200) {
                logAction('change user_type '.$uid.' -> '.($new===''?'(default)':$new));
                users_redirect_with_state(['success'=>'User type updated']);
            } else {
                $error = http_fail_msg($res, 'Failed to update user type');
            }
        }
    }
}

/* ---------- NEW: Send Server Notice ---------- */
if (isset($_POST['action']) && $_POST['action'] === 'send_notice') {
    if (!verifyCsrf($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid CSRF token';
    } else {
        $msg    = trim($_POST['notice_body'] ?? '');
        $target = $_POST['target'] ?? '';
        if ($msg === '') {
            $error = 'Message cannot be empty';
        } else {
            // собрать список получателей
            $recipients = [];
            if ($target === 'all') {
                $from = 0; $limit = 500; $guard = 0;
                while (true) {
                    $url = MATRIX_SERVER."/_synapse/admin/v2/users?limit={$limit}&from={$from}";
                    $res = makeMatrixRequest($url, 'GET', null, ['Authorization: Bearer '.$_SESSION['admin_token']]);
                    if (!($res['success'] ?? false) || (int)$res['http_code'] !== 200) break;
                    $data  = json_decode($res['response'], true) ?: [];
                    $chunk = $data['users'] ?? [];
                    foreach ($chunk as $u) {
                        if (empty($u['deactivated']) && !empty($u['name'])) {
                            $recipients[] = $u['name'];
                        }
                    }
                    if (count($chunk) < $limit) break;
                    $from += $limit;
                    $guard++;
                    if ($guard > 50) break; // предохранитель
                }
            } else {
                $recipients[] = $target;
            }

            if (!$recipients) {
                $error = 'No recipients found';
            } else {
                $sent = 0; $fail = 0;
                foreach ($recipients as $uid) {
                    $payload = json_encode([
                        'user_id' => $uid,
                        'content' => ['msgtype' => 'm.text', 'body' => $msg],
                    ]);
                    $txnId = bin2hex(random_bytes(8)); // короткий idempotent txnId
                    $r = makeMatrixRequest(
                        MATRIX_SERVER.'/_synapse/admin/v1/send_server_notice/'.$txnId,
                        'PUT',
                        $payload,
                        ['Content-Type: application/json', 'Authorization: Bearer '.$_SESSION['admin_token']]
                    );
                    if (($r['success'] ?? false) && (int)$r['http_code'] === 200) $sent++; else $fail++;
                }
                if ($fail === 0) $success = "Server notice sent to $sent recipient(s).";
                else $error = "Sent: $sent, failed: $fail.";
            }
        }
    }
}

/* ---------- fetch list ---------- */
$page    = max(1, (int)($_GET['page_num'] ?? 1)); 
$perPage = (int)($_GET['per_page'] ?? 50);
if (!in_array($perPage, [10,50,100], true)) $perPage = 50;
$search  = trim($_GET['search'] ?? '');
$showDeactivated = isset($_GET['show_deactivated']);

$apiUrl = MATRIX_SERVER.'/_synapse/admin/v2/users?limit='.$perPage.'&from='.(($page-1)*$perPage);
if ($search !== '')   $apiUrl .= '&name='.urlencode($search);
if ($showDeactivated) $apiUrl .= '&deactivated=true';

$listRes = makeMatrixRequest($apiUrl,'GET',null,['Authorization: Bearer '.$_SESSION['admin_token']]);
$users = []; $total = 0;
if (!empty($listRes['success']) && (int)$listRes['http_code']===200) {
    $data = json_decode($listRes['response'], true) ?: [];
    $users = $data['users'] ?? [];
    $total = (int)($data['total'] ?? count($users));
} else {
    $error = $error ?: http_fail_msg($listRes, 'Failed to load users list');
}
$totalPages = max(1, (int)ceil(max(1, $total) / $perPage));

/* ---------- prepare active users for Notice dropdown (first 500) ---------- */
$activeUsers = [];
$auRes = makeMatrixRequest(
    MATRIX_SERVER.'/_synapse/admin/v2/users?limit=500&from=0',
    'GET',
    null,
    ['Authorization: Bearer '.$_SESSION['admin_token']]
);
if (($auRes['success'] ?? false) && (int)$auRes['http_code'] === 200) {
    $auData = json_decode($auRes['response'], true) ?: [];
    foreach (($auData['users'] ?? []) as $u) {
        if (empty($u['deactivated']) && !empty($u['name'])) {
            $activeUsers[] = ['id' => $u['name'], 'label' => $u['displayname'] ?? $u['name']];
        }
    }
}
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

    <div style="display:grid;grid-template-columns:1fr 1fr 1fr 1fr auto;gap:10px;">
      <input class="input input-sm" name="new_username" placeholder="username (without @domain)" required>
      <input class="input input-sm" type="password" name="new_password" placeholder="password" required>
      <input class="input input-sm" name="displayname" placeholder="display name">
      <select class="input input-sm" name="user_type" title="User type">
        <option value="">User</option>
        <option value="moderator">Moderator</option>
        <option value="teamlead">Team Lead</option>
      </select>
      <label style="display:flex;align-items:center;gap:8px;">
        <input type="checkbox" name="is_admin"> Admin
      </label>
    </div>

    <div style="margin-top:10px;">
      <button class="btn btn-sm" type="submit">Create</button>
    </div>
  </form>
</div>

<!-- NEW: Send Server Notice -->
<div class="card">
  <h2>Send Server Notice</h2>
  <form method="post" style="margin-top:10px;">
    <input type="hidden" name="action" value="send_notice">
    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrf_token()) ?>">

    <div style="display:grid;grid-template-columns:1fr 3fr auto;gap:10px;align-items:start;">
      <select class="input input-sm" name="target" required style="min-width:220px;">
        <option value="" disabled selected>Select recipient…</option>
        <option value="all">All active users</option>
        <?php foreach ($activeUsers as $au): ?>
          <option value="<?= htmlspecialchars($au['id']) ?>">
            <?= htmlspecialchars($au['label']) ?>
          </option>
        <?php endforeach; ?>
      </select>

      <textarea class="input input-sm" name="notice_body" rows="2" placeholder="Message text…" required></textarea>

      <button class="btn btn-info btn-sm" type="submit">Send</button>
    </div>

    <div style="font-size:12px;opacity:.7;margin-top:6px;">
      Requires <code>server_notices.enabled: true</code> in homeserver.yaml.
    </div>
  </form>
</div>

<!-- Users list -->
<div class="card">
  <h2>Users</h2>
  <form method="get" style="display:flex;gap:10px;margin:12px 0;align-items:center;">
    <input type="hidden" name="page" value="users">
    <input class="input" name="search" placeholder="Search users…" value="<?= htmlspecialchars($search) ?>" style="flex:1;">
    <select class="input" name="per_page">
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
    Showing <?= count($users) ?> of <?= $total ?> users <?= $search!=='' ? '(filtered)' : '' ?>
  </div>

  <table class="table">
    <thead>
      <tr>
        <th>User ID</th>
        <th>Display Name</th>
        <th>Type</th>
        <th>Status</th>
        <th>Created</th>
        <th>Actions</th>
      </tr>
    </thead>
    <tbody>
    <?php if (!$users): ?>
      <tr><td colspan="6" style="text-align:center;opacity:.7;padding:14px;">No users</td></tr>
    <?php else: foreach ($users as $u):
        $uid     = $u['name'] ?? ($u['user_id'] ?? '');
        $isAdm   = !empty($u['admin']);
        $dead    = !empty($u['deactivated']);
        $created = !empty($u['creation_ts']) ? date('Y-m-d H:i', $u['creation_ts']/1000) : '—';
        $userTypeVal = $u['user_type'] ?? '';

        if ($isAdm) {
            $typeLabel = '<span style="color:#00ff88">Admin</span>';
        } elseif ($userTypeVal === 'moderator') {
            $typeLabel = '<span style="color:#FFA500">Moderator</span>';
        } elseif ($userTypeVal === 'teamlead') {
            $typeLabel = '<span style="color:#58A6FF">Team Lead</span>';
        } else {
            $typeLabel = '<span style="color:#888">User</span>';
        }
    ?>
      <tr>
        <td><?= htmlspecialchars($uid) ?></td>
        <td><?= htmlspecialchars($u['displayname'] ?? 'N/A') ?></td>
        <td><?= $typeLabel ?></td>
        <td><?= $dead ? '<span style="color:#ff6666">Inactive</span>' : '<span style="color:#58A6FF">Active</span>' ?></td>
        <td><?= $created ?></td>
        <td>
          <div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center;">
            <?php if (!$dead): ?>
              <?php if ($uid !== ($_SESSION['admin_user'] ?? '')): ?>
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
              <?php if ($uid !== ($_SESSION['admin_user'] ?? '')): ?>
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

            <!-- inline change user type -->
            <form method="post" style="display:flex;gap:6px;align-items:center;">
              <input type="hidden" name="action" value="change_user_type">
              <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrf_token()) ?>">
              <input type="hidden" name="user_id" value="<?= htmlspecialchars($uid) ?>">
              <select name="new_user_type" class="input input-sm" title="Change user type">
                <option value=""         <?= $userTypeVal==='' ? 'selected' : '' ?>>User</option>
                <option value="moderator"<?= $userTypeVal==='moderator' ? 'selected' : '' ?>>Moderator</option>
                <option value="teamlead" <?= $userTypeVal==='teamlead'  ? 'selected' : '' ?>>Team Lead</option>
              </select>
              <button class="btn btn-sm" type="submit">Set Type</button>
            </form>

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
      <button class="btn js-close-pwd btn-sm" type="button">✕</button>
    </div>
    <form method="post" id="pwdForm" style="margin-top:10px;">
      <input type="hidden" name="action" value="change_password">
      <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrf_token()) ?>">
      <input type="hidden" name="user_id" id="pwdUid" value="">
      <div style="margin:10px 0;">
        <label>New password</label>
        <input type="password" name="new_password" id="pwdNew"
               placeholder="Minimum 6 characters" required minlength="6"
               class="input input-sm" style="width:100%;">
      </div>
      <div style="display:flex;gap:8px;justify-content:center;margin-top:10px;">
        <button class="btn btn-info btn-sm" type="submit">Change</button>
        <button class="btn btn-sm js-close-pwd" type="button" style="background:#666;">Cancel</button>
      </div>
    </form>
  </div>
</div>

<script src="app.js" defer></script>
