<?php
// login.php
$error = null;

if (($_POST['action'] ?? '') === 'login' && !isLoggedIn()) {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';

    if (!verifyCsrf($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid CSRF token';
        usleep(LOGIN_DELAY_MICROSECONDS);
    } elseif (!$username || !$password) {
        $error = 'Enter username and password';
        usleep(LOGIN_DELAY_MICROSECONDS);
    } elseif (!validateUsername($username)) {
        $error = 'Invalid username format';
        usleep(LOGIN_DELAY_MICROSECONDS);
    } else {
        // login
        $loginData = json_encode(['type'=>'m.login.password','user'=>$username,'password'=>$password]);
        $res = makeMatrixRequest(MATRIX_SERVER.'/_matrix/client/r0/login','POST',$loginData,['Content-Type: application/json']);

        if (!$res['success'] || $res['http_code'] !== 200) {
            $error = 'Invalid username or password';
            usleep(LOGIN_DELAY_MICROSECONDS);
        } else {
            $data  = json_decode($res['response'], true);
            $token = $data['access_token'] ?? '';
            if (!$token) {
                $error='Invalid server response';
            } else {
                // check admin
                $adm = makeMatrixRequest(
                    MATRIX_SERVER.'/_synapse/admin/v1/users/@'.$username.':'.MATRIX_DOMAIN.'/admin',
                    'GET', null, ['Authorization: Bearer '.$token]
                );
                if ($adm['success'] && $adm['http_code']===200 && (json_decode($adm['response'],true)['admin'] ?? false)) {
                    $_SESSION['admin_token'] = $token;
                    $_SESSION['admin_user']  = '@'.$username.':'.MATRIX_DOMAIN;
                    logAction('login ok');
                    header('Location: index.php?page=users');
                    exit;
                } else {
                    $error = 'Access denied: admin only';
                }
            }
        }
    }
}
?>
<div class="card" style="max-width:520px;">
  <h2>Admin Login</h2>
  <?php if ($error): ?><div class="alert alert-error" style="margin-top:10px;"><?= htmlspecialchars($error) ?></div><?php endif; ?>

  <form method="POST" style="margin-top:12px;">
    <input type="hidden" name="action" value="login">
    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrf_token()) ?>">

    <label>Username</label>
    <input class="input" name="username" required style="width:100%;padding:10px;background:#181A20;border:1px solid #30363D;border-radius:6px;color:#C9D1D9">

    <label style="margin-top:10px;">Password</label>
    <input class="input" type="password" name="password" required style="width:100%;padding:10px;background:#181A20;border:1px solid #30363D;border-radius:6px;color:#C9D1D9">

    <div style="display:flex;justify-content:center;margin-top:14px;">
      <button class="btn" type="submit">Login</button>
    </div>
  </form>
</div>
