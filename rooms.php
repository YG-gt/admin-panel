<?php
// rooms.php — диагностическая версия: список комнат + создание + инвайт + массовое удаление
// Включаем явный вывод ошибок ТОЛЬКО здесь (удали после починки)
error_reporting(E_ALL);
ini_set('display_errors', '1');

// Мягкая защита: если запущено напрямую
if (!function_exists('isLoggedIn')) {
  require __DIR__ . '/bootstrap.php';
}
if (!isLoggedIn()) {
  echo '<div class="card"><p>Please log in to view this page.</p></div>';
  return;
}

$error   = $_GET['error']   ?? null;
$success = $_GET['success'] ?? null;

/* ===================== Helpers ===================== */

function safe_json_decode($s) {
    if (!is_string($s) || $s === '') return [];
    $d = json_decode($s, true);
    return is_array($d) ? $d : [];
}
function show_http_debug($label, $res) {
    echo '<div class="card alert alert-error" style="white-space:pre-wrap;">';
    echo htmlspecialchars($label)."\n";
    echo 'success: '.(($res['success']??false) ? 'true' : 'false')."\n";
    echo 'http_code: '.(int)($res['http_code']??0)."\n";
    if (!empty($res['error'])) {
        echo 'error: '.htmlspecialchars($res['error'])."\n";
    }
    $body = (string)($res['response'] ?? '');
    if ($body !== '') {
        $short = mb_substr($body, 0, 2000);
        echo "response (truncated):\n".htmlspecialchars($short);
        if (mb_strlen($body) > 2000) echo "\n…(truncated)…";
    }
    echo '</div>';
}

/* ===================== Actions ===================== */

// 1) Создание комнаты
if (($_POST['action'] ?? '') === 'create_room') {
    if (!verifyCsrf($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid CSRF token';
    } else {
        $roomName = trim($_POST['room_name'] ?? '');
        $roomType = ($_POST['room_type'] ?? 'private') === 'public' ? 'public' : 'private';
        if ($roomName === '') {
            $error = 'Please enter room name';
        } else {
            $payload = json_encode([
                'name'       => $roomName,
                'preset'     => $roomType === 'public' ? 'public_chat' : 'private_chat',
                'visibility' => $roomType,
            ]);
            $res = makeMatrixRequest(
                MATRIX_SERVER.'/_matrix/client/r0/createRoom',
                'POST',
                $payload,
                [
                    'Content-Type: application/json',
                    'Authorization: Bearer '.$_SESSION['admin_token']
                ]
            );
            if (!($res['success'] ?? false)) {
                $error = 'Network error during room creation';
                logAction('failed to create room "'.$roomName.'" - network error');
            } elseif ((int)$res['http_code'] === 200) {
                $d = safe_json_decode($res['response'] ?? '');
                $rid = $d['room_id'] ?? '(unknown)';
                $success = 'Room created successfully. Room ID: '.htmlspecialchars($rid);
                logAction('create room "'.$roomName.'" ('.$rid.')');
            } else {
                $error = 'Failed to create room';
                logAction('failed to create room "'.$roomName.'" - http '.(int)$res['http_code']);
                // Покажем диагностический блок
                show_http_debug('createRoom failed', $res);
            }
        }
    }
}

// 2) Инвайт пользователя
if (($_POST['action'] ?? '') === 'invite_to_room') {
    if (!verifyCsrf($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid CSRF token';
    } else {
        $inviteRoomId = trim($_POST['invite_room_id'] ?? '');
        $inviteUserId = trim($_POST['invite_user_id'] ?? '');
        if ($inviteRoomId === '' || $inviteUserId === '') {
            $error = 'Please enter both Room ID and User ID';
        } else {
            $payload = json_encode(['user_id' => $inviteUserId]);
            $res = makeMatrixRequest(
                MATRIX_SERVER.'/_matrix/client/r0/rooms/'.rawurlencode($inviteRoomId).'/invite',
                'POST',
                $payload,
                [
                    'Content-Type: application/json',
                    'Authorization: Bearer '.$_SESSION['admin_token']
                ]
            );
            if (!($res['success'] ?? false)) {
                $error = 'Network error during invite';
                logAction('failed to invite '.$inviteUserId.' to room '.$inviteRoomId.' - network error');
            } elseif ((int)$res['http_code'] === 200) {
                $success = 'User '.htmlspecialchars($inviteUserId).' invited to room '.htmlspecialchars($inviteRoomId);
                logAction('invite '.$inviteUserId.' to room '.$inviteRoomId);
            } else {
                $error = 'Failed to invite user';
                logAction('failed to invite '.$inviteUserId.' to room '.$inviteRoomId.' - http '.(int)$res['http_code']);
                show_http_debug('invite failed', $res);
            }
        }
    }
}

// 3) Массовое удаление (асинхронно)
if (($_POST['action'] ?? '') === 'bulk_rooms') {
    if (!verifyCsrf($_POST['csrf_token'] ?? '')) {
        $error='Invalid CSRF token';
    } else {
        $ids = array_filter((array)($_POST['room_ids'] ?? []), 'strlen');
        if (!$ids) {
            $error='No rooms selected';
        } else {
            $ok=$fail=0;
            foreach ($ids as $rid) {
                $resp = makeMatrixRequest(
                    MATRIX_SERVER.'/_synapse/admin/v2/rooms/'.rawurlencode($rid),
                    'DELETE',
                    null,
                    ['Authorization: Bearer '.$_SESSION['admin_token'], 'Content-Type: application/json']
                );
                if (($resp['success'] ?? false) && (int)$resp['http_code']>=200 && (int)$resp['http_code']<300) {
                    $ok++; logAction('delete room req '.$rid);
                } else {
                    $fail++; logAction('delete room FAILED '.$rid.' '.($resp['response']??$resp['error']??''));
                }
            }
            if ($fail===0) $success = "Deletion requested for $ok room(s) (async).";
            else $error = "Requested deletion: OK $ok, failed $fail.";
        }
    }
}

/* ===================== Filters & Pagination ===================== */

$r_page   = max(1,(int)($_GET['r_page']??1));
$r_per_in = (int)($_GET['r_per_page'] ?? 50);
$r_per    = in_array($r_per_in, [10,50,100], true) ? $r_per_in : 50;
$r_search = trim($_GET['r_search'] ?? '');
$from     = ($r_page-1)*$r_per;

/* ===================== Fetch Rooms ===================== */

$url = MATRIX_SERVER.'/_synapse/admin/v1/rooms?limit='.$r_per.'&from='.$from;
if ($r_search!=='') $url .= '&search_term='.urlencode($r_search);

$res = makeMatrixRequest($url,'GET',null,['Authorization: Bearer '.$_SESSION['admin_token']]);

$rooms = []; $total = 0;
if (($res['success'] ?? false) && (int)$res['http_code']===200) {
    $d = safe_json_decode($res['response'] ?? '');
    $rooms = $d['rooms'] ?? [];
    $total = (int)($d['total_rooms'] ?? count($rooms));
} else {
    $error = $error ?: 'Failed to load rooms list';
    // Включим диагностику, чтобы видеть причину
    show_http_debug('rooms list failed', $res);
}
$pages = max(1,(int)ceil(($total ?: 1)/$r_per));
?>

<?php if ($error): ?>
  <div class="card alert alert-error"><?= htmlspecialchars($error) ?></div>
<?php endif; ?>
<?php if ($success): ?>
  <div class="card alert alert-success"><?= htmlspecialchars($success) ?></div>
<?php endif; ?>

<!-- Создать комнату -->
<div class="card">
  <h2>Create Room</h2>
  <form method="POST" style="margin-top:10px;">
    <input type="hidden" name="action" value="create_room">
    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrf_token()) ?>">
    <div style="display:grid;grid-template-columns:2fr 1fr auto;gap:10px;">
      <input class="input" name="room_name" placeholder="Room name" required
             style="padding:10px;background:#181A20;border:1px solid #30363D;border-radius:6px;color:#C9D1D9">
      <select class="input" name="room_type"
              style="padding:10px;background:#181A20;border:1px solid #30363D;border-radius:6px;color:#C9D1D9">
        <option value="private">Private</option>
        <option value="public">Public</option>
      </select>
      <button class="btn" type="submit">Create</button>
    </div>
  </form>
</div>

<!-- Пригласить пользователя -->
<div class="card">
  <h2>Invite User to Room</h2>
  <form method="POST" style="margin-top:10px;">
    <input type="hidden" name="action" value="invite_to_room">
    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrf_token()) ?>">
    <div style="display:grid;grid-template-columns:2fr 2fr auto;gap:10px;">
      <input class="input" name="invite_room_id" placeholder="!room:domain or roomId" required
             style="padding:10px;background:#181A20;border:1px solid #30363D;border-radius:6px;color:#C9D1D9">
      <input class="input" name="invite_user_id" placeholder="@user:domain" required
             style="padding:10px;background:#181A20;border:1px solid #30363D;border-radius:6px;color:#C9D1D9">
      <button class="btn" type="submit">Invite</button>
    </div>
  </form>
</div>

<!-- Список комнат + массовое удаление -->
<div class="card">
  <h2>Rooms</h2>

  <form method="GET" style="display:flex; gap:10px; margin:10px 0;">
    <input type="hidden" name="page" value="rooms">
    <input name="r_search" placeholder="Search rooms…" value="<?= htmlspecialchars($r_search) ?>"
           style="flex:1;padding:10px;background:#181A20;border:1px solid #30363D;border-radius:6px;color:#C9D1D9">
    <select name="r_per_page" style="padding:10px;background:#181A20;border:1px solid #30363D;border-radius:6px;color:#C9D1D9">
      <option <?= $r_per==10?'selected':'' ?> value="10">10</option>
      <option <?= $r_per==50?'selected':'' ?> value="50">50</option>
      <option <?= $r_per==100?'selected':'' ?> value="100">100</option>
    </select>
    <button class="btn">Search</button>
    <?php if ($r_search || $r_per!=50): ?>
      <a class="btn" href="index.php?page=rooms" style="background:#666">Clear</a>
    <?php endif; ?>
  </form>

  <div style="opacity:.7;margin:8px 0;">Showing <?= count($rooms) ?> of <?= $total ?> rooms</div>

  <form method="POST" onsubmit="return confirm('Delete selected rooms (async)?');">
    <input type="hidden" name="action" value="bulk_rooms">
    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrf_token()) ?>">

    <div style="display:flex; gap:10px; align-items:center; margin:10px 0;">
      <button class="btn" id="bulkBtn" disabled>Delete selected</button>
      <div style="font-size:12px;opacity:.7">Synapse v2 delete is asynchronous</div>
    </div>

    <table style="width:100%;border-collapse:collapse">
      <thead>
        <tr style="border-bottom:1px solid #30363D;color:#58A6FF">
          <th style="padding:10px;text-align:center"><input type="checkbox" id="checkAll"></th>
          <th style="padding:10px;text-align:left">Name</th>
          <th style="padding:10px;text-align:left">Room ID</th>
          <th style="padding:10px;text-align:left">Type</th>
          <th style="padding:10px;text-align:left">Visibility</th>
          <th style="padding:10px;text-align:left">Members</th>
          <th style="padding:10px;text-align:left">Encrypted</th>
          <th style="padding:10px;text-align:left">Creator</th>
        </tr>
      </thead>
      <tbody>
        <?php if (!$rooms): ?>
          <tr><td colspan="8" style="padding:14px;opacity:.7;text-align:center">No rooms</td></tr>
        <?php else: foreach ($rooms as $r):
          $rid = (string)($r['room_id'] ?? '');
          $name = (string)($r['name'] ?? '(no name)');
          $rtype = (string)($r['room_type'] ?? 'room');
          $vis = ($r['public']??false) ? 'public' : (string)($r['join_rules'] ?? 'invite');
          $mem = (int)($r['joined_members'] ?? 0);
          $enc = !empty($r['encryption']) ? 'yes' : 'no';
          $creator = (string)($r['creator'] ?? '—');
        ?>
        <tr style="border-bottom:1px solid #30363D">
          <td style="padding:10px;text-align:center">
            <input class="roomChk" type="checkbox" name="room_ids[]" value="<?= htmlspecialchars($rid) ?>">
          </td>
          <td style="padding:10px"><?= htmlspecialchars($name) ?></td>
          <td style="padding:10px;font-family:monospace"><?= htmlspecialchars($rid) ?></td>
          <td style="padding:10px"><?= htmlspecialchars($rtype) ?></td>
          <td style="padding:10px"><?= htmlspecialchars($vis) ?></td>
          <td style="padding:10px"><?= $mem ?></td>
          <td style="padding:10px"><?= $enc ?></td>
          <td style="padding:10px"><?= htmlspecialchars($creator) ?></td>
        </tr>
        <?php endforeach; endif; ?>
      </tbody>
    </table>
  </form>

  <?php if ($pages>1): ?>
    <div style="display:flex;gap:8px;justify-content:center;margin-top:14px">
      <?php
        $base = 'index.php?page=rooms&r_per_page='.$r_per.'&r_search='.urlencode($r_search);
        if ($r_page>1) echo '<a class="btn" href="'.$base.'&r_page=1">First</a><a class="btn" href="'.$base.'&r_page='.($r_page-1).'">Prev</a>';
        for ($i=max(1,$r_page-2);$i<=min($pages,$r_page+2);$i++){
          if ($i==$r_page) echo '<span class="btn" style="background:#2a3038;cursor:default">'.$i.'</span>';
          else echo '<a class="btn" href="'.$base.'&r_page='.$i.'">'.$i.'</a>';
        }
        if ($r_page<$pages) echo '<a class="btn" href="'.$base.'&r_page='.($r_page+1).'">Next</a><a class="btn" href="'.$base.'&r_page='.$pages.'">Last</a>';
      ?>
    </div>
  <?php endif; ?>
</div>

<script>
  // bulk delete helpers
  const all = document.getElementById('checkAll');
  const btn = document.getElementById('bulkBtn');
  function syncBtn(){ if(btn) btn.disabled = document.querySelectorAll('.roomChk:checked').length===0; }
  if (all) all.addEventListener('change', () => {
    document.querySelectorAll('.roomChk').forEach(cb => cb.checked = all.checked);
    syncBtn();
  });
  document.addEventListener('change', e => {
    if (e.target.classList && e.target.classList.contains('roomChk')) syncBtn();
  });
</script>
