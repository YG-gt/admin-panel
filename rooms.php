<?php
// rooms.php
if (!function_exists('isLoggedIn')) { require __DIR__ . '/bootstrap.php'; }
if (!isLoggedIn()) {
  echo '<div class="card"><p>Please log in to view this page.</p></div>';
  return;
}

$error   = $_GET['error']   ?? null;
$success = $_GET['success'] ?? null;

/* ---------------- Helpers ---------------- */
function safe_json_decode($s){ $d = json_decode((string)$s, true); return is_array($d) ? $d : []; }
function http_fail_msg(array $res, string $fallback='Request failed'){
    $code = (int)($res['http_code'] ?? 0);
    $body = (string)($res['response'] ?? ($res['error'] ?? ''));
    if ($body !== '') $body = mb_substr($body, 0, 300);
    return $fallback . ($code ? " — HTTP $code" : '') . ($body !== '' ? " / $body" : '');
}

/* ---------------- Actions ---------------- */

// 1) Create room / space
if (($_POST['action'] ?? '') === 'create_room') {
    if (!verifyCsrf($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid CSRF token';
    } else {
        $roomName = trim($_POST['room_name'] ?? '');
        $visSel   = ($_POST['room_visibility'] ?? 'private') === 'public' ? 'public' : 'private';
        $kind     = ($_POST['room_kind'] ?? 'room') === 'space' ? 'space' : 'room';

        if ($roomName === '') {
            $error = 'Please enter room name';
        } else {
            $payload = [
                'name'       => $roomName,
                'preset'     => $visSel === 'public' ? 'public_chat' : 'private_chat',
                'visibility' => $visSel,
            ];
            if ($kind === 'space') {
                // Space создаётся через creation_content.type = m.space
                $payload['creation_content'] = ['type' => 'm.space'];
            }

            $res = makeMatrixRequest(
                MATRIX_SERVER.'/_matrix/client/r0/createRoom',
                'POST',
                json_encode($payload),
                ['Content-Type: application/json','Authorization: Bearer '.$_SESSION['admin_token']]
            );

            if (($res['success'] ?? false) && (int)$res['http_code'] === 200) {
                $rid = safe_json_decode($res['response'])['room_id'] ?? '(unknown)';
                $success = ucfirst($kind) . ' created. ID: ' . htmlspecialchars($rid);
                logAction('create '.$kind.' "'.$roomName.'" ('.$rid.')');
            } else {
                $error = http_fail_msg($res, 'Failed to create '.$kind);
                logAction('failed to create '.$kind.' "'.$roomName.'"');
            }
        }
    }
}

// 2) Invite user to room
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
                ['Content-Type: application/json','Authorization: Bearer '.$_SESSION['admin_token']]
            );
            if (($res['success'] ?? false) && (int)$res['http_code'] === 200) {
                $success = 'User '.htmlspecialchars($inviteUserId).' invited to room '.htmlspecialchars($inviteRoomId);
                logAction('invite '.$inviteUserId.' to room '.$inviteRoomId);
            } else {
                $error = http_fail_msg($res, 'Failed to invite user');
                logAction('failed to invite '.$inviteUserId.' to '.$inviteRoomId);
            }
        }
    }
}

// 3) Add child to space (parent=space, child=room)
if (($_POST['action'] ?? '') === 'add_child_to_space') {
    if (!verifyCsrf($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid CSRF token';
    } else {
        // берем из выпадающих списков
        $spaceId = trim($_POST['space_id_select'] ?? '');
        $childId = trim($_POST['child_room_id_select'] ?? '');
        $suggest = !empty($_POST['suggested']);
        if ($spaceId === '' || $childId === '') {
            $error = 'Please select both Space and Room';
        } else {
            $body = [
                'via'       => [MATRIX_DOMAIN],
                'suggested' => $suggest,
            ];
            $res = makeMatrixRequest(
                MATRIX_SERVER.'/_matrix/client/v3/rooms/'.rawurlencode($spaceId).'/state/m.space.child/'.rawurlencode($childId),
                'PUT',
                json_encode($body),
                ['Content-Type: application/json','Authorization: Bearer '.$_SESSION['admin_token']]
            );
            if (($res['success'] ?? false) && (int)$res['http_code'] >= 200 && (int)$res['http_code'] < 300) {
                $success = 'Added room '.htmlspecialchars($childId).' to space '.htmlspecialchars($spaceId);
                logAction('space add child '.$childId.' -> '.$spaceId);
            } else {
                $error = http_fail_msg($res, 'Failed to add child to space');
                logAction('space add child FAILED '.$childId.' -> '.$spaceId);
            }
        }
    }
}

// 4) Delete a single room (v2 async DELETE with JSON; fallback v1 DELETE with JSON)
if (($_POST['action'] ?? '') === 'delete_room') {
    if (!verifyCsrf($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid CSRF token';
    } else {
        $rid = trim($_POST['room_id'] ?? '');
        if ($rid === '') {
            $error = 'No room id given';
        } else {
            $payload = json_encode(['block'=>false, 'purge'=>true], JSON_UNESCAPED_SLASHES);

            // v2 (асинхронный)
            $res_v2 = makeMatrixRequest(
                MATRIX_SERVER.'/_synapse/admin/v2/rooms/'.rawurlencode($rid),
                'DELETE',
                $payload,
                ['Authorization: Bearer '.$_SESSION['admin_token'], 'Content-Type: application/json']
            );
            $ok = ($res_v2['success'] ?? false) && (int)$res_v2['http_code'] >= 200 && (int)$res_v2['http_code'] < 300;

            // fallback: v1 (синхронный)
            if (!$ok) {
                $res_v1 = makeMatrixRequest(
                    MATRIX_SERVER.'/_synapse/admin/v1/rooms/'.rawurlencode($rid),
                    'DELETE',
                    $payload,
                    ['Authorization: Bearer '.$_SESSION['admin_token'], 'Content-Type: application/json']
                );
                $ok = ($res_v1['success'] ?? false) && (int)$res_v1['http_code'] >= 200 && (int)$res_v1['http_code'] < 300;
                if ($ok) logAction('delete room (v1) '.$rid);
            } else {
                logAction('delete room (v2) '.$rid);
            }

            if ($ok) {
                $success = 'Deletion requested';
            } else {
                $error = http_fail_msg($res_v2, 'Failed to delete room');
                logAction('delete room FAILED '.$rid);
            }
        }
    }
}

/* ---------------- Fetch list ---------------- */

$r_page   = max(1,(int)($_GET['r_page']??1));
$r_per_in = (int)($_GET['r_per_page'] ?? 50);
$r_per    = in_array($r_per_in, [10,50,100], true) ? $r_per_in : 50;
$r_search = trim($_GET['r_search'] ?? '');
$from     = ($r_page-1)*$r_per;

$url = MATRIX_SERVER.'/_synapse/admin/v1/rooms?limit='.$r_per.'&from='.$from;
if ($r_search!=='') $url .= '&search_term='.urlencode($r_search);

$res = makeMatrixRequest($url,'GET',null,['Authorization: Bearer '.$_SESSION['admin_token']]);

$rooms = []; $total = 0;
if (($res['success'] ?? false) && (int)$res['http_code']===200) {
    $d = safe_json_decode($res['response']);
    $rooms = $d['rooms'] ?? [];
    $total = (int)($d['total_rooms'] ?? count($rooms));
} else {
    $error = $error ?: http_fail_msg($res, 'Failed to load rooms list');
}
$pages = max(1,(int)ceil(max(1,$total)/$r_per));

/* --- разложим на spaces и обычные комнаты для формы "Add Room to Space" --- */
$spaces = [];
$plainRooms = [];
foreach ($rooms as $r) {
    $rid  = (string)($r['room_id'] ?? '');
    $name = (string)($r['name'] ?? '(no name)');
    $rtype = (string)($r['room_type'] ?? 'room'); // synapse помечает space
    if ($rtype === 'space') {
        $spaces[] = ['room_id'=>$rid, 'name'=>$name];
    } else {
        $plainRooms[] = ['room_id'=>$rid, 'name'=>$name];
    }
}
?>
<?php if ($error): ?>
  <div class="card alert alert-error"><?= htmlspecialchars($error) ?></div>
<?php endif; ?>
<?php if ($success): ?>
  <div class="card alert alert-success"><?= htmlspecialchars($success) ?></div>
<?php endif; ?>

<!-- Create Room / Space -->
<div class="card">
  <h2>Create Room</h2>
  <form method="POST" id="createRoomForm" style="margin-top:10px;">
    <input type="hidden" name="action" value="create_room">
    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrf_token()) ?>">
    <div style="display:grid;grid-template-columns:2fr 1fr 1fr auto;gap:10px;">
      <input class="input" name="room_name" placeholder="Room/Space name" required>
      <select class="input" name="room_kind">
        <option value="room">Room</option>
        <option value="space">Space</option>
      </select>
      <select class="input" name="room_visibility">
        <option value="private">Private</option>
        <option value="public">Public</option>
      </select>
      <button class="btn" type="submit">Create</button>
    </div>
  </form>
</div>

<!-- Invite -->
<div class="card">
  <h2>Invite User to Room</h2>
  <form method="POST" id="inviteForm" style="margin-top:10px;">
    <input type="hidden" name="action" value="invite_to_room">
    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrf_token()) ?>">
    <div style="display:grid;grid-template-columns:2fr 2fr auto;gap:10px;">
      <input class="input" name="invite_room_id" placeholder="!room:domain or roomId" required>
      <input class="input" name="invite_user_id" placeholder="@user:domain" required>
      <button class="btn" type="submit">Invite</button>
    </div>
  </form>
</div>

<!-- Add room to space: два выпадающих -->
<div class="card">
  <h2>Add Room to Space</h2>
  <form method="POST" style="margin-top:10px;">
    <input type="hidden" name="action" value="add_child_to_space">
    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrf_token()) ?>">

    <div style="display:grid;grid-template-columns:2fr 2fr auto auto;gap:10px;align-items:center;">
      <select class="input" name="space_id_select" required>
        <option value="">— Select space —</option>
        <?php foreach ($spaces as $s): ?>
          <option value="<?= htmlspecialchars($s['room_id']) ?>">
            <?= htmlspecialchars($s['name'].'  '.$s['room_id']) ?>
          </option>
        <?php endforeach; ?>
      </select>

      <select class="input" name="child_room_id_select" required>
        <option value="">— Select room —</option>
        <?php foreach ($plainRooms as $pr): ?>
          <option value="<?= htmlspecialchars($pr['room_id']) ?>">
            <?= htmlspecialchars($pr['name'].'  '.$pr['room_id']) ?>
          </option>
        <?php endforeach; ?>
      </select>

      <label style="display:flex;gap:8px;align-items:center;white-space:nowrap;">
        <input type="checkbox" name="suggested"> suggested
      </label>
      <button class="btn" type="submit">Add</button>
    </div>

    <?php if (!$spaces): ?>
      <div class="alert alert-error" style="margin-top:10px;">No spaces found on this page. Use search/pagination if needed.</div>
    <?php endif; ?>
    <?php if (!$plainRooms): ?>
      <div class="alert alert-error" style="margin-top:10px;">No plain rooms found on this page.</div>
    <?php endif; ?>
  </form>
</div>

<!-- List -->
<div class="card">
  <h2>Rooms</h2>

  <form method="GET" style="display:flex; gap:10px; margin:10px 0;">
    <input type="hidden" name="page" value="rooms">
    <input class="input" name="r_search" placeholder="Search rooms…" value="<?= htmlspecialchars($r_search) ?>" style="flex:1;">
    <select class="input" name="r_per_page">
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

  <table style="width:100%;border-collapse:collapse">
    <thead>
      <tr style="border-bottom:1px solid #30363D;color:#58A6FF">
        <th style="padding:10px;text-align:left">Name</th>
        <th style="padding:10px;text-align:left">Room ID</th>
        <th style="padding:10px;text-align:left">Type</th>
        <th style="padding:10px;text-align:left">Visibility</th>
        <th style="padding:10px;text-align:left">Members</th>
        <th style="padding:10px;text-align:left">Encrypted</th>
        <th style="padding:10px;text-align:left">Creator</th>
        <th style="padding:10px;text-align:left">Actions</th>
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
        <td style="padding:10px"><?= htmlspecialchars($name) ?></td>
        <td style="padding:10px;font-family:monospace"><?= htmlspecialchars($rid) ?></td>
        <td style="padding:10px"><?= htmlspecialchars($rtype) ?></td>
        <td style="padding:10px"><?= htmlspecialchars($vis) ?></td>
        <td style="padding:10px"><?= $mem ?></td>
        <td style="padding:10px"><?= $enc ?></td>
        <td style="padding:10px"><?= htmlspecialchars($creator) ?></td>
        <td style="padding:10px">
          <form method="POST" class="js-confirm-form" data-confirm="Delete this room? This purges it from DB.">
            <input type="hidden" name="action" value="delete_room">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrf_token()) ?>">
            <input type="hidden" name="room_id" value="<?= htmlspecialchars($rid) ?>">
            <button class="btn btn-danger btn-sm" type="submit">Delete</button>
          </form>
        </td>
      </tr>
      <?php endforeach; endif; ?>
    </tbody>
  </table>

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

<script src="app.js" defer></script>
