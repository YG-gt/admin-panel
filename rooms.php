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
                // превращаем создаваемую комнату в Space
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

// 3) Add child to space (parent=space, child=room/space)
if (($_POST['action'] ?? '') === 'add_child_to_space') {
    if (!verifyCsrf($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid CSRF token';
    } else {
        $spaceId = trim($_POST['space_id'] ?? '');
        $childId = trim($_POST['child_id'] ?? '');
        $suggest = !empty($_POST['suggested']);
        if ($spaceId === '' || $childId === '') {
            $error = 'Please enter both Space ID and Child Room ID';
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
                $success = 'Added child '.htmlspecialchars($childId).' to space '.htmlspecialchars($spaceId);
                logAction('space add child '.$childId.' -> '.$spaceId);
            } else {
                $error = http_fail_msg($res, 'Failed to add child to space');
                logAction('space add child FAILED '.$childId.' -> '.$spaceId);
            }
        }
    }
}

// 4) Bulk delete rooms (v2 POST, fallback v1 POST, затем v1 DELETE c query)
if (($_POST['action'] ?? '') === 'bulk_rooms') {
    if (!verifyCsrf($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid CSRF token';
    } else {
        $ids = array_filter((array)($_POST['room_ids'] ?? []), 'strlen');
        if (!$ids) {
            $error='No rooms selected';
        } else {
            $ok=0; $fail=0;
            foreach ($ids as $rid) {
                $payload = json_encode(['block'=>false,'purge'=>true], JSON_UNESCAPED_SLASHES);

                // 1) v2 async delete
                $res_v2 = makeMatrixRequest(
                    MATRIX_SERVER.'/_synapse/admin/v2/rooms/'.rawurlencode($rid).'/delete',
                    'POST',
                    $payload,
                    ['Content-Type: application/json','Authorization: Bearer '.$_SESSION['admin_token']]
                );
                $done = ($res_v2['success'] ?? false) && (int)$res_v2['http_code']>=200 && (int)$res_v2['http_code']<300;

                if (!$done) {
                    // 2) v1 POST /delete
                    $res_v1_post = makeMatrixRequest(
                        MATRIX_SERVER.'/_synapse/admin/v1/rooms/'.rawurlencode($rid).'/delete',
                        'POST',
                        $payload,
                        ['Content-Type: application/json','Authorization: Bearer '.$_SESSION['admin_token']]
                    );
                    $done = ($res_v1_post['success'] ?? false) && (int)$res_v1_post['http_code']>=200 && (int)$res_v1_post['http_code']<300;

                    if (!$done) {
                        // 3) v1 DELETE с query-параметрами (без тела)
                        $res_v1_del = makeMatrixRequest(
                            MATRIX_SERVER.'/_synapse/admin/v1/rooms/'.rawurlencode($rid).'?block=false&purge=true',
                            'DELETE',
                            null,
                            ['Authorization: Bearer '.$_SESSION['admin_token']]
                        );
                        $done = ($res_v1_del['success'] ?? false) && (int)$res_v1_del['http_code']>=200 && (int)$res_v1_del['http_code']<300;

                        if ($done) {
                            $ok++; logAction('delete room (v1 DELETE) '.$rid);
                        } else {
                            $fail++;
                            $msg = $res_v1_del['response'] ?? $res_v1_del['error'] ?? $res_v1_post['response'] ?? $res_v1_post['error'] ?? $res_v2['response'] ?? $res_v2['error'] ?? 'unknown';
                            logAction('delete room FAILED '.$rid.' '.$msg);
                        }
                    } else {
                        $ok++; logAction('delete room (v1 POST) '.$rid);
                    }
                } else {
                    $ok++; logAction('delete room (v2 POST) '.$rid);
                }
            }

            if ($fail===0) $success = "Deletion requested for $ok room(s).";
            else           $error   = "Requested deletion: OK $ok, failed $fail.";
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
      <input class="input" name="room_name" placeholder="Room/Space name" required
             style="padding:10px;background:#181A20;border:1px solid #30363D;border-radius:6px;color:#C9D1D9">
      <select class="input" name="room_kind"
              style="padding:10px;background:#181A20;border:1px solid #30363D;border-radius:6px;color:#C9D1D9">
        <option value="room">Room</option>
        <option value="space">Space</option>
      </select>
      <select class="input" name="room_visibility"
              style="padding:10px;background:#181A20;border:1px solid #30363D;border-radius:6px;color:#C9D1D9">
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
      <input class="input" name="invite_room_id" placeholder="!room:domain or roomId" required
             style="padding:10px;background:#181A20;border:1px solid #30363D;border-radius:6px;color:#C9D1D9">
      <input class="input" name="invite_user_id" placeholder="@user:domain" required
             style="padding:10px;background:#181A20;border:1px solid #30363D;border-radius:6px;color:#C9D1D9">
      <button class="btn" type="submit">Invite</button>
    </div>
  </form>
</div>

<!-- Add room to space -->
<div class="card">
  <h2>Add Room to Space</h2>
  <form method="POST" style="margin-top:10px;">
    <input type="hidden" name="action" value="add_child_to_space">
    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrf_token()) ?>">
    <div style="display:grid;grid-template-columns:2fr 2fr auto auto;gap:10px;align-items:center;">
      <input class="input" name="space_id" placeholder="Space ID (e.g. !space:domain)" required
             style="padding:10px;background:#181A20;border:1px solid #30363D;border-radius:6px;color:#C9D1D9">
      <input class="input" name="child_id" placeholder="Child room/space ID" required
             style="padding:10px;background:#181A20;border:1px solid #30363D;border-radius:6px;color:#C9D1D9">
      <label style="display:flex;gap:8px;align-items:center;">
        <input type="checkbox" name="suggested"> suggested
      </label>
      <button class="btn" type="submit">Add</button>
    </div>
  </form>
</div>

<!-- List -->
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

  <form method="POST" id="bulkForm">
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

<script src="app.js" defer></script>
