<?php
// rooms.php
require_login();

$error = $_GET['error']  ?? null;
$success = $_GET['success'] ?? null;

// Bulk delete (async v2)
if (($_POST['action'] ?? '') === 'bulk_rooms') {
    if (!verifyCsrf($_POST['csrf_token'] ?? '')) { $error='Invalid CSRF token'; }
    else {
        $ids = array_filter((array)($_POST['room_ids'] ?? []), 'strlen');
        if (!$ids) $error='No rooms selected';
        else {
            $ok=$fail=0;
            foreach ($ids as $rid) {
                $resp = makeMatrixRequest(
                    MATRIX_SERVER.'/_synapse/admin/v2/rooms/'.rawurlencode($rid),
                    'DELETE', null, ['Authorization: Bearer '.$_SESSION['admin_token'], 'Content-Type: application/json']
                );
                if ($resp['success'] && $resp['http_code']>=200 && $resp['http_code']<300) { $ok++; logAction('delete room req '.$rid); }
                else { $fail++; logAction('delete room FAILED '.$rid.' '.($resp['response']??$resp['error']??'')); }
            }
            if ($fail===0) $success = "Deletion requested for $ok room(s) (async).";
            else $error = "Requested deletion: OK $ok, failed $fail.";
        }
    }
}

// Fetch rooms list (v1)
$r_page = max(1,(int)($_GET['r_page']??1));
$r_per  = in_array((int)($_GET['r_per_page']??50),[10,50,100]) ? (int)($_GET['r_per_page']) : 50;
$r_search = trim($_GET['r_search'] ?? '');
$from = ($r_page-1)*$r_per;
$url = MATRIX_SERVER.'/_synapse/admin/v1/rooms?limit='.$r_per.'&from='.$from;
if ($r_search!=='') $url .= '&search_term='.urlencode($r_search);
$res = makeMatrixRequest($url,'GET',null,['Authorization: Bearer '.$_SESSION['admin_token']]);
$rooms = []; $total = 0;
if ($res['success'] && $res['http_code']===200) {
    $d = json_decode($res['response'],true);
    $rooms = $d['rooms'] ?? [];
    $total = (int)($d['total_rooms'] ?? count($rooms));
}
$pages = max(1,(int)ceil($total/$r_per));
?>

<?php if ($error): ?><div class="card" style="border-color:#ff4444;color:#ff6666;"><?= htmlspecialchars($error) ?></div><?php endif; ?>
<?php if ($success): ?><div class="card" style="border-color:#30363D;color:#79C0FF;"><?= htmlspecialchars($success) ?></div><?php endif; ?>

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
          $rid = $r['room_id']; $name = $r['name'] ?? '(no name)';
          $rtype = $r['room_type'] ?? 'room';
          $vis = ($r['public']??false) ? 'public' : ($r['join_rules'] ?? 'invite');
          $mem = (int)($r['joined_members'] ?? 0);
          $enc = !empty($r['encryption']) ? 'yes' : 'no';
          $creator = $r['creator'] ?? '—';
        ?>
        <tr style="border-bottom:1px solid #30363D">
          <td style="padding:10px;text-align:center"><input class="roomChk" type="checkbox" name="room_ids[]" value="<?= htmlspecialchars($rid) ?>"></td>
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
  const all = document.getElementById('checkAll');
  const btn = document.getElementById('bulkBtn');
  function syncBtn(){ btn.disabled = document.querySelectorAll('.roomChk:checked').length===0; }
  if (all) all.addEventListener('change', () => {
    document.querySelectorAll('.roomChk').forEach(cb => cb.checked = all.checked);
    syncBtn();
  });
  document.addEventListener('change', e => { if (e.target.classList && e.target.classList.contains('roomChk')) syncBtn(); });
</script>
