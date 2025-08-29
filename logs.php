<?php

if (!function_exists('isLoggedIn')) {
  require __DIR__ . '/bootstrap.php';
}

if (!isLoggedIn()) {
  echo '<div class="card"><p>Please log in to view logs.</p></div>';
  return;
}

if (($_POST['action'] ?? '') === 'export_logs') {
  if (!verifyCsrf($_POST['csrf_token'] ?? '')) {
    echo '<div class="card"><div class="alert alert-error">Invalid CSRF token</div></div>';
  } else {
    $rows = [];
    if (file_exists(LOG_FILE)) {
      $lines = file(LOG_FILE, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
      foreach ($lines as $line) {
        if (preg_match('/^\[(.*?)\]\s+(.*?)\s+→\s+(.*)$/u', $line, $m)) {
          $rows[] = [$m[1], $m[2], $m[3]];
        }
      }
    }
    header('Content-Type: text/csv; charset=UTF-8');
    header('Content-Disposition: attachment; filename="matrix-audit-'.date('Y-m-d-H-i-s').'.csv"');
    $out = fopen('php://output', 'w');
    fputcsv($out, ['Timestamp','User','Action']);
    foreach ($rows as $r) fputcsv($out, $r);
    fclose($out);
    exit;
  }
}

$q        = trim($_GET['q'] ?? '');
$lpp      = (int)($_GET['l_per_page'] ?? 50);
if (!in_array($lpp, [10,25,50,100,200], true)) $lpp = 50;
$lp       = max(1, (int)($_GET['l_page'] ?? 1));

$entries = [];
if (file_exists(LOG_FILE)) {
  $lines = file(LOG_FILE, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
  foreach ($lines as $line) {
    if (preg_match('/^\[(.*?)\]\s+(.*?)\s+→\s+(.*)$/u', $line, $m)) {
      $entries[] = ['ts'=>$m[1],'user'=>$m[2],'action'=>$m[3]];
    }
  }
}
usort($entries, fn($a,$b)=>strcmp($b['ts'],$a['ts']));

if ($q !== '') {
  $entries = array_values(array_filter($entries, function($e) use($q){
    return stripos($e['ts'],$q)!==false || stripos($e['user'],$q)!==false || stripos($e['action'],$q)!==false;
  }));
}

$total = count($entries);
$totalPages = max(1, (int)ceil($total / $lpp));
$offset = ($lp - 1) * $lpp;
$entriesPage = array_slice($entries, $offset, $lpp);
?>

<div class="card">
  <h2>Logs</h2>

  <form class="row" method="get" style="gap:10px; align-items:center;">
    <input type="hidden" name="page" value="logs">
    <input class="input" type="text" name="q" placeholder="Filter by text…" value="<?= htmlspecialchars($q) ?>">
    <select class="input" name="l_per_page">
      <?php foreach ([10,25,50,100,200] as $n): ?>
        <option value="<?= $n ?>" <?= $lpp===$n?'selected':'' ?>><?= $n ?> per page</option>
      <?php endforeach; ?>
    </select>
    <button class="btn" type="submit">Search</button>
    <?php if ($q !== '' || $lpp !== 50): ?>
      <a class="btn" style="background:#666" href="?page=logs">Clear</a>
    <?php endif; ?>
  </form>

  <form method="post" style="margin-top:10px;">
    <input type="hidden" name="action" value="export_logs">
    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
    <button class="btn">📥 Download CSV</button>
  </form>
</div>

<div class="card">
  <div class="stats">
    Showing <?= count($entriesPage) ?> of <?= $total ?> log entries
    <?php if ($q !== ''): ?>(filtered by "<?= htmlspecialchars($q) ?>")<?php endif; ?>
  </div>

  <table class="table" style="margin-top:12px;">
    <thead>
      <tr>
        <th style="width:200px">Timestamp</th>
        <th style="width:280px">User</th>
        <th>Action</th>
      </tr>
    </thead>
    <tbody>
      <?php if (!$entriesPage): ?>
        <tr><td colspan="3" style="text-align:center; color:#8B949E;">No entries</td></tr>
      <?php else: foreach ($entriesPage as $e): ?>
        <tr>
          <td><?= htmlspecialchars($e['ts']) ?></td>
          <td><?= htmlspecialchars($e['user']) ?></td>
          <td><?= htmlspecialchars($e['action']) ?></td>
        </tr>
      <?php endforeach; endif; ?>
    </tbody>
  </table>

  <?php if ($totalPages > 1): ?>
    <div class="pagination">
      <?php
        $params = 'page=logs&l_per_page='.$lpp.'&q='.urlencode($q);
        $start = max(1, $lp-2);
        $end   = min($totalPages, $lp+2);
      ?>
      <?php if ($lp > 1): ?>
        <a href="?<?= $params ?>&l_page=1">First</a>
        <a href="?<?= $params ?>&l_page=<?= $lp-1 ?>">Previous</a>
      <?php endif; ?>
      <?php for ($i=$start; $i<=$end; $i++): ?>
        <?php if ($i==$lp): ?>
          <span class="current"><?= $i ?></span>
        <?php else: ?>
          <a href="?<?= $params ?>&l_page=<?= $i ?>"><?= $i ?></a>
        <?php endif; ?>
      <?php endfor; ?>
      <?php if ($lp < $totalPages): ?>
        <a href="?<?= $params ?>&l_page=<?= $lp+1 ?>">Next</a>
        <a href="?<?= $params ?>&l_page=<?= $totalPages ?>">Last</a>
      <?php endif; ?>
    </div>
  <?php endif; ?>
</div>
