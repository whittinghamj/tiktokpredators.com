<?php

/** Metadata-only telemetry: never pass prompts, extracted text, replies or credentials. */
function tp_ollama_worker_monitor_start(PDO $pdo, bool $journal = true): void {
  $runId = bin2hex(random_bytes(16));
  $GLOBALS['tp_ollama_worker_monitor'] = [
    'pdo' => $pdo, 'run_id' => $runId, 'journal' => $journal, 'storage' => true,
    'last_heartbeat' => microtime(true),
    'state' => ['status' => 'Starting', 'case_id' => null, 'evidence_id' => null, 'source_label' => '', 'source_index' => 0, 'source_total' => 0, 'part_index' => 0, 'parts_done' => 0, 'model' => '', 'phase' => 'Starting'],
  ];
  try {
    $stmt = $pdo->prepare("INSERT INTO ollama_worker_state (id, run_id, status, phase, message, started_at, heartbeat_at, phase_started_at)
      VALUES (1, ?, 'Starting', 'Starting', 'Worker started.', NOW(), NOW(), NOW())
      ON DUPLICATE KEY UPDATE run_id = VALUES(run_id), status = 'Starting', phase = 'Starting', message = 'Worker started.',
      case_id = NULL, evidence_id = NULL, source_label = '', source_index = 0, source_total = 0, part_index = 0, parts_done = 0, model = '',
      started_at = NOW(), heartbeat_at = NOW(), phase_started_at = NOW()");
    $stmt->execute([$runId]);
    // Keep a bounded recent log. This indexed delete runs once per worker invocation.
    $maxId = (int)$pdo->query('SELECT MAX(id) FROM ollama_worker_events')->fetchColumn();
    if ($maxId > 5000) {
      $prune = $pdo->prepare('DELETE FROM ollama_worker_events WHERE id <= ?'); $prune->execute([$maxId - 5000]);
    }
  } catch (Throwable $e) {
    $GLOBALS['tp_ollama_worker_monitor']['storage'] = false;
    if ($journal && PHP_SAPI === 'cli') { fwrite(STDERR, "[WARNING] Live worker monitoring storage is unavailable. Run the database migration.\n"); }
  }
}

function tp_ollama_worker_event(string $level, string $message, array $changes = []): void {
  if (empty($GLOBALS['tp_ollama_worker_monitor'])) { return; }
  $context =& $GLOBALS['tp_ollama_worker_monitor'];
  $level = in_array($level, ['INFO', 'WARNING', 'ERROR'], true) ? $level : 'INFO';
  $message = mb_substr(preg_replace('/[\x00-\x1F\x7F]/', ' ', $message) ?? '', 0, 1000, 'UTF-8');
  $state = array_replace($context['state'], array_intersect_key($changes, $context['state']));
  foreach (['source_label' => 300, 'model' => 255, 'phase' => 64, 'status' => 32] as $key => $limit) {
    $state[$key] = mb_substr(preg_replace('/[\x00-\x1F\x7F]/', ' ', (string)$state[$key]) ?? '', 0, $limit, 'UTF-8');
  }
  foreach (['source_index', 'source_total', 'part_index', 'parts_done'] as $key) { $state[$key] = max(0, (int)$state[$key]); }
  foreach (['case_id', 'evidence_id'] as $key) { $state[$key] = (int)$state[$key] > 0 ? (int)$state[$key] : null; }
  $context['state'] = $state; $context['last_heartbeat'] = microtime(true);
  if ($context['journal'] && PHP_SAPI === 'cli') {
    // Filename/title stays in the private dashboard; the journal uses numeric IDs.
    $prefix = '[' . $level . ']';
    if ($state['case_id']) { $prefix .= ' case #' . $state['case_id']; }
    if ($state['evidence_id']) { $prefix .= ' evidence #' . $state['evidence_id']; }
    if ($state['source_total'] && $state['source_index']) { $prefix .= ' source ' . $state['source_index'] . '/' . $state['source_total']; }
    if ($state['part_index']) { $prefix .= ' part ' . $state['part_index']; }
    if ($state['model'] !== '') { $prefix .= ' model ' . $state['model']; }
    fwrite($level === 'ERROR' ? STDERR : STDOUT, $prefix . ' — ' . $message . "\n");
  }
  if (!$context['storage']) { return; }
  try {
    $pdo = $context['pdo'];
    $update = $pdo->prepare('UPDATE ollama_worker_state SET status = ?, case_id = ?, evidence_id = ?, source_label = ?, source_index = ?, source_total = ?, part_index = ?, parts_done = ?, model = ?, phase = ?, message = ?, heartbeat_at = NOW(), phase_started_at = NOW() WHERE id = 1 AND run_id = ?');
    $update->execute([$state['status'], $state['case_id'], $state['evidence_id'], $state['source_label'], $state['source_index'], $state['source_total'], $state['part_index'], $state['parts_done'], $state['model'], $state['phase'], $message, $context['run_id']]);
    $insert = $pdo->prepare('INSERT INTO ollama_worker_events (run_id, level, case_id, evidence_id, source_label, source_index, source_total, part_index, parts_done, model, phase, message) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)');
    $insert->execute([$context['run_id'], $level, $state['case_id'], $state['evidence_id'], $state['source_label'], $state['source_index'], $state['source_total'], $state['part_index'], $state['parts_done'], $state['model'], $state['phase'], $message]);
  } catch (Throwable $e) {
    // Monitoring must never turn a successful analysis into a failed report.
    $context['storage'] = false;
  }
}

/** Called by cURL/extraction loops, including while waiting for a model response. */
function tp_ollama_worker_heartbeat(bool $force = false): void {
  if (empty($GLOBALS['tp_ollama_worker_monitor'])) { return; }
  $context =& $GLOBALS['tp_ollama_worker_monitor'];
  if (!$force && microtime(true) - $context['last_heartbeat'] < 10) { return; }
  $context['last_heartbeat'] = microtime(true);
  if (!$context['storage']) { return; }
  try {
    $stmt = $context['pdo']->prepare('UPDATE ollama_worker_state SET heartbeat_at = NOW() WHERE id = 1 AND run_id = ?');
    $stmt->execute([$context['run_id']]);
  } catch (Throwable $e) { $context['storage'] = false; }
}

/** Read-only global monitor. Caller must verify admin and CSRF before calling. */
function tp_ollama_worker_snapshot(PDO $pdo, int $afterId = 0): array {
  $counts = array_fill_keys(['Queued', 'Processing', 'Ready', 'Partial', 'Failed'], 0);
  foreach ($pdo->query('SELECT status, COUNT(*) AS total FROM case_ollama_reports GROUP BY status') as $row) {
    if (isset($counts[$row['status']])) { $counts[$row['status']] = (int)$row['total']; }
  }
  $running = (bool)$pdo->query("SELECT IS_USED_LOCK('tp_ollama_report_worker') IS NOT NULL")->fetchColumn();
  $active = $pdo->query("SELECT r.case_id, c.case_code, TIMESTAMPDIFF(SECOND, r.updated_at, NOW()) AS elapsed_seconds FROM case_ollama_reports r JOIN cases c ON c.id = r.case_id WHERE r.status = 'Processing' ORDER BY r.queued_at LIMIT 1")->fetch() ?: null;
  $config = tp_ollama_config($pdo);
  $configured = trim($config['base_url']) !== '' && trim($config['default_model']) !== '';
  $state = null; $events = []; $available = true;
  try {
    $state = $pdo->query('SELECT s.run_id, s.status, s.case_id, c.case_code, s.evidence_id, s.source_label, s.source_index, s.source_total, s.part_index, s.parts_done, s.model, s.phase, s.message, TIMESTAMPDIFF(SECOND, s.started_at, NOW()) AS elapsed_seconds, TIMESTAMPDIFF(SECOND, s.heartbeat_at, NOW()) AS heartbeat_age_seconds, TIMESTAMPDIFF(SECOND, s.phase_started_at, NOW()) AS phase_elapsed_seconds FROM ollama_worker_state s LEFT JOIN cases c ON c.id = s.case_id WHERE s.id = 1')->fetch() ?: null;
    $fields = 'e.id, e.level, e.case_id, c.case_code, e.evidence_id, e.source_label, e.source_index, e.source_total, e.part_index, e.parts_done, e.model, e.phase, e.message, TIMESTAMPDIFF(SECOND, e.created_at, NOW()) AS age_seconds';
    if ($afterId > 0) {
      $query = $pdo->prepare('SELECT ' . $fields . ' FROM ollama_worker_events e LEFT JOIN cases c ON c.id = e.case_id WHERE e.id > ? ORDER BY e.id LIMIT 200');
      $query->execute([$afterId]); $events = $query->fetchAll();
    } else {
      $events = array_reverse($pdo->query('SELECT ' . $fields . ' FROM ollama_worker_events e LEFT JOIN cases c ON c.id = e.case_id ORDER BY e.id DESC LIMIT 100')->fetchAll());
    }
  } catch (PDOException $e) {
    // Old worker code/schema can coexist briefly during a deployment.
    if (!in_array((int)($e->errorInfo[1] ?? 0), [1146, 1054], true) && !in_array((string)$e->getCode(), ['42S02', '42S22'], true)) { throw $e; }
    $available = false;
  }
  $stateMatches = $state && $active && (int)$state['case_id'] === (int)$active['case_id'] && $state['status'] === 'Processing';
  $notice = '';
  if (!$available) { $notice = 'Run update.sh to install the live worker log tables.'; }
  elseif ($running && $active && !$stateMatches) { $notice = 'The worker is running. Detailed progress will appear when the updated worker starts its next job.'; }
  elseif (!$running && $active) { $notice = 'A processing job has no active worker connection. The next worker run can resume it.'; }
  return ['running' => $running, 'configured' => $configured, 'counts' => $counts, 'active' => $active, 'state' => $state, 'state_matches_active' => (bool)$stateMatches, 'events' => $events, 'monitor_available' => $available, 'notice' => $notice];
}
