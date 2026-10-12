<?php
if (!function_exists('is_admin')) { http_response_code(404); return; }
// This file is included by index.php after the database and auth bootstrap.
if (!in_array($_POST['action'] ?? '', ['case_ollama_status', 'case_ollama_refresh', 'case_ollama_chat', 'case_ollama_clear_chat', 'ollama_worker_status'], true)) { return; }

function tp_case_ollama_respond(array $payload, int $status = 200): void {
  http_response_code($status);
  header('Content-Type: application/json; charset=utf-8');
  header('Cache-Control: private, no-store, max-age=0');
  header('Vary: Cookie');
  echo json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
  exit;
}

if (!is_admin()) { tp_case_ollama_respond(['ok' => false, 'error' => 'Unauthorized. Admins only.'], 403); }
if (!check_csrf()) { tp_case_ollama_respond(['ok' => false, 'error' => 'Security check failed. Refresh and try again.'], 403); }
$adminId = (int)($_SESSION['user']['id'] ?? 0);
if ($adminId <= 0) { tp_case_ollama_respond(['ok' => false, 'error' => 'Unauthorized. Admins only.'], 403); }
if (($_POST['action'] ?? '') === 'ollama_worker_status') {
  if (session_status() === PHP_SESSION_ACTIVE) { session_write_close(); }
  $afterValue = $_POST['after_id'] ?? '0';
  if (!is_string($afterValue) || !ctype_digit($afterValue) || strlen($afterValue) > 18) {
    tp_case_ollama_respond(['ok' => false, 'error' => 'Invalid log cursor.'], 400);
  }
  try { tp_case_ollama_respond(['ok' => true] + tp_ollama_worker_snapshot($pdo, (int)$afterValue)); }
  catch (Throwable $e) { tp_case_ollama_respond(['ok' => false, 'error' => 'Worker monitoring is unavailable. Run update.sh and check the database connection.'], 503); }
}
$caseIdValue = $_POST['case_id'] ?? '';
$caseId = is_string($caseIdValue) && ctype_digit($caseIdValue) ? (int)$caseIdValue : 0;
$caseCode = tp_post_string('case_code');
if ($caseId <= 0 || $caseCode === '') { tp_case_ollama_respond(['ok' => false, 'error' => 'Invalid case.'], 400); }
// Long inference requests must not block other tabs, approvals or uploads.
if (session_status() === PHP_SESSION_ACTIVE) { session_write_close(); }
$chatLock = null;
try {
  $caseQuery = $pdo->prepare('SELECT id FROM cases WHERE id = ? AND case_code = ? LIMIT 1');
  $caseQuery->execute([$caseId, $caseCode]);
  $caseExists = (bool)$caseQuery->fetchColumn(); $caseQuery->closeCursor();
  if (!$caseExists) { tp_case_ollama_respond(['ok' => false, 'error' => 'Case not found.'], 404); }
  $config = tp_ollama_config($pdo);
  $configured = trim($config['base_url']) !== '' && trim($config['default_model']) !== '';
  $action = $_POST['action'];
  if ($action === 'case_ollama_refresh') {
    if (!tp_case_ollama_enqueue($pdo, $caseId)) { tp_case_ollama_respond(['ok' => false, 'error' => 'Unable to queue the report. Run the database migration.'], 503); }
    tp_case_ollama_respond(['ok' => true, 'message' => 'Private report queued for generation.']);
  }
  if ($action === 'case_ollama_clear_chat') {
    $clearLock = 'tp_ollama_chat_' . $caseId . '_' . $adminId;
    $lockQuery = $pdo->prepare('SELECT GET_LOCK(?, 0)'); $lockQuery->execute([$clearLock]);
    if ((int)$lockQuery->fetchColumn() !== 1) { tp_case_ollama_respond(['ok' => false, 'error' => 'Wait for the current answer before clearing chat.'], 409); }
    $chatLock = $clearLock;
    $delete = $pdo->prepare('DELETE FROM case_ollama_messages WHERE case_id = ? AND user_id = ?');
    $delete->execute([$caseId, $adminId]);
    $release = $pdo->prepare('SELECT RELEASE_LOCK(?)'); $release->execute([$chatLock]); $chatLock = null;
    tp_case_ollama_respond(['ok' => true]);
  }
  $query = $pdo->prepare('SELECT requested_version, processed_version, status, model, error_message, generated_at FROM case_ollama_reports WHERE case_id = ? LIMIT 1');
  $query->execute([$caseId]); $report = $query->fetch() ?: []; $query->closeCursor();
  $ready = in_array($report['status'] ?? '', ['Ready', 'Partial'], true)
    && (int)($report['processed_version'] ?? 0) === (int)($report['requested_version'] ?? -1);
  $loadContent = $action === 'case_ollama_chat' || tp_post_string('known_version') !== (string)($report['processed_version'] ?? 0) || tp_post_string('include_history') === '1';
  if ($ready && $loadContent) {
    $contentQuery = $pdo->prepare("SELECT report_text, report_json FROM case_ollama_reports WHERE case_id = ? AND requested_version = ? AND processed_version = ? AND status IN ('Ready','Partial')");
    $contentQuery->execute([$caseId, (int)$report['processed_version'], (int)$report['processed_version']]);
    $content = $contentQuery->fetch(); $contentQuery->closeCursor();
    if (!$content || $content['report_json'] === null) { $ready = false; }
    else { $report = array_merge($report, $content); }
  }
  $history = [];
  if ($ready && $loadContent) {
    $historyQuery = $pdo->prepare('SELECT question, answer, created_at FROM case_ollama_messages WHERE case_id = ? AND user_id = ? AND report_version = ? ORDER BY id DESC LIMIT 20');
    $historyQuery->execute([$caseId, $adminId, (int)$report['processed_version']]); $history = $historyQuery->fetchAll();
  }
  if ($action === 'case_ollama_status') {
    $data = $ready && $loadContent ? json_decode((string)$report['report_json'], true) : [];
    tp_case_ollama_respond([
      'ok' => true, 'configured' => $configured, 'ready' => $ready,
      'status' => $report['status'] ?? 'Not generated', 'version' => (int)($report['processed_version'] ?? 0),
      'report' => !$ready ? '' : ($loadContent ? (string)$report['report_text'] : null), 'coverage' => $data['coverage'] ?? [],
      'model' => $report['model'] ?? '', 'generated_at' => $report['generated_at'] ?? null,
      'error' => $report['error_message'] ?? '', 'history' => $loadContent ? array_reverse($history) : null,
    ]);
  }
  if (!$configured) { tp_case_ollama_respond(['ok' => false, 'error' => 'Configure an Ollama server and default model in Project Settings first.'], 409); }
  if (!$ready) { tp_case_ollama_respond(['ok' => false, 'error' => 'The private report is not ready. Generate or refresh it before asking questions.'], 409); }
  $questionValue = $_POST['question'] ?? null;
  if (!is_string($questionValue) || !mb_check_encoding($questionValue, 'UTF-8')) { tp_case_ollama_respond(['ok' => false, 'error' => 'Enter a valid text question.'], 400); }
  $question = trim($questionValue);
  if ($question === '' || mb_strlen($question, 'UTF-8') > 2000 || preg_match('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', $question)) {
    tp_case_ollama_respond(['ok' => false, 'error' => 'Enter a question between 1 and 2000 characters.'], 400);
  }
  $chatLock = 'tp_ollama_chat_' . $caseId . '_' . $adminId;
  $lockQuery = $pdo->prepare('SELECT GET_LOCK(?, 0)'); $lockQuery->execute([$chatLock]);
  if ((int)$lockQuery->fetchColumn() !== 1) { $chatLock = null; tp_case_ollama_respond(['ok' => false, 'error' => 'A question is already being answered for this case.'], 409); }
  $answer = tp_case_ollama_answer($config, $report, $question, $history);
  $pdo->beginTransaction();
  $check = $pdo->prepare('SELECT requested_version, processed_version, status FROM case_ollama_reports WHERE case_id = ? FOR UPDATE');
  $check->execute([$caseId]); $current = $check->fetch();
  if (!$current || !in_array($current['status'], ['Ready', 'Partial'], true)
      || (int)$current['requested_version'] !== (int)$report['processed_version']
      || (int)$current['processed_version'] !== (int)$report['processed_version']) {
    $pdo->rollBack();
    $release = $pdo->prepare('SELECT RELEASE_LOCK(?)'); $release->execute([$chatLock]); $chatLock = null;
    tp_case_ollama_respond(['ok' => false, 'error' => 'The case evidence changed while answering. Wait for the refreshed report and ask again.'], 409);
  }
  $save = $pdo->prepare('INSERT INTO case_ollama_messages (case_id, user_id, report_version, question, answer) VALUES (?, ?, ?, ?, ?)');
  $save->execute([$caseId, $adminId, (int)$report['processed_version'], $question, $answer]);
  $pdo->commit();
  $release = $pdo->prepare('SELECT RELEASE_LOCK(?)'); $release->execute([$chatLock]); $chatLock = null;
  tp_case_ollama_respond(['ok' => true, 'answer' => $answer, 'question' => $question, 'version' => (int)$report['processed_version']]);
} catch (Throwable $e) {
  if ($pdo->inTransaction()) { $pdo->rollBack(); }
  if ($chatLock !== null) { try { $release = $pdo->prepare('SELECT RELEASE_LOCK(?)'); $release->execute([$chatLock]); } catch (Throwable $ignored) {} }
  $message = $e instanceof RuntimeException && !($e instanceof PDOException) ? $e->getMessage() : 'Case AI is unavailable. Check the database migration and worker configuration.';
  tp_case_ollama_respond(['ok' => false, 'error' => $message], 503);
}
