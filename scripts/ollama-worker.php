<?php
// Processes one durable case job per invocation. Run as the web/storage owner.
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
define('TP_OLLAMA_WORKER', true);
require dirname(__DIR__) . '/index.php';
if (session_status() === PHP_SESSION_ACTIVE) { session_write_close(); }
set_time_limit(0);
$locked = false;
try {
  $lock = $pdo->query("SELECT GET_LOCK('tp_ollama_report_worker', 0)");
  $locked = (int)$lock->fetchColumn() === 1;
  if (!$locked) { exit(0); }
  $config = tp_ollama_config($pdo);
  $result = tp_case_ollama_work_one($pdo, $config);
  if ($result) { fwrite(STDOUT, 'Case #' . $result['case_id'] . ' report: ' . $result['status'] . ".\n"); }
} catch (Throwable $e) {
  // Reports, source content and credentials are never written to the worker log.
  fwrite(STDERR, "Ollama worker could not process the queue. Check database migrations and server configuration.\n");
  exit(1);
} finally {
  if ($locked) { $pdo->query("SELECT RELEASE_LOCK('tp_ollama_report_worker')"); }
}
