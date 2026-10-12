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
  if (!$locked) { fwrite(STDOUT, "[INFO] Another report worker is already running.\n"); exit(0); }
  tp_ollama_worker_monitor_start($pdo);
  $config = tp_ollama_config($pdo);
  if (trim($config['base_url']) === '' || trim($config['default_model']) === '') {
    tp_ollama_worker_event('WARNING', 'Configure the Ollama server and default model in Project Settings.', ['status' => 'Waiting', 'phase' => 'Configuration']);
  } else {
    $result = tp_case_ollama_work_one($pdo, $config);
    if (!$result) { tp_ollama_worker_event('INFO', 'No queued reports. Waiting for the next timer run.', ['status' => 'Idle', 'phase' => 'Idle']); }
  }
} catch (Throwable $e) {
  // Reports, source content and credentials are never written to the worker log.
  tp_ollama_worker_event('ERROR', 'Worker could not process the queue. Check database migrations and server configuration.', ['status' => 'Failed', 'phase' => 'Failed']);
  fwrite(STDERR, "Ollama worker could not process the queue. Check database migrations and server configuration.\n");
  exit(1);
} finally {
  if ($locked) { $pdo->query("SELECT RELEASE_LOCK('tp_ollama_report_worker')"); }
}
