<?php
if (PHP_SAPI !== 'cli-server') { http_response_code(404); exit; }
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
if ($path === '/web' || $path === '/ui' || $path === '/monitor' || $path === '/failures' || in_array($path, ['/assets/case-ollama.js', '/assets/ollama-worker.js'], true)) {
  if (strpos($path, '/assets/') === 0) { header('Content-Type: application/javascript'); readfile(dirname(__DIR__, 2) . $path); return; }
  require __DIR__ . '/case-ollama-bootstrap.php';
  $pdo = new CaseOllamaTestDatabase(getenv('TP_CASE_OLLAMA_TEST_DB'));
  $_SESSION = ['user' => ['id' => (int)($_GET['user'] ?? 1), 'role' => $_GET['role'] ?? 'admin']];
  if ($path === '/web' || !empty($_POST['action'])) {
    require dirname(__DIR__, 2) . '/lib/case-ollama-failures-http.php';
    require dirname(__DIR__, 2) . '/lib/case-ollama-http.php'; return;
  }
  if ($path === '/failures') {
    if (!is_admin() || (int)($_SESSION['user']['id'] ?? 0) <= 0) { http_response_code(403); }
    header('Cache-Control: private, no-store, max-age=0'); header('Vary: Cookie');
    echo '<!doctype html><html data-bs-theme="dark"><head><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"><link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css"><title>AI Summary Failures preview</title></head><body>';
    require dirname(__DIR__, 2) . '/lib/case-ollama-failures-page.php';
    echo '</body></html>'; return;
  }
  $viewCaseId = 1; $caseCode = 'CASE1';
  echo '<!doctype html><html data-bs-theme="dark"><head><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"><title>Private case AI preview</title></head><body><main class="container py-4"><h2 class="h4 mb-3">Fixture case | CASE1</h2>';
  require dirname(__DIR__, 2) . ($path === '/monitor' ? '/lib/ollama-worker-panel.php' : '/lib/case-ollama-panel.php');
  echo '</main></body></html>'; return;
}
header('Content-Type: application/json');
if (($_SERVER['HTTP_AUTHORIZATION'] ?? '') !== 'Bearer fixture-token') { http_response_code(401); echo '{"error":"bad token"}'; return; }
$input = json_decode(file_get_contents('php://input'), true);
file_put_contents(getenv('TP_CASE_OLLAMA_TEST_LOG'), json_encode(['path' => $path, 'input' => $input]) . "\n", FILE_APPEND);
if ($path === '/api/show') { echo json_encode(['capabilities' => ($input['model'] ?? '') === 'fixture-text' ? ['completion'] : ['completion', 'vision']]); return; }
if ($path === '/api/chat') {
  if (($input['model'] ?? '') === 'fixture-failure') { http_response_code(500); echo '{"error":"sensitive remote error"}'; return; }
  if (($input['stream'] ?? null) !== false) { http_response_code(400); echo '{"error":"stream must be false"}'; return; }
  $last = end($input['messages']);
  foreach ($last['images'] ?? [] as $image) {
    if (!getimagesizefromstring(base64_decode($image, true))) { http_response_code(400); echo '{"error":"invalid image"}'; return; }
  }
  if (!empty($last['images']) && $input['model'] !== 'fixture-vision') { http_response_code(400); echo '{"error":"wrong vision model"}'; return; }
  $answer = 'Fixture analysis: ' . $last['content'];
  if (str_contains($input['messages'][0]['content'], 'Write a private factual evidence overview')) { $answer = 'Fixture overview of all supplied case analyses. Evidence #101 is a text source.'; }
  if (str_contains($input['messages'][0]['content'], 'administrator-only assistant')) {
    $answer = 'For CASE1, Evidence #101 documents the supplied statement.';
    if (str_contains($last['content'], 'XSS_TEST')) { $answer .= ' <script>alert("untrusted output")</script>'; }
  }
  if (($input['model'] ?? '') === 'fixture-mutating' || str_contains($last['content'], 'MUTATE_CASE_DURING_CHAT')) {
    $database = new PDO('sqlite:' . getenv('TP_CASE_OLLAMA_TEST_DB'));
    $database->exec("UPDATE case_ollama_reports SET requested_version = requested_version + 1, report_text = NULL, report_json = NULL, status = CASE WHEN processing_token IS NULL THEN 'Queued' ELSE 'Processing' END WHERE case_id = 1");
  }
  echo json_encode(['done' => true, 'done_reason' => $input['model'] === 'fixture-truncated' ? 'length' : 'stop', 'message' => ['role' => 'assistant', 'content' => $answer]]); return;
}
http_response_code(404); echo '{}';
