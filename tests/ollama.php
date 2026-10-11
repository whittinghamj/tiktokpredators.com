<?php
// The CLI test starts this file as a loopback-only fake Ollama server.
if (PHP_SAPI === 'cli-server') {
  header('Content-Type: application/json');
  $path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
  if ($path === '/authenticated/api/tags') {
    if (($_SERVER['HTTP_AUTHORIZATION'] ?? '') !== 'Bearer test-token') {
      http_response_code(401); echo '{}'; return;
    }
    echo json_encode(['models' => [['name' => 'example:latest'], ['name' => 'other:7b']]]); return;
  }
  if ($path === '/empty/api/tags') {
    if (!empty($_SERVER['HTTP_AUTHORIZATION'])) { http_response_code(403); echo '{}'; return; }
    echo '{"models":[]}'; return;
  }
  if ($path === '/redirect/api/tags') {
    header('Location: /authenticated/api/tags', true, 302); echo '{}'; return;
  }
  if ($path === '/invalid/api/tags') { echo '<html>Not Ollama</html>'; return; }
  if ($path === '/malformed/api/tags') { echo '{"models":[{}]}'; return; }
  if ($path === '/forbidden/api/tags') { http_response_code(403); echo '{}'; return; }
  if ($path === '/unavailable/api/tags') { http_response_code(503); echo '{}'; return; }
  http_response_code(404); echo '{}'; return;
}
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
require dirname(__DIR__) . '/lib/ollama.php';

function ollama_check(bool $condition, string $message): void {
  if (!$condition) { throw new RuntimeException($message); }
}

$defaults = tp_ollama_settings_defaults();
ollama_check(tp_validate_ollama_settings([]) === $defaults, 'Unconfigured settings should be optional.');
$valid = tp_validate_ollama_settings([
  'ollama_base_url' => ' http://192.168.1.10:11434/proxy/ ',
  'ollama_api_key' => ' test-token ',
  'ollama_default_model' => ' example:latest ',
  'ollama_timeout' => '600',
]);
ollama_check($valid['ollama_base_url'] === 'http://192.168.1.10:11434/proxy', 'Base URL was not normalized.');
ollama_check($valid['ollama_api_key'] === 'test-token' && $valid['ollama_default_model'] === 'example:latest', 'Text fields were not trimmed.');
foreach (['http://localhost:11434', 'https://ollama.example.com', 'http://[::1]:11434'] as $url) {
  ollama_check(tp_validate_ollama_settings(['ollama_base_url' => $url])['ollama_base_url'] === $url, 'Valid server address was rejected.');
}
$invalid = [
  ['ollama_base_url' => 'file:///etc/passwd'],
  ['ollama_base_url' => 'ftp://example.com'],
  ['ollama_base_url' => 'http://user:password@example.com'],
  ['ollama_base_url' => 'http://example.com?key=secret'],
  ['ollama_base_url' => 'http://example.com#fragment'],
  ['ollama_base_url' => "http://example.com/\r\nInjected: value"],
  ['ollama_api_key' => "token\r\nInjected: value"],
  ['ollama_api_key' => str_repeat('x', 4097)],
  ['ollama_default_model' => 'model with spaces'],
  ['ollama_default_model' => str_repeat('x', 256)],
  ['ollama_timeout' => '4'], ['ollama_timeout' => '601'],
  ['ollama_timeout' => '1.5'], ['ollama_timeout' => ''],
];
foreach (array_keys($defaults) as $key) { $invalid[] = [$key => ['unexpected-array']]; }
foreach ($invalid as $input) {
  $rejected = false;
  try { tp_validate_ollama_settings($input); } catch (InvalidArgumentException $e) { $rejected = true; }
  ollama_check($rejected, 'Malformed Ollama settings were accepted: ' . json_encode($input));
}
ollama_check(tp_test_ollama_server([])[0] === false, 'A missing server URL should not trigger a request.');

// Exercise the actual settings read/save handlers with a fake PDO, never the app DB.
$source = file_get_contents(dirname(__DIR__) . '/index.php');
$readStart = strpos($source, 'function tp_project_settings(');
$readEnd = strpos($source, 'function tp_discord_webhooks(', $readStart);
$readCode = substr($source, $readStart, $readEnd - $readStart);
$saveStart = strpos($source, '  // Handle project settings save (main admin only)');
$saveEnd = strpos($source, '// Admin-only case ownership transfer.', $saveStart);
$saveCode = substr($source, $saveStart, $saveEnd - $saveStart);
$testStart = strpos($source, '// Test submitted Ollama connection details without saving');
$testEnd = strpos($source, '// Run an explicit OpenAI availability check', $testStart);
$testCode = substr($source, $testStart, $testEnd - $testStart);
$bootstrap = <<<'PHP'
require $argv[1];
class OllamaStatement extends PDOStatement {
  public function execute(?array $params = null): bool { $GLOBALS['writes'][$params[0]] = $params[1]; return true; }
  public function fetchAll(int $mode = PDO::FETCH_DEFAULT, mixed ...$args): array { return $GLOBALS['rows']; }
}
class OllamaDatabase extends PDO {
  public function __construct() {}
  public function query(string $query, ?int $fetchMode = null, mixed ...$args): PDOStatement|false { return new OllamaStatement(); }
  public function prepare(string $query, array $options = []): PDOStatement|false { return new OllamaStatement(); }
}
function throttle() {}
function check_csrf() { return $GLOBALS['csrf']; }
function tp_is_main_admin() { return $GLOBALS['admin']; }
function tp_discord_webhooks(PDO $pdo): array { return []; }
function flash(string $key, string $message) { $GLOBALS['flashes'][$key] = $message; }
function log_console(string $level, string $message) {}
$pdo = new OllamaDatabase();
$payload = json_decode($argv[2], true);
$rows = $payload['rows']; $writes = []; $flashes = [];
$csrf = $payload['csrf']; $admin = $payload['admin']; $_POST = $payload['post'];
eval($payload['read_code']);
if (!empty($payload['read_only'])) { echo json_encode(tp_ollama_config($pdo)); exit; }
if ($_POST['action'] === 'save_project_settings') {
  register_shutdown_function(function () { echo json_encode(['writes' => $GLOBALS['writes'], 'flashes' => $GLOBALS['flashes']]); });
}
eval($payload['handler']);
PHP;
function ollama_isolated_request(array $payload): array {
  global $bootstrap;
  $process = proc_open([PHP_BINARY, '-r', $bootstrap, dirname(__DIR__) . '/lib/ollama.php', json_encode($payload)], [
    0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w'],
  ], $pipes);
  fclose($pipes[0]);
  $output = stream_get_contents($pipes[1]); fclose($pipes[1]);
  $errors = stream_get_contents($pipes[2]); fclose($pipes[2]);
  ollama_check(proc_close($process) === 0 && $errors === '', 'Isolated settings request failed: ' . $errors);
  $result = json_decode($output, true);
  ollama_check(is_array($result), 'Settings handler did not return a result.');
  return $result;
}
$request = [
  'csrf' => true, 'admin' => true, 'rows' => [], 'read_code' => $readCode, 'handler' => $saveCode,
  'post' => ['action' => 'save_project_settings', 'site_title' => 'Example', 'meta_data' => 'Description', 'openai_api_key' => 'existing-openai'] + $valid,
];
$saved = ollama_isolated_request($request);
foreach ($valid as $key => $value) { ollama_check(($saved['writes'][$key] ?? null) === $value, 'A connection field was not persisted: ' . $key); }
ollama_check($saved['writes']['openai_api_key'] === 'existing-openai' && isset($saved['flashes']['success']), 'Existing settings or success feedback changed.');
$rows = [];
foreach ($saved['writes'] as $key => $value) { $rows[] = ['setting_key' => $key, 'setting_value' => $value]; }
$read = ollama_isolated_request(array_replace($request, ['rows' => $rows, 'read_only' => true]));
ollama_check($read === ['base_url' => $valid['ollama_base_url'], 'api_key' => 'test-token', 'default_model' => 'example:latest', 'vision_model' => '', 'timeout' => 600], 'Saved connection details did not reload.');
foreach (['csrf', 'admin'] as $guard) {
  $denied = ollama_isolated_request(array_replace($request, [$guard => false]));
  ollama_check($denied['writes'] === [] && isset($denied['flashes']['error']), 'Unauthorised settings save wrote to the database.');
  $testRequest = array_replace($request, [$guard => false, 'handler' => $testCode, 'post' => ['action' => 'test_ollama_server', 'ajax' => '1'] + $valid]);
  ollama_check(ollama_isolated_request($testRequest)['ok'] === false, 'Unauthorised connection test was accepted.');
}
$invalidRequest = $request;
$invalidRequest['post']['ollama_timeout'] = '601';
$rejected = ollama_isolated_request($invalidRequest);
ollama_check($rejected['writes'] === [] && isset($rejected['flashes']['error']), 'Invalid connection details partially saved other settings.');
$legacyRequest = $request; $legacyRequest['rows'] = $rows;
foreach (array_keys($defaults) as $key) { unset($legacyRequest['post'][$key]); }
$legacySave = ollama_isolated_request($legacyRequest);
foreach ($valid as $key => $value) { ollama_check($legacySave['writes'][$key] === $value, 'Older forms erased connection details.'); }
$clearRequest = $request; $clearRequest['post'] = array_replace($request['post'], $defaults);
$cleared = ollama_isolated_request($clearRequest);
foreach ($defaults as $key => $value) { ollama_check($cleared['writes'][$key] === $value, 'Optional connection details could not be cleared.'); }

// Verify real cURL behavior against local fixtures, including bearer auth and redirects.
$socket = stream_socket_server('tcp://127.0.0.1:0', $errno, $error);
ollama_check($socket !== false, 'Could not reserve a fixture port: ' . $error);
$address = stream_socket_get_name($socket, false); fclose($socket);
$log = tempnam(sys_get_temp_dir(), 'tp-ollama-test-');
$server = proc_open([PHP_BINARY, '-S', $address, __FILE__], [0 => ['pipe', 'r'], 1 => ['file', $log, 'a'], 2 => ['file', $log, 'a']], $pipes);
fclose($pipes[0]);
try {
  $ready = false;
  for ($i = 0; $i < 50; $i++) {
    $probe = @stream_socket_client('tcp://' . $address, $errno, $error, 0.1);
    if ($probe) { fclose($probe); $ready = true; break; }
    usleep(20000);
  }
  ollama_check($ready, 'Fake Ollama server did not start.');
  $connection = ['ollama_base_url' => 'http://' . $address . '/authenticated', 'ollama_api_key' => 'test-token', 'ollama_default_model' => 'example'];
  [$ok, $code, $message] = tp_test_ollama_server($connection);
  ollama_check($ok && $code === 200 && str_contains($message, 'example:latest') && !str_contains($message, 'not in'), 'Authenticated model list or latest-tag matching failed.');
  $testRequest = array_replace($request, ['handler' => $testCode, 'post' => ['action' => 'test_ollama_server', 'ajax' => '1'] + $connection]);
  ollama_check(ollama_isolated_request($testRequest)['ok'] === true, 'Admin AJAX connection test failed.');
  $connection['ollama_api_key'] = '';
  [$ok, $code] = tp_test_ollama_server($connection);
  ollama_check(!$ok && $code === 401, 'Rejected credentials were reported as valid.');
  $connection['ollama_default_model'] = 'missing-model';
  $connection['ollama_base_url'] = 'http://' . $address . '/empty';
  [$ok, $code, $message] = tp_test_ollama_server($connection);
  ollama_check($ok && str_contains($message, 'No models') && str_contains($message, 'not in'), 'Empty servers or missing default models were not reported.');
  foreach (['invalid' => 200, 'malformed' => 200, 'missing' => 404, 'forbidden' => 403, 'unavailable' => 503, 'redirect' => 302] as $path => $expectedCode) {
    $connection['ollama_base_url'] = 'http://' . $address . '/' . $path;
    [$ok, $code] = tp_test_ollama_server($connection);
    ollama_check(!$ok && $code === $expectedCode, 'Unexpected server response or redirect was accepted: ' . $path);
  }
} finally {
  proc_terminate($server); proc_close($server); unlink($log);
}
echo "Ollama validation, persistence, access control and connection checks passed.\n";
