<?php
if (PHP_SAPI !== 'cli' && PHP_SAPI !== 'cli-server') { http_response_code(404); exit; }
require_once dirname(__DIR__, 2) . '/lib/ollama.php';
require_once dirname(__DIR__, 2) . '/lib/ollama-worker-monitor.php';
require_once dirname(__DIR__, 2) . '/lib/case-ollama.php';
require_once dirname(__DIR__, 2) . '/lib/case-ollama-failures.php';

// Use a real SQLite database for behavioral tests, translating only MySQL syntax.
class_alias(class_exists('Pdo\\Sqlite') ? 'Pdo\\Sqlite' : 'PDO', 'CaseOllamaSqliteBase');
class CaseOllamaTestDatabase extends CaseOllamaSqliteBase {
  public function __construct(string $path) {
    parent::__construct('sqlite:' . $path, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC]);
    $this->exec('PRAGMA journal_mode = WAL');
    $function = static fn($condition, $yes, $no) => $condition ? $yes : $no;
    if (method_exists($this, 'createFunction')) { $this->createFunction('IF', $function, 3); }
    else { $this->sqliteCreateFunction('IF', $function, 3); }
    $lock = static fn($name) => getenv('TP_OLLAMA_TEST_WORKER_RUNNING') === '1' ? 123 : null;
    if (method_exists($this, 'createFunction')) { $this->createFunction('IS_USED_LOCK', $lock, 1); }
    else { $this->sqliteCreateFunction('IS_USED_LOCK', $lock, 1); }
  }
  private function translate(string $sql): string {
    $sql = str_replace([' FOR UPDATE', 'NOW()'], ['', 'CURRENT_TIMESTAMP'], $sql);
    $key = strpos($sql, 'INSERT INTO ollama_worker_state') === 0 ? 'id' : 'case_id';
    $sql = str_replace('ON DUPLICATE KEY UPDATE', 'ON CONFLICT(' . $key . ') DO UPDATE SET', $sql);
    $sql = preg_replace('/VALUES\(([a-z_][a-z0-9_]*)\)/i', 'excluded.$1', $sql);
    $sql = preg_replace('/TIMESTAMPDIFF\(SECOND, ([a-z0-9_.]+), CURRENT_TIMESTAMP\)/i', "CAST((julianday('now') - julianday($1)) * 86400 AS INTEGER)", $sql);
    $sql = preg_replace('/SELECT (?:GET_LOCK|RELEASE_LOCK)\(\?,[^)]*\)|SELECT RELEASE_LOCK\(\?\)/', 'SELECT CASE WHEN ? IS NOT NULL THEN 1 ELSE 0 END', $sql);
    return $sql;
  }
  public function prepare(string $query, array $options = []): PDOStatement|false { return parent::prepare($this->translate($query), $options); }
  public function query(string $query, ?int $fetchMode = null, mixed ...$args): PDOStatement|false { return $fetchMode === null ? parent::query($this->translate($query)) : parent::query($this->translate($query), $fetchMode, ...$args); }
}
function is_admin(): bool { return ($_SESSION['user']['role'] ?? '') === 'admin'; }
function check_csrf(): bool { return is_string($_POST['csrf_token'] ?? null) && hash_equals('test-csrf', $_POST['csrf_token']); }
function csrf_field(): void { echo '<input type="hidden" name="csrf_token" value="test-csrf">'; }
function flash(string $key, ?string $value = null): string {
  if ($value !== null) { $_SESSION['flash'][$key] = $value; return ''; }
  $value = $_SESSION['flash'][$key] ?? ''; unset($_SESSION['flash'][$key]); return $value;
}
function tp_post_string(string $key): string { return is_string($_POST[$key] ?? null) ? trim($_POST[$key]) : ''; }
function log_console(string $level, string $message): void {}
function tp_client_ip(): array { return ['127.0.0.1', '']; }
function get_case_tiktok_usernames(PDO $pdo, int $caseId): string { return ''; }
function get_case_tags(PDO $pdo, int $caseId): array { return []; }
function find_person_photo_url(string $code): string { return ''; }
function tp_ollama_config(PDO $pdo): array {
  return ['base_url' => getenv('TP_CASE_OLLAMA_TEST_URL'), 'api_key' => 'fixture-token', 'default_model' => 'fixture-text', 'vision_model' => 'fixture-vision', 'timeout' => 5];
}
// Load the actual safety/orientation helpers without bootstrapping the application DB.
$testSource = file_get_contents(dirname(__DIR__, 2) . '/index.php');
$testEventStart = strpos($testSource, 'function log_case_event(');
$testEventEnd = strpos($testSource, '    function tp_header(', $testEventStart);
eval(substr($testSource, $testEventStart, $testEventEnd - $testEventStart));
$testImageStart = strpos($testSource, 'function tp_evidence_ini_bytes(');
$testImageEnd = strpos($testSource, '/** Encode a dynamically oriented image', $testImageStart);
eval(substr($testSource, $testImageStart, $testImageEnd - $testImageStart));
$testPathStart = strpos($testSource, 'function tp_normalize_absolute_storage_path(');
$testPathEnd = strpos($testSource, '/** Ensure the private derivative directory', $testPathStart);
$testPathCode = substr($testSource, $testPathStart, $testPathEnd - $testPathStart);
eval(str_replace('__DIR__', var_export(dirname(__DIR__, 2), true), $testPathCode));
$_SERVER['DOCUMENT_ROOT'] = dirname(__DIR__, 2);
$storagePath = getenv('TP_CASE_OLLAMA_TEST_STORAGE');
