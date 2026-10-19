<?php
// Isolated HTTP fixture: execute the real upload handlers against temporary storage.
if (PHP_SAPI !== 'cli-server' || !getenv('TP_EVIDENCE_UPLOAD_TEST_DIR')) { http_response_code(404); exit; }
$directory = getenv('TP_EVIDENCE_UPLOAD_TEST_DIR');
$storagePath = $directory . '/private';
$pdo = new PDO('sqlite:' . $directory . '/fixture.sqlite', null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC]);
$_SESSION = ['user' => ['id' => 1, 'role' => 'admin']];
function throttle(): void {}
function check_csrf(): bool { return ($_POST['csrf_token'] ?? '') === 'test-csrf'; }
function is_moderator(): bool { return false; }
function can_manage_case_submission(PDO $pdo, int $caseId): bool { return true; }
function flash(string $key, ?string $value = null): void {}
function log_console(string $level, string $message): void {}
function log_case_event(PDO $pdo, int $caseId, string $event, string $subject, string $detail, int $evidenceId, $noteId): void {}

$applicationRoot = dirname(__DIR__, 2);
$source = file_get_contents($applicationRoot . '/index.php');
$start = strpos($source, 'function tp_normalize_absolute_storage_path(');
$end = strpos($source, '/** Ensure the private derivative directory', $start);
eval(str_replace('__DIR__', var_export($applicationRoot, true), substr($source, $start, $end - $start)));
$start = strpos($source, '// Handle evidence upload (admin only)');
$end = strpos($source, '// Save a server-rendered public derivative', $start);
eval(substr($source, $start, $end - $start));
