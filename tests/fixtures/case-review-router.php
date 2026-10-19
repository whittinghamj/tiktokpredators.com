<?php
if (PHP_SAPI !== 'cli-server' || !getenv('TP_CASE_REVIEW_TEST_DIR')) { http_response_code(404); exit; }
$root = dirname(__DIR__, 2);
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
if (in_array($path, ['/assets/case-review.css', '/assets/case-review.js', '/assets/site.css'], true)) {
    header('Content-Type: ' . (str_ends_with($path, '.css') ? 'text/css' : 'application/javascript'));
    readfile($root . $path); return;
}
class_alias(class_exists('Pdo\\Sqlite') ? 'Pdo\\Sqlite' : 'PDO', 'CaseReviewSqliteBase');
class CaseReviewTestDatabase extends CaseReviewSqliteBase {
    public function prepare(string $query, array $options = []): PDOStatement|false {
        $query = str_replace(['ON DUPLICATE KEY UPDATE', 'UTC_TIMESTAMP()'], ['ON CONFLICT(case_id) DO UPDATE SET', 'CURRENT_TIMESTAMP'], $query);
        $query = preg_replace('/VALUES\(([a-z_]+)\)/i', 'excluded.$1', $query);
        return parent::prepare($query, $options);
    }
}
$directory = getenv('TP_CASE_REVIEW_TEST_DIR');
$storagePath = $directory . '/private';
$pdo = new CaseReviewTestDatabase('sqlite:' . $directory . '/fixture.sqlite', null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC]);
$role = $_GET['role'] ?? $_COOKIE['tp_case_review_fixture_role'] ?? 'guest';
$userId = (int)($_GET['user'] ?? $_COOKIE['tp_case_review_fixture_user'] ?? 1);
if ($path === '/share-ui') {
    setcookie('tp_case_review_fixture_role', $role, ['path' => '/', 'httponly' => true, 'samesite' => 'Strict']);
    setcookie('tp_case_review_fixture_user', (string)$userId, ['path' => '/', 'httponly' => true, 'samesite' => 'Strict']);
}
$_SESSION = $role === 'guest' ? [] : ['user' => ['id' => $userId, 'role' => $role]];
$_SESSION['csrf_token'] = 'test-csrf';
function check_csrf(): bool { return ($_POST['csrf_token'] ?? '') === 'test-csrf'; }
function log_console(string $level, string $message): void {}
function get_case_tiktok_usernames(PDO $pdo, int $caseId): string { return ''; }
function get_case_tags(PDO $pdo, int $caseId): array { return ['fixture' => 'Fixture tag']; }
$source = file_get_contents($root . '/index.php');
foreach ([
    ['function current_user_role()', 'function tp_is_main_admin('],
    ['function find_person_photo_url(', '/** Public profile-photo roster'],
    ['function tp_request_scheme(', 'function tp_social_summary('],
    ['function tp_evidence_ini_bytes(', "/**\n * Apply a deliberately strong pixelation"],
] as [$from, $until]) {
    $start = strpos($source, $from);
    $end = strpos($source, $until, $start);
    if ($start === false || $end === false) { throw new RuntimeException('Fixture source boundary missing.'); }
    eval(str_replace('__DIR__', var_export($root, true), substr($source, $start, $end - $start)));
}
require $root . '/lib/case-review.php';
$tp_evidence_redactions_ready = ($_GET['schema'] ?? '') !== 'missing';
$tp_evidence_rotation_ready = true;
if ($path === '/share-ui' && empty($_POST['action'])) {
    $viewCase = $pdo->query('SELECT * FROM cases WHERE id = 1')->fetch();
    $viewCaseId = 1;
    echo '<!doctype html><html data-bs-theme="dark"><head><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"><script defer src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script></head><body><main class="container py-4"><button class="btn btn-outline-warning" data-bs-toggle="modal" data-bs-target="#caseReviewShareModal">Share for Review</button>';
    require $root . '/lib/case-review-share.php';
    echo '</main></body></html>'; return;
}
require $root . '/lib/case-review-http.php';
$start = strpos($source, '// Secure evidence streaming endpoint.');
$end = strpos($source, '// Start a short-lived, session-bound Catch a Pred round.', $start);
eval(substr($source, $start, $end - $start));
http_response_code(404);
