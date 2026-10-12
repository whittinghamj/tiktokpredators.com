<?php
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
// Isolated query-path regression check; no production database or network access.
require_once dirname(__DIR__) . '/lib/case-ollama.php';
$source = file_get_contents(dirname(__DIR__) . '/index.php');
$start = strpos($source, '  $whereParts = ["c.status NOT IN');
$end = strpos($source, 'if ($rs && count($rs) > 0):', $start);
$listing = 'try {' . substr($source, $start, $end - $start);
final class ListingStatement extends PDOStatement {
    private array $rows;
    public function __construct(array $rows) { $this->rows = $rows; }
    public function execute(?array $params = null): bool { return true; }
    public function fetchAll(int $mode = PDO::FETCH_DEFAULT, mixed ...$args): array { return $this->rows; }
    public function getIterator(): Iterator { return new ArrayIterator($this->rows); }
}
final class ListingDatabase extends PDO {
    public array $queries = [];
    public array $fixture = [];
    public array $reports = [];
    public bool $summaryUnavailable = false;
    public function __construct() {}
    public function prepare(string $query, array $options = []): PDOStatement|false {
        $this->queries[] = $query;
        if (str_contains($query, 'FROM case_ollama_reports')) {
            if ($this->summaryUnavailable) { throw new PDOException('Synthetic missing report table'); }
            return new ListingStatement($this->reports);
        }
        if (strpos($query, 'SELECT case_id, COUNT(*)') === 0) { return new ListingStatement([1 => 7]); }
        if (strpos($query, 'SELECT ctl.case_id') === 0) {
            return new ListingStatement([['case_id' => 1, 'slug' => 'example', 'label' => 'Example']]);
        }
        return new ListingStatement($this->fixture);
    }
}
function tp_case_tag_options(): array { return ['example' => 'Example']; }
function is_admin(): bool { return ($_SESSION['user']['role'] ?? '') === 'admin'; }
function log_console(string $level, string $message): void { throw new RuntimeException($message); }
function check(bool $condition, string $message): void {
    if (!$condition) { throw new RuntimeException($message); }
}
$pdo = new ListingDatabase();
$search = 'test'; $tagFilter = 'example'; $_GET = ['page' => '2']; $_SESSION = [];
$pdo->fixture = array_map(fn($id) => ['id' => $id], range(1, 25));
eval($listing);
check(count($rs) === 24 && $caseHasNext, 'Page should trim the lookahead row.');
check(count($pdo->queries) === 3, 'List must batch counts and tags in three queries.');
check(str_contains($pdo->queries[0], 'LIMIT 25 OFFSET 24'), 'Second page offset is wrong.');
check(!str_contains($pdo->queries[0], 'FROM case_views'), 'Analytics table must only be queried for selected cases.');
check($rs[0]['case_view_count'] === 7 && $caseTagsById[1]['example'] === 'Example', 'Batch results were not mapped to cards.');
check(count($queryParams) === 11, 'Search and tag placeholders changed.');
check($caseAiBadgesById === [], 'Public listings must not read AI summary metadata.');
$_SESSION = ['user' => ['role' => 'admin']]; $pdo->queries = [];
$pdo->reports = [
    ['case_id' => 1, 'status' => 'Ready', 'requested_version' => 2, 'processed_version' => 2],
    ['case_id' => 2, 'status' => 'Queued', 'requested_version' => 1, 'processed_version' => 0],
    ['case_id' => 3, 'status' => 'Processing', 'requested_version' => 1, 'processed_version' => 0],
    ['case_id' => 4, 'status' => 'Ready', 'requested_version' => 3, 'processed_version' => 2],
    ['case_id' => 5, 'status' => 'Partial', 'requested_version' => 1, 'processed_version' => 1],
    ['case_id' => 6, 'status' => 'Failed', 'requested_version' => 1, 'processed_version' => 0],
];
eval($listing);
check(count($pdo->queries) === 4, 'Admin summary statuses must use a single batch query.');
foreach ([1 => 'Complete', 2 => 'Pending', 3 => 'Pending', 4 => 'Pending', 5 => 'Partial', 6 => 'Failed', 7 => 'Not started'] as $id => $label) {
    check(str_contains($caseAiBadgesById[$id], 'AI Summary: ' . $label), 'Incorrect AI summary badge for case #' . $id);
}
check(count($caseAiBadgesById) === 24 && !isset($caseAiBadgesById[25]), 'AI badges must exclude the pagination lookahead case.');
check(!str_contains($pdo->queries[3], 'report_text') && !str_contains($pdo->queries[3], 'report_json') && !str_contains($pdo->queries[3], 'error_message'), 'Case listing fetched private report content.');
$pdo->summaryUnavailable = true; $pdo->queries = [];
eval($listing);
check(count($rs) === 24 && str_contains($caseAiBadgesById[1], 'AI Summary: Unavailable'), 'A report table outage hid cases or falsely showed not started.');
$pdo->summaryUnavailable = false;
foreach (['viewer', 'moderator', ''] as $role) {
    $_SESSION = ['user' => ['role' => $role]]; $pdo->queries = [];
    eval($listing);
    check(count($pdo->queries) === 3 && $caseAiBadgesById === [] && tp_case_ollama_summary_badge($pdo->reports[0]) === '', 'Non-admin AI summary metadata was exposed.');
}
$pdo->fixture = []; $pdo->queries = []; $_GET = ['page' => '-5']; $search = ''; $tagFilter = '';
eval($listing);
check($casePage === 1 && !$caseHasNext && count($pdo->queries) === 1, 'Empty/invalid page handling failed.');
$viewStart = strpos($source, 'function log_case_view(');
$viewEnd = strpos($source, 'function get_case_view_count', $viewStart);
check(!str_contains(substr($source, $viewStart, $viewEnd - $viewStart), 'tp_geo_lookup_api('), 'Page-view tracking must not make network calls.');
check(!preg_match('/\$pdo->exec\([\s\S]{0,10}[\'\"](?:ALTER|CREATE)/', $source), 'Runtime schema DDL returned.');
// HTML analytics must only issue tickets, with no DB writes or scans.
$queueStart = strpos($source, '    function log_case_view(');
$queueEnd = strpos($source, '    function tp_write_case_view', $queueStart);
eval(substr($source, $queueStart, $queueEnd - $queueStart));
$pdo->queries = [];
$_SESSION = []; $_SERVER['REQUEST_URI'] = '/?view=case&code=EXAMPLE';
for ($i = 0; $i < 15; $i++) { log_case_view($pdo, $i); }
check(count($pdo->queries) === 0, 'HTML analytics accessed the database.');
check(count($_SESSION['pending_case_views']) === 12, 'Pending tickets are not bounded.');
$ticket = $GLOBALS['tp_view_ticket'];
check($_SESSION['pending_case_views'][$ticket]['case_id'] === 14, 'Ticket is not bound to its case.');
check($_SESSION['pending_case_views'][$ticket]['request']['REQUEST_URI'] === $_SERVER['REQUEST_URI'], 'Original request context was lost.');
check(strpos($source, 'session_write_close();', strpos($source, 'unset($_SESSION[\'pending_case_views\'][$ticket]);')) < strpos($source, 'tp_write_case_view($pdo, $caseId);', strpos($source, 'if (($_POST[\'action\'] ?? \'\') === \'update_view_client\')')), 'Async analytics must release the session before querying.');
echo "Performance regression checks passed.\n";
