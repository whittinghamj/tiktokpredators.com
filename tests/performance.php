<?php
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
// Isolated query-path regression check; no production database or network access.
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
    public function __construct() {}
    public function prepare(string $query, array $options = []): PDOStatement|false {
        $this->queries[] = $query;
        if (strpos($query, 'SELECT case_id, COUNT(*)') === 0) { return new ListingStatement([1 => 7]); }
        if (strpos($query, 'SELECT ctl.case_id') === 0) {
            return new ListingStatement([['case_id' => 1, 'slug' => 'example', 'label' => 'Example']]);
        }
        return new ListingStatement($this->fixture);
    }
}
function tp_case_tag_options(): array { return ['example' => 'Example']; }
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
$pdo->fixture = []; $pdo->queries = []; $_GET = ['page' => '-5']; $search = ''; $tagFilter = '';
eval($listing);
check($casePage === 1 && !$caseHasNext && count($pdo->queries) === 1, 'Empty/invalid page handling failed.');
$viewStart = strpos($source, 'function log_case_view(');
$viewEnd = strpos($source, 'function get_case_view_count', $viewStart);
check(!str_contains(substr($source, $viewStart, $viewEnd - $viewStart), 'tp_geo_lookup_api('), 'Page-view tracking must not make network calls.');
check(!preg_match('/\$pdo->exec\([\s\S]{0,10}[\'\"](?:ALTER|CREATE)/', $source), 'Runtime schema DDL returned.');
echo "Performance regression checks passed.\n";
