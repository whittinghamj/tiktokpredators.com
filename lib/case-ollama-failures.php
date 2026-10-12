<?php

/** These reads include private diagnostics and must never run for other roles. */
function tp_case_ollama_failures_authorize(): void {
  if (!is_admin() || (int)($_SESSION['user']['id'] ?? 0) <= 0) {
    throw new RuntimeException('Unauthorized. Admins only.');
  }
}

function tp_case_ollama_failures_list(PDO $pdo, string $filter = '', int $page = 1): array {
  tp_case_ollama_failures_authorize();
  $filter = in_array($filter, ['Failed', 'Partial'], true) ? $filter : '';
  $condition = "(r.status = 'Failed' OR (r.status = 'Partial' AND r.requested_version = r.processed_version))";
  $counts = ['Failed' => 0, 'Partial' => 0];
  foreach ($pdo->query('SELECT r.status, COUNT(*) AS total FROM case_ollama_reports r JOIN cases c ON c.id = r.case_id WHERE ' . $condition . ' GROUP BY r.status') as $row) {
    $counts[$row['status']] = (int)$row['total'];
  }
  $total = $filter !== '' ? $counts[$filter] : array_sum($counts);
  $perPage = 20;
  $page = max(1, min($page, max(1, (int)ceil($total / $perPage))));
  $where = $condition . ($filter !== '' ? ' AND r.status = ?' : '');
  // Large evidence reports are fetched only when the admin opens one report.
  $query = $pdo->prepare('SELECT r.case_id, c.case_code, c.case_name, r.status, r.requested_version, r.processed_version, r.error_message, r.model, r.queued_at, r.generated_at, r.updated_at FROM case_ollama_reports r JOIN cases c ON c.id = r.case_id WHERE ' . $where . ' ORDER BY r.updated_at DESC, r.case_id DESC LIMIT ' . $perPage . ' OFFSET ' . (($page - 1) * $perPage));
  $query->execute($filter !== '' ? [$filter] : []);
  return ['rows' => $query->fetchAll(), 'counts' => $counts, 'total' => $total, 'page' => $page, 'per_page' => $perPage, 'filter' => $filter];
}

function tp_case_ollama_failure_report(PDO $pdo, int $caseId): ?array {
  tp_case_ollama_failures_authorize();
  if ($caseId <= 0) { return null; }
  $query = $pdo->prepare("SELECT r.case_id, c.case_code, c.case_name, r.status, r.requested_version, r.processed_version, r.error_message, r.model, r.queued_at, r.generated_at, r.updated_at,
    CASE WHEN r.status = 'Partial' AND r.requested_version = r.processed_version THEN r.report_text ELSE NULL END AS report_text,
    CASE WHEN r.status = 'Partial' AND r.requested_version = r.processed_version THEN r.report_json ELSE NULL END AS report_json
    FROM case_ollama_reports r JOIN cases c ON c.id = r.case_id WHERE r.case_id = ? AND (r.status = 'Failed' OR (r.status = 'Partial' AND r.requested_version = r.processed_version)) LIMIT 1");
  $query->execute([$caseId]); $report = $query->fetch(); $query->closeCursor();
  if (!$report) { return null; }
  $data = json_decode((string)($report['report_json'] ?? ''), true);
  $report['coverage_issues'] = [];
  foreach ((is_array($data) && is_array($data['coverage'] ?? null) ? $data['coverage'] : []) as $entry) {
    if (is_array($entry) && (!empty($entry['issues']) || ($entry['status'] ?? '') !== 'Analysed')) {
      $report['coverage_issues'][] = $entry;
    }
  }
  unset($report['report_json']);
  $report['events'] = []; $report['events_available'] = true;
  try {
    $events = $pdo->prepare('SELECT created_at, level, evidence_id, source_label, phase, message, model FROM ollama_worker_events WHERE case_id = ? AND created_at >= ? ORDER BY id DESC LIMIT 40');
    $events->execute([$caseId, $report['queued_at']]);
    $report['events'] = array_reverse($events->fetchAll());
  } catch (Throwable $e) { $report['events_available'] = false; }
  return $report;
}

/** Lock the issue/version so duplicate retries cannot invalidate an in-progress job. */
function tp_case_ollama_retry_failure(PDO $pdo, int $caseId, string $caseCode, int $version): void {
  tp_case_ollama_failures_authorize();
  if ($caseId <= 0 || $caseCode === '' || $version <= 0) { throw new RuntimeException('Invalid case report.'); }
  $pdo->beginTransaction();
  try {
    $query = $pdo->prepare('SELECT r.status, r.requested_version, r.processed_version FROM case_ollama_reports r JOIN cases c ON c.id = r.case_id WHERE r.case_id = ? AND c.case_code = ? FOR UPDATE');
    $query->execute([$caseId, $caseCode]); $report = $query->fetch(); $query->closeCursor();
    if (!$report || (int)$report['requested_version'] !== $version
        || !in_array($report['status'], ['Failed', 'Partial'], true)
        || ($report['status'] === 'Partial' && (int)$report['processed_version'] !== $version)) {
      throw new RuntimeException('This report has changed or is already queued. Refresh the failures page.');
    }
    if (!tp_case_ollama_enqueue($pdo, $caseId)) { throw new RuntimeException('Unable to queue the report. Check the database migration.'); }
    $pdo->commit();
  } catch (Throwable $e) { if ($pdo->inTransaction()) { $pdo->rollBack(); } throw $e; }
}
