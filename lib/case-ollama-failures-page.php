<?php
if (!function_exists('is_admin') || !is_admin() || (int)($_SESSION['user']['id'] ?? 0) <= 0) {
  echo '<main class="container-xl py-4"><div class="alert alert-danger">Unauthorized. Admins only.</div></main>'; return;
}
$failureFilter = is_string($_GET['status'] ?? null) ? $_GET['status'] : '';
$failurePageValue = $_GET['page'] ?? '1';
$failurePage = is_string($failurePageValue) && ctype_digit($failurePageValue) ? max(1, min(100000, (int)$failurePageValue)) : 1;
$failureReportValue = $_GET['report'] ?? '';
$failureReportId = is_string($failureReportValue) && ctype_digit($failureReportValue) && strlen($failureReportValue) <= 18 ? (int)$failureReportValue : 0;
$failureData = null; $failureReport = null; $failurePageError = '';
try {
  $failureData = tp_case_ollama_failures_list($pdo, $failureFilter, $failurePage);
  if ($failureReportId > 0) { $failureReport = tp_case_ollama_failure_report($pdo, $failureReportId); }
} catch (Throwable $e) { $failurePageError = 'AI summary failure reports are unavailable. Run update.sh and check the database connection.'; }
$failureEscape = static fn($value) => htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
$failureLink = static fn(array $params = []) => '?' . http_build_query(array_merge(['view' => 'ai_summary_failures'], $params));
?>
<main class="py-4" id="ai-summary-failures">
  <div class="container-xl">
    <div class="d-flex flex-wrap justify-content-between align-items-center gap-2 mb-3">
      <div>
        <h2 class="h4 mb-1"><i class="bi bi-exclamation-triangle me-2"></i>AI Summary Failures</h2>
        <div class="small text-secondary">Private to admins. Review failed summaries and missing evidence coverage, then retry a case.</div>
      </div>
      <div class="d-flex flex-wrap gap-2">
        <a class="btn btn-outline-light btn-sm" href="<?php echo $failureEscape($failureLink(['status' => $failureData['filter'] ?? '', 'page' => $failureData['page'] ?? 1])); ?>#ai-summary-failures"><i class="bi bi-arrow-clockwise me-1"></i>Refresh</a>
        <a class="btn btn-outline-info btn-sm" href="?view=system_health#ollama-worker-monitor"><i class="bi bi-terminal me-1"></i>Worker Log</a>
      </div>
    </div>
    <?php if ($failurePageError !== ''): ?>
      <div class="alert alert-warning"><?php echo $failureEscape($failurePageError); ?></div>
    <?php else: ?>
      <nav class="d-flex flex-wrap gap-2 mb-3" aria-label="AI summary failure filters">
        <?php foreach (['' => 'All issues', 'Failed' => 'Failed', 'Partial' => 'Partial'] as $filter => $label): ?>
          <a class="btn btn-sm <?php echo $failureData['filter'] === $filter ? 'btn-primary' : 'btn-outline-light'; ?>" <?php if ($failureData['filter'] === $filter): ?>aria-current="page"<?php endif; ?> href="<?php echo $failureEscape($failureLink(['status' => $filter])); ?>#ai-summary-failures"><?php echo $label; ?> <span class="badge text-bg-dark ms-1"><?php echo $filter === '' ? array_sum($failureData['counts']) : $failureData['counts'][$filter]; ?></span></a>
        <?php endforeach; ?>
      </nav>
      <?php if ($failureReportId > 0 && !$failureReport): ?>
        <div class="alert alert-info">This case no longer has a failed or partial summary. It may already be queued or complete.</div>
      <?php endif; ?>
      <?php if ($failureReport): ?>
        <section class="card glass mb-4" id="ai-summary-report" aria-labelledby="aiSummaryFailureReportHeading">
          <div class="card-body">
            <div class="d-flex flex-wrap justify-content-between align-items-start gap-2 mb-3">
              <div>
                <h3 class="h5 mb-1" id="aiSummaryFailureReportHeading"><?php echo $failureReport['status'] === 'Failed' ? 'Failure report' : 'Partial summary report'; ?> — <?php echo $failureEscape($failureReport['case_name'] ?: $failureReport['case_code']); ?></h3>
                <div class="small text-secondary"><?php echo $failureEscape($failureReport['case_code']); ?> · Report version <?php echo (int)$failureReport['requested_version']; ?></div>
              </div>
              <?php echo tp_case_ollama_summary_badge($failureReport); ?>
            </div>
            <div class="alert alert-<?php echo $failureReport['status'] === 'Failed' ? 'danger' : 'warning'; ?> small" style="white-space:pre-wrap;overflow-wrap:anywhere;"><?php echo $failureEscape($failureReport['error_message'] ?: ($failureReport['status'] === 'Failed' ? 'Generation failed without a recorded error. Check the worker log.' : 'Some uploaded sources could not be fully analysed. Review the coverage below.')); ?></div>
            <div class="row g-2 small mb-3">
              <div class="col-md-4"><span class="text-secondary">Queued: </span><?php echo $failureEscape($failureReport['queued_at'] ?? '—'); ?></div>
              <div class="col-md-4"><span class="text-secondary">Last updated: </span><?php echo $failureEscape($failureReport['updated_at'] ?? '—'); ?></div>
              <div class="col-md-4"><span class="text-secondary">Last saved summary model: </span><?php echo $failureEscape($failureReport['model'] ?: 'Not recorded'); ?></div>
            </div>
            <?php if ($failureReport['coverage_issues']): ?>
              <h4 class="h6">Evidence coverage issues</h4>
              <div class="vstack gap-2 mb-3">
                <?php foreach ($failureReport['coverage_issues'] as $entry): ?>
                  <div class="border rounded p-3 small">
                    <div class="fw-semibold"><?php echo $failureEscape(($entry['filename'] ?? '') ?: ($entry['title'] ?? 'Source')); ?></div>
                    <div class="text-secondary"><?php echo !empty($entry['evidence_id']) ? 'Evidence #' . (int)$entry['evidence_id'] . ' · ' : ''; ?><?php echo $failureEscape($entry['status'] ?? 'Unknown'); ?> · <?php echo (int)($entry['parts'] ?? 0); ?> parts analysed</div>
                    <ul class="mb-0 mt-2"><?php foreach ((is_array($entry['issues'] ?? null) ? $entry['issues'] : []) as $issue): ?><li><?php echo $failureEscape($issue); ?></li><?php endforeach; ?></ul>
                  </div>
                <?php endforeach; ?>
              </div>
            <?php endif; ?>
            <?php if (!empty($failureReport['report_text'])): ?>
              <details class="mb-3"><summary class="text-info small">View available AI summary</summary><pre class="small mt-2 p-3 border rounded" style="white-space:pre-wrap;overflow-wrap:anywhere;max-height:32rem;overflow:auto;"><?php echo $failureEscape($failureReport['report_text']); ?></pre></details>
            <?php elseif ($failureReport['status'] === 'Failed'): ?>
              <p class="small text-secondary">This attempt failed before an AI summary was saved. The recorded error and worker activity are shown here.</p>
            <?php endif; ?>
            <details class="mb-3"><summary class="text-info small">Recent worker activity for this case</summary>
              <?php if ($failureReport['events']): ?>
                <pre class="small mt-2 p-3 border rounded" style="white-space:pre-wrap;overflow-wrap:anywhere;max-height:24rem;overflow:auto;"><?php foreach ($failureReport['events'] as $event) {
                  $line = $event['created_at'] . ' [' . $event['level'] . '] ' . $event['phase'] . ': ' . $event['message'];
                  if ($event['source_label'] !== '') { $line .= ' · Source: ' . $event['source_label']; }
                  if ($event['model'] !== '') { $line .= ' · Model: ' . $event['model']; }
                  echo $failureEscape($line) . "\n";
                } ?></pre>
              <?php else: ?><div class="small text-secondary mt-2"><?php echo $failureReport['events_available'] ? 'No recent worker events are retained for this case. Check the service journal for older activity.' : 'Worker event history is unavailable. Check the Ollama Worker Log and deployment.'; ?></div><?php endif; ?>
            </details>
            <div class="d-flex flex-wrap gap-2">
              <a class="btn btn-outline-light btn-sm" href="?view=case&amp;code=<?php echo rawurlencode($failureReport['case_code']); ?>#case-ollama">Open Case</a>
              <form method="post" action="" class="m-0">
                <?php csrf_field(); ?><input type="hidden" name="action" value="case_ollama_retry_failure"><input type="hidden" name="case_id" value="<?php echo (int)$failureReport['case_id']; ?>"><input type="hidden" name="case_code" value="<?php echo $failureEscape($failureReport['case_code']); ?>"><input type="hidden" name="report_version" value="<?php echo (int)$failureReport['requested_version']; ?>">
                <button class="btn btn-primary btn-sm" type="submit"><i class="bi bi-arrow-repeat me-1"></i>Retry AI Summary</button>
              </form>
            </div>
          </div>
        </section>
      <?php endif; ?>
      <div class="card glass">
        <div class="card-body">
          <?php if (!$failureData['rows']): ?><div class="text-secondary">No <?php echo $failureData['filter'] !== '' ? strtolower($failureData['filter']) : 'failed or partial'; ?> AI summaries to review.</div>
          <?php else: ?>
            <div class="table-responsive"><table class="table align-middle mb-0">
              <thead><tr><th>Case</th><th>AI Summary</th><th>Issue</th><th>Last updated</th><th>Actions</th></tr></thead>
              <tbody><?php foreach ($failureData['rows'] as $issue): ?><tr>
                <td><a href="?view=case&amp;code=<?php echo rawurlencode($issue['case_code']); ?>#case-ollama"><?php echo $failureEscape($issue['case_name'] ?: $issue['case_code']); ?></a><div class="text-secondary small"><?php echo $failureEscape($issue['case_code']); ?></div></td>
                <td><?php echo tp_case_ollama_summary_badge($issue); ?></td>
                <td class="small" style="min-width:12rem;max-width:28rem;white-space:pre-wrap;overflow-wrap:anywhere;"><?php echo $failureEscape($issue['error_message'] ?: ($issue['status'] === 'Failed' ? 'Generation failed. Open the failure report for details.' : 'Some evidence could not be fully analysed.')); ?></td>
                <td class="small text-secondary text-nowrap"><?php echo $failureEscape($issue['updated_at'] ?? '—'); ?></td>
                <td><div class="d-flex flex-wrap gap-2">
                  <a class="btn btn-outline-info btn-sm text-nowrap" href="<?php echo $failureEscape($failureLink(['status' => $failureData['filter'], 'page' => $failureData['page'], 'report' => (int)$issue['case_id']])); ?>#ai-summary-report">View Report</a>
                  <form method="post" action="" class="m-0">
                    <?php csrf_field(); ?><input type="hidden" name="action" value="case_ollama_retry_failure"><input type="hidden" name="case_id" value="<?php echo (int)$issue['case_id']; ?>"><input type="hidden" name="case_code" value="<?php echo $failureEscape($issue['case_code']); ?>"><input type="hidden" name="report_version" value="<?php echo (int)$issue['requested_version']; ?>">
                    <button class="btn btn-outline-light btn-sm text-nowrap" type="submit">Retry</button>
                  </form>
                </div></td>
              </tr><?php endforeach; ?></tbody>
            </table></div>
          <?php endif; ?>
        </div>
      </div>
      <?php if ($failureData['page'] > 1 || $failureData['total'] > $failureData['per_page']): ?>
        <nav class="d-flex justify-content-between align-items-center mt-3" aria-label="AI summary failures pages">
          <span class="small text-secondary">Page <?php echo $failureData['page']; ?> · <?php echo $failureData['total']; ?> issue(s)</span><div class="d-flex gap-2">
          <?php foreach (['Previous' => $failureData['page'] - 1, 'Next' => $failureData['page'] + 1] as $label => $target): ?>
            <?php if ($target >= 1 && ($target - 1) * $failureData['per_page'] < $failureData['total']): ?><a class="btn btn-outline-light btn-sm" href="<?php echo $failureEscape($failureLink(['status' => $failureData['filter'], 'page' => $target])); ?>#ai-summary-failures"><?php echo $label; ?></a><?php endif; ?>
          <?php endforeach; ?></div>
        </nav>
      <?php endif; ?>
    <?php endif; ?>
  </div>
</main>
