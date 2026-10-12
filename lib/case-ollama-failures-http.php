<?php
if (($_POST['action'] ?? '') !== 'case_ollama_retry_failure') { return; }
if (!is_admin() || (int)($_SESSION['user']['id'] ?? 0) <= 0) {
  http_response_code(403); echo 'Unauthorized. Admins only.'; exit;
}
if (!check_csrf()) {
  http_response_code(403); echo 'Security check failed. Refresh the page and try again.'; exit;
}
$idValue = tp_post_string('case_id'); $versionValue = tp_post_string('report_version');
try {
  if (!ctype_digit($idValue) || !ctype_digit($versionValue) || strlen($idValue) > 18 || strlen($versionValue) > 18) {
    throw new RuntimeException('Invalid case report.');
  }
  tp_case_ollama_retry_failure($pdo, (int)$idValue, tp_post_string('case_code'), (int)$versionValue);
  flash('success', 'AI summary queued for another attempt. Follow its progress in the Ollama Worker Log.');
} catch (Throwable $e) {
  $message = $e instanceof RuntimeException && !($e instanceof PDOException) ? $e->getMessage() : 'Unable to retry the AI summary. Check the database connection.';
  flash('error', $message);
}
header('Location: ?view=ai_summary_failures#ai-summary-failures', true, 303); exit;
