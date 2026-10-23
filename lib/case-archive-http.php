<?php
if (!in_array(($_POST['action'] ?? ''), ['archive_case', 'restore_archived_case'], true)) { return; }
tp_case_review_headers();
if (!is_admin()) { http_response_code(403); exit('Only a site admin can archive or restore cases.'); }
if (!check_csrf()) { http_response_code(403); exit('Security check failed. Refresh and try again.'); }
$archiveCaseId = (int)($_POST['case_id'] ?? 0);
$archiveCaseCode = $_POST['case_code'] ?? '';
if ($archiveCaseId <= 0 || !is_string($archiveCaseCode)) { http_response_code(400); exit('Invalid case reference.'); }
$restoreArchive = $_POST['action'] === 'restore_archived_case';
try {
    $pdo->beginTransaction();
    $query = $pdo->prepare('SELECT id, case_code, case_name, status FROM cases WHERE id = ? AND case_code = ? LIMIT 1 FOR UPDATE');
    $query->execute([$archiveCaseId, $archiveCaseCode]);
    $archiveCase = $query->fetch();
    if (!$archiveCase) { $pdo->rollBack(); http_response_code(404); exit('Case not found.'); }
    if ($restoreArchive && $archiveCase['status'] !== 'Archived') {
        $pdo->rollBack(); http_response_code(409); exit('This case is no longer archived.');
    }
    $newArchiveStatus = $restoreArchive ? 'Being Built' : 'Archived';
    if ($archiveCase['status'] !== $newArchiveStatus) {
        $query = $pdo->prepare('UPDATE case_review_links SET revoked_at = CURRENT_TIMESTAMP WHERE case_id = ?');
        $query->execute([$archiveCaseId]);
        $query = $pdo->prepare('UPDATE cases SET status = ? WHERE id = ?');
        $query->execute([$newArchiveStatus, $archiveCaseId]);
        log_case_event($pdo, $archiveCaseId, $restoreArchive ? 'case_restored_from_archive' : 'case_archived',
            $archiveCase['case_name'] ?: $archiveCaseCode,
            $restoreArchive ? 'Archived case restored to the private Being Built workflow. Review is required before publication.' : 'Case archived and removed from public view. Private links expire after seven days.');
    }
    $pdo->commit();
    flash('success', $restoreArchive ? 'Case restored to Being Built. Submit it for review before publishing.' : 'Case archived and removed from public view. You can create a private link valid for 7 days.');
    header('Location: ?view=case&code=' . rawurlencode($archiveCaseCode) . '#case-view'); exit;
} catch (Throwable $e) {
    if (isset($pdo) && $pdo->inTransaction()) { $pdo->rollBack(); }
    log_console('ERROR', 'Case archive update: ' . $e->getMessage());
    http_response_code(503); exit('Unable to update the archive. Please try again.');
}
