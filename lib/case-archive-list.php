<?php
if (empty($_SESSION['user'])) { return; }
$archivedRows = [];
try {
    $archiveSql = "SELECT c.id, c.case_code, c.case_name, c.person_name, c.status, c.created_by,
        u.display_name AS creator_name, (SELECT COUNT(*) FROM evidence e WHERE e.case_id = c.id) AS evidence_count
        FROM cases c LEFT JOIN users u ON u.id = c.created_by WHERE c.status = 'Archived'";
    $archiveParams = [];
    if (!can_moderate_cases()) {
        $archiveSql .= ' AND c.created_by = ?';
        $archiveParams[] = (int)$_SESSION['user']['id'];
    }
    if (($pendingTagFilter ?? '') !== '') {
        $archiveSql .= ' AND EXISTS (SELECT 1 FROM case_tag_links ctl JOIN case_tags ct ON ct.id = ctl.tag_id WHERE ctl.case_id = c.id AND ct.slug = ?)';
        $archiveParams[] = $pendingTagFilter;
    }
    $query = $pdo->prepare($archiveSql . ' ORDER BY c.updated_at DESC, c.id DESC');
    $query->execute($archiveParams);
    $archivedRows = $query->fetchAll();
} catch (Throwable $e) { $_SESSION['sql_error'] = $e->getMessage(); }
?>
<div class="col-12" id="archived-cases" data-case-review-section data-case-review-status="archived private non-public">
  <div class="card glass border-secondary">
    <div class="card-body">
      <div class="d-flex align-items-center justify-content-between mb-3">
        <h2 class="h5 mb-0"><i class="bi bi-archive me-2"></i>Archived Cases</h2>
        <span class="badge text-bg-secondary">Archived</span>
      </div>
      <p class="alert alert-warning"><strong>Archived — non-public information.</strong> These cases are no longer publicly visible. Open a case to create a private link that expires after 7 days.</p>
      <?php if ($archivedRows): ?>
      <div class="table-responsive">
        <table class="table table-sm align-middle mb-0">
          <thead><tr><th>Case</th><th>Owner</th><th>Subject</th><th>Evidence</th><th class="text-end">Actions</th></tr></thead>
          <tbody>
            <?php foreach ($archivedRows as $archivedCase): ?>
            <tr data-case-review-row>
              <td><strong><?= htmlspecialchars($archivedCase['case_name'] ?: $archivedCase['case_code']) ?></strong><div class="small text-secondary"><?= htmlspecialchars($archivedCase['case_code']) ?></div></td>
              <td><?= htmlspecialchars($archivedCase['creator_name'] ?? 'Unknown') ?></td>
              <td><?= htmlspecialchars($archivedCase['person_name'] ?? '') ?></td>
              <td><?= (int)$archivedCase['evidence_count'] ?></td>
              <td class="text-end"><a class="btn btn-outline-warning btn-sm" href="?view=case&amp;code=<?= rawurlencode($archivedCase['case_code']) ?>#case-view">Open / share privately</a></td>
            </tr>
            <?php endforeach; ?>
          </tbody>
        </table>
      </div>
      <?php else: ?><div class="alert alert-secondary mb-0">No archived cases to show.</div><?php endif; ?>
    </div>
  </div>
</div>
