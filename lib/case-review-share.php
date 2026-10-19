<?php
if (empty($viewCase) || !tp_can_share_case_review($viewCase)) { return; }
?>
<div class="modal fade" id="caseReviewShareModal" tabindex="-1" aria-labelledby="caseReviewShareTitle" aria-hidden="true" data-case-id="<?= (int)$viewCaseId ?>" data-csrf="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">
  <div class="modal-dialog modal-dialog-centered">
    <div class="modal-content">
      <div class="modal-header">
        <h3 class="modal-title h5" id="caseReviewShareTitle">Share unpublished case for review</h3>
        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
      </div>
      <div class="modal-body">
        <p>Anyone with the private link can review this case and its evidence without signing in. They cannot edit, approve, or publish the case.</p>
        <p class="small text-secondary">A warning banner identifies the case as unverified and unpublished. Existing blur areas and sensitivity restrictions still apply.</p>
        <p class="small text-secondary">Links expire after 7 days. Creating a new link replaces the previous link. Revoke the link below to stop access sooner.</p>
        <div id="caseReviewLinkResult" class="d-none">
          <label for="caseReviewLink" class="form-label">Private review link</label>
          <div class="input-group mb-2">
            <input id="caseReviewLink" class="form-control" type="url" readonly spellcheck="false">
            <button id="caseReviewCopy" type="button" class="btn btn-outline-light">Copy</button>
          </div>
          <div id="caseReviewExpiry" class="small text-secondary mb-2"></div>
        </div>
        <p id="caseReviewMessage" class="small mb-0" role="status" aria-live="polite"></p>
      </div>
      <div class="modal-footer">
        <button id="caseReviewRevoke" type="button" class="btn btn-outline-danger">Revoke link</button>
        <button id="caseReviewCreate" type="button" class="btn btn-warning">Create review link</button>
      </div>
    </div>
  </div>
</div>
<script defer src="assets/case-review.js?v=1"></script>
