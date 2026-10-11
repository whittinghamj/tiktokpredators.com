<?php
if (!function_exists('is_admin') || !is_admin() || (int)($viewCaseId ?? 0) <= 0) { return; }
?>
<section class="card glass mb-3" id="case-ollama" aria-labelledby="caseOllamaHeading" data-case-id="<?php echo (int)$viewCaseId; ?>" data-case-code="<?php echo htmlspecialchars($caseCode); ?>">
  <div class="card-body">
    <div class="d-flex flex-wrap align-items-center justify-content-between gap-2 mb-2">
      <div>
        <h3 class="h5 mb-1" id="caseOllamaHeading"><i class="bi bi-chat-dots me-2"></i>Ask Ollama about this case</h3>
        <div class="small text-secondary"><i class="bi bi-lock me-1"></i>Private to admins. Answers use this case’s evidence report.</div>
      </div>
      <button type="button" class="btn btn-outline-info btn-sm" id="caseOllamaRefresh"><i class="bi bi-arrow-repeat me-1"></i>Generate / Refresh Report</button>
    </div>
    <div class="small text-secondary mb-2" id="caseOllamaStatus" role="status" aria-live="polite">Loading private report status…</div>
    <div class="alert alert-warning small d-none" id="caseOllamaWarning"></div>
    <details class="mb-3" id="caseOllamaReportDetails">
      <summary class="small text-info">View private evidence report and file coverage</summary>
      <pre class="small mt-2 mb-0 p-3 border rounded" id="caseOllamaReport" style="white-space:pre-wrap;overflow-wrap:anywhere;max-height:32rem;overflow:auto;">Report not generated yet.</pre>
    </details>
    <div class="vstack gap-3 mb-3" id="caseOllamaConversation" role="log" aria-live="polite" style="max-height:32rem;overflow:auto;"></div>
    <form id="caseOllamaChatForm">
      <?php csrf_field(); ?>
      <label class="form-label" for="caseOllamaQuestion">Your question about this case</label>
      <textarea id="caseOllamaQuestion" name="question" class="form-control mb-2" rows="3" maxlength="2000" placeholder="Ask about the uploaded evidence, statements, dates, or gaps…" required disabled></textarea>
      <div class="d-flex flex-wrap align-items-center justify-content-between gap-2">
        <div class="small text-secondary">AI analysis can contain mistakes. Check the cited evidence.</div>
        <div class="d-flex gap-2">
          <button type="button" class="btn btn-outline-secondary btn-sm" id="caseOllamaClear">Clear My Chat</button>
          <button type="submit" class="btn btn-primary btn-sm" id="caseOllamaSend" disabled><i class="bi bi-send me-1"></i>Ask Ollama</button>
        </div>
      </div>
    </form>
    <noscript><div class="alert alert-info mt-3 mb-0">Enable JavaScript to use the private case chat.</div></noscript>
  </div>
</section>
<script src="assets/case-ollama.js?v=<?php echo (int)filemtime(__DIR__ . '/../assets/case-ollama.js'); ?>" defer></script>
