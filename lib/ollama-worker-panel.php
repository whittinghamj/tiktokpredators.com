<?php
if (!function_exists('is_admin') || !is_admin()) { return; }
?>
<section class="card glass mb-4" id="ollama-worker-monitor" aria-labelledby="ollamaWorkerHeading">
  <div class="card-body">
    <div class="d-flex flex-wrap justify-content-between align-items-center gap-2 mb-3">
      <div>
        <h2 class="h5 mb-1" id="ollamaWorkerHeading"><i class="bi bi-terminal me-2"></i>Ollama Worker — Live Log</h2>
        <div class="small text-secondary">Current report activity and recent worker events. Refreshes every 3 seconds.</div>
      </div>
      <div class="d-flex align-items-center gap-2">
        <span class="badge text-bg-secondary" id="ollamaWorkerBadge">Connecting</span>
        <button type="button" class="btn btn-outline-light btn-sm" id="ollamaWorkerPause">Pause Live Updates</button>
      </div>
    </div>
    <form id="ollamaWorkerMonitorToken" class="d-none"><?php csrf_field(); ?></form>
    <div class="alert alert-warning small d-none" id="ollamaWorkerNotice" role="status"></div>
    <div class="row g-3 small mb-3">
      <div class="col-md-4"><div class="text-secondary">Active case</div><div class="fw-semibold" id="ollamaWorkerCase">Loading…</div></div>
      <div class="col-md-4"><div class="text-secondary">Current activity</div><div class="fw-semibold" id="ollamaWorkerPhase">Loading…</div></div>
      <div class="col-md-4"><div class="text-secondary">Elapsed / heartbeat</div><div id="ollamaWorkerTiming">—</div></div>
      <div class="col-md-8"><div class="text-secondary">Current source</div><div class="font-monospace" id="ollamaWorkerSource" style="overflow-wrap:anywhere;">—</div></div>
      <div class="col-md-4"><div class="text-secondary">Source progress</div><div id="ollamaWorkerProgress">—</div></div>
      <div class="col-12"><span class="text-secondary">Model: </span><span class="font-monospace" id="ollamaWorkerModel">—</span></div>
    </div>
    <div class="d-flex flex-wrap gap-2 mb-3" id="ollamaWorkerCounts" aria-label="Report queue counts"></div>
    <div class="d-flex flex-wrap justify-content-between align-items-center gap-2 mb-2">
      <label class="small d-flex align-items-center gap-2"><input type="checkbox" class="form-check-input mt-0" id="ollamaWorkerFollow" checked>Follow newest events</label>
      <span class="small text-secondary" id="ollamaWorkerUpdated" role="status">Waiting for worker status…</span>
    </div>
    <div class="border rounded p-3 bg-dark font-monospace small" id="ollamaWorkerLog" role="log" aria-label="Live Ollama worker log" style="max-height:28rem;overflow:auto;overflow-wrap:anywhere;white-space:pre-wrap;min-height:8rem;"></div>
    <details class="mt-3">
      <summary class="small text-info">Watch the worker from the command line</summary>
      <pre class="small mt-2 mb-0" style="white-space:pre-wrap;">sudo journalctl -u tiktokpredators-ollama.service -n 100 -f
sudo systemctl status tiktokpredators-ollama.service tiktokpredators-ollama.timer</pre>
    </details>
    <noscript><div class="alert alert-info mt-3 mb-0">Enable JavaScript to watch live worker activity.</div></noscript>
  </div>
</section>
<script src="assets/ollama-worker.js?v=<?php echo (int)filemtime(__DIR__ . '/../assets/ollama-worker.js'); ?>" defer></script>
