(function () {
  'use strict';
  var panel = document.getElementById('ollama-worker-monitor');
  if (!panel) return;
  var token = document.querySelector('#ollamaWorkerMonitorToken [name="csrf_token"]').value;
  var badge = document.getElementById('ollamaWorkerBadge');
  var pause = document.getElementById('ollamaWorkerPause');
  var notice = document.getElementById('ollamaWorkerNotice');
  var caseLabel = document.getElementById('ollamaWorkerCase');
  var phase = document.getElementById('ollamaWorkerPhase');
  var timing = document.getElementById('ollamaWorkerTiming');
  var source = document.getElementById('ollamaWorkerSource');
  var progress = document.getElementById('ollamaWorkerProgress');
  var model = document.getElementById('ollamaWorkerModel');
  var counts = document.getElementById('ollamaWorkerCounts');
  var log = document.getElementById('ollamaWorkerLog');
  var follow = document.getElementById('ollamaWorkerFollow');
  var updated = document.getElementById('ollamaWorkerUpdated');
  var afterId = 0, paused = false, busy = false, timer = null, stopped = false;

  function duration(value) {
    var seconds = Math.max(0, Number(value) || 0);
    if (seconds < 60) return Math.floor(seconds) + 's';
    if (seconds < 3600) return Math.floor(seconds / 60) + 'm ' + Math.floor(seconds % 60) + 's';
    return Math.floor(seconds / 3600) + 'h ' + Math.floor(seconds % 3600 / 60) + 'm';
  }
  function message(text) { notice.textContent = text || ''; notice.classList.toggle('d-none', !text); }
  function schedule() { clearTimeout(timer); if (!stopped) timer = setTimeout(poll, 3000); }
  function render(data) {
    var state = data.state_matches_active ? data.state : null;
    var active = data.active;
    var label = !data.configured ? 'Needs configuration' : data.running ? 'Running' : active ? 'Interrupted' : data.counts.Queued ? 'Waiting for next run' : 'Idle';
    badge.textContent = label;
    badge.className = 'badge text-bg-' + (!data.configured || (!data.running && active) ? 'warning' : data.running ? 'success' : 'secondary');
    caseLabel.replaceChildren();
    if (active) {
      var link = document.createElement('a');
      link.textContent = active.case_code || 'Case #' + active.case_id;
      link.href = '?view=case&code=' + encodeURIComponent(active.case_code || '') + '#case-view';
      caseLabel.appendChild(link);
    } else { caseLabel.textContent = 'No active case'; }
    phase.textContent = state ? state.phase : active ? 'Processing report' : data.state ? data.state.message : 'Waiting for first worker event';
    source.textContent = state && state.source_label ? state.source_label : '—';
    model.textContent = state && state.model ? state.model : '—';
    timing.textContent = active ? duration(state ? state.elapsed_seconds : active.elapsed_seconds) + ' elapsed' : '—';
    if (state) timing.textContent += ' · heartbeat ' + duration(state.heartbeat_age_seconds) + ' ago · current activity ' + duration(state.phase_elapsed_seconds);
    progress.textContent = state && Number(state.source_total) > 0 ? 'Source ' + state.source_index + ' of ' + state.source_total + ' · ' + state.parts_done + ' parts analysed' + (Number(state.part_index) > 0 ? ' · current part ' + state.part_index : '') : '—';
    counts.replaceChildren();
    ['Queued', 'Processing', 'Ready', 'Partial', 'Failed'].forEach(function (status) {
      var item = document.createElement('span');
      item.className = 'badge text-bg-' + (status === 'Failed' ? 'danger' : status === 'Partial' ? 'warning' : status === 'Ready' ? 'success' : 'secondary');
      item.textContent = status + ': ' + (Number(data.counts[status]) || 0); counts.appendChild(item);
    });
    var warning = data.notice || '';
    if (!data.configured) warning = 'Set the Ollama server and default model in Project Settings.';
    else if (state && Number(state.heartbeat_age_seconds) > 60) warning = 'The worker connection is active, but its heartbeat is older than a minute. Check the current activity and service log.';
    message(warning);
    (data.events || []).forEach(function (event) {
      if (Number(event.id) <= afterId) return;
      afterId = Number(event.id);
      var row = document.createElement('div');
      row.className = event.level === 'ERROR' ? 'text-danger' : event.level === 'WARNING' ? 'text-warning' : '';
      var date = new Date(Date.now() - Math.max(0, Number(event.age_seconds) || 0) * 1000);
      var parts = [date.toLocaleTimeString(), '[' + event.level + ']'];
      if (event.case_id) parts.push(event.case_code || 'case #' + event.case_id);
      if (event.evidence_id) parts.push('evidence #' + event.evidence_id);
      if (Number(event.source_total) > 0 && Number(event.source_index) > 0) parts.push('source ' + event.source_index + '/' + event.source_total);
      if (Number(event.part_index) > 0) parts.push('part ' + event.part_index);
      parts.push(event.phase + ': ' + event.message);
      if (event.source_label) parts.push('(' + event.source_label + ')');
      row.textContent = parts.join(' · '); log.appendChild(row);
    });
    while (log.childElementCount > 500) log.firstElementChild.remove();
    if (follow.checked) log.scrollTop = log.scrollHeight;
    if (!log.childElementCount && data.monitor_available) log.textContent = 'No worker events recorded yet.';
    updated.textContent = 'Updated ' + new Date().toLocaleTimeString();
  }
  async function poll() {
    clearTimeout(timer);
    if (stopped) return;
    if (paused || busy || document.hidden) { schedule(); return; }
    busy = true;
    try {
      var body = new FormData(); body.append('action', 'ollama_worker_status'); body.append('csrf_token', token); body.append('after_id', String(afterId));
      var response = await fetch(window.location.href, { method: 'POST', credentials: 'same-origin', cache: 'no-store', headers: { 'X-Requested-With': 'XMLHttpRequest' }, body: body });
      var data;
      try { data = await response.json(); }
      catch (error) { throw new Error('Could not read worker status. Refresh the page if your session has expired.'); }
      if (!response.ok || !data.ok) throw new Error(data.error || 'Worker status request failed.');
      if (!log.childElementCount) log.textContent = '';
      if (!paused) render(data);
    } catch (error) {
      if (!paused) {
        badge.textContent = 'Unavailable'; badge.className = 'badge text-bg-warning';
        updated.textContent = 'Live updates unavailable'; message(error.message || 'Unable to load worker status.');
      }
    } finally { busy = false; schedule(); }
  }
  pause.addEventListener('click', function () {
    paused = !paused; pause.textContent = paused ? 'Resume Live Updates' : 'Pause Live Updates';
    if (paused) updated.textContent = 'Live updates paused'; else poll();
  });
  document.addEventListener('visibilitychange', function () { if (!document.hidden && !paused) poll(); });
  window.addEventListener('pagehide', function () { stopped = true; clearTimeout(timer); });
  poll();
})();
