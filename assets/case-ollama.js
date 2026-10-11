(function () {
  'use strict';
  var panel = document.getElementById('case-ollama');
  if (!panel) return;
  var form = document.getElementById('caseOllamaChatForm');
  var question = document.getElementById('caseOllamaQuestion');
  var send = document.getElementById('caseOllamaSend');
  var refresh = document.getElementById('caseOllamaRefresh');
  var clear = document.getElementById('caseOllamaClear');
  var status = document.getElementById('caseOllamaStatus');
  var warning = document.getElementById('caseOllamaWarning');
  var report = document.getElementById('caseOllamaReport');
  var conversation = document.getElementById('caseOllamaConversation');
  var token = form.querySelector('[name="csrf_token"]').value;
  var busy = false, ready = false, version = null, timer = null, loadedHistory = false;

  function showWarning(message) {
    warning.textContent = message || '';
    warning.classList.toggle('d-none', !message);
  }
  function controls() {
    question.disabled = busy || !ready;
    send.disabled = busy || !ready;
    refresh.disabled = busy;
    clear.disabled = busy;
  }
  async function request(action, values) {
    var data = new FormData();
    data.append('action', action);
    data.append('case_id', panel.dataset.caseId);
    data.append('case_code', panel.dataset.caseCode);
    data.append('csrf_token', token);
    Object.keys(values || {}).forEach(function (key) { data.append(key, values[key]); });
    var response = await fetch(window.location.href, {
      method: 'POST', credentials: 'same-origin', cache: 'no-store',
      headers: { 'X-Requested-With': 'XMLHttpRequest' }, body: data
    });
    var result;
    try { result = await response.json(); }
    catch (error) { throw new Error('The case AI request could not be completed. Refresh the page if your session has expired.'); }
    if (!response.ok || !result.ok) throw new Error(result.error || 'Case AI request failed.');
    return result;
  }
  function addMessage(label, content, isAnswer) {
    var wrapper = document.createElement('div');
    wrapper.className = 'border rounded p-3';
    var title = document.createElement('div');
    title.className = 'small fw-semibold mb-1 ' + (isAnswer ? 'text-info' : 'text-secondary');
    title.textContent = label;
    var body = document.createElement('div');
    body.className = 'small'; body.style.whiteSpace = 'pre-wrap'; body.style.overflowWrap = 'anywhere';
    body.textContent = content;
    wrapper.appendChild(title); wrapper.appendChild(body); conversation.appendChild(wrapper);
    conversation.scrollTop = conversation.scrollHeight;
  }
  function schedulePoll() {
    clearTimeout(timer);
    timer = setTimeout(loadStatus, 8000);
  }
  async function loadStatus() {
    if (busy || document.hidden) { schedulePoll(); return; }
    try {
      var data = await request('case_ollama_status', { known_version: version === null ? '' : String(version), include_history: loadedHistory ? '0' : '1' });
      ready = data.ready && data.configured;
      if (version !== null && (version !== data.version || !data.ready)) {
        conversation.replaceChildren(); loadedHistory = false;
      }
      version = data.version;
      status.textContent = 'Report: ' + data.status + (data.generated_at ? ' · Generated ' + data.generated_at : '') + (data.model ? ' · Model ' + data.model : '');
      if (data.report !== null) report.textContent = data.report || 'Report not ready. Generate a report, then wait for the background analysis to finish.';
      if (!data.configured) {
        showWarning('Set the Ollama server URL and Default Model in Project Settings to generate reports and use case chat.');
      } else if (data.error) {
        showWarning(data.error);
      } else if (data.status === 'Partial') {
        showWarning('Some uploads could not be fully analysed. Check the file coverage in the private report before relying on an answer.');
      } else if (data.status === 'Queued' || data.status === 'Processing') {
        showWarning('The evidence report is being prepared. It may take several minutes for large cases.');
      } else { showWarning(''); }
      if (data.ready && !loadedHistory) {
        conversation.replaceChildren();
        (data.history || []).forEach(function (exchange) {
          addMessage('You', exchange.question, false); addMessage('Ollama', exchange.answer, true);
        });
        loadedHistory = true;
      }
      controls();
    } catch (error) { ready = false; controls(); showWarning(error.message); }
    schedulePoll();
  }
  refresh.addEventListener('click', async function () {
    busy = true; controls(); showWarning('');
    try {
      await request('case_ollama_refresh'); ready = false; loadedHistory = false;
      conversation.replaceChildren(); report.textContent = 'A fresh private report has been queued.';
    } catch (error) { showWarning(error.message); }
    finally { busy = false; controls(); loadStatus(); }
  });
  clear.addEventListener('click', async function () {
    busy = true; controls();
    try { await request('case_ollama_clear_chat'); conversation.replaceChildren(); }
    catch (error) { showWarning(error.message); }
    finally { busy = false; controls(); }
  });
  form.addEventListener('submit', async function (event) {
    event.preventDefault();
    var text = question.value.trim();
    if (busy || !ready || !text || !form.reportValidity()) return;
    busy = true; controls(); showWarning(''); status.textContent = 'Ollama is reading the case context and answering…';
    try {
      var result = await request('case_ollama_chat', { question: text });
      addMessage('You', result.question, false); addMessage('Ollama', result.answer, true);
      question.value = ''; loadedHistory = true;
    } catch (error) { showWarning(error.message); }
    finally { busy = false; controls(); loadStatus(); }
  });
  window.addEventListener('pagehide', function () { clearTimeout(timer); });
  loadStatus();
})();
