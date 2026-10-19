(function () {
  'use strict';
  var modal = document.getElementById('caseReviewShareModal');
  if (!modal) return;
  var create = document.getElementById('caseReviewCreate');
  var revoke = document.getElementById('caseReviewRevoke');
  var copy = document.getElementById('caseReviewCopy');
  var link = document.getElementById('caseReviewLink');
  var result = document.getElementById('caseReviewLinkResult');
  var message = document.getElementById('caseReviewMessage');
  function setMessage(value, error) {
    message.textContent = value;
    message.className = 'small mb-0 ' + (error ? 'text-danger' : 'text-success');
  }
  async function changeLink(action) {
    create.disabled = revoke.disabled = true;
    setMessage('Working…', false);
    try {
      var body = new FormData();
      body.append('action', action);
      body.append('case_id', modal.dataset.caseId);
      body.append('csrf_token', modal.dataset.csrf);
      var response = await fetch(window.location.pathname, { method: 'POST', body: body, credentials: 'same-origin' });
      var data;
      try { data = await response.json(); }
      catch (error) { throw new Error('The server returned an unexpected response. Refresh and try again.'); }
      if (!response.ok || !data.ok) throw new Error(data.error || 'Unable to update the review link.');
      link.value = data.url || '';
      result.classList.toggle('d-none', !data.url);
      document.getElementById('caseReviewExpiry').textContent = data.expires_at ? 'Expires ' + new Date(data.expires_at).toLocaleString('en-GB') : '';
      create.textContent = data.url ? 'Create replacement link' : 'Create review link';
      setMessage(data.url ? 'Review link created. Copy it to share with your reviewer.' : 'Review link revoked. Previous links no longer work.', false);
    } catch (error) {
      setMessage(error.message || 'Unable to reach the server. Please try again.', true);
    } finally {
      create.disabled = revoke.disabled = false;
    }
  }
  create.addEventListener('click', function () { changeLink('create_case_review_link'); });
  revoke.addEventListener('click', function () { changeLink('revoke_case_review_link'); });
  copy.addEventListener('click', async function () {
    try {
      await navigator.clipboard.writeText(link.value);
      setMessage('Review link copied.', false);
    } catch (error) {
      link.focus();
      link.select();
      setMessage('Select and copy the review link above.', false);
    }
  });
}());
