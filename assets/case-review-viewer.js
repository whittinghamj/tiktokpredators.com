(function () {
  'use strict';
  var dialog = document.getElementById('reviewEvidenceDialog');
  if (!dialog || typeof dialog.showModal !== 'function') return;
  var items = Array.from(document.querySelectorAll('[data-review-item]'));
  if (!items.length) return;
  var content = document.getElementById('reviewViewerContent');
  var title = document.getElementById('reviewViewerTitle');
  var meta = document.getElementById('reviewViewerMeta');
  var previous = document.getElementById('reviewViewerPrevious');
  var next = document.getElementById('reviewViewerNext');
  var counter = document.getElementById('reviewViewerCounter');
  var currentIndex = -1;
  var opener = null;
  var textRequest = null;

  function clearPreview() {
    if (textRequest) { textRequest.abort(); textRequest = null; }
    content.querySelectorAll('video, audio').forEach(function (media) {
      media.pause();
      media.removeAttribute('src');
      media.load();
    });
    content.querySelectorAll('iframe').forEach(function (frame) { frame.removeAttribute('src'); });
    content.replaceChildren();
  }

  function openFileLink(item) {
    var link = document.createElement('a');
    link.href = item.dataset.evidenceSrc;
    link.target = '_blank';
    link.rel = 'noopener noreferrer';
    link.textContent = item.dataset.evidenceKind === 'url' ? 'Open external evidence' : 'Open evidence file';
    return link;
  }

  function showItem(index) {
    if (index < 0 || index >= items.length) return;
    clearPreview();
    currentIndex = index;
    var item = items[index];
    var kind = item.dataset.evidenceKind;
    title.textContent = item.dataset.evidenceTitle;
    meta.textContent = item.querySelector('.review-item-meta').textContent;
    counter.textContent = (index + 1) + ' of ' + items.length;
    previous.disabled = index === 0;
    next.disabled = index === items.length - 1;
    var media;
    if (kind === 'image') {
      media = document.createElement('img');
      media.alt = item.dataset.evidenceTitle;
    } else if (kind === 'video' || kind === 'audio') {
      media = document.createElement(kind);
      media.controls = true;
      media.preload = 'metadata';
      if (kind === 'video') media.playsInline = true;
    } else if (kind === 'pdf') {
      media = document.createElement('iframe');
      media.title = item.dataset.evidenceTitle;
      media.referrerPolicy = 'no-referrer';
    } else if (kind === 'text') {
      media = document.createElement('pre');
      media.textContent = 'Loading text…';
    }
    if (media) {
      media.className = 'review-viewer-media review-viewer-' + kind;
      media.addEventListener('error', function () {
        if (!content.contains(media)) return;
        var error = document.createElement('p');
        error.className = 'review-muted';
        error.setAttribute('role', 'status');
        error.textContent = 'This preview could not be loaded. The review link may have expired, or this file may be unavailable.';
        media.replaceWith(error);
      }, { once: true });
      content.appendChild(media);
      if (kind === 'text') {
        textRequest = new AbortController();
        fetch(item.dataset.evidenceSrc, { signal: textRequest.signal, credentials: 'same-origin', referrerPolicy: 'no-referrer' })
          .then(function (response) {
            if (!response.ok) throw new Error('Text preview unavailable.');
            return response.text();
          })
          .then(function (text) { if (content.contains(media)) media.textContent = text; })
          .catch(function (error) {
            if (error.name !== 'AbortError' && content.contains(media)) media.textContent = 'This text preview could not be loaded. Open the file to review it, or check whether the review link has expired.';
          });
      } else {
        media.src = item.dataset.evidenceSrc;
      }
    } else {
      var description = document.createElement('p');
      description.className = 'review-muted';
      description.textContent = kind === 'url' ? 'This evidence links to an external website.' : 'This file does not have a browser preview. Open the file to review it.';
      content.appendChild(description);
    }
    var fileLink = document.createElement('p');
    fileLink.className = 'review-viewer-file-link';
    fileLink.appendChild(openFileLink(item));
    content.appendChild(fileLink);
    content.scrollTop = 0;
  }

  document.querySelectorAll('.review-preview-trigger').forEach(function (trigger) {
    trigger.addEventListener('click', function (event) {
      // Keep ordinary new-tab gestures and the no-JavaScript link fallback.
      if (event.button !== 0 || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return;
      var index = items.indexOf(trigger.closest('[data-review-item]'));
      if (index < 0) return;
      event.preventDefault();
      opener = trigger;
      showItem(index);
      dialog.showModal();
      document.body.classList.add('review-viewer-open');
    });
  });
  previous.addEventListener('click', function () { showItem(currentIndex - 1); });
  next.addEventListener('click', function () { showItem(currentIndex + 1); });
  document.getElementById('reviewViewerClose').addEventListener('click', function () { dialog.close(); });
  dialog.addEventListener('close', function () {
    clearPreview();
    document.body.classList.remove('review-viewer-open');
    if (opener && opener.isConnected) opener.focus({ preventScroll: true });
  });
  dialog.addEventListener('click', function (event) {
    if (event.target !== dialog) return;
    var bounds = dialog.getBoundingClientRect();
    if (event.clientX < bounds.left || event.clientX > bounds.right || event.clientY < bounds.top || event.clientY > bounds.bottom) dialog.close();
  });
  document.addEventListener('keydown', function (event) {
    if (!dialog.open || event.defaultPrevented || event.altKey || event.ctrlKey || event.metaKey) return;
    // Arrow keys retain their native seeking/editing behavior inside media controls.
    if (event.target.closest('video, audio, iframe, input, textarea, select, [contenteditable="true"]')) return;
    if (event.key === 'ArrowLeft') {
      event.preventDefault();
      showItem(currentIndex - 1);
    } else if (event.key === 'ArrowRight') {
      event.preventDefault();
      showItem(currentIndex + 1);
    }
  });
}());
