<?php
if (!isset($reviewCase, $reviewToken, $reviewEvidence)) { http_response_code(404); exit; }
$escape = static fn($value): string => htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
$reviewArchived = ($reviewCase['status'] ?? '') === 'Archived';
[$warningTitle, $warningText] = tp_case_review_warning($reviewCase);
$reviewPhoto = tp_person_photo_thumbnail_url((string)$reviewCase['case_code'], 640);
if ($reviewPhoto !== '') { $reviewPhoto .= '&review_token=' . rawurlencode($reviewToken); }
$details = [
    'Case name' => $reviewCase['case_name'], 'Person name' => $reviewCase['person_name'],
    'Location' => tp_mask_case_location_house_number($reviewCase['location']),
    'Phone number' => tp_mask_case_phone_number($reviewCase['phone_number']),
    'Snapchat' => $reviewCase['snapchat_username'], 'Discord' => $reviewCase['discord_username'],
    'TikTok' => $reviewCase['tiktok_username'], 'Status' => $reviewCase['status'],
    'Sensitivity' => $reviewCase['sensitivity'], 'Opened' => $reviewCase['opened_at'],
];
?>
<!doctype html>
<html lang="en-GB">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex, nofollow, noarchive, noimageindex">
  <meta name="referrer" content="no-referrer">
  <title><?= $reviewArchived ? 'Archived case — non-public information' : 'Unverified case — private review' ?></title>
  <link rel="stylesheet" href="assets/case-review.css?v=2">
  <script defer src="assets/case-review-viewer.js?v=2"></script>
</head>
<body>
  <aside class="review-warning" role="alert">
    <strong><?= $escape($warningTitle) ?></strong>
    <span><?= $escape($warningText) ?></span>
  </aside>
  <main class="review-container">
    <header class="review-heading">
      <p class="review-eyebrow">Private case review · <?= $escape($reviewCase['case_code']) ?></p>
      <h1><?= $escape($reviewCase['case_name'] ?: $reviewCase['person_name'] ?: 'Case details') ?></h1>
      <p class="review-muted"><?= $reviewArchived ? 'Archived case details and evidence are shared privately. This case is no longer public.' : 'Review the details and evidence, then send any corrections to the person who shared this link. The case remains unpublished.' ?></p>
    </header>
    <section class="review-card" aria-labelledby="details-heading">
      <h2 id="details-heading">Case details</h2>
      <?php if ($reviewPhoto !== ''): ?><img class="review-photo" src="<?= $escape($reviewPhoto) ?>" alt="Case profile photo"><?php endif; ?>
      <dl class="review-details">
        <?php foreach ($details as $label => $value): ?>
          <div><dt><?= $escape($label) ?></dt><dd><?= $escape(trim((string)$value) !== '' ? $value : '—') ?></dd></div>
        <?php endforeach; ?>
      </dl>
      <?php if ($reviewTags): ?><p class="review-muted">Tags: <?= $escape(implode(', ', $reviewTags)) ?></p><?php endif; ?>
      <h3>Summary</h3>
      <p class="review-text"><?= $escape($reviewCase['initial_summary']) ?></p>
    </section>
    <section aria-labelledby="evidence-heading">
      <h2 id="evidence-heading">Evidence <span class="review-count"><?= count($reviewEvidence) ?></span></h2>
      <p class="review-muted">Existing public blur areas and sensitivity restrictions also apply to this review.</p>
      <?php if (!$reviewEvidence): ?><p class="review-card review-muted">No evidence has been added yet.</p><?php endif; ?>
      <div class="review-evidence-grid">
      <?php foreach ($reviewEvidence as $item):
        $url = '?action=serve_evidence&id=' . (int)$item['id'] . '&variant=public&review_token=' . rawurlencode($reviewToken);
        $mime = strtolower((string)$item['mime_type']);
        $externalUrl = in_array(strtolower((string)parse_url((string)$item['filepath'], PHP_URL_SCHEME)), ['http', 'https'], true);
        $image = strpos($mime, 'image/') === 0 && strpos($mime, 'svg') === false;
        $blocked = $reviewCase['sensitivity'] === 'Sealed' || ($reviewCase['sensitivity'] === 'Restricted' && !$image);
        $kind = 'file';
        if ($externalUrl) { $kind = 'url'; }
        elseif ($image) { $kind = 'image'; }
        elseif (strpos($mime, 'video/') === 0 || $mime === 'application/ogg') { $kind = 'video'; }
        elseif (strpos($mime, 'audio/') === 0) { $kind = 'audio'; }
        elseif ($mime === 'application/pdf') { $kind = 'pdf'; }
        elseif ($mime === 'text/plain') { $kind = 'text'; }
        $title = $item['title'] ?: 'Evidence #' . (int)$item['id'];
        $evidencePage = '?view=case_review&review_token=' . rawurlencode($reviewToken) . '&evidence_id=' . (int)$item['id'];
        $previewUrl = $externalUrl ? $evidencePage : $url;
        $previewLabel = ['video' => 'Video', 'audio' => 'Audio', 'pdf' => 'PDF', 'text' => 'Text', 'file' => 'File', 'url' => 'External link'][$kind] ?? 'Image';
      ?>
        <article class="review-card review-evidence"<?php if (!$blocked): ?> data-review-item data-evidence-id="<?= (int)$item['id'] ?>" data-evidence-title="<?= $escape($title) ?>" data-evidence-src="<?= $escape($previewUrl) ?>" data-evidence-page="<?= $escape($evidencePage) ?>" data-evidence-kind="<?= $escape($kind) ?>"<?php endif; ?>>
          <h3><?= $escape($title) ?></h3>
          <p class="review-muted review-item-meta">Evidence #<?= (int)$item['id'] ?> · <?= $escape($item['created_at']) ?></p>
          <?php if ($blocked): ?>
            <p class="review-muted">This evidence is unavailable under the case sensitivity restrictions.</p>
          <?php elseif ($kind === 'image'): ?>
            <a class="review-preview-trigger review-preview-image" href="<?= $escape($evidencePage) ?>" target="_blank" rel="noopener noreferrer" aria-haspopup="dialog" aria-controls="reviewEvidenceDialog" aria-label="<?= $escape('Preview ' . $title) ?>"><img loading="lazy" class="review-media" src="<?= $escape($url . '&thumbnail=1') ?>" alt="<?= $escape($title) ?>"></a>
            <a class="review-preview-trigger" href="<?= $escape($evidencePage) ?>" target="_blank" rel="noopener noreferrer" aria-haspopup="dialog" aria-controls="reviewEvidenceDialog">Preview image</a>
          <?php else: ?>
            <a class="review-preview-trigger review-file-preview" href="<?= $escape($evidencePage) ?>" target="_blank" rel="noopener noreferrer" aria-haspopup="dialog" aria-controls="reviewEvidenceDialog" aria-label="<?= $escape('Preview ' . $title) ?>">
              <span class="review-file-icon" aria-hidden="true"><?= $escape(['video' => '▶', 'audio' => '♫', 'pdf' => 'PDF', 'text' => 'TXT', 'url' => '↗'][$kind] ?? 'FILE') ?></span>
              <span>Preview <?= $escape(strtolower($previewLabel)) ?></span>
            </a>
          <?php endif; ?>
        </article>
      <?php endforeach; ?>
      </div>
    </section>
    <footer class="review-muted"><?= $reviewArchived ? 'Archived case — non-public information. ' : '' ?>Private review only. This link expires <?= $escape($reviewCase['expires_at']) ?> UTC and may be revoked by the case owner or an authorized reviewer.</footer>
  </main>
  <dialog class="review-viewer" id="reviewEvidenceDialog" aria-labelledby="reviewViewerTitle" aria-describedby="reviewViewerWarning">
    <div class="review-viewer-shell">
      <div class="review-viewer-warning" id="reviewViewerWarning"><strong><?= $escape($warningTitle) ?></strong> · Private, read-only review</div>
      <header class="review-viewer-header">
        <div>
          <h2 id="reviewViewerTitle">Evidence preview</h2>
          <p class="review-muted" id="reviewViewerMeta"></p>
        </div>
        <button type="button" class="review-viewer-button review-viewer-close" id="reviewViewerClose" aria-label="Close evidence viewer" autofocus>×</button>
      </header>
      <div class="review-viewer-content" id="reviewViewerContent"></div>
      <footer class="review-viewer-footer">
        <nav class="review-viewer-navigation" aria-label="Evidence navigation">
          <button type="button" class="review-viewer-button" id="reviewViewerPrevious" aria-label="Previous evidence">← Previous</button>
          <span id="reviewViewerCounter" role="status" aria-live="polite" aria-atomic="true"></span>
          <button type="button" class="review-viewer-button" id="reviewViewerNext" aria-label="Next evidence">Next →</button>
        </nav>
        <p class="review-muted review-viewer-hint">Use ← and → to browse. Press Esc to close.</p>
      </footer>
    </div>
  </dialog>
</body>
</html>
