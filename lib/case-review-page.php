<?php
if (!isset($reviewCase, $reviewToken, $reviewEvidence)) { http_response_code(404); exit; }
$escape = static fn($value): string => htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
$reviewPhoto = tp_person_photo_thumbnail_url((string)$reviewCase['case_code'], 640);
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
  <title>Unverified case — private review</title>
  <link rel="stylesheet" href="assets/case-review.css?v=1">
</head>
<body>
  <aside class="review-warning" role="alert">
    <strong>UNVERIFIED &amp; UNPUBLISHED CASE</strong>
    <span>This case has NOT been verified, approved, or published. It may contain mistakes or unverified allegations. This private link is for read-only review.</span>
  </aside>
  <main class="review-container">
    <header class="review-heading">
      <p class="review-eyebrow">Private case review · <?= $escape($reviewCase['case_code']) ?></p>
      <h1><?= $escape($reviewCase['case_name'] ?: $reviewCase['person_name'] ?: 'Case details') ?></h1>
      <p class="review-muted">Review the details and evidence, then send any corrections to the person who shared this link. The case remains unpublished.</p>
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
      ?>
        <article class="review-card review-evidence">
          <h3><?= $escape($item['title'] ?: 'Evidence #' . (int)$item['id']) ?></h3>
          <p class="review-muted">Evidence #<?= (int)$item['id'] ?> · <?= $escape($item['created_at']) ?></p>
          <?php if ($blocked): ?>
            <p class="review-muted">This evidence is unavailable under the case sensitivity restrictions.</p>
          <?php elseif ($externalUrl): ?>
            <a href="<?= $escape($item['filepath']) ?>" target="_blank" rel="noopener noreferrer">Open external evidence</a>
          <?php elseif ($image): ?>
            <a href="<?= $escape($url) ?>" target="_blank" rel="noopener noreferrer"><img loading="lazy" class="review-media" src="<?= $escape($url . '&thumbnail=1') ?>" alt="<?= $escape($item['title'] ?: 'Evidence image') ?>"></a>
            <a href="<?= $escape($url) ?>" target="_blank" rel="noopener noreferrer">View full image</a>
          <?php elseif (strpos($mime, 'video/') === 0): ?>
            <video class="review-media" controls preload="metadata" src="<?= $escape($url) ?>"></video>
          <?php elseif (strpos($mime, 'audio/') === 0): ?>
            <audio controls preload="metadata" src="<?= $escape($url) ?>"></audio>
          <?php else: ?>
            <a href="<?= $escape($url) ?>" target="_blank" rel="noopener noreferrer">View evidence file</a>
          <?php endif; ?>
        </article>
      <?php endforeach; ?>
      </div>
    </section>
    <footer class="review-muted">Private review only. This link expires <?= $escape($reviewCase['expires_at']) ?> UTC and may be revoked by the case owner or an authorized reviewer.</footer>
  </main>
</body>
</html>
