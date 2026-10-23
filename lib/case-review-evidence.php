<?php
if (!isset($reviewCase, $reviewToken, $reviewItem)) { http_response_code(404); exit; }
$escape = static fn($value): string => htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
[$warningTitle, $warningText] = tp_case_review_warning($reviewCase);
$mime = strtolower((string)$reviewItem['mime_type']);
$image = strpos($mime, 'image/') === 0 && strpos($mime, 'svg') === false;
$blocked = $reviewCase['sensitivity'] === 'Sealed' || ($reviewCase['sensitivity'] === 'Restricted' && !$image);
$external = in_array(strtolower((string)parse_url((string)$reviewItem['filepath'], PHP_URL_SCHEME)), ['http', 'https'], true);
$rawUrl = '?action=serve_evidence&id=' . (int)$reviewItem['id'] . '&variant=public&review_token=' . rawurlencode($reviewToken);
$title = $reviewItem['title'] ?: 'Evidence #' . (int)$reviewItem['id'];
?>
<!doctype html>
<html lang="en-GB">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex, nofollow, noarchive, noimageindex">
  <meta name="referrer" content="no-referrer">
  <title><?= $escape($warningTitle) ?> — evidence preview</title>
  <link rel="stylesheet" href="assets/case-review.css?v=2">
</head>
<body>
  <aside class="review-warning" role="alert"><strong><?= $escape($warningTitle) ?></strong><span><?= $escape($warningText) ?></span></aside>
  <main class="review-container">
    <p><a href="?view=case_review&amp;review_token=<?= $escape($reviewToken) ?>">Back to private case</a></p>
    <h1><?= $escape($title) ?></h1>
    <section class="review-card">
      <?php if ($blocked): ?>
        <p>This evidence is unavailable under the case sensitivity restrictions.</p>
      <?php elseif ($external): ?>
        <p>This evidence links to an external website. The case information remains private.</p>
        <a href="<?= $escape($reviewItem['filepath']) ?>" target="_blank" rel="noopener noreferrer">Open external evidence</a>
      <?php elseif ($image): ?>
        <img class="review-media" src="<?= $escape($rawUrl) ?>" alt="<?= $escape($title) ?>">
      <?php elseif (strpos($mime, 'video/') === 0 || $mime === 'application/ogg'): ?>
        <video class="review-media" controls preload="metadata" src="<?= $escape($rawUrl) ?>"></video>
      <?php elseif (strpos($mime, 'audio/') === 0): ?>
        <audio controls preload="metadata" src="<?= $escape($rawUrl) ?>"></audio>
      <?php elseif (in_array($mime, ['application/pdf', 'text/plain'], true)): ?>
        <iframe class="review-viewer-media review-viewer-pdf" title="<?= $escape($title) ?>" referrerpolicy="no-referrer" src="<?= $escape($rawUrl) ?>"></iframe>
      <?php else: ?>
        <p>This file does not have a browser preview.</p>
      <?php endif; ?>
      <?php if (!$blocked && !$external): ?>
        <p class="review-muted"><?= $escape($warningTitle) ?>. Any downloaded copy remains private.</p>
        <a href="<?= $escape($rawUrl . '&download=1') ?>" download>Download private evidence</a>
      <?php endif; ?>
    </section>
    <footer class="review-muted"><?= $escape($warningTitle) ?>. This link expires <?= $escape($reviewCase['expires_at']) ?> UTC.</footer>
  </main>
</body>
</html>
