<?php
if (!isset($pdo)) { return; }

if (($_GET['view'] ?? '') === 'case_review' && !in_array(($_SERVER['REQUEST_METHOD'] ?? 'GET'), ['GET', 'HEAD'], true)) {
    tp_case_review_headers();
    header('Allow: GET, HEAD');
    http_response_code(405); exit('This review is read-only.');
}

if (in_array(($_POST['action'] ?? ''), ['create_case_review_link', 'revoke_case_review_link'], true)) {
    tp_case_review_headers();
    header('Content-Type: application/json; charset=utf-8');
    if (!check_csrf()) { tp_evidence_json_response(['ok' => false, 'error' => 'Security check failed. Refresh and try again.'], 403); }
    $caseId = (int)($_POST['case_id'] ?? 0);
    try {
        $query = $pdo->prepare('SELECT id, status, created_by FROM cases WHERE id = ? LIMIT 1');
        $query->execute([$caseId]);
        $case = $query->fetch();
        if (!$case || !tp_can_share_case_review($case)) {
            tp_evidence_json_response(['ok' => false, 'error' => 'You cannot share this case for private review.'], 403);
        }
        if ($_POST['action'] === 'revoke_case_review_link') {
            $query = $pdo->prepare('UPDATE case_review_links SET revoked_at = CURRENT_TIMESTAMP WHERE case_id = ?');
            $query->execute([$caseId]);
            tp_evidence_json_response(['ok' => true]);
        }
        $token = bin2hex(random_bytes(32));
        $expiresAt = gmdate('Y-m-d H:i:s', time() + 7 * 86400);
        // One current link per case; replacing it immediately invalidates earlier links.
        $query = $pdo->prepare('INSERT INTO case_review_links (case_id, token_hash, created_by, expires_at) VALUES (?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE token_hash = VALUES(token_hash), created_by = VALUES(created_by),
            expires_at = VALUES(expires_at), created_at = CURRENT_TIMESTAMP, revoked_at = NULL');
        $query->execute([$caseId, hash('sha256', $token), (int)$_SESSION['user']['id'], $expiresAt]);
        tp_evidence_json_response(['ok' => true, 'url' => tp_absolute_url('/?view=case_review&review_token=' . $token), 'expires_at' => str_replace(' ', 'T', $expiresAt) . 'Z']);
    } catch (Throwable $e) {
        log_console('ERROR', 'Case review link storage: ' . $e->getMessage());
        tp_evidence_json_response(['ok' => false, 'error' => 'Review links are unavailable. Ask the site administrator to run the database migrations.'], 503);
    }
}

if (($_GET['view'] ?? '') === 'case_review') {
    tp_case_review_headers();
    header("Content-Security-Policy: default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'self'; img-src 'self'; media-src 'self'; frame-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'self'");
    $reviewToken = $_GET['review_token'] ?? '';
    $reviewCase = tp_case_review_lookup($pdo, $reviewToken);
    if (!$reviewCase) {
        http_response_code(404); exit('This private link is invalid, expired, revoked, or the case is no longer private.');
    }
    if (array_key_exists('evidence_id', $_GET)) {
        $evidenceId = $_GET['evidence_id'];
        if (!is_string($evidenceId) || !ctype_digit($evidenceId)) { http_response_code(404); exit('Not found'); }
        $query = $pdo->prepare('SELECT id, type, title, filepath, mime_type, created_at FROM evidence WHERE id = ? AND case_id = ? LIMIT 1');
        $query->execute([(int)$evidenceId, (int)$reviewCase['id']]);
        $reviewItem = $query->fetch();
        if (!$reviewItem) { http_response_code(404); exit('Not found'); }
        if (session_status() === PHP_SESSION_ACTIVE) { session_write_close(); }
        if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'HEAD') { require __DIR__ . '/case-review-evidence.php'; }
        exit;
    }
    $reviewCase['tiktok_username'] = get_case_tiktok_usernames($pdo, (int)$reviewCase['id']) ?: $reviewCase['tiktok_username'];
    $reviewTags = get_case_tags($pdo, (int)$reviewCase['id']);
    $query = $pdo->prepare('SELECT id, type, title, filepath, mime_type, created_at FROM evidence WHERE case_id = ? ORDER BY created_at DESC, id DESC');
    $query->execute([(int)$reviewCase['id']]);
    $reviewEvidence = $query->fetchAll();
    if (session_status() === PHP_SESSION_ACTIVE) { session_write_close(); }
    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'HEAD') { require __DIR__ . '/case-review-page.php'; }
    exit;
}
