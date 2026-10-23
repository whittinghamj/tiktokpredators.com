<?php
if (($_GET['action'] ?? '') !== 'serve_case_photo') { return; }
tp_case_review_headers();
if (!in_array(($_SERVER['REQUEST_METHOD'] ?? 'GET'), ['GET', 'HEAD'], true)) {
    header('Allow: GET, HEAD'); http_response_code(405); exit('Read-only access.');
}
$code = $_GET['code'] ?? '';
$widthValue = $_GET['width'] ?? '640';
if (!is_string($code) || !preg_match('/\A[A-Za-z0-9_-]{1,100}\z/D', $code)
    || !is_string($widthValue) || !in_array($widthValue, ['160', '640', '1200'], true)) {
    http_response_code(404); exit;
}
try {
    if (!isset($pdo)) { throw new RuntimeException('Storage unavailable'); }
    $query = $pdo->prepare('SELECT id, case_code, status, created_by FROM cases WHERE case_code = ? LIMIT 1');
    $query->execute([$code]);
    $photoCase = $query->fetch();
    $tokenRequest = array_key_exists('review_token', $_GET);
    $tokenCase = $tokenRequest ? tp_case_review_lookup($pdo, $_GET['review_token']) : null;
    $allowed = $photoCase && ($tokenRequest
        ? ($tokenCase && (int)$tokenCase['id'] === (int)$photoCase['id'])
        : tp_case_is_visible($photoCase));
    if (!$allowed) { http_response_code(404); exit; }
} catch (Throwable $e) { http_response_code(503); exit('Photo unavailable'); }
if ($photoCase['status'] === 'Archived') { header('X-Case-Notice: Archived case - non-public information'); }
$source = tp_person_photo_source_path($code);
if ($source === '' || !is_file($source) || is_link($source)) { http_response_code(404); exit; }
if (session_status() === PHP_SESSION_ACTIVE) { session_write_close(); }
$selected = $source;
$mime = @mime_content_type($source);
if (($_GET['original'] ?? '') !== '1') {
    require_once __DIR__ . '/photo-thumbnails.php';
    $version = hash('sha256', $source . '|' . filemtime($source) . '|' . filesize($source) . '|' . fileinode($source) . '|' . filectime($source));
    $cacheDirectory = dirname($source) . '/thumbnails';
    $cache = $cacheDirectory . '/' . $code . '-' . $widthValue . '-' . $version . '.preview';
    if (is_link($cacheDirectory) || is_link($cache)) { http_response_code(503); exit; }
    if (is_file($cache) || tp_build_photo_thumbnail($source, $cache, (int)$widthValue)) {
        $selected = $cache;
        $mime = function_exists('imagewebp') ? 'image/webp' : 'image/jpeg';
    }
}
if (!in_array($mime, ['image/jpeg', 'image/png', 'image/webp'], true)) { http_response_code(404); exit; }
header('Content-Type: ' . $mime);
if ($photoCase['status'] === 'Archived') {
    $photoExtension = ['image/jpeg' => 'jpg', 'image/png' => 'png', 'image/webp' => 'webp'][$mime];
    header('Content-Disposition: inline; filename="archived-non-public-profile.' . $photoExtension . '"');
}
header('Content-Length: ' . filesize($selected));
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'HEAD') { readfile($selected); }
exit;
