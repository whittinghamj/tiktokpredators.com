<?php
// Profile photos already have public raster URLs. This endpoint needs no DB or session.
require __DIR__ . '/lib/photo-thumbnails.php';
$code = $_GET['code'] ?? '';
$width = (int)($_GET['width'] ?? 640);
if (!is_string($code) || !preg_match('/\A[A-Za-z0-9_-]{1,100}\z/D', $code)
    || !in_array($width, [160, 640, 1200], true)) { http_response_code(404); exit; }
$source = '';
foreach (['jpg', 'jpeg', 'png', 'webp'] as $extension) {
    $candidate = __DIR__ . '/uploads/people/' . $code . '.' . $extension;
    if (is_file($candidate) && !is_link($candidate)) { $source = $candidate; break; }
}
if ($source === '') { http_response_code(404); exit; }
$version = hash('sha256', $source . '|' . filemtime($source) . '|' . filesize($source) . '|' . fileinode($source) . '|' . filectime($source));
$cacheDirectory = __DIR__ . '/uploads/people/thumbnails';
if (is_link($cacheDirectory)) { http_response_code(503); exit; }
$cache = $cacheDirectory . '/' . $code . '-' . $width . '-' . $version . '.preview';
$etag = '"' . $version . '-' . $width . '-v1"';
if (is_link($cache)) { http_response_code(503); exit; }
if (!is_file($cache) && !tp_build_photo_thumbnail($source, $cache, $width)) {
    // Gracefully retain the original public image on hosts without GD or cache permissions.
    header('Cache-Control: no-store');
    header('Location: uploads/people/' . rawurlencode(basename($source)), true, 302); exit;
}
header('Content-Type: ' . (function_exists('imagewebp') ? 'image/webp' : 'image/jpeg'));
header('Cache-Control: public, max-age=604800');
header('ETag: ' . $etag);
header('X-Content-Type-Options: nosniff');
if (trim($_SERVER['HTTP_IF_NONE_MATCH'] ?? '') === $etag) { http_response_code(304); exit; }
header('Content-Length: ' . filesize($cache));
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'HEAD') { readfile($cache); }
