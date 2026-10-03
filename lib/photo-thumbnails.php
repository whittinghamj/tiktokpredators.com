<?php
/** Bounded public-photo preview generation; originals remain untouched. */
function tp_build_photo_thumbnail(string $source, string $destination, int $maxWidth): bool {
    if (!in_array($maxWidth, [160, 640, 1200], true) || !function_exists('imagecreatefromstring')) { return false; }
    $size = @filesize($source);
    $info = @getimagesize($source);
    if (!$info || !in_array($info['mime'] ?? '', ['image/jpeg', 'image/png', 'image/webp'], true)
        || !$size || $size > 25 * 1024 * 1024) { return false; }
    [$width, $height] = $info;
    if ($width < 1 || $height < 1 || $width > 20000 || $height > 20000 || $width > intdiv(20000000, $height)) { return false; }
    $limit = trim(ini_get('memory_limit'));
    $bytes = (int)$limit;
    $unit = strtolower(substr($limit, -1));
    if ($unit === 'g') { $bytes *= 1024 ** 3; }
    elseif ($unit === 'm') { $bytes *= 1024 ** 2; }
    elseif ($unit === 'k') { $bytes *= 1024; }
    if ($bytes > 0 && $width * $height * 12 + $size * 2 + 8388608 > $bytes - memory_get_usage(true)) { return false; }
    $data = @file_get_contents($source);
    if ($data === false) { return false; }
    $image = @imagecreatefromstring($data);
    unset($data);
    if (!$image) { return false; }
    // Respect JPEG camera orientation before resizing.
    if (($info['mime'] ?? '') === 'image/jpeg' && function_exists('exif_read_data')) {
        $exif = @exif_read_data($source);
        $orientation = (int)($exif['Orientation'] ?? 1);
        if (in_array($orientation, [2, 4, 5, 7], true)) { imageflip($image, IMG_FLIP_HORIZONTAL); }
        $angle = [3 => 180, 4 => 180, 5 => -90, 6 => -90, 7 => 90, 8 => 90][$orientation] ?? 0;
        if ($angle) {
            $rotated = @imagerotate($image, $angle, 0);
            if (!$rotated) { return false; }
            $image = $rotated;
        }
    }
    $width = imagesx($image); $height = imagesy($image);
    $scale = min(1, $maxWidth / max($width, $height));
    $preview = imagecreatetruecolor(max(1, (int)round($width * $scale)), max(1, (int)round($height * $scale)));
    if (!$preview) { return false; }
    imagealphablending($preview, false); imagesavealpha($preview, true);
    imagefill($preview, 0, 0, imagecolorallocatealpha($preview, 0, 0, 0, 127));
    imagecopyresampled($preview, $image, 0, 0, 0, 0, imagesx($preview), imagesy($preview), $width, $height);
    $directory = dirname($destination);
    if (!is_dir($directory) && !@mkdir($directory, 0755, true) && !is_dir($directory)) { return false; }
    $temporary = @tempnam($directory, '.preview-');
    if ($temporary === false) { return false; }
    if (function_exists('imagewebp')) { $ok = @imagewebp($preview, $temporary, 78); }
    else { $ok = @imagejpeg($preview, $temporary, 78); }
    if ($ok) { @chmod($temporary, 0644); $ok = @rename($temporary, $destination); }
    if (!$ok) { @unlink($temporary); }
    return $ok;
}
