<?php
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
require dirname(__DIR__) . '/lib/photo-thumbnails.php';
$directory = sys_get_temp_dir() . '/tp-preview-test-' . bin2hex(random_bytes(8));
mkdir($directory, 0700);
try {
    $source = $directory . '/source.png';
    $image = imagecreatetruecolor(1800, 1000);
    for ($y = 0; $y < 1000; $y += 5) {
        for ($x = 0; $x < 1800; $x += 5) {
            $color = imagecolorallocate($image, ($x * 17 + $y) % 256, ($x + $y * 23) % 256, ($x * 3 + $y * 7) % 256);
            imagefilledrectangle($image, $x, $y, $x + 4, $y + 4, $color);
        }
    }
    imagepng($image, $source, 0);
    foreach ([160, 640, 1200] as $width) {
        $destination = $directory . '/' . $width . '.preview';
        if (!tp_build_photo_thumbnail($source, $destination, $width)) { throw new RuntimeException('Preview failed.'); }
        $info = getimagesize($destination);
        if ($info[0] !== $width || abs($info[1] - round(1000 * $width / 1800)) > 1) { throw new RuntimeException('Wrong preview dimensions.'); }
        if (filesize($destination) >= filesize($source) / 4) { throw new RuntimeException('Preview was not substantially smaller.'); }
        echo $width . 'px preview: ' . filesize($destination) . ' bytes (original: ' . filesize($source) . ").\n";
    }
    if (tp_build_photo_thumbnail($source, $directory . '/invalid.preview', 999)) { throw new RuntimeException('Unbounded width accepted.'); }
    file_put_contents($directory . '/fake.png', '<?php invalid ?>');
    if (tp_build_photo_thumbnail($directory . '/fake.png', $directory . '/bad.preview', 640)) { throw new RuntimeException('Invalid image accepted.'); }
    echo "Photo thumbnail checks passed.\n";
} finally {
    foreach (glob($directory . '/*') as $file) { unlink($file); }
    rmdir($directory);
}
