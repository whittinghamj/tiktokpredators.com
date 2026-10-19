<?php
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
// Real multipart uploads, isolated from the application database and existing evidence.
function upload_check(bool $condition, string $message): void {
    if (!$condition) { throw new RuntimeException($message); }
}
function upload_test_post(string $url, string $action, string $source, string $filename, string $title = '', string $type = 'image', int $expectedStatus = 0): array {
    $request = curl_init($url);
    curl_setopt_array($request, [CURLOPT_POST => true, CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 120, CURLOPT_POSTFIELDS => [
        'action' => $action, 'csrf_token' => 'test-csrf', 'case_id' => '1', 'case_code' => 'TEST', 'type' => $type, 'title' => $title,
        'evidence_file' => new CURLFile($source, $type === 'image' ? 'image/png' : 'application/octet-stream', $filename),
    ]]);
    $response = curl_exec($request);
    $status = (int)curl_getinfo($request, CURLINFO_HTTP_CODE);
    upload_check($response !== false, 'Upload request failed: ' . curl_error($request));
    upload_check($status === ($expectedStatus ?: ($action === 'upload_evidence_ajax' ? 200 : 302)), 'Unexpected upload HTTP status: ' . $status);
    if ($action === 'upload_evidence_ajax') {
        $result = json_decode($response, true);
        upload_check(is_array($result) && isset($result['ok']), 'Invalid JSON upload response: ' . $response);
        return $result;
    }
    return [];
}
function upload_test_server(string $directory, array $overrides = []): array {
    $socket = stream_socket_server('tcp://127.0.0.1:0', $errno, $error);
    upload_check($socket !== false, 'Could not allocate a test server port.');
    $address = stream_socket_get_name($socket, false); fclose($socket);
    // Use the deployment settings; CLI servers do not automatically read .user.ini.
    $settings = array_replace(parse_ini_file(dirname(__DIR__) . '/.user.ini', false, INI_SCANNER_RAW), $overrides);
    $command = [PHP_BINARY];
    foreach ($settings as $name => $value) { $command[] = '-d'; $command[] = $name . '=' . $value; }
    array_push($command, '-S', $address, __DIR__ . '/fixtures/evidence-upload-router.php');
    $process = proc_open($command, [0 => ['pipe', 'r'], 1 => ['file', $directory . '/server.log', 'a'], 2 => ['file', $directory . '/server.log', 'a']], $pipes);
    upload_check(is_resource($process), 'Could not start the test server.'); fclose($pipes[0]);
    for ($attempt = 0; $attempt < 100; $attempt++) {
        $probe = @stream_socket_client('tcp://' . $address, $errno, $error, 0.1);
        if ($probe) { fclose($probe); return [$process, 'http://' . $address]; }
        usleep(10000);
    }
    proc_terminate($process); proc_close($process);
    throw new RuntimeException('Test server did not start.');
}

$directory = sys_get_temp_dir() . '/tp-evidence-upload-test-' . bin2hex(random_bytes(8));
mkdir($directory, 0700);
putenv('TP_EVIDENCE_UPLOAD_TEST_DIR=' . $directory);
$servers = [];
try {
    $pdo = new PDO('sqlite:' . $directory . '/fixture.sqlite', null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC]);
    $pdo->exec('CREATE TABLE evidence (id INTEGER PRIMARY KEY AUTOINCREMENT, case_id INTEGER, type TEXT, title TEXT, filepath TEXT UNIQUE, storage_path TEXT, original_filename TEXT NOT NULL, mime_type TEXT, size_bytes INTEGER, hash_sha256 TEXT UNIQUE, sha256_hex TEXT UNIQUE, uploaded_by INTEGER, created_by INTEGER)');
    [$process, $baseUrl] = upload_test_server($directory); $servers[] = $process;
    $expected = [];
    $expectedContents = [];
    $sequence = 0;
    foreach (['upload_evidence', 'upload_evidence_ajax'] as $action) {
        foreach (['Screenshot_1.png', 'Screenshot_1.png', str_repeat('s', 240) . '.PNG', '_Screenshot.png', 'Screenshot'] as $filename) {
            $sequence++;
            $image = imagecreatetruecolor(2, 2);
            imagefill($image, 0, 0, imagecolorallocate($image, $sequence * 20, 50, 100));
            $source = $directory . '/source.png';
            imagepng($image, $source);
            $contents = file_get_contents($source);
            $title = $sequence === 2 ? 'Custom evidence title' : '';
            upload_test_post($baseUrl, $action, $source, $filename, $title);
            $row = $pdo->query('SELECT * FROM evidence ORDER BY id DESC LIMIT 1')->fetch();
            upload_check($row && (int)$row['id'] === $sequence, $action . ' failed to save ' . $filename);
            $extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
            $storedName = basename($row['filepath']);
            upload_check((bool)preg_match('/\A[0-9a-f]{64}' . ($extension !== '' ? '\.' . $extension : '') . '\z/', $storedName), 'Stored filename is not an opaque hex name with the original extension.');
            upload_check($row['original_filename'] === $filename, 'Original filename metadata was lost.');
            upload_check($row['title'] === ($title !== '' ? $title : $filename), 'Evidence title did not remain readable.');
            upload_check($row['hash_sha256'] === hash('sha256', $contents) && $row['sha256_hex'] === $row['hash_sha256'], 'Content hash changed during renaming.');
            upload_check($row['mime_type'] === 'image/png' && (int)$row['size_bytes'] === strlen($contents), 'File metadata changed during renaming.');
            $storedPath = $directory . '/private/evidence/' . $storedName;
            upload_check(file_get_contents($storedPath) === $contents, 'Uploaded content changed.');
            upload_check(!isset($expected[$storedPath]), 'Two uploads share a storage filename.');
            $expected[$storedPath] = $contents;
            $expectedContents[] = $contents;
        }
        // Duplicate rejection must never overwrite or delete any earlier upload.
        file_put_contents($directory . '/source.png', $expectedContents[0]);
        foreach (['Screenshot_1.png', 'renamed.png'] as $filename) {
            upload_test_post($baseUrl, $action, $directory . '/source.png', $filename);
            upload_check((int)$pdo->query('SELECT COUNT(*) FROM evidence')->fetchColumn() === $sequence, 'Identical content was inserted again.');
            foreach ($expected as $path => $contents) {
                upload_check(is_file($path) && file_get_contents($path) === $contents, 'Duplicate cleanup damaged existing evidence.');
            }
            upload_check(count(glob($directory . '/private/evidence/*')) === $sequence, 'Rejected upload left an orphaned file.');
            upload_check(glob($directory . '/private/evidence/.upload-*') === [], 'Upload left a temporary file.');
        }
        echo $action . ": same-name uploads, long names, metadata and duplicate cleanup passed.\n";
    }
    [$process, $limitedUrl] = upload_test_server($directory, ['upload_max_filesize' => '1M', 'post_max_size' => '2M']); $servers[] = $process;
    $source = $directory . '/oversized.bin';
    $file = fopen($source, 'wb'); ftruncate($file, 1100 * 1024); fclose($file);
    $result = upload_test_post($limitedUrl . '/?action=upload_evidence_ajax', 'upload_evidence_ajax', $source, 'oversized.bin', '', 'other');
    upload_check(!$result['ok'] && str_contains($result['error'], 'Maximum file size: 1 MB'), 'PHP per-file limit did not return a readable error.');
    $file = fopen($source, 'wb'); ftruncate($file, 3 * 1024 * 1024); fclose($file);
    $result = upload_test_post($limitedUrl . '/?action=upload_evidence_ajax', 'upload_evidence_ajax', $source, 'oversized.bin', '', 'other', 413);
    upload_check(!$result['ok'] && str_contains($result['error'], 'request-size limit of 2 MB'), 'Discarded POST body did not return a JSON size error.');
    upload_check((int)$pdo->query('SELECT COUNT(*) FROM evidence')->fetchColumn() === $sequence, 'Rejected large upload created evidence.');
    echo "PHP per-file and discarded-POST size limit checks passed.\n";
    if (in_array('--large', $argv, true)) {
        $source = $directory . '/large.bin';
        $file = fopen($source, 'wb'); fwrite($file, 'Large upload fixture'); ftruncate($file, 400 * 1024 * 1024); fclose($file);
        $result = upload_test_post($baseUrl . '/?action=upload_evidence_ajax', 'upload_evidence_ajax', $source, 'large.bin', '', 'other');
        upload_check(!empty($result['ok']), '400 MB upload failed: ' . json_encode($result));
        $row = $pdo->query('SELECT * FROM evidence ORDER BY id DESC LIMIT 1')->fetch();
        $stored = $directory . '/private/evidence/' . basename($row['filepath']);
        upload_check((int)$row['size_bytes'] === 400 * 1024 * 1024 && filesize($stored) === 400 * 1024 * 1024, 'Large upload was truncated.');
        upload_check(hash_file('sha256', $stored) === hash_file('sha256', $source) && $row['hash_sha256'] === hash_file('sha256', $source), 'Large upload bytes or hash changed.');
        echo "400 MB multipart upload, stored size and SHA-256 integrity check passed.\n";
    }
} finally {
    foreach ($servers as $process) { if (is_resource($process)) { proc_terminate($process); proc_close($process); } }
    putenv('TP_EVIDENCE_UPLOAD_TEST_DIR');
    $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($directory, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
    foreach ($files as $file) { $file->isDir() ? rmdir($file->getPathname()) : unlink($file->getPathname()); }
    rmdir($directory);
}
