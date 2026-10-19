<?php
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
function review_check(bool $condition, string $message): void {
    if (!$condition) { throw new RuntimeException($message); }
}
function review_request(string $url, ?array $input = null, string $method = ''): array {
    $request = curl_init($url);
    $headers = [];
    curl_setopt_array($request, [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 5, CURLOPT_HEADERFUNCTION => static function ($request, string $line) use (&$headers): int {
        $parts = explode(':', $line, 2);
        if (count($parts) === 2) { $headers[strtolower($parts[0])] = trim($parts[1]); }
        return strlen($line);
    }]);
    if ($input !== null) { curl_setopt_array($request, [CURLOPT_POST => true, CURLOPT_POSTFIELDS => http_build_query($input)]); }
    if ($method === 'HEAD') { curl_setopt($request, CURLOPT_NOBODY, true); }
    elseif ($method !== '') { curl_setopt($request, CURLOPT_CUSTOMREQUEST, $method); }
    $body = curl_exec($request);
    review_check($body !== false, 'HTTP fixture request failed: ' . curl_error($request));
    return [(int)curl_getinfo($request, CURLINFO_HTTP_CODE), $body, $headers];
}
$directory = sys_get_temp_dir() . '/tp-case-review-test-' . bin2hex(random_bytes(8));
mkdir($directory, 0700); mkdir($directory . '/private', 0700);
mkdir($directory . '/private/evidence', 0700); mkdir($directory . '/private/redactions', 0700);
putenv('TP_CASE_REVIEW_TEST_DIR=' . $directory);
$process = null;
try {
    $pdo = new PDO('sqlite:' . $directory . '/fixture.sqlite', null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC]);
    $pdo->exec('CREATE TABLE cases (id INTEGER PRIMARY KEY, case_code TEXT, case_name TEXT, person_name TEXT, location TEXT, phone_number TEXT, snapchat_username TEXT, discord_username TEXT, tiktok_username TEXT, initial_summary TEXT, status TEXT, sensitivity TEXT, opened_at TEXT, created_by INTEGER)');
    $pdo->exec('CREATE TABLE case_review_links (case_id INTEGER PRIMARY KEY, token_hash TEXT UNIQUE, created_by INTEGER, created_at TEXT DEFAULT CURRENT_TIMESTAMP, expires_at TEXT, revoked_at TEXT)');
    $pdo->exec('CREATE TABLE evidence (id INTEGER PRIMARY KEY, case_id INTEGER, type TEXT, title TEXT, filepath TEXT, mime_type TEXT, size_bytes INTEGER, hash_sha256 TEXT, sha256_hex TEXT, rotation_degrees INTEGER DEFAULT 0, created_at TEXT DEFAULT CURRENT_TIMESTAMP)');
    $pdo->exec('CREATE TABLE evidence_redactions (evidence_id INTEGER PRIMARY KEY, public_filepath TEXT, public_mime_type TEXT, public_size_bytes INTEGER, public_sha256 TEXT, source_sha256 TEXT, source_rotation INTEGER, source_width INTEGER, source_height INTEGER, mask_json TEXT, region_count INTEGER, updated_by INTEGER, updated_at TEXT)');
    $pdo->exec("INSERT INTO cases VALUES (1, 'REVIEW1', 'Draft case for review', 'Example person', '12 Example Street', '01234567890', 'example', 'example', 'example', 'DRAFT_SUMMARY <script>alert(1)</script>', 'Being Built', 'Standard', '2026-10-19 10:00:00', 7), (2, 'REVIEW2', 'OTHER_CASE_SECRET', '', '', '', '', '', '', 'OTHER_CASE_SECRET', 'Pending', 'Standard', '2026-10-19 10:00:00', 8)");
    $image = imagecreatetruecolor(16, 16);
    imagefill($image, 0, 0, imagecolorallocate($image, 200, 40, 60));
    imagepng($image, $directory . '/private/evidence/source.png');
    imagefill($image, 0, 0, imagecolorallocate($image, 50, 40, 200));
    imagepng($image, $directory . '/private/redactions/public.png');
    $sourceBytes = file_get_contents($directory . '/private/evidence/source.png');
    $publicBytes = file_get_contents($directory . '/private/redactions/public.png');
    $sourceHash = hash('sha256', $sourceBytes);
    $insert = $pdo->prepare("INSERT INTO evidence (id, case_id, type, title, filepath, mime_type, size_bytes, hash_sha256, sha256_hex) VALUES (?, ?, 'image', ?, 'private:evidence/source.png', 'image/png', ?, ?, ?)");
    $insert->execute([101, 1, 'Screenshot for review', strlen($sourceBytes), $sourceHash, $sourceHash]);
    $insert->execute([201, 2, 'OTHER_CASE_EVIDENCE', strlen($sourceBytes), $sourceHash, $sourceHash]);
    $socket = stream_socket_server('tcp://127.0.0.1:0', $errno, $error);
    review_check($socket !== false, 'Could not allocate fixture port.');
    $address = stream_socket_get_name($socket, false); fclose($socket);
    $process = proc_open([PHP_BINARY, '-S', $address, __DIR__ . '/fixtures/case-review-router.php'], [0 => ['pipe', 'r'], 1 => ['file', $directory . '/server.log', 'a'], 2 => ['file', $directory . '/server.log', 'a']], $pipes);
    review_check(is_resource($process), 'Could not start fixture server.'); fclose($pipes[0]);
    $ready = false;
    for ($attempt = 0; $attempt < 100; $attempt++) {
        $probe = @stream_socket_client('tcp://' . $address, $errno, $error, 0.1);
        if ($probe) { fclose($probe); $ready = true; break; }
        usleep(10000);
    }
    review_check($ready, 'Fixture server did not start.');
    $base = 'http://' . $address;
    $create = ['action' => 'create_case_review_link', 'case_id' => '1', 'csrf_token' => 'test-csrf'];
    foreach (['guest', 'viewer', 'moderator'] as $role) {
        [$status] = review_request($base . '/?role=' . $role . '&user=99', $create);
        review_check($status === 403, 'Unrelated ' . $role . ' could share a building case.');
    }
    [$status] = review_request($base . '/?role=admin', array_replace($create, ['csrf_token' => 'invalid']));
    review_check($status === 403, 'Link creation accepted invalid CSRF.');
    [$status, $body] = review_request($base . '/?role=viewer&user=7', $create);
    $created = json_decode($body, true);
    review_check($status === 200 && !empty($created['ok']), 'Case owner could not create a link: ' . $body);
    $url = $created['url'];
    parse_str(parse_url($url, PHP_URL_QUERY), $query);
    $token = $query['review_token'];
    $stored = $pdo->query('SELECT * FROM case_review_links')->fetch();
    review_check($stored['token_hash'] === hash('sha256', $token) && $stored['token_hash'] !== $token, 'Stored a plaintext bearer token.');
    [$status, $page, $headers] = review_request($url);
    review_check($status === 200 && str_contains($page, 'NOT been verified, approved, or published') && str_contains($page, 'DRAFT_SUMMARY'), 'Anonymous private review did not render its warning and case.');
    review_check(strpos($page, 'UNVERIFIED &amp; UNPUBLISHED CASE') < strpos($page, '<main'), 'Warning banner is not above the case.');
    review_check(!str_contains($page, '<script>') && str_contains($page, '&lt;script&gt;') && !str_contains($page, '<form') && !str_contains($page, 'OTHER_CASE_SECRET'), 'Review exposed active content, editing controls or another case.');
    review_check(!str_contains($page, '12 Example Street') && !str_contains($page, '01234567890'), 'Review bypassed anonymous field redaction.');
    review_check($headers['referrer-policy'] === 'no-referrer' && str_contains($headers['x-robots-tag'], 'noindex') && str_contains($headers['cache-control'], 'no-store'), 'Review privacy headers are missing.');
    review_check(str_contains($page, '<dialog ') && str_contains($page, 'aria-label="Previous evidence"') && str_contains($page, 'aria-label="Next evidence"') && str_contains($page, 'aria-controls="reviewEvidenceDialog"'), 'Review evidence does not expose an accessible navigable viewer.');
    review_check(str_contains($headers['content-security-policy'], "script-src 'self'") && !str_contains($headers['content-security-policy'], 'unsafe-inline'), 'Viewer scripts loosened the review content security policy.');
    [$status, $head] = review_request($url, null, 'HEAD');
    review_check($status === 200 && $head === '', 'Review HEAD request returned content.');
    [$status] = review_request($url . '&role=admin', $create);
    review_check($status === 405, 'Read-only review accepted a mutation.');
    [$status] = review_request($base . '/?view=case_review&review_token[]=bad');
    review_check($status === 404, 'Array token was accepted.');
    [$status] = review_request($base . '/?view=case_review&review_token=' . str_repeat('a', 64));
    review_check($status === 404, 'Unknown review token was accepted.');
    $mediaUrl = $base . '/?action=serve_evidence&id=101&review_token=' . $token;
    [$status, $bytes] = review_request($mediaUrl);
    review_check($status === 200 && $bytes === $sourceBytes, 'Anonymous reviewer could not view this case evidence.');
    foreach ([$base . '/?action=serve_evidence&id=101', str_replace('id=101', 'id=201', $mediaUrl), $mediaUrl . '&variant=original&role=admin', $mediaUrl . 'bad&role=admin'] as $deniedUrl) {
        [$status] = review_request($deniedUrl);
        review_check($status === 404, 'Review link exposed unauthorized evidence or originals.');
    }
    [$status] = review_request($mediaUrl . '&schema=missing');
    review_check($status === 503, 'Review bypassed unavailable redaction metadata.');
    $redaction = $pdo->prepare("INSERT INTO evidence_redactions (evidence_id, public_filepath, public_mime_type, public_size_bytes, public_sha256, source_sha256, source_rotation, source_width, source_height, mask_json, region_count) VALUES (101, 'private:redactions/public.png', 'image/png', ?, ?, ?, 0, 16, 16, '[]', 1)");
    $redaction->execute([strlen($publicBytes), hash('sha256', $publicBytes), $sourceHash]);
    [$status, $bytes] = review_request($mediaUrl . '&role=admin');
    review_check($status === 200 && $bytes === $publicBytes, 'Review bypassed the saved public blur for an authenticated administrator.');
    $pdo->exec("UPDATE evidence_redactions SET public_sha256 = 'invalid'");
    [$status] = review_request($mediaUrl);
    review_check($status === 503, 'Review fell back to the original after redaction integrity failure.');
    $pdo->exec('DELETE FROM evidence_redactions');
    $pdo->exec("UPDATE cases SET sensitivity = 'Sealed' WHERE id = 1");
    [$status] = review_request($mediaUrl);
    review_check($status === 403, 'Review bypassed sealed evidence.');
    [$status, $sealedPage] = review_request($url);
    review_check($status === 200 && !str_contains($sealedPage, ' data-review-item'), 'Sealed evidence was included in the viewer navigation.');
    $pdo->exec("UPDATE cases SET sensitivity = 'Standard' WHERE id = 1");
    [$status, $body] = review_request($base . '/?role=admin', $create);
    $replacement = json_decode($body, true)['url'];
    [$status] = review_request($url);
    review_check($status === 404, 'Replacement link left the earlier link active.');
    [$status] = review_request($base . '/?role=viewer&user=99', ['action' => 'revoke_case_review_link', 'case_id' => 1, 'csrf_token' => 'test-csrf']);
    review_check($status === 403, 'Unrelated user could revoke the link.');
    [$status] = review_request($base . '/?role=viewer&user=7', ['action' => 'revoke_case_review_link', 'case_id' => 1, 'csrf_token' => 'test-csrf']);
    review_check($status === 200, 'Case owner could not revoke the link.');
    [$status] = review_request($replacement);
    review_check($status === 404, 'Revoked link remained usable.');
    foreach (['Pending', 'Rejected'] as $caseStatus) {
        $pdo->prepare('UPDATE cases SET status = ? WHERE id = 1')->execute([$caseStatus]);
        [$status, $body] = review_request($base . '/?role=moderator&user=99', $create);
        $activeUrl = json_decode($body, true)['url'];
        review_check($status === 200, 'Moderator could not share ' . $caseStatus . ' case.');
        [$status] = review_request($activeUrl);
        review_check($status === 200, 'Shared ' . $caseStatus . ' case was unavailable.');
    }
    $pdo->exec("UPDATE case_review_links SET expires_at = '2000-01-01 00:00:00'");
    [$status] = review_request($activeUrl);
    review_check($status === 404, 'Expired link remained usable.');
    [$status, $body] = review_request($base . '/?role=admin', $create);
    $activeUrl = json_decode($body, true)['url'];
    $pdo->exec("UPDATE cases SET status = 'Verified' WHERE id = 1");
    [$status] = review_request($activeUrl);
    review_check($status === 404, 'Review link remained active after publication.');
    [$status] = review_request($base . '/?role=admin', $create);
    review_check($status === 403, 'Published case could be shared as unpublished.');
    $pdo->exec("UPDATE cases SET status = 'Being Built' WHERE id = 1");
    echo "Case review checks passed: permissions, anonymous read-only access, warning, escaping, evidence isolation, public blurs, expiry, replacement, revocation and publication.\n";
    if (in_array('--preview', $argv, true)) {
        // Mixed local fixtures make modal navigation and media cleanup reviewable.
        $image = imagecreatetruecolor(240, 160);
        imagefill($image, 0, 0, imagecolorallocate($image, 50, 40, 200));
        imagepng($image, $directory . '/private/evidence/second.png');
        $samples = str_repeat("\0\0", 8000);
        file_put_contents($directory . '/private/evidence/audio.wav', 'RIFF' . pack('V', 36 + strlen($samples)) . 'WAVEfmt ' . pack('VvvVVvv', 16, 1, 1, 8000, 16000, 2, 16) . 'data' . pack('V', strlen($samples)) . $samples);
        file_put_contents($directory . '/private/evidence/statement.txt', "Fixture statement for private review.\n<script>Untrusted evidence remains plain text.</script>\n");
        file_put_contents($directory . '/private/evidence/document.bin', 'Unsupported document fixture.');
        $objects = [
            '<< /Type /Catalog /Pages 2 0 R >>',
            '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
            '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 400 200] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>',
            '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',
        ];
        $pdfText = 'BT /F1 16 Tf 30 140 Td (Private review PDF fixture) Tj ET';
        $objects[] = '<< /Length ' . strlen($pdfText) . ">>\nstream\n" . $pdfText . "\nendstream";
        $pdf = "%PDF-1.4\n"; $offsets = [0];
        foreach ($objects as $number => $object) { $offsets[] = strlen($pdf); $pdf .= ($number + 1) . " 0 obj\n" . $object . "\nendobj\n"; }
        $xref = strlen($pdf); $pdf .= "xref\n0 6\n0000000000 65535 f \n";
        foreach (array_slice($offsets, 1) as $offset) { $pdf .= sprintf("%010d 00000 n \n", $offset); }
        $pdf .= "trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n" . $xref . "\n%%EOF\n";
        file_put_contents($directory . '/private/evidence/document.pdf', $pdf);
        $fixtures = [
            [102, 'image', 'Second screenshot', 'second.png', 'image/png'],
            [103, 'audio', 'Audio statement', 'audio.wav', 'audio/wav'],
            [104, 'other', 'Text statement', 'statement.txt', 'text/plain'],
            [105, 'pdf', 'PDF document', 'document.pdf', 'application/pdf'],
            [106, 'doc', 'Other document', 'document.bin', 'application/octet-stream'],
            [107, 'url', 'External source', 'https://example.com/', 'text/url'],
        ];
        $previewInsert = $pdo->prepare('INSERT INTO evidence (id, case_id, type, title, filepath, mime_type, created_at) VALUES (?, 1, ?, ?, ?, ?, ?)');
        foreach ($fixtures as [$id, $type, $title, $filename, $mime]) {
            $previewInsert->execute([$id, $type, $title, $type === 'url' ? $filename : 'private:evidence/' . $filename, $mime, '2026-01-01 00:00:' . sprintf('%02d', 110 - $id)]);
        }
        echo "Preview: " . $activeUrl . "\nShare controls: " . $base . "/share-ui?role=admin\n";
        flush();
        $previewRunning = true;
        if (function_exists('pcntl_async_signals')) {
            pcntl_async_signals(true);
            pcntl_signal(SIGTERM, static function () use (&$previewRunning): void { $previewRunning = false; });
            pcntl_signal(SIGINT, static function () use (&$previewRunning): void { $previewRunning = false; });
        }
        // Bound preview lifetime so a forgotten fixture cleans up automatically.
        for ($seconds = 0; $seconds < 600 && $previewRunning; $seconds++) { sleep(1); }
    }
} finally {
    if (is_resource($process)) { proc_terminate($process); proc_close($process); }
    putenv('TP_CASE_REVIEW_TEST_DIR');
    $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($directory, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
    foreach ($files as $file) { $file->isDir() ? rmdir($file->getPathname()) : unlink($file->getPathname()); }
    rmdir($directory);
}
