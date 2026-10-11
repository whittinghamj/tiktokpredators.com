<?php
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
$directory = sys_get_temp_dir() . '/tp-case-ollama-test-' . bin2hex(random_bytes(8));
mkdir($directory, 0700); mkdir($directory . '/evidence', 0700); mkdir($directory . '/notes', 0700);
$directory = realpath($directory);
putenv('TP_CASE_OLLAMA_TEST_STORAGE=' . $directory);
putenv('TP_CASE_OLLAMA_TEST_DB=' . $directory . '/fixture.sqlite');
putenv('TP_CASE_OLLAMA_TEST_LOG=' . $directory . '/requests.jsonl');
require __DIR__ . '/fixtures/case-ollama-bootstrap.php';
function case_ai_check(bool $condition, string $message): void { if (!$condition) { throw new RuntimeException($message); } }
function case_ai_server(string $directory): array {
  $socket = stream_socket_server('tcp://127.0.0.1:0', $errno, $error);
  case_ai_check($socket !== false, 'Could not allocate a fixture port.');
  $address = stream_socket_get_name($socket, false); fclose($socket);
  $process = proc_open([PHP_BINARY, '-S', $address, __DIR__ . '/fixtures/ollama-server.php'], [0 => ['pipe', 'r'], 1 => ['file', $directory . '/server.log', 'a'], 2 => ['file', $directory . '/server.log', 'a']], $pipes);
  fclose($pipes[0]);
  for ($i = 0; $i < 100; $i++) {
    $probe = @stream_socket_client('tcp://' . $address, $errno, $error, 0.1);
    if ($probe) { fclose($probe); return [$process, 'http://' . $address]; }
    usleep(10000);
  }
  proc_terminate($process); proc_close($process); throw new RuntimeException('Fixture server did not start.');
}
function case_ai_post(string $url, array $input): array {
  $ch = curl_init($url);
  curl_setopt_array($ch, [CURLOPT_POST => true, CURLOPT_POSTFIELDS => http_build_query($input), CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 10]);
  $body = curl_exec($ch); $status = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
  $result = json_decode((string)$body, true);
  case_ai_check(is_array($result), 'Private endpoint returned invalid JSON: ' . $body);
  return [$status, $result];
}
$servers = [];
try {
  $pdo = new CaseOllamaTestDatabase($directory . '/fixture.sqlite');
  $pdo->exec('CREATE TABLE cases (id INTEGER PRIMARY KEY, case_code TEXT, case_name TEXT, person_name TEXT, date_of_birth TEXT, location TEXT, phone_number TEXT, snapchat_username TEXT, discord_username TEXT, tiktok_username TEXT, initial_summary TEXT, status TEXT, sensitivity TEXT, opened_at TEXT)');
  $pdo->exec('CREATE TABLE evidence (id INTEGER PRIMARY KEY, case_id INTEGER, type TEXT, title TEXT, filepath TEXT, original_filename TEXT, mime_type TEXT, size_bytes INTEGER, hash_sha256 TEXT, rotation_degrees INTEGER DEFAULT 0, created_at TEXT)');
  $pdo->exec('CREATE TABLE case_notes (id INTEGER PRIMARY KEY, case_id INTEGER, note_text TEXT, created_at TEXT)');
  $pdo->exec('CREATE TABLE case_events (case_id INTEGER, event_type TEXT, subject TEXT, detail TEXT, ref_evidence_id INTEGER, ref_note_id INTEGER, created_by INTEGER, public_ip TEXT, forwarded_for TEXT)');
  $pdo->exec("CREATE TABLE case_ollama_reports (case_id INTEGER PRIMARY KEY, requested_version INTEGER DEFAULT 1, processed_version INTEGER DEFAULT 0, status TEXT DEFAULT 'Queued', processing_token TEXT, report_text TEXT, report_json TEXT, model TEXT, error_message TEXT, queued_at TEXT DEFAULT CURRENT_TIMESTAMP, generated_at TEXT)");
  $pdo->exec('CREATE TABLE case_ollama_messages (id INTEGER PRIMARY KEY AUTOINCREMENT, case_id INTEGER, user_id INTEGER, report_version INTEGER, question TEXT, answer TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP)');
  $pdo->exec("INSERT INTO cases (id, case_code, case_name, initial_summary, status, sensitivity) VALUES (1, 'CASE1', 'Fixture case', 'CASE1 supplied summary', 'Pending', 'Restricted'), (2, 'CASE2', 'Other case', 'SECRET_CASE2_CONTENT', 'Verified', 'Standard')");
  $text = str_repeat('Recorded statement with a date and a username. ', 500) . ' FINAL_TEXT_SENTINEL';
  file_put_contents($directory . '/evidence/statement.txt', $text);
  $image = imagecreatetruecolor(2400, 80); imagepng($image, $directory . '/evidence/screenshot.png'); unset($image);
  file_put_contents($directory . '/evidence/unreadable.bin', "\0\x01\x02\xFF" . str_repeat("\x00", 100));
  $docx = new ZipArchive(); $docx->open($directory . '/evidence/document.docx', ZipArchive::CREATE);
  $docx->addFromString('word/document.xml', '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>DOCX_BODY_SENTINEL</w:t></w:r></w:p></w:body></w:document>');
  $docx->addFromString('word/media/unsupported.emf', "\0\x01\x02\xFF");
  $docx->addFromString('word/header1.xml', '<w:hdr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:p><w:r><w:t>DOCX_HEADER_SENTINEL</w:t></w:r></w:p></w:hdr>');
  $docx->addFile($directory . '/evidence/screenshot.png', 'word/media/image1.png'); $docx->close();
  $insert = $pdo->prepare('INSERT INTO evidence (id, case_id, type, title, filepath, original_filename, mime_type) VALUES (?, 1, ?, ?, ?, ?, ?)');
  foreach ([[101, 'other', 'Statement', 'statement.txt', 'text/plain'], [102, 'image', 'Screenshot', 'screenshot.png', 'image/png'], [103, 'doc', 'Document', 'document.docx', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'], [104, 'other', 'Binary upload', 'unreadable.bin', 'application/octet-stream']] as $file) {
    $insert->execute([$file[0], $file[1], $file[2], 'private:evidence/' . $file[3], $file[3], $file[4]]);
  }
  $pdo->exec("INSERT INTO case_notes VALUES (1, 1, 'CASE_NOTE_SENTINEL', CURRENT_TIMESTAMP)");
  case_ai_check(tp_resolve_uploaded_file('private:evidence/../../etc/passwd') === null, 'Traversal token was accepted.');
  case_ai_check(tp_resolve_uploaded_file('/etc/passwd') === null, 'Absolute outside path was accepted.');
  case_ai_check(tp_resolve_uploaded_file('private:evidence/statement.txt') === $directory . '/evidence/statement.txt', 'Private evidence did not resolve.');
  $chunks = tp_case_ollama_chunks($text, 6000, 300);
  case_ai_check(count($chunks) > 1 && str_contains(end($chunks), 'FINAL_TEXT_SENTINEL'), 'Long text was truncated.');
  $unicode = str_repeat('文書', 8000);
  foreach (tp_case_ollama_chunks($unicode) as $chunk) { case_ai_check(mb_check_encoding($chunk, 'UTF-8'), 'Chunking broke UTF-8.'); }
  case_ai_check(tp_case_ollama_chunks("\xFF\xFE" . mb_convert_encoding('UTF16 文書', 'UTF-16LE', 'UTF-8'))[0] === 'UTF16 文書', 'UTF-16 text was not decoded.');
  case_ai_check(tp_case_ollama_process([PHP_BINARY, '-r', 'echo $argv[1];', 'literal $(echo injected)'], $directory) === 'literal $(echo injected)', 'Document commands interpreted shell syntax.');
  $timedOut = false;
  try { tp_case_ollama_process([PHP_BINARY, '-r', 'usleep(500000);'], $directory, 0); }
  catch (TpOllamaEvidenceException $e) { $timedOut = str_contains($e->getMessage(), 'timed out'); }
  case_ai_check($timedOut, 'Document process timeout was not enforced.');
  case_ai_check(tp_case_ollama_enqueue($pdo, 1), 'Case did not queue.');
  case_ai_check(tp_case_ollama_enqueue($pdo, 1), 'Repeated queue failed.');
  case_ai_check((int)$pdo->query('SELECT requested_version FROM case_ollama_reports WHERE case_id = 1')->fetchColumn() === 2, 'Jobs were not deduplicated/versioned.');
  tp_case_ollama_enqueue($pdo, 999);
  case_ai_check((int)$pdo->query('SELECT COUNT(*) FROM case_ollama_reports')->fetchColumn() === 1, 'A missing case was queued.');
  foreach (['case_submitted_for_review', 'case_resubmitted', 'case_approved', 'evidence_added', 'evidence_deleted'] as $event) {
    $before = (int)$pdo->query('SELECT requested_version FROM case_ollama_reports WHERE case_id = 1')->fetchColumn();
    log_case_event($pdo, 1, $event);
    case_ai_check((int)$pdo->query('SELECT requested_version FROM case_ollama_reports WHERE case_id = 1')->fetchColumn() === $before + 1, 'Workflow event did not queue a report: ' . $event);
  }
  [$process, $apiUrl] = case_ai_server($directory); $servers[] = $process;
  putenv('TP_CASE_OLLAMA_TEST_URL=' . $apiUrl);
  [$process, $webUrl] = case_ai_server($directory); $servers[] = $process;
  $config = tp_ollama_config($pdo);
  $job = tp_case_ollama_work_one($pdo, $config);
  case_ai_check($job['status'] === 'Partial', 'Unsupported evidence was not recorded as partial.');
  $report = $pdo->query('SELECT * FROM case_ollama_reports WHERE case_id = 1')->fetch();
  $data = json_decode($report['report_json'], true);
  case_ai_check(count($data['coverage']) === 6, 'Evidence, notes or case details were omitted.');
  case_ai_check(str_contains($report['report_json'], 'FINAL_TEXT_SENTINEL') && str_contains($report['report_json'], 'DOCX_BODY_SENTINEL') && str_contains($report['report_json'], 'DOCX_HEADER_SENTINEL') && str_contains($report['report_json'], 'CASE_NOTE_SENTINEL'), 'Source extraction lost text.');
  case_ai_check(!str_contains($report['report_json'], 'SECRET_CASE2_CONTENT'), 'Other-case data leaked into a report.');
  $imageSegments = array_filter($data['segments'], static fn($part) => str_contains($part['label'], '[pixels'));
  case_ai_check(count($imageSegments) === 4, 'Screenshot or embedded-image tiles were skipped.');
  foreach ($data['segments'] as $part) { case_ai_check(!isset($part['image']), 'Image bytes were stored in the report.'); }
  $input = ['action' => 'case_ollama_status', 'case_id' => '1', 'case_code' => 'CASE1', 'csrf_token' => 'test-csrf'];
  foreach (['viewer', 'moderator', ''] as $role) {
    [$status, $response] = case_ai_post($webUrl . '/web?role=' . urlencode($role), $input);
    case_ai_check($status === 403 && !isset($response['report']), 'Non-admin accessed a private report.');
  }
  [$status] = case_ai_post($webUrl . '/web', array_replace($input, ['csrf_token' => 'bad']));
  case_ai_check($status === 403, 'Report endpoint accepted invalid CSRF.');
  [$status] = case_ai_post($webUrl . '/web', array_replace($input, ['case_code' => 'CASE2']));
  case_ai_check($status === 404, 'Mismatched case identity was accepted.');
  [$status, $response] = case_ai_post($webUrl . '/web', $input);
  case_ai_check($status === 200 && $response['ready'] && str_contains($response['report'], 'Evidence #101'), 'Admin could not read the report.');
  [$status, $response] = case_ai_post($webUrl . '/web', $input + ['known_version' => (string)$report['processed_version']]);
  case_ai_check($response['report'] === null && $response['history'] === null, 'Polling retransmitted an unchanged large report.');
  $chat = array_replace($input, ['action' => 'case_ollama_chat', 'question' => 'What does Evidence #101 record?']);
  [$status, $response] = case_ai_post($webUrl . '/web', $chat);
  case_ai_check($status === 200 && str_contains($response['answer'], 'Evidence #101'), 'Admin chat failed.');
  [$status, $otherAdmin] = case_ai_post($webUrl . '/web?user=2', $input);
  case_ai_check($otherAdmin['history'] === [], 'An admin received another admin’s conversation.');
  [$status, $ownAdmin] = case_ai_post($webUrl . '/web', $input);
  case_ai_check(count($ownAdmin['history']) === 1, 'Own conversation was not persisted.');
  [$status] = case_ai_post($webUrl . '/web', array_replace($chat, ['question' => ['array']]));
  case_ai_check($status === 400, 'Malformed chat input was accepted.');
  $context = tp_case_ollama_chat_context($report, 'FINAL_TEXT_SENTINEL', 14000);
  case_ai_check(str_contains($context, 'FINAL_TEXT_SENTINEL') && !str_contains($context, 'SECRET_CASE2_CONTENT'), 'Question retrieval omitted relevant text or mixed cases.');
  [$status] = case_ai_post($webUrl . '/web', array_replace($input, ['action' => 'case_ollama_refresh']));
  case_ai_check($status === 200, 'Report refresh failed.');
  $stale = $pdo->query('SELECT * FROM case_ollama_reports WHERE case_id = 1')->fetch();
  case_ai_check($stale['status'] === 'Queued' && $stale['report_text'] === null && $stale['report_json'] === null, 'Changed evidence left the old report accessible.');
  [$status] = case_ai_post($webUrl . '/web', $chat);
  case_ai_check($status === 409, 'Chat used a stale report.');
  $config['vision_model'] = 'fixture-text';
  tp_case_ollama_work_one($pdo, $config);
  $limited = $pdo->query('SELECT * FROM case_ollama_reports WHERE case_id = 1')->fetch();
  case_ai_check($limited['status'] === 'Partial' && str_contains($limited['report_text'], 'vision support'), 'Missing vision support was not disclosed.');
  $messagesBefore = (int)$pdo->query('SELECT COUNT(*) FROM case_ollama_messages')->fetchColumn();
  [$status] = case_ai_post($webUrl . '/web', array_replace($chat, ['question' => 'MUTATE_CASE_DURING_CHAT']));
  case_ai_check($status === 409 && (int)$pdo->query('SELECT COUNT(*) FROM case_ollama_messages')->fetchColumn() === $messagesBefore, 'A stale in-flight answer was saved or returned.');
  $config['default_model'] = 'fixture-mutating'; $config['vision_model'] = 'fixture-vision';
  $mutated = tp_case_ollama_work_one($pdo, $config);
  $invalidated = $pdo->query('SELECT * FROM case_ollama_reports WHERE case_id = 1')->fetch();
  case_ai_check($mutated['status'] === 'Queued' && $invalidated['report_text'] === null && $invalidated['processing_token'] === null, 'An in-flight report overwrote newer evidence.');
  tp_case_ollama_enqueue($pdo, 1); $config['default_model'] = 'fixture-failure';
  tp_case_ollama_work_one($pdo, $config);
  $failed = $pdo->query('SELECT * FROM case_ollama_reports WHERE case_id = 1')->fetch();
  case_ai_check($failed['status'] === 'Failed' && !str_contains($failed['error_message'], 'sensitive remote error'), 'Model failure was hidden or leaked its raw response.');
  $config['default_model'] = 'fixture-truncated';
  $rejected = false;
  try { tp_ollama_chat($config, [['role' => 'user', 'content' => 'Test']]); } catch (RuntimeException $e) { $rejected = str_contains($e->getMessage(), 'output limit'); }
  case_ai_check($rejected, 'Truncated model output was stored as complete.');
  $requests = file_get_contents($directory . '/requests.jsonl');
  case_ai_check(!str_contains($requests, 'SECRET_CASE2_CONTENT'), 'An inference request contained another case.');
  $source = file_get_contents(dirname(__DIR__) . '/index.php');
  case_ai_check(str_contains($source, "if (is_admin() && \$viewCaseId > 0) { require __DIR__ . '/lib/case-ollama-panel.php'; }"), 'Case panel lost its admin-only rendering guard.');
  echo "Private evidence extraction, chunking, vision, report storage, access control, chat isolation, stale-report and model-error checks passed.\n";
  if (in_array('--preview', $argv, true)) {
    tp_case_ollama_enqueue($pdo, 1); tp_case_ollama_work_one($pdo, tp_ollama_config($pdo));
    echo 'Browser preview: ' . $webUrl . '/ui' . "\n";
    echo 'Stop preview by creating: ' . $directory . '/stop-preview' . "\n";
    while (!is_file($directory . '/stop-preview')) { sleep(1); }
  }
} finally {
  foreach ($servers as $server) { proc_terminate($server); proc_close($server); }
  $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($directory, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
  foreach ($iterator as $file) { $file->isDir() ? rmdir($file->getPathname()) : unlink($file->getPathname()); }
  rmdir($directory);
}
