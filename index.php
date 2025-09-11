<?php
// ---- Minimal auth bootstrap (no frameworks) ----
if (session_status() === PHP_SESSION_NONE) {
    // Secure session settings
    ini_set('session.use_strict_mode', 1);
    ini_set('session.cookie_httponly', 1);
    ini_set('session.cookie_secure', isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 1 : 0);
    ini_set('session.cookie_samesite', 'Lax');
    session_start();
}

// Evidence storage path (absolute directory where files are stored, outside web root if possible)
$storagePath = '/var/www/html/tiktokpredators.com/uploads/';

// Flash helper
function flash(string $key, ?string $val = null){
    if ($val === null) {
        if (!empty($_SESSION['flash'][$key])) { $msg = $_SESSION['flash'][$key]; unset($_SESSION['flash'][$key]); return $msg; }
        return '';
    }
    $_SESSION['flash'][$key] = $val;
}

// CSRF token helper
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
function csrf_field(){ echo '<input type="hidden" name="csrf_token" value="'.htmlspecialchars($_SESSION['csrf_token']).'">'; }
function check_csrf(){ return isset($_POST['csrf_token']) && hash_equals($_SESSION['csrf_token'] ?? '', $_POST['csrf_token']); }

// VERY simple throttle (per-session)
$_SESSION['auth_attempts'] = $_SESSION['auth_attempts'] ?? 0;
$_SESSION['auth_last'] = $_SESSION['auth_last'] ?? 0;
function current_user_role(){ return $_SESSION['user']['role'] ?? 'guest'; }
function is_admin(){ return (current_user_role()==='admin'); }
function is_logged_in(){ return !empty($_SESSION['user']); }
$view = $_GET['view'] ?? 'cases';
function throttle(){
    $now = time();
    if ($now - ($_SESSION['auth_last'] ?? 0) < 3) { sleep(1); }
}

// Helper: find person photo URL by case code (tries common extensions)
function find_person_photo_url(string $caseCode): string {
    $baseDir = __DIR__ . '/uploads/people/';
    $baseRel = 'uploads/people/';
    $exts = ['jpg','jpeg','png','webp'];
    foreach ($exts as $ext) {
        $abs = $baseDir . $caseCode . '.' . $ext;
        if (is_file($abs)) {
            return $baseRel . $caseCode . '.' . $ext;
        }
    }
    return '';
}

// Generate a unique case code like CASE-2025-AB12CD34 (random, collision-checked)
function generate_case_code(PDO $pdo): string {
    $year = date('Y');
    for ($i = 0; $i < 5; $i++) { // retry a few times if duplicate
        $rand = strtoupper(substr(bin2hex(random_bytes(5)), 0, 8)); // 8 hex chars
        $code = "CASE-{$year}-{$rand}";
        // quick existence check
        $stmt = $pdo->prepare('SELECT 1 FROM cases WHERE case_code = ? LIMIT 1');
        $stmt->execute([$code]);
        if (!$stmt->fetch()) return $code;
    }
    // Fallback: include microtime entropy
    return "CASE-{$year}-" . strtoupper(substr(bin2hex(random_bytes(8)), 0, 8));
}

// PDO connection (configure these env vars or replace with constants)
$dsn = getenv('DB_DSN') ?: 'mysql:host=10.254.6.110;dbname=tiktokpredators;charset=utf8mb4';
$dbu = getenv('DB_USER') ?: 'stiliam';
$dbp = getenv('DB_PASS') ?: 'WRceFeIy58I0ypAgD5fu';
try { $pdo = new PDO($dsn, $dbu, $dbp, [PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE=>PDO::FETCH_ASSOC]); }
catch (Throwable $e) {
    // Record DB error for debugging and show a safe message
    $_SESSION['last_db_error'] = $e->getMessage();
    $_SESSION['sql_error'] = $e->getMessage();
    flash('error', 'Database connection failed. Please check configuration.');
    $_SESSION['auth_tab'] = 'register';
}

// Secure evidence streaming endpoint
if (($_GET['action'] ?? '') === 'serve_evidence') {
    $eid = (int)($_GET['id'] ?? 0);
    if ($eid <= 0) { http_response_code(400); exit('Bad request'); }
    try {
        $q = $pdo->prepare('SELECT e.id, e.filepath, e.mime_type, e.type, e.case_id, c.sensitivity FROM evidence e JOIN cases c ON c.id = e.case_id WHERE e.id = ? LIMIT 1');
        $q->execute([$eid]);
        $row = $q->fetch();
    } catch (Throwable $e) {
        http_response_code(500); exit('Server error');
    }
    if (!$row) { http_response_code(404); exit('Not found'); }
    $rel = $row['filepath'] ?? '';
    $mime = $row['mime_type'] ?? 'application/octet-stream';
    $type = $row['type'] ?? 'other';
    $sens = $row['sensitivity'] ?? 'Standard';
    $abs  = __DIR__ . '/' . ltrim($rel, '/');
    $uploadsRoot = realpath(__DIR__ . '/uploads');
    $absReal = @realpath($abs);
    // Basic path safety
    if (!$absReal || !$uploadsRoot || strncmp($absReal, $uploadsRoot, strlen($uploadsRoot)) !== 0) {
        http_response_code(403); exit('Forbidden');
    }
    if (!is_file($absReal)) { http_response_code(404); exit('Not found'); }

    // Send restrictive headers
    header('X-Content-Type-Options: nosniff');
    header('Cache-Control: private, no-transform');

    $isImage = (strpos($mime, 'image/') === 0);
    $isAdmin = is_admin();
    $isRestricted = ($sens === 'Restricted');

    // For restricted cases: non-admins must not get raw images.
    if ($isRestricted && !$isAdmin) {
        if ($isImage) {
            // Render a blurred, reduced version server-side using GD
            $data = @file_get_contents($absReal);
            if ($data === false) { http_response_code(404); exit('Not found'); }
            $img = @imagecreatefromstring($data);
            if (!$img) { http_response_code(415); exit('Unsupported media'); }

            // Downscale to max width 640 (keeping aspect)
            $w = imagesx($img); $h = imagesy($img);
            $maxW = 640;
            if ($w > $maxW) {
                $nw = $maxW; $nh = (int)round($h * ($maxW / $w));
                $small = imagecreatetruecolor($nw, $nh);
                imagecopyresampled($small, $img, 0, 0, 0, 0, $nw, $nh, $w, $h);
                imagedestroy($img);
                $img = $small;
            }
            // Apply heavy gaussian blur
            for ($i = 0; $i < 8; $i++) { @imagefilter($img, IMG_FILTER_GAUSSIAN_BLUR); }

            header('Content-Type: image/jpeg');
            // Prevent download as "real" with generic filename
            header('Content-Disposition: inline; filename="restricted.jpg"');
            imagejpeg($img, null, 60);
            imagedestroy($img);
            exit;
        } else {
            // For non-images in restricted cases, block direct access
            http_response_code(403); exit('Restricted');
        }
    }

    // Non-restricted OR admin: stream raw file
    $size = @filesize($absReal);
    header('Content-Type: ' . $mime);
    if ($size) { header('Content-Length: ' . $size); }
    header('Content-Disposition: inline; filename="' . basename($absReal) . '"');
    $fp = fopen($absReal, 'rb');
    if ($fp) { fpassthru($fp); fclose($fp); }
    else { readfile($absReal); }
    exit;
}

// Handle login POST
if (($_POST['action'] ?? '') === 'login') {
    throttle();
    if (!check_csrf()) { flash('error', 'Security check failed. Please refresh and try again.'); $_SESSION['auth_tab'] = 'login'; header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit; }
    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    if (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($password) < 8) {
        flash('error', 'Invalid email or password.');
        $_SESSION['auth_tab'] = 'login';
        header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit;
    }
    try {
        $stmt = $pdo->prepare('SELECT id, email, display_name, password_hash, role FROM users WHERE email = ? AND is_active = 1');
        $stmt->execute([$email]);
        $user = $stmt->fetch();
        if ($user && password_verify($password, $user['password_hash'])) {
            session_regenerate_id(true);
            $_SESSION['user'] = [
              'id' => $user['id'],
              'email' => $user['email'],
              'display_name' => $user['display_name'] ?? '',
              'role' => $user['role']
            ];
            $_SESSION['auth_attempts'] = 0; $_SESSION['auth_last'] = time();
            flash('success', 'Welcome back, '. htmlspecialchars($user['email']));
        } else {
            $_SESSION['auth_attempts'] = (int)$_SESSION['auth_attempts'] + 1; $_SESSION['auth_last'] = time();
            flash('error', 'Incorrect email or password.');
            $_SESSION['auth_tab'] = 'login';
        }
    } catch (Throwable $e) {
        $_SESSION['sql_error'] = $e->getMessage();
        $_SESSION['auth_tab'] = 'login';
        flash('error', 'Unable to process login at this time.');
    }
    header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit;
}

// Handle register POST
if (($_POST['action'] ?? '') === 'register') {
    throttle();
    if (!check_csrf()) { flash('error', 'Security check failed. Please refresh and try again.'); $_SESSION['auth_tab'] = 'register'; header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit; }
    $email = trim($_POST['email'] ?? '');
    $displayName = trim($_POST['display_name'] ?? '');
    $password = $_POST['password'] ?? '';
    $confirm = $_POST['password_confirm'] ?? '';
    $agree = isset($_POST['agree']);

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        flash('error', 'Please enter a valid email address.');
        $_SESSION['auth_tab'] = 'register';
        header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit;
    }
    if ($displayName === '') {
        flash('error', 'Please enter a display name.');
        $_SESSION['auth_tab'] = 'register';
        header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit;
    }
    if (!$agree) {
        flash('error', 'You must accept the terms to register.');
        $_SESSION['auth_tab'] = 'register';
        header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit;
    }
    if (strlen($password) < 8) {
        flash('error', 'Password must be at least 8 characters.');
        $_SESSION['auth_tab'] = 'register';
        header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit;
    }
    if (!hash_equals($password, $confirm)) {
        flash('error', 'Passwords do not match.');
        $_SESSION['auth_tab'] = 'register';
        header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit;
    }

    try {
        $stmt = $pdo->prepare('SELECT id FROM users WHERE email = ? LIMIT 1');
        $stmt->execute([$email]);
        if ($stmt->fetch()) {
            flash('error', 'An account with that email already exists.');
            $_SESSION['auth_tab'] = 'register';
            header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit;
        }
        $hash = password_hash($password, PASSWORD_DEFAULT);
        $ins = $pdo->prepare('INSERT INTO users (email, display_name, password_hash, role, is_active) VALUES (?, ?, ?, "viewer", 1)');
        $ins->execute([$email, $displayName, $hash]);
        flash('success', 'Registration successful. You can now log in.');
    } catch (Throwable $e) {
        // Map common PDO errors to user-friendly messages, append safe error code
        $code = 0;
        if ($e instanceof PDOException && isset($e->errorInfo[1])) {
            $code = (int)$e->errorInfo[1];
        }
        $public = 'Unable to register right now.';
        if ($code === 1062) {
            $public = 'That email is already registered.';
        } elseif (stripos($e->getMessage(), 'foreign key') !== false) {
            $public = 'Invalid reference on registration.';
        }
        // Store raw message for debugging (not shown unless debug enabled)
        $_SESSION['last_register_error'] = $e->getMessage();
        $_SESSION['sql_error'] = $e->getMessage();
        flash('error', $public.' [ERR#'.$code.']');
        $_SESSION['auth_tab'] = 'register';
    }
    header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit;
}

// Handle create case POST (admin only)
if (($_POST['action'] ?? '') === 'create_case') {
    throttle();
    if (!check_csrf()) { flash('error', 'Security check failed. Please refresh and try again.'); header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit; }
    if (empty($_SESSION['user']) || (($_SESSION['user']['role'] ?? '') !== 'admin')) {
        flash('error', 'Unauthorized. Admins only.'); header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit;
    }

    // Collect & validate inputs
    $case_name = trim($_POST['case_name'] ?? '');
    $person_name = trim($_POST['person_name'] ?? '');
    $tiktok_username = trim(ltrim($_POST['tiktok_username'] ?? '', '@'));
    $initial_summary = trim($_POST['initial_summary'] ?? '');
    $sensitivity = $_POST['sensitivity'] ?? '';
    $status = $_POST['status'] ?? '';

    $allowed_sensitivity = ['Standard','Restricted','Sealed'];
    $allowed_status = ['Open','In Review','Verified','Closed'];

    if ($case_name === '' || $initial_summary === '') {
        flash('error', 'Case name and initial summary are required.');
        $_SESSION['open_modal'] = 'createCase';
        $_SESSION['form_error'] = 'Case name and initial summary are required.';
        header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit;
    }
    if (!in_array($sensitivity, $allowed_sensitivity, true)) {
        flash('error', 'Invalid sensitivity.');
        $_SESSION['open_modal'] = 'createCase';
        $_SESSION['form_error'] = 'Invalid sensitivity selected.';
        header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit;
    }
    if (!in_array($status, $allowed_status, true)) {
        flash('error', 'Invalid status.');
        $_SESSION['open_modal'] = 'createCase';
        $_SESSION['form_error'] = 'Invalid status selected.';
        header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit;
    }

    try {
        $case_code = generate_case_code($pdo);
        $stmt = $pdo->prepare('INSERT INTO cases (case_code, case_name, person_name, tiktok_username, initial_summary, sensitivity, status, created_by, opened_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW())');
        $stmt->execute([
            $case_code,
            $case_name,
            ($person_name !== '' ? $person_name : null),
            ($tiktok_username !== '' ? $tiktok_username : null),
            $initial_summary,
            $sensitivity,
            $status,
            $_SESSION['user']['id'] ?? null
        ]);
        $case_id = (int)$pdo->lastInsertId();
        // Optional: handle person photo upload
        if (!empty($_FILES['person_photo']['name']) && $_FILES['person_photo']['error'] === UPLOAD_ERR_OK) {
            $pf = $_FILES['person_photo'];
            $pmime = $pf['type'] ?? '';
            $allowedImg = ['image/jpeg'=>'jpg','image/png'=>'png','image/webp'=>'webp'];
            $ext = $allowedImg[$pmime] ?? null;
            if (!$ext) {
                // Try mime_content_type for safer detection
                $det = @mime_content_type($pf['tmp_name']) ?: '';
                $ext = $allowedImg[$det] ?? null;
            }
            if ($ext) {
                $peopleDir = __DIR__ . '/uploads/people';
                if (!is_dir($peopleDir)) { @mkdir($peopleDir, 0755, true); }
                $destAbs = $peopleDir . '/' . $case_code . '.' . $ext;
                // Remove other ext variants to keep a single current file
                foreach (['jpg','jpeg','png','webp'] as $rmext) {
                    $cand = $peopleDir . '/' . $case_code . '.' . $rmext;
                    if (is_file($cand)) { @unlink($cand); }
                }
                @move_uploaded_file($pf['tmp_name'], $destAbs);
            }
        }
        flash('success', 'Case created successfully. ID: ' . htmlspecialchars($case_code));
        // jump to full admin case view
        header('Location: '. strtok($_SERVER['REQUEST_URI'], '?') . '?admin_case=' . urlencode($case_code) . '#admin-case');
        exit;
    } catch (Throwable $e) {
        $_SESSION['open_modal'] = 'createCase';
        $_SESSION['sql_error'] = $e->getMessage();
        flash('error', 'Unable to create case.');
    }
    header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit;
}

// Handle update case (admin only)
if (($_POST['action'] ?? '') === 'update_case') {
    throttle();
    if (!check_csrf()) { flash('error', 'Security check failed.'); header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit; }
    if (empty($_SESSION['user']) || (($_SESSION['user']['role'] ?? '') !== 'admin')) { flash('error', 'Unauthorized.'); header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit; }

    $case_id = (int)($_POST['case_id'] ?? 0);
    $case_code = trim($_POST['case_code'] ?? '');
    $case_name = trim($_POST['case_name'] ?? '');
    $person_name = trim($_POST['person_name'] ?? '');
    $tiktok_username = trim(ltrim($_POST['tiktok_username'] ?? '', '@'));
    $initial_summary = trim($_POST['initial_summary'] ?? '');
    $sensitivity = $_POST['sensitivity'] ?? '';
    $status = $_POST['status'] ?? '';

    $allowed_sensitivity = ['Standard','Restricted','Sealed'];
    $allowed_status = ['Open','In Review','Verified','Closed'];

    if ($case_id <= 0 || $case_code === '') {
        flash('error', 'Invalid case reference.');
        header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit;
    }
    if ($case_name === '' || $initial_summary === '') {
        flash('error', 'Case name and summary are required.');
        header('Location: ?view=case&code=' . urlencode($case_code) . '#case-view'); exit;
    }
    if (!in_array($sensitivity, $allowed_sensitivity, true)) { $sensitivity = 'Standard'; }
    if (!in_array($status, $allowed_status, true)) { $status = 'Open'; }

    // Optional: update person photo
    if (!empty($_FILES['person_photo']['name']) && $_FILES['person_photo']['error'] === UPLOAD_ERR_OK) {
        $pf = $_FILES['person_photo'];
        $pmime = $pf['type'] ?? '';
        $allowedImg = ['image/jpeg'=>'jpg','image/png'=>'png','image/webp'=>'webp'];
        $ext = $allowedImg[$pmime] ?? null;
        if (!$ext) {
            $det = @mime_content_type($pf['tmp_name']) ?: '';
            $ext = $allowedImg[$det] ?? null;
        }
        if ($ext) {
            $peopleDir = __DIR__ . '/uploads/people';
            if (!is_dir($peopleDir)) { @mkdir($peopleDir, 0755, true); }
            $destAbs = $peopleDir . '/' . $case_code . '.' . $ext;
            foreach (['jpg','jpeg','png','webp'] as $rmext) {
                $cand = $peopleDir . '/' . $case_code . '.' . $rmext;
                if (is_file($cand)) { @unlink($cand); }
            }
            @move_uploaded_file($pf['tmp_name'], $destAbs);
        }
    }

    try {
        $u = $pdo->prepare('UPDATE cases SET case_name = ?, person_name = ?, tiktok_username = ?, initial_summary = ?, sensitivity = ?, status = ? WHERE id = ? LIMIT 1');
        $u->execute([
            $case_name,
            ($person_name !== '' ? $person_name : null),
            ($tiktok_username !== '' ? $tiktok_username : null),
            $initial_summary,
            $sensitivity,
            $status,
            $case_id
        ]);
        flash('success', 'Case updated.');
    } catch (Throwable $e) {
        $_SESSION['sql_error'] = $e->getMessage();
        flash('error', 'Unable to update case.');
    }
    header('Location: ?view=case&code=' . urlencode($case_code) . '#case-view'); exit;
}

// Handle add case note (admin only)
if (($_POST['action'] ?? '') === 'add_case_note') {
    throttle();
    if (!check_csrf()) { flash('error', 'Security check failed.'); header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit; }
    if (empty($_SESSION['user']) || (($_SESSION['user']['role'] ?? '') !== 'admin')) { flash('error', 'Unauthorized.'); header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit; }

    $case_id = (int)($_POST['case_id'] ?? 0);
    $note = trim($_POST['note_text'] ?? '');
    $redir_code = trim($_POST['case_code'] ?? '');

    if ($case_id <= 0 || $note === '') {
        flash('error', 'Note text is required.');
        $redirUrl = trim($_POST['redirect_url'] ?? '');
        if ($redirUrl !== '') { header('Location: ' . $redirUrl); exit; }
        header('Location: ?admin_case=' . urlencode($redir_code) . '#admin-case'); exit;
    }

    try {
        $stmt = $pdo->prepare('INSERT INTO case_notes (case_id, note_text, created_by) VALUES (?, ?, ?)');
        $stmt->execute([$case_id, $note, $_SESSION['user']['id'] ?? null]);
        flash('success', 'Note added.');
    } catch (Throwable $e) {
        $_SESSION['sql_error'] = $e->getMessage();
        flash('error', 'Unable to add note.');
    }
    $redirUrl = trim($_POST['redirect_url'] ?? '');
    if ($redirUrl !== '') { header('Location: ' . $redirUrl); exit; }
    header('Location: ?admin_case=' . urlencode($redir_code) . '#admin-case'); exit;
}

// Handle add evidence note (admin only)
if (($_POST['action'] ?? '') === 'add_evidence_note') {
    throttle();
    if (!check_csrf()) { flash('error', 'Security check failed.'); header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit; }
    if (empty($_SESSION['user']) || (($_SESSION['user']['role'] ?? '') !== 'admin')) { flash('error', 'Unauthorized. Admins only.'); header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit; }

    $case_id = (int)($_POST['case_id'] ?? 0);
    $note = trim($_POST['note_text'] ?? '');
    $redir_code = trim($_POST['case_code'] ?? '');
    $redir_url = trim($_POST['redirect_url'] ?? '');

    if ($case_id <= 0 || $note === '') {
        flash('error', 'Note text is required.');
        if ($redir_url !== '') { header('Location: ' . $redir_url); exit; }
        header('Location: ?admin_case=' . urlencode($redir_code) . '#admin-case'); exit;
    }

    // Prepare safe title (truncate to 255 chars to avoid DB overflow)
    $title = mb_substr($note, 0, 255, 'UTF-8');

    // Persist full note text to a file (so we don't lose long notes)
    $notesDir = __DIR__ . '/uploads/notes';
    if (!is_dir($notesDir)) { @mkdir($notesDir, 0755, true); }
    $filename = 'note_' . uniqid('', true) . '.txt';
    $destAbs = $notesDir . '/' . $filename;
    $destRel = 'uploads/notes/' . $filename;
    $writeOk = @file_put_contents($destAbs, $note);
    if ($writeOk === false) {
        flash('error', 'Unable to store note file.');
        if ($redir_url !== '') { header('Location: ' . $redir_url); exit; }
        header('Location: ?admin_case=' . urlencode($redir_code) . '#admin-case'); exit;
    }

    $mime = 'text/plain';
    $size = filesize($destAbs) ?: strlen($note);
    $hash = @hash_file('sha256', $destAbs);
    if (!$hash) { $hash = hash('sha256', $note); }

    try {
        // Store as an evidence row of type 'other'
        $stmt = $pdo->prepare('INSERT INTO evidence (case_id, type, title, filepath, storage_path, original_filename, mime_type, size_bytes, hash_sha256, sha256_hex, uploaded_by, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)');
        $stmt->execute([
            $case_id,
            'other',
            $title,
            $destRel,
            $storagePath,
            $filename,
            $mime,
            $size,
            $hash,
            $hash,
            $_SESSION['user']['id'] ?? null,
            $_SESSION['user']['id'] ?? null
        ]);
        flash('success', 'Evidence note added.');
    } catch (Throwable $e) {
        $_SESSION['sql_error'] = $e->getMessage();
        flash('error', 'Unable to add evidence note.');
    }
    if ($redir_url !== '') { header('Location: ' . $redir_url); exit; }
    header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit;
}

// Handle evidence upload (admin only)
if (($_POST['action'] ?? '') === 'upload_evidence') {
    throttle();
    if (!check_csrf()) { flash('error', 'Security check failed.'); header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit; }
    if (empty($_SESSION['user']) || (($_SESSION['user']['role'] ?? '') !== 'admin')) { flash('error', 'Unauthorized.'); header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit; }

    $case_id = (int)($_POST['case_id'] ?? 0);
    $redir_code = trim($_POST['case_code'] ?? '');
    $title = trim($_POST['title'] ?? '');
    $type = $_POST['type'] ?? 'other';
    $allowedTypes = ['image','video','audio','pdf','doc','url','other'];
    if (!in_array($type, $allowedTypes, true)) $type = 'other';

    // Special handling for URL evidence: no file upload, just a destination URL.
    if ($type === 'url') {
        $url = trim($_POST['url_value'] ?? '');
        if ($case_id <= 0 || $url === '' || !filter_var($url, FILTER_VALIDATE_URL)) {
            flash('error', 'Please provide a valid URL.');
            $redirUrl = trim($_POST['redirect_url'] ?? '');
            if ($redirUrl !== '') { header('Location: ' . $redirUrl); exit; }
            header('Location: ?admin_case=' . urlencode($redir_code) . '#admin-case'); exit;
        }
        $mime = 'text/url';
        $size = 0;
        $hash = hash('sha256', $url);
        // Derive a non-null "original_filename" from the URL to satisfy NOT NULL constraint
        $urlPath = (string)parse_url($url, PHP_URL_PATH);
        $origName = basename($urlPath);
        if ($origName === '' || $origName === '/' || $origName === '.') {
            $host = (string)parse_url($url, PHP_URL_HOST);
            $origName = ($host !== '' ? $host : 'url') . '.link';
        }
        // Ensure it is a safe filename
        $origName = preg_replace('/[^A-Za-z0-9_.\\-]/', '_', $origName);
        try {
            $stmt = $pdo->prepare('INSERT INTO evidence (case_id, type, title, filepath, storage_path, original_filename, mime_type, size_bytes, hash_sha256, sha256_hex, uploaded_by, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)');
            $stmt->execute([
                $case_id,
                'url',
                ($title !== '' ? $title : $url),
                $url,                 // store destination URL in filepath
                $storagePath,
                $origName,
                $mime,
                $size,
                $hash,
                $hash,
                $_SESSION['user']['id'] ?? null,
                $_SESSION['user']['id'] ?? null
            ]);
            flash('success', 'URL evidence added.');
        } catch (Throwable $e) {
            $_SESSION['sql_error'] = $e->getMessage();
            // Fallback: some schemas have evidence.type as ENUM without 'url'
            $msg = strtolower($e->getMessage());
            $enumIssue = (strpos($msg, 'incorrect enum value') !== false) || (strpos($msg, 'data truncated for column') !== false);
            if ($enumIssue) {
                try {
                    $stmt = $pdo->prepare('INSERT INTO evidence (case_id, type, title, filepath, storage_path, original_filename, mime_type, size_bytes, hash_sha256, sha256_hex, uploaded_by, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)');
                    $stmt->execute([
                        $case_id,
                        'other', // fallback
                        ($title !== '' ? $title : $url),
                        $url,
                        $storagePath,
                        $origName,
                        $mime,
                        $size,
                        $hash,
                        $hash,
                        $_SESSION['user']['id'] ?? null,
                        $_SESSION['user']['id'] ?? null
                    ]);
                    flash('success', 'URL evidence added (stored as type "other" due to DB enum).');
                } catch (Throwable $e2) {
                    $_SESSION['sql_error'] = $e2->getMessage();
                    flash('error', 'Unable to save URL evidence.');
                }
            } else {
                flash('error', 'Unable to save URL evidence.');
            }
        }
        $redirUrl = trim($_POST['redirect_url'] ?? '');
        if ($redirUrl !== '') { header('Location: ' . $redirUrl); exit; }
        header('Location: ?admin_case=' . urlencode($redir_code) . '#admin-case'); exit;
    }

    if ($case_id <= 0 || ($type !== 'url' && empty($_FILES['evidence_file']['name']))) {
        flash('error', 'Please choose a file.');
        $redirUrl = trim($_POST['redirect_url'] ?? '');
        if ($redirUrl !== '') { header('Location: ' . $redirUrl); exit; }
        header('Location: ?admin_case=' . urlencode($redir_code) . '#admin-case'); exit;
    }

    $uploadDir = __DIR__ . '/uploads';
    if (!is_dir($uploadDir)) { @mkdir($uploadDir, 0755, true); }

    $f = $_FILES['evidence_file'];
    if ($f['error'] !== UPLOAD_ERR_OK) { flash('error', 'Upload failed with code: '. (int)$f['error']); $redirUrl = trim($_POST['redirect_url'] ?? ''); if ($redirUrl !== '') { header('Location: ' . $redirUrl); exit; } header('Location: ?admin_case=' . urlencode($redir_code) . '#admin-case'); exit; }

    $safeName = preg_replace('/[^A-Za-z0-9_.\\-]/', '_', basename($f['name']));
    $destRel = 'uploads/' . uniqid('ev_', true) . '_' . $safeName;
    $destAbs = __DIR__ . '/' . $destRel;
    if (!move_uploaded_file($f['tmp_name'], $destAbs)) { flash('error', 'Unable to save uploaded file.'); $redirUrl = trim($_POST['redirect_url'] ?? ''); if ($redirUrl !== '') { header('Location: ' . $redirUrl); exit; } header('Location: ?admin_case=' . urlencode($redir_code) . '#admin-case'); exit; }

    $mime = mime_content_type($destAbs) ?: ($f['type'] ?? 'application/octet-stream');
    $size = filesize($destAbs) ?: 0;
    $hash = hash_file('sha256', $destAbs);

    try {

        // Use global storage path and set uploaded_by and created_by to current user
        $stmt = $pdo->prepare('INSERT INTO evidence (case_id, type, title, filepath, storage_path, original_filename, mime_type, size_bytes, hash_sha256, sha256_hex, uploaded_by, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)');
        $stmt->execute([
            $case_id,
            $type,
            ($title !== '' ? $title : $safeName),
            $destRel,
            $storagePath,
            $safeName,
            $mime,
            $size,
            $hash,
            $hash,
            $_SESSION['user']['id'] ?? null,
            $_SESSION['user']['id'] ?? null
        ]);
        flash('success', 'Evidence uploaded.');
    } catch (Throwable $e) {
        $_SESSION['sql_error'] = $e->getMessage();
        flash('error', 'Unable to save evidence.');
    }
    $redirUrl = trim($_POST['redirect_url'] ?? '');
    if ($redirUrl !== '') { header('Location: ' . $redirUrl); exit; }
    header('Location: ?admin_case=' . urlencode($redir_code) . '#admin-case'); exit;
}

// Handle update evidence (admin only)
if (($_POST['action'] ?? '') === 'update_evidence') {
    throttle();
    if (!check_csrf()) { flash('error', 'Security check failed.'); header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit; }
    if (empty($_SESSION['user']) || (($_SESSION['user']['role'] ?? '') !== 'admin')) { flash('error', 'Unauthorized.'); header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit; }

    $evidence_id = (int)($_POST['evidence_id'] ?? 0);
    $case_id = (int)($_POST['case_id'] ?? 0);
    $title = trim($_POST['title'] ?? '');
    $type = $_POST['type'] ?? 'other';
    $allowedTypes = ['image','video','audio','pdf','doc','url','other'];
    if (!in_array($type, $allowedTypes, true)) $type = 'other';

    if ($evidence_id <= 0 || $case_id <= 0) { flash('error', 'Invalid evidence.'); $ru = trim($_POST['redirect_url'] ?? ''); if ($ru!==''){header('Location: '.$ru); exit;} header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit; }

    try {
        if ($type === 'url') {
            $url = trim($_POST['url_value'] ?? '');
            if ($url === '' || !filter_var($url, FILTER_VALIDATE_URL)) {
                flash('error', 'Please provide a valid URL.');
                $ru = trim($_POST['redirect_url'] ?? '');
                if ($ru!==''){ header('Location: '.$ru); exit; }
                header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit;
            }
            // Recompute a safe original filename for URL updates
            $urlPath = (string)parse_url($url, PHP_URL_PATH);
            $origName = basename($urlPath);
            if ($origName === '' || $origName === '/' || $origName === '.') {
                $host = (string)parse_url($url, PHP_URL_HOST);
                $origName = ($host !== '' ? $host : 'url') . '.link';
            }
            $origName = preg_replace('/[^A-Za-z0-9_.\\-]/', '_', $origName);
            try {
                $u = $pdo->prepare('UPDATE evidence SET title = ?, type = ?, filepath = ?, original_filename = ?, mime_type = "text/url" WHERE id = ? AND case_id = ? LIMIT 1');
                $u->execute([$title, $type, $url, $origName, $evidence_id, $case_id]);
            } catch (Throwable $e) {
                $_SESSION['sql_error'] = $e->getMessage();
                $msg = strtolower($e->getMessage());
                $enumIssue = (strpos($msg, 'incorrect enum value') !== false) || (strpos($msg, 'data truncated for column') !== false);
                if ($enumIssue) {
                    $u = $pdo->prepare('UPDATE evidence SET title = ?, type = ?, filepath = ?, original_filename = ?, mime_type = "text/url" WHERE id = ? AND case_id = ? LIMIT 1');
                    $u->execute([$title, 'other', $url, $origName, $evidence_id, $case_id]);
                    flash('success', 'Evidence updated (stored as type "other" due to DB enum).');
                } else {
                    throw $e;
                }
            }
        } else {
            $u = $pdo->prepare('UPDATE evidence SET title = ?, type = ? WHERE id = ? AND case_id = ? LIMIT 1');
            $u->execute([$title, $type, $evidence_id, $case_id]);
        }
        if ($type !== 'url') {
            flash('success', 'Evidence updated.');
        }
    } catch (Throwable $e) {
        $_SESSION['sql_error'] = $e->getMessage();
        flash('error', 'Unable to update evidence.');
    }
    $ru = trim($_POST['redirect_url'] ?? ''); if ($ru!==''){header('Location: '.$ru); exit;} header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit;
}

// Handle delete evidence (admin only)
if (($_POST['action'] ?? '') === 'delete_evidence') {
    throttle();
    if (!check_csrf()) { flash('error', 'Security check failed.'); header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit; }
    if (empty($_SESSION['user']) || (($_SESSION['user']['role'] ?? '') !== 'admin')) { flash('error', 'Unauthorized.'); header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit; }

    $evidence_id = (int)($_POST['evidence_id'] ?? 0);
    $case_id = (int)($_POST['case_id'] ?? 0);
    $ru = trim($_POST['redirect_url'] ?? '');

    if ($evidence_id <= 0 || $case_id <= 0) { flash('error', 'Invalid evidence.'); if($ru!==''){header('Location: '.$ru); exit;} header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit; }

    try {
        // fetch row for path
        $s = $pdo->prepare('SELECT filepath FROM evidence WHERE id = ? AND case_id = ? LIMIT 1');
        $s->execute([$evidence_id, $case_id]);
        $row = $s->fetch();
        if ($row) {
            $rel = $row['filepath'];
            $abs = __DIR__ . '/' . ltrim($rel, '/');
        }
        // delete row first
        $d = $pdo->prepare('DELETE FROM evidence WHERE id = ? AND case_id = ? LIMIT 1');
        $d->execute([$evidence_id, $case_id]);
        // best-effort remove file
        if (!empty($abs) && is_file($abs) && strpos(realpath($abs), realpath(__DIR__ . '/uploads')) === 0) { @unlink($abs); }
        flash('success', 'Evidence deleted.');
    } catch (Throwable $e) {
        $_SESSION['sql_error'] = $e->getMessage();
        flash('error', 'Unable to delete evidence.');
    }
    if($ru!==''){header('Location: '.$ru); exit;} header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit;
}

// Handle delete case (admin only)
if (($_POST['action'] ?? '') === 'delete_case') {
    throttle();
    if (!check_csrf()) { flash('error', 'Security check failed.'); header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit; }
    if (empty($_SESSION['user']) || (($_SESSION['user']['role'] ?? '') !== 'admin')) { flash('error', 'Unauthorized.'); header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit; }

    $case_id = (int)($_POST['case_id'] ?? 0);
    $case_code = trim($_POST['case_code'] ?? '');

    if ($case_id <= 0) { flash('error', 'Invalid case.'); header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit; }

    // Collect file paths for later removal
    $files = [];
    try {
        $s = $pdo->prepare('SELECT filepath FROM evidence WHERE case_id = ?');
        $s->execute([$case_id]);
        $files = $s->fetchAll();
    } catch (Throwable $e) { $_SESSION['sql_error'] = $e->getMessage(); }

    try {
        $pdo->beginTransaction();
        // Delete evidence, notes, then case row
        $d1 = $pdo->prepare('DELETE FROM evidence WHERE case_id = ?');
        $d1->execute([$case_id]);
        $d2 = $pdo->prepare('DELETE FROM case_notes WHERE case_id = ?');
        $d2->execute([$case_id]);
        $d3 = $pdo->prepare('DELETE FROM cases WHERE id = ? LIMIT 1');
        $d3->execute([$case_id]);
        $pdo->commit();
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) { $pdo->rollBack(); }
        $_SESSION['sql_error'] = $e->getMessage();
        flash('error', 'Unable to delete case.');
        header('Location: ?view=case&code=' . urlencode($case_code) . '#case-view'); exit;
    }

    // Best-effort file cleanup after DB commit
    if ($files) {
        foreach ($files as $row) {
            $rel = $row['filepath'] ?? '';
            if ($rel !== '') {
                $abs = __DIR__ . '/' . ltrim($rel, '/');
                $uploadsRoot = realpath(__DIR__ . '/uploads');
                $absReal = @realpath($abs);
                if ($uploadsRoot && $absReal && strncmp($absReal, $uploadsRoot, strlen($uploadsRoot)) === 0 && is_file($absReal)) {
                    @unlink($absReal);
                }
            }
        }
    }

    flash('success', 'Case and all associated evidence/notes deleted.');
    header('Location: ?view=cases#cases'); exit;
}

// Handle delete user (admin only)
if (($_POST['action'] ?? '') === 'delete_user') {
    throttle();
    if (!check_csrf()) { flash('error', 'Security check failed.'); header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit; }
    if (empty($_SESSION['user']) || (($_SESSION['user']['role'] ?? '') !== 'admin')) { flash('error', 'Unauthorized.'); header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit; }

    $user_id = (int)($_POST['user_id'] ?? 0);
    $ru = trim($_POST['redirect_url'] ?? '?view=users#users');

    if ($user_id <= 0) { flash('error', 'Invalid user.'); header('Location: '. $ru); exit; }
    if (($user_id === (int)($_SESSION['user']['id'] ?? 0))) { flash('error', 'You cannot delete your own account.'); header('Location: '. $ru); exit; }

    try {
        // Best-effort nullify foreign keys if they exist (avoid FK constraint errors)
        try { $pdo->prepare('UPDATE evidence SET uploaded_by = NULL WHERE uploaded_by = ?')->execute([$user_id]); } catch (Throwable $e) {}
        try { $pdo->prepare('UPDATE evidence SET created_by = NULL WHERE created_by = ?')->execute([$user_id]); } catch (Throwable $e) {}
        try { $pdo->prepare('UPDATE case_notes SET created_by = NULL WHERE created_by = ?')->execute([$user_id]); } catch (Throwable $e) {}

        $d = $pdo->prepare('DELETE FROM users WHERE id = ? LIMIT 1');
        $d->execute([$user_id]);
        if ($d->rowCount() > 0) {
            flash('success', 'User deleted.');
        } else {
            flash('error', 'User not found or could not be deleted.');
        }
    } catch (Throwable $e) {
        $_SESSION['sql_error'] = $e->getMessage();
        flash('error', 'Unable to delete user.');
    }
    header('Location: '. $ru); exit;
}

// Handle logout
if (isset($_GET['logout'])) {
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000, $params['path'], $params['domain'], $params['secure'], $params['httponly']);
    }
    session_destroy();
    header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit;
}
?>
<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>TikTokPredators — Case & Evidence Manager</title>
  <meta name="description" content="Secure, auditable case & evidence management platform for vetted users." />
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" />
  <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css" rel="stylesheet" />
  <style>
    :root {
      --tp-primary: #7c4dff; /* violet */
      --tp-accent: #19c37d;  /* green */
    }
    .navbar-brand span { color: var(--tp-primary); }
    .hero {
      background: radial-gradient(1200px 600px at 80% -10%, rgba(124,77,255,.2), transparent),
                  radial-gradient(800px 400px at 10% -10%, rgba(25,195,125,.15), transparent);
    }
    .glass { backdrop-filter: blur(8px); background: rgba(255,255,255,.06); border: 1px solid rgba(255,255,255,.12); }
    .badge-role { background: rgba(124,77,255,.2); border: 1px solid rgba(124,77,255,.35); }
    .placeholder-tile { aspect-ratio: 16/9; background: repeating-linear-gradient(45deg, #222 0 10px, #1b1b1b 10px 20px); border-radius: .75rem; position: relative; overflow: hidden; }
    .placeholder-tile .text { position: absolute; inset: 0; display: grid; place-items: center; color: #888 }
    .audit-list { max-height: 280px; overflow-y: auto; }
    .case-grid .card { transition: transform .15s ease, box-shadow .15s ease; }
    .case-grid .card:hover { transform: translateY(-2px); box-shadow: 0 6px 32px rgba(0,0,0,.35); }
    .avatar { width: 36px; height: 36px; border-radius: 50%; object-fit: cover; }
    .dropzone { border: 2px dashed rgba(255,255,255,.25); border-radius: 1rem; padding: 2rem; text-align: center; }
    .timeline { border-left: 2px solid rgba(255,255,255,.1); padding-left: 1rem; }
    .timeline .item { position: relative; margin-bottom: 1rem; }
    .timeline .item::before { content: ""; position: absolute; left: -1.1rem; top: .25rem; width: .65rem; height: .65rem; background: var(--tp-primary); border-radius: 50%; box-shadow: 0 0 0 3px rgba(124,77,255,.25); }
    
    /* Evidence modal: full-width media */
    .evidence-modal .modal-dialog { max-width: 95vw; }
    .evidence-modal .modal-body { padding: 0; }
    .evidence-modal img,
    .evidence-modal video,
    .evidence-modal iframe { width: 100%; height: auto; display: block; object-fit: contain; }
    
    /* Restricted-mode media blurring (non-admins on Restricted cases) */
    footer a { color: inherit }
  </style>
</head>
<body>
  <?php if ($msg = flash('success')): ?>
    <div class="alert alert-success border-0 rounded-0 mb-0 text-center"><?php echo $msg; ?></div>
  <?php endif; ?>
  <?php if ($msg = flash('error')): ?>
    <div class="alert alert-danger border-0 rounded-0 mb-0 text-center"><?php echo $msg; ?></div>
  <?php endif; ?>
  <?php if (is_admin() && !empty($_SESSION['sql_error'])): ?>
    <div class="alert alert-warning border-0 rounded-0 mb-0 text-center">
      <div><strong>SQL hint:</strong> <?php echo htmlspecialchars($_SESSION['sql_error']); unset($_SESSION['sql_error']); ?></div>
      <div class="small">If this mentions an ENUM issue on <code>evidence.type</code>, run:
        <code>ALTER TABLE evidence MODIFY COLUMN type ENUM('image','video','audio','pdf','doc','url','other') NOT NULL DEFAULT 'other';</code>
      </div>
    </div>
  <?php endif; ?>
  <?php $openAuth = $_SESSION['auth_tab'] ?? ''; unset($_SESSION['auth_tab']); ?>
  <?php $openModal = $_SESSION['open_modal'] ?? ''; unset($_SESSION['open_modal']); $formError = $_SESSION['form_error'] ?? ''; unset($_SESSION['form_error']); ?>
  <!-- Top Navbar -->
  <nav class="navbar navbar-expand-lg border-bottom sticky-top bg-body glass">
    <div class="container-xl">
      <a class="navbar-brand fw-bold" href="#"><i class="bi bi-shield-lock me-2 text-primary"></i> TikTok<span>Predators</span></a>
      <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#topNav"><span class="navbar-toggler-icon"></span></button>
      <div class="collapse navbar-collapse" id="topNav">
        <ul class="navbar-nav me-auto mb-2 mb-lg-0">
<li class="nav-item"><a class="nav-link <?php echo ($view==='cases')?'active':''; ?>" href="?view=cases#cases">Cases</a></li>
<?php if (is_admin()): ?>
  <li class="nav-item"><a class="nav-link <?php echo ($view==='users')?'active':''; ?>" href="?view=users#users">Users</a></li>
<?php endif; ?>
        </ul>
        <div class="d-flex align-items-center gap-2">
          <!-- Auth state -->
          <?php if (empty($_SESSION['user'])): ?>
            <button class="btn btn-outline-light btn-sm" data-bs-toggle="modal" data-bs-target="#authModal" data-auth-tab="register"><i class="bi bi-person-plus me-1"></i> Register</button>
            <button class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#authModal" data-auth-tab="login"><i class="bi bi-box-arrow-in-right me-1"></i> Login</button>
          <?php else: ?>
            <div class="dropdown">
              <?php $dn = $_SESSION['user']['display_name'] ?? ''; $label = $dn !== '' ? $dn : ($_SESSION['user']['email'] ?? 'Account'); ?>
              <button class="btn btn-outline-light btn-sm dropdown-toggle" data-bs-toggle="dropdown" aria-expanded="false">
                <i class="bi bi-person-check me-1"></i> <?php echo htmlspecialchars($label); ?>
              </button>
              <ul class="dropdown-menu dropdown-menu-end">
                <li class="dropdown-item-text">
                  <div class="fw-semibold"><?php echo htmlspecialchars($label); ?></div>
                  <div class="small text-secondary"><?php echo htmlspecialchars($_SESSION['user']['email'] ?? ''); ?></div>
                </li>
                <li><span class="dropdown-item-text small text-secondary">Role: <?php echo htmlspecialchars($_SESSION['user']['role'] ?? 'viewer'); ?></span></li>
                <li><hr class="dropdown-divider"></li>
                <li><a class="dropdown-item" href="?logout=1"><i class="bi bi-box-arrow-right me-2"></i>Logout</a></li>
              </ul>
            </div>
          <?php endif; ?>
        </div>
      </div>
    </div>
  </nav>



  <!-- Cases Grid + Right Rail -->
  <?php if ($view === 'cases'): ?>
  <main class="py-4" id="cases">
    <div class="container-xl">
      <div class="row g-4">
        <div class="col-12 case-grid">
          <div class="d-flex align-items-center justify-content-between mb-2">
            <h2 class="h4 mb-0">Recent Cases</h2>
            <div class="btn-group">
              <button class="btn btn-outline-light btn-sm"><i class="bi bi-sort-alpha-down"></i></button>
              <button class="btn btn-outline-light btn-sm"><i class="bi bi-funnel"></i></button>
              <?php if (!empty($_SESSION['user']) && ($_SESSION['user']['role'] ?? '') === 'admin'): ?>
                <button class="btn btn-primary btn-sm" data-bs-toggle="modal" data-bs-target="#createCaseModal"><i class="bi bi-folder-plus me-1"></i> Add Case</button>
              <?php endif; ?>
            </div>
          </div>
          <div class="row g-3 row-cols-1 row-cols-md-2">
<?php
try {
  // Pull recent cases by latest activity (evidence added) or opened date
  $sql = "SELECT c.id, c.case_code, c.case_name, c.person_name, c.tiktok_username, c.initial_summary, c.status, c.sensitivity, c.opened_at,
                 COALESCE(ev.cnt, 0) AS evidence_count,
                 COALESCE(ev.last_added, c.opened_at) AS last_activity
          FROM cases c
          LEFT JOIN (
            SELECT case_id, COUNT(*) AS cnt, MAX(created_at) AS last_added
            FROM evidence
            GROUP BY case_id
          ) ev ON ev.case_id = c.id
          ORDER BY last_activity DESC
          LIMIT 20";
  $rs = $pdo->query($sql)->fetchAll();
} catch (Throwable $e) {
  $_SESSION['sql_error'] = $e->getMessage();
  $rs = [];
}

if ($rs && count($rs) > 0):
  foreach ($rs as $row):
    $code  = $row['case_code'];
    $name  = $row['case_name'] ?: $row['case_code'];
    $person= $row['person_name'] ?: '';
    $tuser = $row['tiktok_username'] ? '@'.htmlspecialchars($row['tiktok_username']) : '';
    $sum   = trim($row['initial_summary'] ?? '');
    $sum   = $sum !== '' ? mb_strimwidth($sum, 0, 180, '…', 'UTF-8') : 'No summary provided.';
    $evc   = (int)($row['evidence_count'] ?? 0);
    $status= $row['status'] ?? 'Open';
    $sens  = $row['sensitivity'] ?? 'Standard';
    $opened= $row['opened_at'] ?? '';
    $last  = $row['last_activity'] ?? $opened;
    $photoUrl = '';
    $photoPath = find_person_photo_url($code);
    if ($photoPath !== '') { $photoUrl = $photoPath; }
?>
  <div class="col">
    <div class="card h-100">
      <?php if (!empty($photoUrl)) { ?>
        <img src="<?php echo htmlspecialchars($photoUrl); ?>" class="card-img-top" alt="" style="aspect-ratio:16/9; object-fit:cover;">
      <?php } ?>
      <div class="card-body">
        <div class="d-flex justify-content-between align-items-start">
          <div>
            <a href="?view=case&code=<?php echo urlencode($code); ?>#case-view" class="stretched-link text-decoration-none"><h3 class="h6 mb-1"><?php echo htmlspecialchars($name); ?></h3></a>
            <div class="small text-secondary">
              <?php if ($person !== ''): ?>Subject: <span class="text-white"><?php echo htmlspecialchars($person); ?></span><?php endif; ?>
              <?php if ($tuser !== ''): ?><?php if($person!==''): ?>&nbsp;•&nbsp;<?php endif; ?><span class="text-white"><?php echo $tuser; ?></span><?php endif; ?>
            </div>
          </div>
          <span class="badge rounded-pill text-bg-dark border"><?php echo htmlspecialchars($status); ?></span>
        </div>
        <p class="small mt-3 mb-2 text-secondary"><?php echo htmlspecialchars($sum); ?></p>
        <div class="mt-2 d-flex gap-2 flex-wrap">
          <span class="badge text-bg-dark border"><i class="bi bi-files me-1"></i><?php echo $evc; ?> evidence</span>
          <span class="badge text-bg-dark border"><i class="bi bi-shield-lock me-1"></i><?php echo htmlspecialchars($sens); ?></span>
          <span class="badge text-bg-dark border" title="Last activity">
            <i class="bi bi-clock-history me-1"></i><?php echo htmlspecialchars(date('d M Y H:i', strtotime($last))); ?>
          </span>
        </div>
      </div>
      <div class="card-footer d-flex justify-content-between align-items-center small">
        <span><i class="bi bi-hash"></i> <?php echo htmlspecialchars($code); ?></span>
        <div class="d-flex gap-2">
          <a class="btn btn-sm btn-outline-light" href="?view=case&code=<?php echo urlencode($code); ?>#case-view" title="Open read-only case view"><i class="bi bi-box-arrow-up-right me-1"></i>Open</a>
        </div>
      </div>
    </div>
  </div>
<?php endforeach; else: ?>
  <div class="col-12">
    <div class="alert alert-secondary">No cases found yet.</div>
  </div>
<?php endif; ?>
</div>

        </div>
      </div>
    </div>
  </main>
  <?php endif; ?>

  <?php if ($view === 'users'): ?>
  <main class="py-4" id="users">
    <div class="container-xl">
      <div class="d-flex align-items-center justify-content-between mb-3">
        <h2 class="h4 mb-0">User Management</h2>
        <div class="d-flex gap-2">
          <button class="btn btn-primary btn-sm" data-bs-toggle="modal" data-bs-target="#addUserModal"><i class="bi bi-person-plus me-1"></i> Add User</button>
          <a class="btn btn-outline-light btn-sm" href="?view=cases#cases"><i class="bi bi-arrow-left me-1"></i> Back to Cases</a>
        </div>
      </div>

      <?php if (!is_admin()): ?>
        <div class="alert alert-danger">Unauthorized. Admins only.</div>
      <?php else: ?>
        <div class="card glass">
          <div class="card-body">
            <?php
            $users = [];
            try {
              $q = $pdo->query('SELECT id, email, display_name, role, is_active, created_at FROM users ORDER BY created_at DESC');
              $users = $q->fetchAll();
            } catch (Throwable $e) {
              $_SESSION['sql_error'] = $e->getMessage();
              $users = [];
            }
            ?>
            <div class="table-responsive">
              <table class="table table-sm align-middle">
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Display Name</th>
                    <th>Email</th>
                    <th>Role</th>
                    <th>Status</th>
                    <th>Created</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  <?php if ($users && count($users) > 0): foreach ($users as $u): ?>
                    <tr>
                      <td><?php echo (int)$u['id']; ?></td>
                      <td><?php echo htmlspecialchars($u['display_name'] ?? ''); ?></td>
                      <td><?php echo htmlspecialchars($u['email'] ?? ''); ?></td>
                      <td><span class="badge text-bg-dark border"><?php echo htmlspecialchars($u['role'] ?? 'viewer'); ?></span></td>
                      <td><?php echo ((int)($u['is_active'] ?? 0) ? '<span class="badge bg-success">Active</span>' : '<span class="badge bg-secondary">Disabled</span>'); ?></td>
                      <td><?php echo htmlspecialchars($u['created_at'] ?? ''); ?></td>
                      <td>
                        <?php if ((int)$u['id'] !== (int)($_SESSION['user']['id'] ?? 0)): ?>
                          <form method="post" action="" class="d-inline" onsubmit="return confirm('Delete this user permanently? This cannot be undone.');">
                            <input type="hidden" name="action" value="delete_user">
                            <?php csrf_field(); ?>
                            <input type="hidden" name="user_id" value="<?php echo (int)$u['id']; ?>">
                            <input type="hidden" name="redirect_url" value="?view=users#users">
                            <button type="submit" class="btn btn-sm btn-outline-danger"><i class="bi bi-person-x me-1"></i>Delete</button>
                          </form>
                        <?php else: ?>
                          <span class="text-secondary small">(You)</span>
                        <?php endif; ?>
                      </td>
                    </tr>
                  <?php endforeach; else: ?>
                    <tr><td colspan="7" class="text-secondary">No users found.</td></tr>
                  <?php endif; ?>
                </tbody>
              </table>
            </div>
          </div>
        </div>
      <?php endif; ?>
    </div>
  </main>
  <?php endif; ?>

  <?php if ($view === 'case'): ?>
    <?php
      $caseCode = trim($_GET['code'] ?? '');
      $viewCase = null; $viewCaseId = 0; $viewEv = [];
      if ($caseCode !== '') {
        try {
          $st = $pdo->prepare('SELECT id, case_code, case_name, person_name, tiktok_username, initial_summary, status, sensitivity, opened_at FROM cases WHERE case_code = ? LIMIT 1');
          $st->execute([$caseCode]);
          $viewCase = $st->fetch();
          $viewCaseId = (int)($viewCase['id'] ?? 0);
        } catch (Throwable $e) { $_SESSION['sql_error'] = $e->getMessage(); }
        if ($viewCaseId > 0) {
          try {
            $st2 = $pdo->prepare('SELECT id, type, title, filepath, mime_type, size_bytes, created_at FROM evidence WHERE case_id = ? ORDER BY created_at DESC');
            $st2->execute([$viewCaseId]);
            $viewEv = $st2->fetchAll();
          } catch (Throwable $e) { $_SESSION['sql_error'] = $e->getMessage(); }
        }
      }
    ?>
    <?php
      $tp_isRestrictedForNonAdmin = false;
      if (!empty($viewCase)) {
        $tp_isRestrictedForNonAdmin = (($viewCase['sensitivity'] ?? '') === 'Restricted') && !is_admin();
      }
      if ($tp_isRestrictedForNonAdmin) {
        echo '<script>document.addEventListener("DOMContentLoaded",function(){document.body.dataset.restricted="1";});</script>';
      }
    ?>
    <section class="py-5 border-top" id="case-view">
      <div class="container-xl">
        <div class="d-flex align-items-center justify-content-between mb-3">
          <h2 class="h4 mb-0">Case <?php echo htmlspecialchars($caseCode ?: ''); ?></h2>
          <div class="d-flex gap-2">
            <?php if (!empty($_SESSION['user']) && (($_SESSION['user']['role'] ?? '') === 'admin')): ?>
              <button class="btn btn-primary btn-sm" data-bs-toggle="modal" data-bs-target="#addEvidenceModal"><i class="bi bi-cloud-plus me-1"></i> Add Evidence / Note</button>
              <form method="post" action="" class="d-inline" onsubmit="return confirm('This will permanently delete the entire case and all evidence/notes. This cannot be undone. Continue?');">
                <input type="hidden" name="action" value="delete_case">
                <?php csrf_field(); ?>
                <input type="hidden" name="case_id" value="<?php echo (int)$viewCaseId; ?>">
                <input type="hidden" name="case_code" value="<?php echo htmlspecialchars($caseCode); ?>">
                <button type="submit" class="btn btn-outline-danger btn-sm"><i class="bi bi-trash me-1"></i> Delete Case</button>
              </form>
            <?php endif; ?>
            <a class="btn btn-outline-light btn-sm" href="?view=cases#cases"><i class="bi bi-arrow-left me-1"></i> Back to Cases</a>
          </div>
        </div>
        <?php if (!empty($_SESSION['user']) && (($_SESSION['user']['role'] ?? '') === 'admin')): ?>
  <div class="modal fade" id="addEvidenceModal" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog modal-lg modal-dialog-centered">
      <div class="modal-content">
        <div class="modal-header">
          <h5 class="modal-title"><i class="bi bi-cloud-plus me-2"></i>Add Evidence or Note</h5>
          <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
        </div>
        <div class="modal-body">
          <ul class="nav nav-tabs" id="addEvTabs" role="tablist">
            <li class="nav-item" role="presentation">
              <button class="nav-link active" id="ev-upload-tab" data-bs-toggle="tab" data-bs-target="#ev-upload-pane" type="button" role="tab">Upload Evidence</button>
            </li>
            <li class="nav-item" role="presentation">
              <button class="nav-link" id="ev-note-tab" data-bs-toggle="tab" data-bs-target="#ev-note-pane" type="button" role="tab">Add Note</button>
            </li>
            <li class="nav-item" role="presentation">
              <button class="nav-link" id="ev-url-tab" data-bs-toggle="tab" data-bs-target="#ev-url-pane" type="button" role="tab">Add URL</button>
            </li>
          </ul>
          <div class="tab-content pt-3">
            <div class="tab-pane fade show active" id="ev-upload-pane" role="tabpanel">
              <form class="mb-2" method="post" action="" enctype="multipart/form-data" id="evUploadForm">
                <input type="hidden" name="action" value="upload_evidence">
                <?php csrf_field(); ?>
                <input type="hidden" name="case_id" value="<?php echo (int)$viewCaseId; ?>">
                <input type="hidden" name="case_code" value="<?php echo htmlspecialchars($caseCode); ?>">
                <input type="hidden" name="redirect_url" value="?view=case&amp;code=<?php echo urlencode($caseCode); ?>#case-view">
                <div class="row g-2 align-items-end">
                  <div class="col-md-5">
                    <label class="form-label">Title</label>
                    <input type="text" name="title" class="form-control" placeholder="Optional title">
                  </div>
                  <div class="col-md-3">
                    <label class="form-label">Type</label>
                    <select name="type" class="form-select">
                      <option value="image">Image</option>
                      <option value="pdf">PDF</option>
                      <option value="url">URL (no file)</option>
                    </select>
                  </div>
                  <div class="col-md-4">
                    <label class="form-label">File</label>
                    <input type="file" name="evidence_file" class="form-control" accept="image/*,application/pdf" required>
                  </div>
                </div>
              </form>
            </div>
            <div class="tab-pane fade" id="ev-note-pane" role="tabpanel">
              <form class="mb-2" method="post" action="" id="evNoteForm">
                <input type="hidden" name="action" value="add_evidence_note">
                <?php csrf_field(); ?>
                <input type="hidden" name="case_id" value="<?php echo (int)$viewCaseId; ?>">
                <input type="hidden" name="case_code" value="<?php echo htmlspecialchars($caseCode); ?>">
                <input type="hidden" name="redirect_url" value="?view=case&amp;code=<?php echo urlencode($caseCode); ?>#case-view">
                <label class="form-label">Note Text</label>
                <textarea name="note_text" class="form-control" rows="4" placeholder="Write a concise internal note..." required></textarea>
              </form>
            </div>
            <div class="tab-pane fade" id="ev-url-pane" role="tabpanel">
              <form class="mb-2" method="post" action="" id="evUrlForm">
                <input type="hidden" name="action" value="upload_evidence">
                <?php csrf_field(); ?>
                <input type="hidden" name="case_id" value="<?php echo (int)$viewCaseId; ?>">
                <input type="hidden" name="case_code" value="<?php echo htmlspecialchars($caseCode); ?>">
                <input type="hidden" name="redirect_url" value="?view=case&amp;code=<?php echo urlencode($caseCode); ?>#case-view">
                <input type="hidden" name="type" value="url">
                <div class="row g-2 align-items-end">
                  <div class="col-md-6">
                    <label class="form-label">Title</label>
                    <input type="text" name="title" class="form-control" placeholder="Brief title (optional)">
                  </div>
                  <div class="col-md-6">
                    <label class="form-label">Destination URL</label>
                    <input type="url" name="url_value" class="form-control" placeholder="https://example.com/page" required>
                  </div>
                </div>
              </form>
            </div>
          </div>
        </div>
        <div class="modal-footer">
          <button class="btn btn-outline-light" data-bs-dismiss="modal">Close</button>
          <button class="btn btn-primary" type="submit" form="evUploadForm"><i class="bi bi-cloud-arrow-up me-1"></i> Save Upload</button>
          <button class="btn btn-success" type="submit" form="evNoteForm"><i class="bi bi-journal-plus me-1"></i> Save Note</button>
          <button class="btn btn-info" type="submit" form="evUrlForm"><i class="bi bi-link-45deg me-1"></i> Save URL</button>
        </div>
      </div>
    </div>
  </div>
<?php endif; ?>
        <?php if ($viewCase): ?>
          <div class="row g-4">
            <div class="col-lg-4">
              <div class="card glass h-100">
                <div class="card-body">
                  <div class="d-flex justify-content-between align-items-center mb-3">
                    <h3 class="h6 mb-0">Case Details</h3>
                    <?php if (is_admin()): ?>
                      <button class="btn btn-sm btn-outline-light" data-bs-toggle="modal" data-bs-target="#editCaseModal">
                        <i class="bi bi-pencil me-1"></i> Edit
                      </button>
                    <?php endif; ?>
                  </div>
                  <?php $casePhoto = find_person_photo_url($caseCode); if ($casePhoto !== '') { ?>
                    <div class="mb-3">
                      <img src="<?php echo htmlspecialchars($casePhoto); ?>" alt="" class="rounded" style="width:96px;height:96px;object-fit:cover;">
                    </div>
                  <?php } ?>
                  <div class="small text-secondary">Case Name</div>
                  <div class="mb-2"><?php echo htmlspecialchars($viewCase['case_name'] ?? ''); ?></div>
                  <div class="small text-secondary">Person Name</div>
                  <div class="mb-2"><?php echo htmlspecialchars($viewCase['person_name'] ?? ''); ?></div>
                  <div class="small text-secondary">TikTok Username</div>
                  <div class="mb-2"><?php echo $viewCase['tiktok_username'] ? '@'.htmlspecialchars($viewCase['tiktok_username']) : '<span class="text-secondary">—</span>'; ?></div>
                  <div class="small text-secondary">Status</div>
                  <div class="mb-2"><span class="badge text-bg-dark border"><?php echo htmlspecialchars($viewCase['status']); ?></span></div>
                  <div class="small text-secondary">Sensitivity</div>
                  <div class="mb-2"><span class="badge text-bg-dark border"><?php echo htmlspecialchars($viewCase['sensitivity']); ?></span></div>
                  <div class="small text-secondary">Opened</div>
                  <div class="mb-2"><?php echo htmlspecialchars($viewCase['opened_at']); ?></div>
                  <div class="small text-secondary">Summary</div>
                  <div class="mb-0"><?php echo nl2br(htmlspecialchars($viewCase['initial_summary'] ?? '')); ?></div>
                </div>
              </div>
            </div>
            <div class="col-lg-8">
              <div class="card glass">
                <div class="card-body">
                  <div class="d-flex align-items-center justify-content-between mb-2">
                    <h3 class="h6 mb-0">Evidence</h3>
                  </div>
                  <div class="table-responsive">
                    <table class="table table-sm align-middle">
                      <thead><tr><th>Type</th><th>Title</th><th>File</th></tr></thead>
                      <tbody>
                        <?php if ($viewEv) { foreach ($viewEv as $e) { ?>
                          <tr>
                            <td><?php echo htmlspecialchars($e['type']); ?></td>
                            <td><?php echo htmlspecialchars($e['title']); ?></td>
                            <td>
                              <?php if (($e['type'] ?? '') === 'note' || (isset($e['mime_type'], $e['filepath']) && $e['mime_type'] === 'text/plain' && strpos($e['filepath'], 'uploads/notes/') === 0)) { ?>
                                <button type="button" class="btn btn-sm btn-outline-light btn-view-note"
                                        data-bs-toggle="modal" data-bs-target="#noteModal"
                                        data-id="<?php echo (int)$e['id']; ?>"
                                        data-case-id="<?php echo (int)$viewCaseId; ?>"
                                        data-src="<?php echo htmlspecialchars($e['filepath']); ?>"
                                        data-title="<?php echo htmlspecialchars($e['title'] ?? 'Note'); ?>">
                                  View
                                </button>
                                <?php if (is_admin()): ?>
                                  <div class="btn-group ms-1">
                                    <button type="button" class="btn btn-sm btn-outline-warning btn-edit-evidence" data-bs-toggle="modal" data-bs-target="#evidenceModal"
                                            data-id="<?php echo (int)$e['id']; ?>" data-case-id="<?php echo (int)$viewCaseId; ?>" data-src="<?php echo htmlspecialchars($e['filepath']); ?>" data-title="<?php echo htmlspecialchars($e['title']); ?>" data-type="<?php echo htmlspecialchars($e['type'] ?? 'other'); ?>" data-mime="<?php echo htmlspecialchars($e['mime_type']); ?>" data-admin="1">
                                      Edit
                                    </button>
                                    <form method="post" action="" class="d-inline" onsubmit="return confirm('Delete this evidence permanently?');">
                                      <input type="hidden" name="action" value="delete_evidence">
                                      <?php csrf_field(); ?>
                                      <input type="hidden" name="evidence_id" value="<?php echo (int)$e['id']; ?>">
                                      <input type="hidden" name="case_id" value="<?php echo (int)$viewCaseId; ?>">
                                      <input type="hidden" name="redirect_url" value="?view=case&amp;code=<?php echo urlencode($caseCode); ?>#case-view">
                                      <button type="submit" class="btn btn-sm btn-outline-danger">Delete</button>
                                    </form>
                                  </div>
                                <?php endif; ?>
                              <?php } else {
                                  $isUrl = (($e['type'] ?? '') === 'url') || (($e['mime_type'] ?? '') === 'text/url');
                                  if ($isUrl) { ?>
                                    <a class="btn btn-sm btn-outline-light"
                                       href="<?php echo htmlspecialchars($e['filepath']); ?>"
                                       target="_blank" rel="noopener">
                                      Open
                                    </a>
                                    <?php if (is_admin()): ?>
                                      <div class="btn-group ms-1">
                                        <button type="button" class="btn btn-sm btn-outline-warning btn-edit-evidence" data-bs-toggle="modal" data-bs-target="#evidenceModal"
                                                data-id="<?php echo (int)$e['id']; ?>" data-case-id="<?php echo (int)$viewCaseId; ?>" data-src="<?php echo htmlspecialchars($e['filepath']); ?>" data-title="<?php echo htmlspecialchars($e['title']); ?>" data-type="<?php echo htmlspecialchars($e['type'] ?? 'other'); ?>" data-mime="<?php echo htmlspecialchars($e['mime_type']); ?>" data-admin="1" data-url="1">
                                          Edit
                                        </button>
                                        <form method="post" action="" class="d-inline" onsubmit="return confirm('Delete this evidence permanently?');">
                                          <input type="hidden" name="action" value="delete_evidence">
                                          <?php csrf_field(); ?>
                                          <input type="hidden" name="evidence_id" value="<?php echo (int)$e['id']; ?>">
                                          <input type="hidden" name="case_id" value="<?php echo (int)$viewCaseId; ?>">
                                          <input type="hidden" name="redirect_url" value="?view=case&amp;code=<?php echo urlencode($caseCode); ?>#case-view">
                                          <button type="submit" class="btn btn-sm btn-outline-danger">Delete</button>
                                        </form>
                                      </div>
                                    <?php endif; ?>
                                  <?php } else { ?>
                                    <button type="button" class="btn btn-sm btn-outline-light btn-view-evidence"
                                            data-bs-toggle="modal" data-bs-target="#evidenceModal"
                                            data-id="<?php echo (int)$e['id']; ?>"
                                            data-case-id="<?php echo (int)$viewCaseId; ?>"
                                            data-src="?action=serve_evidence&amp;id=<?php echo (int)$e['id']; ?>"
                                            data-title="<?php echo htmlspecialchars($e['title']); ?>"
                                            data-type="<?php echo htmlspecialchars($e['type'] ?? 'other'); ?>"
                                            data-mime="<?php echo htmlspecialchars($e['mime_type']); ?>">
                                      View
                                    </button>
                                    <?php if (is_admin()): ?>
                                      <div class="btn-group ms-1">
                                        <button type="button" class="btn btn-sm btn-outline-warning btn-edit-evidence" data-bs-toggle="modal" data-bs-target="#evidenceModal"
                                                data-id="<?php echo (int)$e['id']; ?>" data-case-id="<?php echo (int)$viewCaseId; ?>" data-src="?action=serve_evidence&amp;id=<?php echo (int)$e['id']; ?>" data-title="<?php echo htmlspecialchars($e['title']); ?>" data-type="<?php echo htmlspecialchars($e['type'] ?? 'other'); ?>" data-mime="<?php echo htmlspecialchars($e['mime_type']); ?>" data-admin="1">
                                          Edit
                                        </button>
                                        <form method="post" action="" class="d-inline" onsubmit="return confirm('Delete this evidence permanently?');">
                                          <input type="hidden" name="action" value="delete_evidence">
                                          <?php csrf_field(); ?>
                                          <input type="hidden" name="evidence_id" value="<?php echo (int)$e['id']; ?>">
                                          <input type="hidden" name="case_id" value="<?php echo (int)$viewCaseId; ?>">
                                          <input type="hidden" name="redirect_url" value="?view=case&amp;code=<?php echo urlencode($caseCode); ?>#case-view">
                                          <button type="submit" class="btn btn-sm btn-outline-danger">Delete</button>
                                        </form>
                                      </div>
                                    <?php endif; ?>
                                  <?php } ?>
                              <?php } ?>
                            </td>
                          </tr>
                        <?php } } else { ?>
                          <tr><td colspan="3" class="text-secondary">No evidence available.</td></tr>
                        <?php } ?>
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>
            </div>
          </div>
<?php if (is_admin() && $viewCase): ?>
  <div class="modal fade" id="editCaseModal" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog modal-lg modal-dialog-centered">
      <div class="modal-content">
        <div class="modal-header">
          <h5 class="modal-title"><i class="bi bi-pencil-square me-2"></i>Edit Case Details</h5>
          <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
        </div>
        <div class="modal-body">
          <form method="post" action="" id="editCaseFormView" enctype="multipart/form-data">
            <input type="hidden" name="action" value="update_case">
            <?php csrf_field(); ?>
            <input type="hidden" name="case_id" value="<?php echo (int)$viewCaseId; ?>">
            <input type="hidden" name="case_code" value="<?php echo htmlspecialchars($caseCode); ?>">
            <input type="hidden" name="redirect_url" value="?view=case&amp;code=<?php echo urlencode($caseCode); ?>#case-view">

            <div class="row g-2">
              <div class="col-md-6">
                <label class="form-label">Case Name</label>
                <input type="text" name="case_name" class="form-control" value="<?php echo htmlspecialchars($viewCase['case_name'] ?? ''); ?>" required>
              </div>
              <div class="col-md-6">
                <label class="form-label">TikTok Username</label>
                <div class="input-group">
                  <span class="input-group-text">@</span>
                  <input type="text" name="tiktok_username" class="form-control" value="<?php echo htmlspecialchars($viewCase['tiktok_username'] ?? ''); ?>">
                </div>
              </div>
            </div>

            <div class="row g-2 mt-2">
              <div class="col-md-6">
                <label class="form-label">Person Name</label>
                <input type="text" name="person_name" class="form-control" value="<?php echo htmlspecialchars($viewCase['person_name'] ?? ''); ?>">
              </div>
              <div class="col-md-3">
                <label class="form-label">Sensitivity</label>
                <select name="sensitivity" class="form-select" required>
                  <?php $sensOpts = ['Standard','Restricted','Sealed']; foreach ($sensOpts as $opt) { $sel = (($viewCase['sensitivity'] ?? '') === $opt) ? ' selected' : ''; echo '<option value="'.htmlspecialchars($opt).'"'.$sel.'>'.htmlspecialchars($opt)."</option>"; } ?>
                </select>
              </div>
              <div class="col-md-3">
                <label class="form-label">Status</label>
                <select name="status" class="form-select" required>
                  <?php $statOpts = ['Open','In Review','Verified','Closed']; foreach ($statOpts as $opt) { $sel = (($viewCase['status'] ?? '') === $opt) ? ' selected' : ''; echo '<option value="'.htmlspecialchars($opt).'"'.$sel.'>'.htmlspecialchars($opt)."</option>"; } ?>
                </select>
              </div>
            </div>

            <div class="row g-2 mt-2">
              <div class="col-md-6">
                <label class="form-label">Update Person Photo</label>
                <input type="file" name="person_photo" class="form-control" accept="image/*">
                <small class="text-secondary">Leave blank to keep current</small>
              </div>
            </div>

            <div class="mt-3">
              <label class="form-label">Initial Summary</label>
              <textarea name="initial_summary" class="form-control" rows="4" required><?php echo htmlspecialchars($viewCase['initial_summary'] ?? ''); ?></textarea>
            </div>
          </form>
        </div>
        <div class="modal-footer">
          <button class="btn btn-outline-light" data-bs-dismiss="modal">Cancel</button>
          <button class="btn btn-primary" type="submit" form="editCaseFormView"><i class="bi bi-save me-1"></i> Save Changes</button>
        </div>
      </div>
    </div>
  </div>
<?php endif; ?>
        <?php else: ?>
          <div class="alert alert-danger"><i class="bi bi-exclamation-octagon me-2"></i>Case not found or unavailable.</div>
        <?php endif; ?>
      </div>
    </section>
  <?php endif; ?>

  <?php
  $adminCaseCode = $_GET['admin_case'] ?? '';
  if (!empty($adminCaseCode) && !empty($_SESSION['user']) && (($_SESSION['user']['role'] ?? '') === 'admin')) {
      // Fetch case meta
      $caseRow = null; $caseId = 0;
      try {
          $s = $pdo->prepare('SELECT id, case_code, case_name, person_name, tiktok_username, initial_summary, status, sensitivity, opened_at FROM cases WHERE case_code = ? LIMIT 1');
          $s->execute([$adminCaseCode]);
          $caseRow = $s->fetch();
          $caseId = (int)($caseRow['id'] ?? 0);
      } catch (Throwable $e) {
          $_SESSION['sql_error'] = $e->getMessage();
      }
      // Fetch notes
      $notes = [];
      if ($caseId > 0) {
          try {
              $n = $pdo->prepare('SELECT cn.id, cn.note_text, cn.created_at, u.display_name FROM case_notes cn LEFT JOIN users u ON u.id = cn.created_by WHERE cn.case_id = ? ORDER BY cn.created_at DESC LIMIT 50');
              $n->execute([$caseId]);
              $notes = $n->fetchAll();
          } catch (Throwable $e) { $_SESSION['sql_error'] = $e->getMessage(); }
      }
      // Fetch evidence
      $ev = [];
      if ($caseId > 0) {
          try {
              $evi = $pdo->prepare('SELECT id, type, title, filepath, mime_type, size_bytes, created_at FROM evidence WHERE case_id = ? ORDER BY created_at DESC LIMIT 100');
              $evi->execute([$caseId]);
              $ev = $evi->fetchAll();
          } catch (Throwable $e) { $_SESSION['sql_error'] = $e->getMessage(); }
      }
  ?>
<section class="py-5 border-top" id="admin-case">
  <div class="container-xl">
    <div class="d-flex align-items-center justify-content-between mb-3">
      <h2 class="h4 mb-0">Admin: Case <?php echo htmlspecialchars($adminCaseCode); ?></h2>
      <a class="btn btn-outline-light btn-sm" href="#cases"><i class="bi bi-grid-1x2 me-1"></i> Back to dashboard</a>
    </div>

    <?php if ($caseRow) { ?>
    <div class="row g-4">
      <div class="col-lg-4">
        <div class="card glass h-100">
                <div class="card-body">
                  <div class="d-flex justify-content-between align-items-center mb-3">
                    <h3 class="h6 mb-0">Case Details</h3>
                    <button class="btn btn-sm btn-outline-light" data-bs-toggle="modal" data-bs-target="#editCaseModal"><i class="bi bi-pencil me-1"></i> Edit</button>
                  </div>
                  <?php $adminCasePhoto = find_person_photo_url($caseRow['case_code'] ?? ''); if ($adminCasePhoto !== '') { ?>
                    <div class="mb-3">
                      <img src="<?php echo htmlspecialchars($adminCasePhoto); ?>" alt="" class="rounded" style="width:96px;height:96px;object-fit:cover;">
                    </div>
                  <?php } ?>
                  <div class="small text-secondary">Case Name</div>
                  <div class="mb-2"><?php echo htmlspecialchars($caseRow['case_name'] ?? ''); ?></div>
                  <div class="small text-secondary">Person Name</div>
                  <div class="mb-2"><?php echo htmlspecialchars($caseRow['person_name'] ?? ''); ?></div>
                  <div class="small text-secondary">TikTok Username</div>
                  <div class="mb-2"><?php echo $caseRow['tiktok_username'] ? '@'.htmlspecialchars($caseRow['tiktok_username']) : '<span class="text-secondary">—</span>'; ?></div>
                  <div class="small text-secondary">Status</div>
                  <div class="mb-2"><span class="badge text-bg-dark border"><?php echo htmlspecialchars($caseRow['status']); ?></span></div>
                  <div class="small text-secondary">Sensitivity</div>
                  <div class="mb-2"><span class="badge text-bg-dark border"><?php echo htmlspecialchars($caseRow['sensitivity']); ?></span></div>
                  <div class="small text-secondary">Opened</div>
                  <div class="mb-2"><?php echo htmlspecialchars($caseRow['opened_at']); ?></div>
                  <div class="small text-secondary">Initial Summary</div>
                  <div class="mb-0"><?php echo nl2br(htmlspecialchars($caseRow['initial_summary'] ?? '')); ?></div>
          </div>
        </div>
      </div>

      <div class="col-lg-8">
        <ul class="nav nav-pills mb-3" id="caseAdminTabs" role="tablist">
          <li class="nav-item" role="presentation">
            <button class="nav-link active" id="notes-tab" data-bs-toggle="tab" data-bs-target="#notes-pane" type="button" role="tab">Notes</button>
          </li>
          <li class="nav-item" role="presentation">
            <button class="nav-link" id="uploads-tab" data-bs-toggle="tab" data-bs-target="#uploads-pane" type="button" role="tab">Uploads / Evidence</button>
          </li>
          <li class="nav-item" role="presentation">
            <button class="nav-link" id="photos-tab" data-bs-toggle="tab" data-bs-target="#photos-pane" type="button" role="tab">Photos</button>
          </li>
          <li class="nav-item" role="presentation">
            <button class="nav-link" id="pdfs-tab" data-bs-toggle="tab" data-bs-target="#pdfs-pane" type="button" role="tab">PDFs</button>
          </li>
        </ul>

        <div class="tab-content">
          <!-- Notes -->
          <div class="tab-pane fade show active" id="notes-pane" role="tabpanel">
            <form class="mb-3" method="post" action="">
              <input type="hidden" name="action" value="add_case_note">
              <?php csrf_field(); ?>
              <input type="hidden" name="case_id" value="<?php echo (int)$caseId; ?>">
              <input type="hidden" name="case_code" value="<?php echo htmlspecialchars($adminCaseCode); ?>">
              <label class="form-label">Add Note</label>
              <textarea name="note_text" class="form-control" rows="3" placeholder="Write an internal note…" required></textarea>
              <div class="text-end mt-2"><button class="btn btn-primary btn-sm" type="submit"><i class="bi bi-journal-plus me-1"></i> Save Note</button></div>
            </form>
            <ul class="list-group list-group-flush">
              <?php if ($notes) { foreach ($notes as $n) { ?>
                <li class="list-group-item bg-transparent text-white">
                  <div class="small text-secondary"><?php echo htmlspecialchars($n['created_at']); ?> • <?php echo htmlspecialchars($n['display_name'] ?? ''); ?></div>
                  <div><?php echo nl2br(htmlspecialchars($n['note_text'])); ?></div>
                </li>
              <?php } } else { ?>
                <li class="list-group-item bg-transparent text-secondary">No notes yet.</li>
              <?php } ?>
            </ul>
          </div>

          <!-- Uploads/Evidence -->
          <div class="tab-pane fade" id="uploads-pane" role="tabpanel">
            <form class="mb-3" method="post" action="" enctype="multipart/form-data">
              <input type="hidden" name="action" value="upload_evidence">
              <?php csrf_field(); ?>
              <input type="hidden" name="case_id" value="<?php echo (int)$caseId; ?>">
              <input type="hidden" name="case_code" value="<?php echo htmlspecialchars($adminCaseCode); ?>">
              <div class="row g-2 align-items-end">
                <div class="col-md-4">
                  <label class="form-label">Title</label>
                  <input type="text" name="title" class="form-control" placeholder="Optional title">
                </div>
                <div class="col-md-3">
                  <label class="form-label">Type</label>
                  <select name="type" class="form-select">
                    <option value="image">Image</option>
                    <option value="video">Video</option>
                    <option value="audio">Audio</option>
                    <option value="pdf">PDF</option>
                    <option value="doc">Document</option>
                    <option value="url">URL (no file)</option>
                    <option value="other" selected>Other</option>
                  </select>
                </div>
                <div class="col-md-5">
                  <label class="form-label">File</label>
                  <input type="file" name="evidence_file" class="form-control" required>
                </div>
              </div>
              <div class="text-end mt-2"><button class="btn btn-primary btn-sm" type="submit"><i class="bi bi-cloud-arrow-up me-1"></i> Upload</button></div>
            </form>
            <form class="mb-3" method="post" action="">
              <input type="hidden" name="action" value="upload_evidence">
              <?php csrf_field(); ?>
              <input type="hidden" name="case_id" value="<?php echo (int)$caseId; ?>">
              <input type="hidden" name="case_code" value="<?php echo htmlspecialchars($adminCaseCode); ?>">
              <input type="hidden" name="type" value="url">
              <div class="row g-2 align-items-end">
                <div class="col-md-4">
                  <label class="form-label">Title</label>
                  <input type="text" name="title" class="form-control" placeholder="Optional title">
                </div>
                <div class="col-md-8">
                  <label class="form-label">Destination URL</label>
                  <input type="url" name="url_value" class="form-control" placeholder="https://example.com/page" required>
                </div>
              </div>
              <div class="text-end mt-2"><button class="btn btn-info btn-sm" type="submit"><i class="bi bi-link-45deg me-1"></i> Add URL</button></div>
            </form>

            <div class="table-responsive">
              <table class="table table-sm align-middle">
                <thead><tr><th>Type</th><th>Title</th><th>File</th><th>MIME</th><th>Size</th><th>Added</th></tr></thead>
                <tbody>
                  <?php if ($ev) { foreach ($ev as $e) { ?>
                    <tr>
                      <td><?php echo htmlspecialchars($e['type']); ?></td>
                      <td><?php echo htmlspecialchars($e['title']); ?></td>
                      <td>
                        <?php if (($e['type'] ?? '') === 'note' || (isset($e['mime_type'], $e['filepath']) && $e['mime_type'] === 'text/plain' && strpos($e['filepath'], 'uploads/notes/') === 0)) { ?>
                          <button type="button" class="btn btn-sm btn-outline-light btn-view-note"
                                  data-bs-toggle="modal" data-bs-target="#noteModal"
                                  data-id="<?php echo (int)$e['id']; ?>"
                                  data-case-id="<?php echo (int)$caseId; ?>"
                                  data-src="<?php echo htmlspecialchars($e['filepath']); ?>"
                                  data-title="<?php echo htmlspecialchars($e['title'] ?? 'Note'); ?>">
                            View
                          </button>
                          <div class="btn-group ms-1">
                            <button type="button" class="btn btn-sm btn-outline-warning btn-edit-evidence" data-bs-toggle="modal" data-bs-target="#evidenceModal"
                                    data-id="<?php echo (int)$e['id']; ?>" data-case-id="<?php echo (int)$caseId; ?>" data-src="<?php echo htmlspecialchars($e['filepath']); ?>" data-title="<?php echo htmlspecialchars($e['title']); ?>" data-type="<?php echo htmlspecialchars($e['type'] ?? 'other'); ?>" data-mime="<?php echo htmlspecialchars($e['mime_type']); ?>" data-admin="1">
                              Edit
                            </button>
                            <form method="post" action="" class="d-inline" onsubmit="return confirm('Delete this evidence permanently?');">
                              <input type="hidden" name="action" value="delete_evidence">
                              <?php csrf_field(); ?>
                              <input type="hidden" name="evidence_id" value="<?php echo (int)$e['id']; ?>">
                              <input type="hidden" name="case_id" value="<?php echo (int)$caseId; ?>">
                              <input type="hidden" name="redirect_url" value="?admin_case=<?php echo urlencode($adminCaseCode); ?>#admin-case">
                              <button type="submit" class="btn btn-sm btn-outline-danger">Delete</button>
                            </form>
                          </div>
                        <?php } else {
                            $isUrl = (($e['type'] ?? '') === 'url') || (($e['mime_type'] ?? '') === 'text/url');
                            if ($isUrl) { ?>
                              <a class="btn btn-sm btn-outline-light"
                                 href="<?php echo htmlspecialchars($e['filepath']); ?>"
                                 target="_blank" rel="noopener">
                                Open
                              </a>
                              <div class="btn-group ms-1">
                                <button type="button" class="btn btn-sm btn-outline-warning btn-edit-evidence" data-bs-toggle="modal" data-bs-target="#evidenceModal"
                                        data-id="<?php echo (int)$e['id']; ?>" data-case-id="<?php echo (int)$caseId; ?>" data-src="<?php echo htmlspecialchars($e['filepath']); ?>" data-title="<?php echo htmlspecialchars($e['title']); ?>" data-type="<?php echo htmlspecialchars($e['type'] ?? 'other'); ?>" data-mime="<?php echo htmlspecialchars($e['mime_type']); ?>" data-admin="1" data-url="1">
                                  Edit
                                </button>
                                <form method="post" action="" class="d-inline" onsubmit="return confirm('Delete this evidence permanently?');">
                                  <input type="hidden" name="action" value="delete_evidence">
                                  <?php csrf_field(); ?>
                                  <input type="hidden" name="evidence_id" value="<?php echo (int)$e['id']; ?>">
                                  <input type="hidden" name="case_id" value="<?php echo (int)$caseId; ?>">
                                  <input type="hidden" name="redirect_url" value="?admin_case=<?php echo urlencode($adminCaseCode); ?>#admin-case">
                                  <button type="submit" class="btn btn-sm btn-outline-danger">Delete</button>
                                </form>
                              </div>
                            <?php } else { ?>
                              <button type="button" class="btn btn-sm btn-outline-light btn-view-evidence"
                                      data-bs-toggle="modal" data-bs-target="#evidenceModal"
                                      data-id="<?php echo (int)$e['id']; ?>"
                                      data-case-id="<?php echo (int)$caseId; ?>"
                                      data-src="?action=serve_evidence&amp;id=<?php echo (int)$e['id']; ?>"
                                      data-title="<?php echo htmlspecialchars($e['title']); ?>"
                                      data-type="<?php echo htmlspecialchars($e['type'] ?? 'other'); ?>"
                                      data-mime="<?php echo htmlspecialchars($e['mime_type']); ?>">
                                View
                              </button>
                              <div class="btn-group ms-1">
                                <button type="button" class="btn btn-sm btn-outline-warning btn-edit-evidence" data-bs-toggle="modal" data-bs-target="#evidenceModal"
                                        data-id="<?php echo (int)$e['id']; ?>" data-case-id="<?php echo (int)$caseId; ?>" data-src="?action=serve_evidence&amp;id=<?php echo (int)$e['id']; ?>" data-title="<?php echo htmlspecialchars($e['title']); ?>" data-type="<?php echo htmlspecialchars($e['type'] ?? 'other'); ?>" data-mime="<?php echo htmlspecialchars($e['mime_type']); ?>" data-admin="1">
                                  Edit
                                </button>
                                <form method="post" action="" class="d-inline" onsubmit="return confirm('Delete this evidence permanently?');">
                                  <input type="hidden" name="action" value="delete_evidence">
                                  <?php csrf_field(); ?>
                                  <input type="hidden" name="evidence_id" value="<?php echo (int)$e['id']; ?>">
                                  <input type="hidden" name="case_id" value="<?php echo (int)$caseId; ?>">
                                  <input type="hidden" name="redirect_url" value="?admin_case=<?php echo urlencode($adminCaseCode); ?>#admin-case">
                                  <button type="submit" class="btn btn-sm btn-outline-danger">Delete</button>
                                </form>
                              </div>
                            <?php } ?>
                        <?php } ?>
                      </td>
                      <td class="small text-secondary"><?php echo htmlspecialchars($e['mime_type']); ?></td>
                      <td class="small text-secondary"><?php echo number_format((int)$e['size_bytes']); ?> B</td>
                      <td class="small text-secondary"><?php echo htmlspecialchars($e['created_at']); ?></td>
                    </tr>
                  <?php } } else { ?>
                    <tr><td colspan="6" class="text-secondary">No evidence uploaded yet.</td></tr>
                  <?php } ?>
                </tbody>
              </table>
            </div>
          </div>

          <!-- Photos -->
          <div class="tab-pane fade" id="photos-pane" role="tabpanel">
            <div class="row g-2">
              <?php if ($ev) { $hasImg=false; foreach ($ev as $e) { if ($e['type']==='image') { $hasImg=true; ?>
                <div class="col-6 col-md-4">
                  <div class="card h-100">
                    <img src="?action=serve_evidence&amp;id=<?php echo (int)$e['id']; ?>" class="card-img-top" alt="">
                    <div class="card-body p-2">
                      <div class="small text-truncate" title="<?php echo htmlspecialchars($e['title']); ?>"><?php echo htmlspecialchars($e['title']); ?></div>
                    </div>
                  </div>
                </div>
              <?php } } if(!$hasImg) { ?>
                <div class="col-12 text-secondary">No photos yet.</div>
              <?php } } ?>
            </div>
          </div>

          <!-- PDFs -->
          <div class="tab-pane fade" id="pdfs-pane" role="tabpanel">
            <ul class="list-group list-group-flush">
              <?php if ($ev) { $hasPdf=false; foreach ($ev as $e) { if ($e['type']==='pdf') { $hasPdf=true; ?>
                <li class="list-group-item bg-transparent text-white d-flex justify-content-between align-items-center">
                  <span><i class="bi bi-filetype-pdf me-2"></i><?php echo htmlspecialchars($e['title']); ?></span>
                  <a href="<?php echo htmlspecialchars($e['filepath']); ?>" target="_blank" class="btn btn-sm btn-outline-light">Open</a>
                </li>
              <?php } } if(!$hasPdf) { ?>
                <li class="list-group-item bg-transparent text-secondary">No PDFs yet.</li>
              <?php } } ?>
            </ul>
          </div>
        </div>
      </div>
    </div>
      <!-- Edit Case Modal (Admin) -->
      <div class="modal fade" id="editCaseModal" tabindex="-1" aria-hidden="true">
        <div class="modal-dialog modal-lg modal-dialog-centered">
          <div class="modal-content">
            <div class="modal-header">
              <h5 class="modal-title"><i class="bi bi-pencil-square me-2"></i>Edit Case Details</h5>
              <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
            </div>
            <div class="modal-body">
              <form method="post" action="" id="editCaseForm" enctype="multipart/form-data">
                <input type="hidden" name="action" value="update_case">
                <?php csrf_field(); ?>
                <input type="hidden" name="case_id" value="<?php echo (int)$caseId; ?>">
                <input type="hidden" name="case_code" value="<?php echo htmlspecialchars($adminCaseCode); ?>">
                <input type="hidden" name="redirect_url" value="?admin_case=<?php echo urlencode($adminCaseCode); ?>#admin-case">

                <div class="row g-2">
                  <div class="col-md-6">
                    <label class="form-label">Case Name</label>
                    <input type="text" name="case_name" class="form-control" value="<?php echo htmlspecialchars($caseRow['case_name'] ?? ''); ?>" required>
                  </div>
                  <div class="col-md-6">
                    <label class="form-label">TikTok Username</label>
                    <div class="input-group">
                      <span class="input-group-text">@</span>
                      <input type="text" name="tiktok_username" class="form-control" value="<?php echo htmlspecialchars($caseRow['tiktok_username'] ?? ''); ?>">
                    </div>
                  </div>
                </div>

                <div class="row g-2 mt-2">
                  <div class="col-md-6">
                    <label class="form-label">Person Name</label>
                    <input type="text" name="person_name" class="form-control" value="<?php echo htmlspecialchars($caseRow['person_name'] ?? ''); ?>">
                  </div>
                  <div class="col-md-3">
                    <label class="form-label">Sensitivity</label>
                    <select name="sensitivity" class="form-select" required>
                      <?php $sensOpts = ['Standard','Restricted','Sealed']; foreach ($sensOpts as $opt) { $sel = (($caseRow['sensitivity'] ?? '') === $opt) ? ' selected' : ''; echo '<option value="'.htmlspecialchars($opt).'"'.$sel.'>'.htmlspecialchars($opt)."</option>"; } ?>
                    </select>
                  </div>
                  <div class="col-md-3">
                    <label class="form-label">Status</label>
                    <select name="status" class="form-select" required>
                      <?php $statOpts = ['Open','In Review','Verified','Closed']; foreach ($statOpts as $opt) { $sel = (($caseRow['status'] ?? '') === $opt) ? ' selected' : ''; echo '<option value="'.htmlspecialchars($opt).'"'.$sel.'>'.htmlspecialchars($opt)."</option>"; } ?>
                    </select>
                  </div>
                </div>

                <div class="row g-2 mt-2">
                  <div class="col-md-6">
                    <label class="form-label">Update Person Photo</label>
                    <input type="file" name="person_photo" class="form-control" accept="image/*">
                    <small class="text-secondary">Leave blank to keep current</small>
                  </div>
                </div>

                <div class="mt-3">
                  <label class="form-label">Initial Summary</label>
                  <textarea name="initial_summary" class="form-control" rows="4" required><?php echo htmlspecialchars($caseRow['initial_summary'] ?? ''); ?></textarea>
                </div>
              </form>
            </div>
            <div class="modal-footer">
              <button class="btn btn-outline-light" data-bs-dismiss="modal">Cancel</button>
              <button class="btn btn-primary" type="submit" form="editCaseForm"><i class="bi bi-save me-1"></i> Save Changes</button>
            </div>
          </div>
        </div>
      </div>
    <?php } else { ?>
      <div class="alert alert-danger"><i class="bi bi-exclamation-octagon me-2"></i>Case not found or unavailable.</div>
    <?php } ?>
  </div>
</section>
<?php } ?>


  <!-- Admin Section (Mock) -->
  <?php if ($view === 'admin' && is_admin()): ?>
  <section class="py-5 border-top" id="admin">
    <div class="container-xl">
      <div class="row g-4">
        <div class="col-lg-6">
          <div class="card glass h-100">
            <div class="card-body">
              <div class="d-flex justify-content-between align-items-center mb-2">
                <h2 class="h6 mb-0">User Management</h2>
                <button class="btn btn-sm btn-primary"><i class="bi bi-person-plus me-1"></i> Invite</button>
              </div>
              <div class="table-responsive">
                <table class="table table-sm align-middle">
                  <thead><tr><th>User</th><th>Role</th><th>Status</th><th class="text-end">Actions</th></tr></thead>
                  <tbody>
                    <tr>
                      <td><img src="https://placehold.co/36x36" class="avatar me-2" alt="" /> Jane Doe</td>
                      <td><span class="badge rounded-pill badge-role">Analyst</span></td>
                      <td><span class="badge text-bg-success-subtle border">Active</span></td>
                      <td class="text-end"><button class="btn btn-outline-light btn-sm"><i class="bi bi-gear"></i></button></td>
                    </tr>
                    <tr>
                      <td><img src="https://placehold.co/36x36" class="avatar me-2" alt="" /> John Smith</td>
                      <td><span class="badge rounded-pill text-bg-secondary">Viewer</span></td>
                      <td><span class="badge text-bg-warning-subtle border">Pending</span></td>
                      <td class="text-end"><button class="btn btn-outline-light btn-sm"><i class="bi bi-gear"></i></button></td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </div>
        <div class="col-lg-6">
          <div class="card glass h-100">
            <div class="card-body">
              <h2 class="h6 mb-2">Retention & Legal Notices</h2>
              <div class="alert alert-warning small"><i class="bi bi-exclamation-triangle me-2"></i>All uploads must have explicit consent or lawful basis for processing. Sensitive data must be redacted prior to sharing outside the platform.</div>
              <div class="dropzone">
                <i class="bi bi-file-earmark-lock display-6 d-block"></i>
                <p class="mb-1">Drop updated policy PDFs here</p>
                <small class="text-secondary">Admins only • Versioning & checksum enforced</small>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </section>
  <?php endif; ?>



  <?php if ($view === 'users'): ?>
    <?php if (!is_admin()): ?>
      <section class="py-5 border-top" id="users">
        <div class="container-xl">
          <div class="alert alert-danger"><i class="bi bi-shield-lock me-2"></i>Unauthorized. Admins only.</div>
        </div>
      </section>
    <?php else: ?>
    <?php endif; ?>
  <?php endif; ?>

  <!-- Global Evidence Viewer / Editor Modal -->
  <div class="modal fade evidence-modal" id="evidenceModal" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog modal-xl modal-dialog-centered">
      <div class="modal-content">
        <div class="modal-header">
          <h5 class="modal-title"><i class="bi bi-file-earmark-text me-2"></i><span id="evModalTitle">Evidence</span></h5>
          <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
        </div>
        <div class="modal-body">
          <div class="row g-3">
            <div class="col-lg-8">
              <div id="evPreview" class="ratio ratio-16x9 bg-dark d-flex align-items-center justify-content-center rounded">
                <div class="text-secondary small">No preview available</div>
              </div>
              <div class="mt-2 small text-secondary"><span id="evSize">—</span></div>
            </div>
            <div class="col-lg-4">
              <?php if (is_admin()): ?>
              <div class="card glass">
                <div class="card-body">
                  <h6 class="mb-2">Edit Evidence</h6>
                  <form method="post" action="" id="evEditForm">
                    <input type="hidden" name="action" value="update_evidence">
                    <?php csrf_field(); ?>
                    <input type="hidden" name="evidence_id" id="evId">
                    <input type="hidden" name="case_id" id="evCaseId">
                    <div class="mb-2">
                      <label class="form-label">Title</label>
                      <input type="text" name="title" id="evTitle" class="form-control">
                    </div>
                    <div class="mb-2">
                      <label class="form-label">Type</label>
                      <select name="type" id="evType" class="form-select">
                        <option value="image">Image</option>
                        <option value="video">Video</option>
                        <option value="audio">Audio</option>
                        <option value="pdf">PDF</option>
                        <option value="doc">Document</option>
                        <option value="other">Other</option>
                      </select>
                    </div>
                    <div class="d-grid">
                      <button class="btn btn-primary" type="submit"><i class="bi bi-save me-1"></i> Save</button>
                    </div>
                  </form>
                </div>
              </div>
              <?php else: ?>
              
              <?php endif; ?>
            </div>
          </div>
        </div>
        <div class="modal-footer">
          <button class="btn btn-outline-light" data-bs-dismiss="modal">Close</button>
        </div>
      </div>
    </div>
  </div>

  <?php if (is_admin()): ?>
  <!-- Create Case Modal (Admin) -->
  <div class="modal fade" id="createCaseModal" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog modal-lg modal-dialog-centered">
      <div class="modal-content">
        <div class="modal-header">
          <h5 class="modal-title"><i class="bi bi-folder-plus me-2"></i>Create Case</h5>
          <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
        </div>
        <div class="modal-body">
          <form method="post" action="" id="createCaseForm" enctype="multipart/form-data">
            <input type="hidden" name="action" value="create_case">
            <?php csrf_field(); ?>
            <div class="row g-2">
              <div class="col-md-6">
                <label class="form-label">Case Name</label>
                <input type="text" name="case_name" class="form-control" placeholder="Case title" required>
              </div>
              <div class="col-md-6">
                <label class="form-label">Person Name</label>
                <input type="text" name="person_name" class="form-control" placeholder="Optional">
              </div>
            </div>
            <div class="row g-2 mt-2">
              <div class="col-md-6">
                <label class="form-label">TikTok Username</label>
                <div class="input-group">
                  <span class="input-group-text">@</span>
                  <input type="text" name="tiktok_username" class="form-control" placeholder="username (no @)">
                </div>
              </div>
              <div class="col-md-3">
                <label class="form-label">Sensitivity</label>
                <select name="sensitivity" class="form-select" required>
                  <option value="Standard" selected>Standard</option>
                  <option value="Restricted">Restricted</option>
                  <option value="Sealed">Sealed</option>
                </select>
              </div>
              <div class="col-md-3">
                <label class="form-label">Status</label>
                <select name="status" class="form-select" required>
                  <option value="Open" selected>Open</option>
                  <option value="In Review">In Review</option>
                  <option value="Verified">Verified</option>
                  <option value="Closed">Closed</option>
                </select>
              </div>
            </div>
            <div class="row g-2 mt-2">
              <div class="col-md-6">
                <label class="form-label">Person Photo (optional)</label>
                <input type="file" name="person_photo" class="form-control" accept="image/*">
                <small class="text-secondary">JPEG, PNG, or WEBP</small>
              </div>
            </div>
            <div class="mt-3">
              <label class="form-label">Initial Summary</label>
              <textarea name="initial_summary" class="form-control" rows="4" placeholder="Short summary of allegations and current state…" required></textarea>
            </div>
          </form>
        </div>
        <div class="modal-footer">
          <button class="btn btn-outline-light" data-bs-dismiss="modal">Cancel</button>
          <button class="btn btn-primary" type="submit" form="createCaseForm"><i class="bi bi-save2 me-1"></i> Create Case</button>
        </div>
      </div>
    </div>
  </div>
  <?php endif; ?>

  <!-- Auth Modal -->
  <div class="modal fade" id="authModal" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered">
      <div class="modal-content">
        <div class="modal-header">
          <h5 class="modal-title"><i class="bi bi-shield-lock me-2"></i>Account</h5>
          <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
        </div>
        <div class="modal-body">
          <ul class="nav nav-tabs" id="authTabs" role="tablist">
            <li class="nav-item" role="presentation">
              <button class="nav-link <?php echo ($openAuth==='login')?'active':''; ?>" data-bs-toggle="tab" data-bs-target="#login-pane" type="button" role="tab">Login</button>
            </li>
            <li class="nav-item" role="presentation">
              <button class="nav-link <?php echo ($openAuth==='register')?'active':''; ?>" data-bs-toggle="tab" data-bs-target="#register-pane" type="button" role="tab">Register</button>
            </li>
          </ul>
          <div class="tab-content pt-3">
            <!-- Login Pane -->
            <div class="tab-pane fade <?php echo ($openAuth==='login')?'show active':''; ?>" id="login-pane" role="tabpanel">
              <form method="post" action="">
                <input type="hidden" name="action" value="login">
                <?php csrf_field(); ?>
                <div class="mb-2">
                  <label class="form-label">Email</label>
                  <input type="email" name="email" class="form-control" placeholder="you@example.com" required>
                </div>
                <div class="mb-2">
                  <label class="form-label">Password</label>
                  <input type="password" name="password" class="form-control" minlength="8" required>
                </div>
                <div class="d-grid">
                  <button class="btn btn-primary" type="submit"><i class="bi bi-box-arrow-in-right me-1"></i> Login</button>
                </div>
              </form>
            </div>
            <!-- Register Pane -->
            <div class="tab-pane fade <?php echo ($openAuth==='register')?'show active':''; ?>" id="register-pane" role="tabpanel">
              <form method="post" action="">
                <input type="hidden" name="action" value="register">
                <?php csrf_field(); ?>
                <div class="mb-2">
                  <label class="form-label">Email</label>
                  <input type="email" name="email" class="form-control" placeholder="you@example.com" required>
                </div>
                <div class="mb-2">
                  <label class="form-label">Display Name</label>
                  <input type="text" name="display_name" class="form-control" placeholder="Your name" required>
                </div>
                <div class="mb-2">
                  <label class="form-label">Password</label>
                  <input type="password" name="password" class="form-control" minlength="8" required>
                </div>
                <div class="mb-3">
                  <label class="form-label">Confirm Password</label>
                  <input type="password" name="password_confirm" class="form-control" minlength="8" required>
                </div>
                <div class="form-check mb-3">
                  <input class="form-check-input" type="checkbox" name="agree" id="agreeTerms" required>
                  <label class="form-check-label small" for="agreeTerms">I agree to the terms and privacy policy.</label>
                </div>
                <div class="d-grid">
                  <button class="btn btn-success" type="submit"><i class="bi bi-person-plus me-1"></i> Create Account</button>
                </div>
              </form>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
  
  <!-- Bootstrap JS Bundle -->
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
  <script>
  document.addEventListener('DOMContentLoaded', function () {
    // Evidence modal dynamic preview + admin edit wiring
    (function () {
      var evModal = document.getElementById('evidenceModal');
      if (!evModal) return;
  
      evModal.addEventListener('show.bs.modal', function (event) {
        var btn = event.relatedTarget;
        if (!btn) return;
        var src = btn.getAttribute('data-src') || '';
        var title = btn.getAttribute('data-title') || '';
        var mime = btn.getAttribute('data-mime') || '';
        var type = btn.getAttribute('data-type') || '';
        var id = btn.getAttribute('data-id') || '';
        var caseId = btn.getAttribute('data-case-id') || '';
  
        // Fallbacks
        if (!type && mime.indexOf('/') > -1) type = mime.split('/')[0];
        if (!title || title.trim() === '') {
          // Derive from filename as last resort
          try { title = src.split('/').pop(); } catch (e) { title = 'Evidence'; }
        }
  
        // Set header fields
        var titleEl = document.getElementById('evModalTitle');
        if (titleEl) titleEl.textContent = title;
        var sizeEl = document.getElementById('evSize');
        if (sizeEl) sizeEl.textContent = '';
  
        // Render preview
        var preview = document.getElementById('evPreview');
        if (preview) {
          preview.classList.add('ratio','ratio-16x9');
          preview.innerHTML = '';
          var safeSrc = src;
          if (type === 'image' || (mime.indexOf('image/') === 0)) {
            preview.classList.remove('ratio','ratio-16x9');
            var img = document.createElement('img');
            img.src = safeSrc;
            img.alt = title;
            img.className = 'img-fluid rounded';
            preview.appendChild(img);
          } else if (type === 'video' || mime.indexOf('video/') === 0) {
            preview.innerHTML = '<video controls class="w-100 h-100"><source src="'+safeSrc+'" type="'+mime+'"></video>';
          } else if (type === 'audio' || mime.indexOf('audio/') === 0) {
            preview.classList.remove('ratio','ratio-16x9');
            preview.innerHTML = '<audio controls class="w-100"><source src="'+safeSrc+'" type="'+mime+'"></audio>';
          } else if (type === 'pdf' || mime === 'application/pdf') {
            preview.innerHTML = '<iframe src="'+safeSrc+'" class="w-100 h-100 rounded" loading="lazy"></iframe>';
          } else {
            preview.innerHTML = '<iframe src="'+safeSrc+'" class="w-100 h-100 rounded" loading="lazy"></iframe>';
          }
        }
  
        // Admin edit fields (if present)
        var evId = document.getElementById('evId');
        var evCaseId = document.getElementById('evCaseId');
        var evTitle = document.getElementById('evTitle');
        var evType = document.getElementById('evType');
        if (evId && evCaseId && evTitle && evType) {
          evId.value = id;
          evCaseId.value = caseId;
          evTitle.value = title;
          if (evType.querySelector('option[value="'+type+'"]')) {
            evType.value = type;
          }
        }
      });
  
      evModal.addEventListener('hidden.bs.modal', function () {
        var preview = document.getElementById('evPreview');
        if (preview) {
          preview.innerHTML = '<div class="text-secondary small">No preview available</div>';
          preview.classList.add('ratio','ratio-16x9');
        }
      });
    })();
  
    // Auth modal tab behavior based on triggers and server-side preference
    (function () {
      var authModalEl = document.getElementById('authModal');
      if (!authModalEl) return;
      authModalEl.addEventListener('show.bs.modal', function (event) {
        var trigger = event.relatedTarget;
        var preferred = trigger && trigger.getAttribute('data-auth-tab') ? trigger.getAttribute('data-auth-tab') : 'login';
        var btn = document.querySelector('#authModal [data-bs-target="#' + (preferred === 'register' ? 'register-pane' : 'login-pane') + '"]');
        if (btn) { new bootstrap.Tab(btn).show(); }
      });
      var openPref = <?php echo json_encode($openAuth); ?>;
      if (openPref === 'login' || openPref === 'register') {
        var modal = new bootstrap.Modal(authModalEl);
        modal.show();
        var btn = document.querySelector('#authModal [data-bs-target="#' + (openPref === 'register' ? 'register-pane' : 'login-pane') + '"]');
        if (btn) { new bootstrap.Tab(btn).show(); }
      }
    })();
  
    // Theme toggle
    (function () {
      var themeToggle = document.getElementById('themeToggle');
      if (!themeToggle) return;
      themeToggle.addEventListener('click', function () {
        var html = document.documentElement;
        var current = html.getAttribute('data-bs-theme') || 'dark';
        html.setAttribute('data-bs-theme', current === 'dark' ? 'light' : 'dark');
      });
    })();
  });
  </script>

  <script>
document.addEventListener('click', function (ev) {
  var btn = ev.target.closest('.btn-view-note');
  if (!btn) return;
  var src = btn.getAttribute('data-src') || '';
  var title = btn.getAttribute('data-title') || 'Note';
  var contentEl = document.getElementById('noteModalContent');
  var titleEl = document.getElementById('noteModalTitle');
  var rawEl = document.getElementById('noteModalOpenRaw');
  if (contentEl) contentEl.textContent = 'Loading…';
  if (titleEl) titleEl.textContent = title;
  if (rawEl) rawEl.href = src;

  if (src) {
    fetch(src, { credentials: 'same-origin' })
      .then(function (r) { return r.ok ? r.text() : Promise.reject(new Error('Unable to load note')); })
      .then(function (txt) { if (contentEl) contentEl.textContent = txt; })
      .catch(function () { if (contentEl) contentEl.textContent = 'Unable to load note.'; });
  } else {
    if (contentEl) contentEl.textContent = 'No note source found.';
  }
}, false);
</script>

  <div class="modal fade" id="noteModal" tabindex="-1" aria-hidden="true">
  <div class="modal-dialog modal-lg modal-dialog-centered">
    <div class="modal-content">
      <div class="modal-header">
        <h5 class="modal-title"><i class="bi bi-journal-text me-2"></i><span id="noteModalTitle">Note</span></h5>
        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
      </div>
      <div class="modal-body">
        <div class="border rounded p-3 bg-body-tertiary" style="max-height:60vh;overflow:auto;">
          <pre class="mb-0" id="noteModalContent" style="white-space:pre-wrap;word-wrap:break-word;"></pre>
        </div>
        <div class="mt-2 small">
          <a id="noteModalOpenRaw" href="#" target="_blank" rel="noopener">Open raw file</a>
        </div>
      </div>
      <div class="modal-footer">
        <button class="btn btn-outline-light" data-bs-dismiss="modal">Close</button>
      </div>
    </div>
  </div>
</div>
  </body>
  </html>