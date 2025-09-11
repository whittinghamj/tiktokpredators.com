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
$GLOBALS['storagePath'] = '/var/www/html/tiktokpredators.com/uploads/';

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
        header('Location: ?admin_case=' . urlencode($case_code) . '#admin-case'); exit;
    }
    if (!in_array($sensitivity, $allowed_sensitivity, true)) { $sensitivity = 'Standard'; }
    if (!in_array($status, $allowed_status, true)) { $status = 'Open'; }

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
    header('Location: ?admin_case=' . urlencode($case_code) . '#admin-case'); exit;
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

// Handle evidence upload (admin only)
if (($_POST['action'] ?? '') === 'upload_evidence') {
    throttle();
    if (!check_csrf()) { flash('error', 'Security check failed.'); header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit; }
    if (empty($_SESSION['user']) || (($_SESSION['user']['role'] ?? '') !== 'admin')) { flash('error', 'Unauthorized.'); header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit; }

    $case_id = (int)($_POST['case_id'] ?? 0);
    $redir_code = trim($_POST['case_code'] ?? '');
    $title = trim($_POST['title'] ?? '');
    $type = $_POST['type'] ?? 'other';
    $allowedTypes = ['image','video','audio','pdf','doc','other'];
    if (!in_array($type, $allowedTypes, true)) $type = 'other';

    if ($case_id <= 0 || empty($_FILES['evidence_file']['name'])) {
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
            $GLOBALS['storagePath'],
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
    $allowedTypes = ['image','video','audio','pdf','doc','other'];
    if (!in_array($type, $allowedTypes, true)) $type = 'other';

    if ($evidence_id <= 0 || $case_id <= 0) { flash('error', 'Invalid evidence.'); $ru = trim($_POST['redirect_url'] ?? ''); if ($ru!==''){header('Location: '.$ru); exit;} header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit; }

    try {
        $u = $pdo->prepare('UPDATE evidence SET title = ?, type = ? WHERE id = ? AND case_id = ? LIMIT 1');
        $u->execute([$title, $type, $evidence_id, $case_id]);
        flash('success', 'Evidence updated.');
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
  <li class="nav-item"><a class="nav-link <?php echo ($view==='add')?'active':''; ?>" href="?view=add#add">Add Content</a></li>
  <li class="nav-item"><a class="nav-link <?php echo ($view==='users')?'active':''; ?>" href="?view=users#users">Users</a></li>
  <li class="nav-item"><a class="nav-link <?php echo ($view==='admin')?'active':''; ?>" href="?view=admin#admin">Admin</a></li>
<?php endif; ?>
        </ul>
        <div class="d-flex align-items-center gap-2">
          <!-- Theme toggle + auth state -->
          <button id="themeToggle" class="btn btn-outline-light btn-sm" title="Toggle theme"><i class="bi bi-moon-stars"></i></button>
          <?php if (empty($_SESSION['user'])): ?>
            <button class="btn btn-outline-light btn-sm" data-bs-toggle="modal" data-bs-target="#authModal" data-auth-tab="register"><i class="bi bi-person-plus me-1"></i> Register</button>
            <button class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#authModal" data-auth-tab="login"><i class="bi bi-box-arrow-in-right me-1"></i> Login</button>
          <?php else: ?>
            <?php if (is_admin()): ?>
              <a class="btn btn-success btn-sm" href="?view=add#add"><i class="bi bi-cloud-plus me-1"></i> Add</a>
            <?php endif; ?>
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
        <div class="col-lg-8 case-grid">
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
?>
  <div class="col">
    <div class="card h-100">
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

        <!-- Right Rail: Case Detail / Audit -->
        <div class="col-lg-4">
          <div class="card glass">
            <div class="card-body">
              <div class="d-flex align-items-center justify-content-between">
                <h2 class="h6 mb-0">Case Snapshot</h2>
                <button class="btn btn-sm btn-outline-light"><i class="bi bi-pencil"></i></button>
              </div>
              <div class="mt-3">
                <div class="d-flex align-items-center gap-2 mb-2">
                  <img src="https://placehold.co/72x72" alt="Subject avatar" class="rounded" width="48" height="48" />
                  <div>
                    <div class="fw-semibold">@example_user123</div>
                    <div class="small text-secondary">TikTok Subject</div>
                  </div>
                </div>
                <div class="row g-2 small">
                  <div class="col-6"><span class="text-secondary">Case ID</span><div>CASE-2025-0001</div></div>
                  <div class="col-6"><span class="text-secondary">Status</span><div><span class="badge text-bg-warning-subtle border">In Review</span></div></div>
                  <div class="col-6"><span class="text-secondary">Opened</span><div>09 Sep 2025</div></div>
                  <div class="col-6"><span class="text-secondary">Custodian</span><div>J. Doe</div></div>
                  <div class="col-12 mt-2"><span class="text-secondary">Summary</span>
                    <p class="mb-2">Alleged inappropriate DM exchanges. Evidence includes screenshots, screen recordings, and exported chat logs. Pending metadata verification.</p>
                  </div>
                </div>
              </div>
              <hr />
              <div>
                <div class="d-flex align-items-center justify-content-between mb-2">
                  <h3 class="h6 mb-0">Chain of Custody</h3>
                  <button class="btn btn-sm btn-outline-success"><i class="bi bi-plus-lg"></i></button>
                </div>
                <div class="timeline small">
                  <div class="item">
                    <div class="fw-semibold">Evidence imported</div>
                    <div class="text-secondary">by Jane • 09 Sep 2025 10:14</div>
                  </div>
                  <div class="item">
                    <div class="fw-semibold">Hash verified (SHA-256)</div>
                    <div class="text-secondary">by System • 09 Sep 2025 10:15</div>
                  </div>
                  <div class="item">
                    <div class="fw-semibold">Access granted to analyst team</div>
                    <div class="text-secondary">by Admin • 09 Sep 2025 10:20</div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div class="card mt-3 glass">
            <div class="card-body">
              <div class="d-flex justify-content-between align-items-center mb-2">
                <h3 class="h6 mb-0">Audit Log</h3>
                <button class="btn btn-sm btn-outline-light"><i class="bi bi-arrow-clockwise"></i></button>
              </div>
              <ul class="list-group list-group-flush audit-list">
                <li class="list-group-item bg-transparent text-white small"><i class="bi bi-key me-2"></i>Login success • <span class="text-secondary">10:35</span></li>
                <li class="list-group-item bg-transparent text-white small"><i class="bi bi-eye me-2"></i>Viewed case CASE-2025-0001 • <span class="text-secondary">10:36</span></li>
                <li class="list-group-item bg-transparent text-white small"><i class="bi bi-cloud-arrow-up me-2"></i>Uploaded file clip_12.mp4 • <span class="text-secondary">10:40</span></li>
                <li class="list-group-item bg-transparent text-white small"><i class="bi bi-shield-check me-2"></i>Checksum verified • <span class="text-secondary">10:41</span></li>
                <li class="list-group-item bg-transparent text-white small"><i class="bi bi-pen me-2"></i>Updated status to In Review • <span class="text-secondary">10:45</span></li>
              </ul>
            </div>
          </div>
        </div>
      </div>
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
                <input type="hidden" name="action" value="add_case_note">
                <?php csrf_field(); ?>
                <input type="hidden" name="case_id" value="<?php echo (int)$viewCaseId; ?>">
                <input type="hidden" name="case_code" value="<?php echo htmlspecialchars($caseCode); ?>">
                <input type="hidden" name="redirect_url" value="?view=case&amp;code=<?php echo urlencode($caseCode); ?>#case-view">
                <label class="form-label">Note Text</label>
                <textarea name="note_text" class="form-control" rows="4" placeholder="Write a concise internal note..." required></textarea>
              </form>
            </div>
          </div>
        </div>
        <div class="modal-footer">
          <button class="btn btn-outline-light" data-bs-dismiss="modal">Close</button>
          <button class="btn btn-primary" type="submit" form="evUploadForm"><i class="bi bi-cloud-arrow-up me-1"></i> Save Upload</button>
          <button class="btn btn-success" type="submit" form="evNoteForm"><i class="bi bi-journal-plus me-1"></i> Save Note</button>
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
                      <thead><tr><th>Type</th><th>Title</th><th>File</th><th class="d-none d-md-table-cell">MIME</th><th class="d-none d-md-table-cell">Size</th><th>Added</th></tr></thead>
                      <tbody>
                        <?php if ($viewEv) { foreach ($viewEv as $e) { ?>
                          <tr>
                            <td><?php echo htmlspecialchars($e['type']); ?></td>
                            <td><?php echo htmlspecialchars($e['title']); ?></td>
                            <td>
                              <button type="button" class="btn btn-sm btn-outline-light btn-view-evidence"
                                      data-bs-toggle="modal" data-bs-target="#evidenceModal"
                                      data-id="<?php echo (int)$e['id']; ?>"
                                      data-case-id="<?php echo (int)$viewCaseId; ?>"
                                      data-src="<?php echo htmlspecialchars($e['filepath']); ?>"
                                      data-title="<?php echo htmlspecialchars($e['title']); ?>"
                                      data-type="<?php echo htmlspecialchars($e['type'] ?? 'other'); ?>"
                                      data-mime="<?php echo htmlspecialchars($e['mime_type']); ?>">
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
                            </td>
                            <td class="small text-secondary d-none d-md-table-cell"><?php echo htmlspecialchars($e['mime_type']); ?></td>
                            <td class="small text-secondary d-none d-md-table-cell"><?php echo number_format((int)$e['size_bytes']); ?> B</td>
                            <td class="small text-secondary"><?php echo htmlspecialchars($e['created_at']); ?></td>
                          </tr>
                        <?php } } else { ?>
                          <tr><td colspan="6" class="text-secondary">No evidence available.</td></tr>
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
          <form method="post" action="" id="editCaseFormView">
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

            <div class="table-responsive">
              <table class="table table-sm align-middle">
                <thead><tr><th>Type</th><th>Title</th><th>File</th><th>MIME</th><th>Size</th><th>Added</th></tr></thead>
                <tbody>
                  <?php if ($ev) { foreach ($ev as $e) { ?>
                    <tr>
                      <td><?php echo htmlspecialchars($e['type']); ?></td>
                      <td><?php echo htmlspecialchars($e['title']); ?></td>
                      <td>
                        <button type="button" class="btn btn-sm btn-outline-light btn-view-evidence"
                                data-bs-toggle="modal" data-bs-target="#evidenceModal"
                                data-id="<?php echo (int)$e['id']; ?>"
                                data-case-id="<?php echo (int)$caseId; ?>"
                                data-src="<?php echo htmlspecialchars($e['filepath']); ?>"
                                data-title="<?php echo htmlspecialchars($e['title']); ?>"
                                data-type="<?php echo htmlspecialchars($e['type'] ?? 'other'); ?>"
                                data-mime="<?php echo htmlspecialchars($e['mime_type']); ?>">
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
                    <img src="<?php echo htmlspecialchars($e['filepath']); ?>" class="card-img-top" alt="">
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
              <form method="post" action="" id="editCaseForm">
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

  <?php if ($view === 'add'): ?>
    <?php if (!is_admin()): ?>
      <section class="py-5 border-top" id="add">
        <div class="container-xl">
          <div class="alert alert-danger"><i class="bi bi-shield-lock me-2"></i>Unauthorized. Admins only.</div>
        </div>
      </section>
    <?php else: ?>
      <section class="py-5 border-top" id="add">
        <div class="container-xl">
          <div class="d-flex align-items-center justify-content-between mb-3">
            <h2 class="h4 mb-0">Add Content / Upload Evidence</h2>
            <a class="btn btn-outline-light btn-sm" href="?view=cases#cases"><i class="bi bi-grid-1x2 me-1"></i> Back to Cases</a>
          </div>
          <div class="card glass">
            <div class="card-body">
              <form class="mb-3" method="post" action="" enctype="multipart/form-data">
                <input type="hidden" name="action" value="upload_evidence">
                <?php csrf_field(); ?>
                <div class="row g-2 align-items-end">
                  <div class="col-md-3">
                    <label class="form-label">Case ID (numeric)</label>
                    <input type="number" name="case_id" class="form-control" placeholder="e.g., 123" required>
                  </div>
                  <div class="col-md-3">
                    <label class="form-label">Case Code</label>
                    <input type="text" name="case_code" class="form-control" placeholder="e.g., CASE-2025-AB12CD34" required>
                  </div>
                  <div class="col-md-3">
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
                      <option value="other" selected>Other</option>
                    </select>
                  </div>
                  <div class="col-12">
                    <label class="form-label">File</label>
                    <input type="file" name="evidence_file" class="form-control" required>
                  </div>
                </div>
                <div class="text-end mt-3"><button class="btn btn-primary" type="submit"><i class="bi bi-cloud-arrow-up me-1"></i> Upload</button></div>
              </form>
            </div>
          </div>
        </div>
      </section>
    <?php endif; ?>
  <?php endif; ?>

  <?php if ($view === 'users'): ?>
    <?php if (!is_admin()): ?>
      <section class="py-5 border-top" id="users">
        <div class="container-xl">
          <div class="alert alert-danger"><i class="bi bi-shield-lock me-2"></i>Unauthorized. Admins only.</div>
        </div>
      </section>
    <?php else: ?>
      <section class="py-5 border-top" id="users">
        <div class="container-xl">
          <div class="row g-4">
            <div class="col-lg-8">
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
</file>
  <!-- Evidence Viewer Modal (shared for all roles) -->
  <div class="modal fade" id="evidenceModal" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog modal-xl modal-dialog-centered">
      <div class="modal-content">
        <div class="modal-header">
          <h5 class="modal-title"><i class="bi bi-eye me-2"></i><span id="evModalTitle">View Evidence</span></h5>
          <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
        </div>
        <div class="modal-body">
          <div id="evPreview" class="ratio ratio-16x9 border rounded d-flex align-items-center justify-content-center bg-body-tertiary">
            <div class="text-secondary">Loading preview…</div>
          </div>

          <!-- Admin-only edit form (shown only when opened via .btn-edit-evidence) -->
          <form class="mt-3 d-none" id="evEditForm" method="post" action="">
            <input type="hidden" name="action" value="update_evidence">
            <?php csrf_field(); ?>
            <input type="hidden" name="evidence_id" id="evEditEvidenceId" value="">
            <input type="hidden" name="case_id" id="evEditCaseId" value="">
            <input type="hidden" name="redirect_url" id="evEditRedirectUrl" value="">
            <div class="row g-2 align-items-end">
              <div class="col-md-6">
                <label class="form-label">Title</label>
                <input type="text" class="form-control" name="title" id="evEditTitle" value="">
              </div>
              <div class="col-md-3">
                <label class="form-label">Type</label>
                <select class="form-select" name="type" id="evEditType">
                  <option value="image">Image</option>
                  <option value="video">Video</option>
                  <option value="audio">Audio</option>
                  <option value="pdf">PDF</option>
                  <option value="doc">Document</option>
                  <option value="other">Other</option>
                </select>
              </div>
              <div class="col-md-3 text-end">
                <button type="submit" class="btn btn-primary"><i class="bi bi-save me-1"></i>Save Changes</button>
              </div>
            </div>
          </form>
        </div>
        <div class="modal-footer">
          <button class="btn btn-outline-light" data-bs-dismiss="modal">Close</button>
        </div>
      </div>
    </div>
  </div>

  <!-- Scripts: Bootstrap and modal logic -->
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
  <script>
    (function(){
      function renderPreview(src, mime, type){
        const wrap = document.getElementById('evPreview');
        if(!wrap) return;
        const safeSrc = src;
        let html = '';
        const m = (mime || '').toLowerCase();
        const t = (type || '').toLowerCase();
        if(m.startsWith('image/') || t === 'image'){
          html = '<img src="'+safeSrc+'" alt="evidence" class="w-100 h-100 object-fit-contain">';
        } else if(m === 'application/pdf' || t === 'pdf'){
          html = '<iframe src="'+safeSrc+'#toolbar=0" class="w-100 h-100" title="PDF"></iframe>';
        } else if(m.startsWith('video/') || t === 'video'){
          html = '<video controls class="w-100 h-100"><source src="'+safeSrc+'" type="'+(m||'video/mp4')+'">Your browser does not support the video tag.</video>';
        } else if(m.startsWith('audio/') || t === 'audio'){
          html = '<audio controls class="w-100"><source src="'+safeSrc+'" type="'+(m||'audio/mpeg')+'">Your browser does not support the audio element.</audio>';
        } else {
          html = '<iframe src="'+safeSrc+'" class="w-100 h-100" title="Preview"></iframe>';
        }
        wrap.innerHTML = html;
      }

      function openForView(btn){
        const title = btn.getAttribute('data-title') || 'View Evidence';
        const src   = btn.getAttribute('data-src') || '';
        const mime  = btn.getAttribute('data-mime') || '';
        const type  = btn.getAttribute('data-type') || '';
        document.getElementById('evModalTitle').textContent = title;
        renderPreview(src, mime, type);
        // ensure edit form hidden for viewers
        document.getElementById('evEditForm').classList.add('d-none');
      }

      function openForEdit(btn){
        const title = btn.getAttribute('data-title') || 'Edit Evidence';
        const src   = btn.getAttribute('data-src') || '';
        const mime  = btn.getAttribute('data-mime') || '';
        const type  = btn.getAttribute('data-type') || '';
        const evid  = btn.getAttribute('data-id') || '';
        const caseId= btn.getAttribute('data-case-id') || '';
        document.getElementById('evModalTitle').textContent = title + ' (Edit)';
        renderPreview(src, mime, type);
        // populate admin form
        const f = document.getElementById('evEditForm');
        f.classList.remove('d-none');
        document.getElementById('evEditEvidenceId').value = evid;
        document.getElementById('evEditCaseId').value = caseId;
        document.getElementById('evEditTitle').value = btn.getAttribute('data-title') || '';
        document.getElementById('evEditType').value = (type || 'other');
        document.getElementById('evEditRedirectUrl').value = window.location.pathname + window.location.search + (window.location.hash || '');
      }

      document.addEventListener('click', function(e){
        const t = e.target.closest('.btn-view-evidence');
        if(t){ openForView(t); }
        const te = e.target.closest('.btn-edit-evidence');
        if(te){ openForEdit(te); }
      }, true);

      // Clear preview when modal hides
      document.addEventListener('hidden.bs.modal', function(evt){
        if(evt.target && evt.target.id === 'evidenceModal'){
          const wrap = document.getElementById('evPreview');
          if(wrap) wrap.innerHTML = '<div class="text-secondary">Loading preview…</div>';
          const f = document.getElementById('evEditForm');
          if(f) f.classList.add('d-none');
        }
      });
    })();
  </script>
</body>