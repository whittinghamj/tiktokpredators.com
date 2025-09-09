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
function throttle(){
    $now = time();
    if ($now - ($_SESSION['auth_last'] ?? 0) < 3) { sleep(1); }
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
        $stmt = $pdo->prepare('SELECT id, email, password_hash, role FROM users WHERE email = ? AND is_active = 1');
        $stmt->execute([$email]);
        $user = $stmt->fetch();
        if ($user && password_verify($password, $user['password_hash'])) {
            session_regenerate_id(true);
            $_SESSION['user'] = [ 'id'=>$user['id'], 'email'=>$user['email'], 'role'=>$user['role'] ];
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
  <!-- Top Navbar -->
  <nav class="navbar navbar-expand-lg border-bottom sticky-top bg-body glass">
    <div class="container-xl">
      <a class="navbar-brand fw-bold" href="#"><i class="bi bi-shield-lock me-2 text-primary"></i> TikTok<span>Predators</span></a>
      <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#topNav"><span class="navbar-toggler-icon"></span></button>
      <div class="collapse navbar-collapse" id="topNav">
        <ul class="navbar-nav me-auto mb-2 mb-lg-0">
          <li class="nav-item"><a class="nav-link active" href="#">Dashboard</a></li>
          <li class="nav-item"><a class="nav-link" href="#cases">Cases</a></li>
          <li class="nav-item"><a class="nav-link" href="#evidence">Evidence</a></li>
          <li class="nav-item"><a class="nav-link" href="#reports">Reports</a></li>
          <li class="nav-item"><a class="nav-link" href="#admin">Admin</a></li>
        </ul>
        <div class="d-flex align-items-center gap-2">
          <!-- Theme toggle + auth state -->
          <button id="themeToggle" class="btn btn-outline-light btn-sm" title="Toggle theme"><i class="bi bi-moon-stars"></i></button>
          <?php if (empty($_SESSION['user'])): ?>
            <button class="btn btn-outline-light btn-sm" data-bs-toggle="modal" data-bs-target="#authModal" data-auth-tab="register"><i class="bi bi-person-plus me-1"></i> Register</button>
            <button class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#authModal" data-auth-tab="login"><i class="bi bi-box-arrow-in-right me-1"></i> Login</button>
          <?php else: ?>
            <div class="dropdown">
              <button class="btn btn-outline-light btn-sm dropdown-toggle" data-bs-toggle="dropdown" aria-expanded="false">
                <i class="bi bi-person-check me-1"></i> <?php echo htmlspecialchars($_SESSION['user']['email']); ?>
              </button>
              <ul class="dropdown-menu dropdown-menu-end">
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

  <!-- Hero / Search -->
  <header class="hero border-bottom py-5">
    <div class="container-xl">
      <div class="row g-4 align-items-center">
        <div class="col-lg-7">
          <h1 class="display-5 fw-bold">Manage Cases & Evidence with Security, Legality & Auditability</h1>
          <p class="lead text-secondary">A privacy-first workspace for vetted teams to collect, preserve, and review case materials related to alleged predatory activity on TikTok.</p>
          <div class="input-group input-group-lg mt-4">
            <span class="input-group-text"><i class="bi bi-search"></i></span>
            <input type="search" class="form-control" placeholder="Search cases by ID, subject, keyword, tag…" aria-label="Search cases">
            <button class="btn btn-primary"><i class="bi bi-filter me-1"></i> Filters</button>
          </div>
          <div class="mt-3 d-flex gap-2 flex-wrap">
            <span class="badge text-bg-dark border"><i class="bi bi-hash me-1"></i> grooming</span>
            <span class="badge text-bg-dark border"><i class="bi bi-hash me-1"></i> messages</span>
            <span class="badge text-bg-dark border"><i class="bi bi-hash me-1"></i> screenshots</span>
            <span class="badge text-bg-dark border"><i class="bi bi-hash me-1"></i> escalation</span>
          </div>
        </div>
        <div class="col-lg-5">
          <!-- Mockup: dashboard preview tile -->
          <div class="placeholder-tile shadow-sm">
            <div class="text">
              <div class="text-center">
                <i class="bi bi-grid-1x2 display-5 d-block"></i>
                <span class="small">Dashboard Preview</span>
              </div>
            </div>
          </div>
          <div class="row g-2 mt-2">
            <div class="col-6"><div class="placeholder-tile"><div class="text"><span>Case Card</span></div></div></div>
            <div class="col-6"><div class="placeholder-tile"><div class="text"><span>Media Tile</span></div></div></div>
          </div>
        </div>
      </div>
    </div>
  </header>

  <!-- KPI Cards -->
  <section class="py-4">
    <div class="container-xl">
      <div class="row g-3 row-cols-2 row-cols-md-4">
        <div class="col">
          <div class="card h-100 glass">
            <div class="card-body">
              <div class="d-flex justify-content-between align-items-center">
                <div>
                  <div class="text-secondary small">Open Cases</div>
                  <div class="h3 mb-0">42</div>
                </div>
                <i class="bi bi-folder2-open fs-3 text-primary"></i>
              </div>
            </div>
          </div>
        </div>
        <div class="col">
          <div class="card h-100 glass">
            <div class="card-body">
              <div class="d-flex justify-content-between align-items-center">
                <div>
                  <div class="text-secondary small">Items in Review</div>
                  <div class="h3 mb-0">118</div>
                </div>
                <i class="bi bi-eye fs-3"></i>
              </div>
            </div>
          </div>
        </div>
        <div class="col">
          <div class="card h-100 glass">
            <div class="card-body">
              <div class="d-flex justify-content-between align-items-center">
                <div>
                  <div class="text-secondary small">Flagged</div>
                  <div class="h3 mb-0">9</div>
                </div>
                <i class="bi bi-flag fs-3 text-danger"></i>
              </div>
            </div>
          </div>
        </div>
        <div class="col">
          <div class="card h-100 glass">
            <div class="card-body">
              <div class="d-flex justify-content-between align-items-center">
                <div>
                  <div class="text-secondary small">Chain-of-Custody OK</div>
                  <div class="h3 mb-0">99.2%</div>
                </div>
                <i class="bi bi-shield-check fs-3 text-success"></i>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </section>

  <!-- Cases Grid + Right Rail -->
  <main class="py-4" id="cases">
    <div class="container-xl">
      <div class="row g-4">
        <div class="col-lg-8 case-grid">
          <div class="d-flex align-items-center justify-content-between mb-2">
            <h2 class="h4 mb-0">Recent Cases</h2>
            <div class="btn-group">
              <button class="btn btn-outline-light btn-sm"><i class="bi bi-sort-alpha-down"></i></button>
              <button class="btn btn-outline-light btn-sm"><i class="bi bi-funnel"></i></button>
              <button class="btn btn-primary btn-sm" data-bs-toggle="modal" data-bs-target="#createCaseModal"><i class="bi bi-folder-plus me-1"></i> New Case</button>
            </div>
          </div>
          <div class="row g-3 row-cols-1 row-cols-md-2">
            <!-- Case Card (repeat server-side) -->
            <div class="col">
              <div class="card h-100">
                <div class="card-body">
                  <div class="d-flex justify-content-between align-items-start">
                    <div>
                      <a href="#" class="stretched-link text-decoration-none"><h3 class="h6 mb-1">CASE-2025-0001</h3></a>
                      <div class="small text-secondary">Subject: <span class="text-white">@example_user123</span></div>
                    </div>
                    <span class="badge rounded-pill text-bg-warning-subtle border"><i class="bi bi-hourglass-split me-1"></i> In Review</span>
                  </div>
                  <div class="mt-3 d-flex gap-2 flex-wrap">
                    <span class="badge text-bg-dark border">DMs</span>
                    <span class="badge text-bg-dark border">Screenshots</span>
                    <span class="badge text-bg-dark border">Under 18</span>
                  </div>
                </div>
                <div class="card-footer d-flex justify-content-between small">
                  <span><i class="bi bi-clock"></i> Updated 2h ago</span>
                  <span><i class="bi bi-people"></i> 3 assignees</span>
                </div>
              </div>
            </div>
            <div class="col">
              <div class="card h-100">
                <div class="card-body">
                  <div class="d-flex justify-content-between align-items-start">
                    <div>
                      <a href="#" class="stretched-link text-decoration-none"><h3 class="h6 mb-1">CASE-2025-0002</h3></a>
                      <div class="small text-secondary">Subject: <span class="text-white">@subject_handle</span></div>
                    </div>
                    <span class="badge rounded-pill text-bg-success-subtle border"><i class="bi bi-check2-circle me-1"></i> Verified</span>
                  </div>
                  <div class="mt-3 d-flex gap-2 flex-wrap">
                    <span class="badge text-bg-dark border">Video</span>
                    <span class="badge text-bg-dark border">Metadata</span>
                  </div>
                </div>
                <div class="card-footer d-flex justify-content-between small">
                  <span><i class="bi bi-clock"></i> Updated yesterday</span>
                  <span><i class="bi bi-people"></i> 1 assignee</span>
                </div>
              </div>
            </div>
            <!-- /Case Card -->
          </div>

          <!-- Evidence Gallery Mock -->
          <div id="evidence" class="mt-4">
            <div class="d-flex align-items-center justify-content-between mb-2">
              <h2 class="h5 mb-0">Evidence Gallery</h2>
              <button class="btn btn-outline-light btn-sm" data-bs-toggle="modal" data-bs-target="#uploadModal"><i class="bi bi-cloud-arrow-up me-1"></i> Upload</button>
            </div>
            <div class="row g-2 row-cols-2 row-cols-md-3">
              <!-- Mock tiles -->
              <div class="col"><div class="placeholder-tile"><div class="text"><i class="bi bi-file-earmark-image me-1"></i> image_001.png</div></div></div>
              <div class="col"><div class="placeholder-tile"><div class="text"><i class="bi bi-film me-1"></i> clip_12.mp4</div></div></div>
              <div class="col"><div class="placeholder-tile"><div class="text"><i class="bi bi-chat-dots me-1"></i> dm_export.json</div></div></div>
              <div class="col"><div class="placeholder-tile"><div class="text"><i class="bi bi-filetype-pdf me-1"></i> warrant.pdf</div></div></div>
              <div class="col"><div class="placeholder-tile"><div class="text"><i class="bi bi-mic me-1"></i> call_05.m4a</div></div></div>
              <div class="col"><div class="placeholder-tile"><div class="text"><i class="bi bi-filetype-log me-1"></i> chain.log</div></div></div>
            </div>
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

  <!-- Reports Section (Mock) -->
  <section class="py-5 border-top" id="reports">
    <div class="container-xl">
      <div class="d-flex align-items-center justify-content-between mb-3">
        <h2 class="h4 mb-0">Reports</h2>
        <div class="btn-group">
          <button class="btn btn-outline-light btn-sm"><i class="bi bi-download me-1"></i> Export</button>
          <button class="btn btn-outline-light btn-sm"><i class="bi bi-printer me-1"></i> Print</button>
        </div>
      </div>
      <div class="row g-3">
        <div class="col-lg-8">
          <div class="card glass">
            <div class="card-body">
              <h3 class="h6">Monthly Activity</h3>
              <div class="placeholder-tile" style="aspect-ratio: 21/9">
                <div class="text"><i class="bi bi-graph-up-arrow me-1"></i> Chart placeholder</div>
              </div>
            </div>
          </div>
        </div>
        <div class="col-lg-4">
          <div class="card glass">
            <div class="card-body">
              <h3 class="h6">Breakdown</h3>
              <div class="placeholder-tile" style="aspect-ratio: 1/1">
                <div class="text"><i class="bi bi-pie-chart me-1"></i> Pie chart placeholder</div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </section>

  <!-- Admin Section (Mock) -->
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

  <footer class="border-top py-4">
    <div class="container-xl d-flex flex-wrap justify-content-between align-items-center gap-3">
      <div class="small">© <span id="year"></span> TikTokPredators. For reporting and documentation only. Not affiliated with TikTok.</div>
      <div class="d-flex gap-3 small">
        <a href="#" data-bs-toggle="modal" data-bs-target="#privacyModal"><i class="bi bi-shield-lock me-1"></i> Privacy</a>
        <a href="#" data-bs-toggle="modal" data-bs-target="#tosModal"><i class="bi bi-file-text me-1"></i> Terms</a>
        <a href="#" data-bs-toggle="modal" data-bs-target="#disclaimerModal"><i class="bi bi-exclamation-octagon me-1"></i> Disclaimer</a>
      </div>
    </div>
  </footer>
  <?php if (getenv('APP_DEBUG') === '1'): ?>
    <div class="container-xl my-3">
      <details class="small">
        <summary class="text-secondary">Debug info (visible only with APP_DEBUG=1)</summary>
        <?php if (!empty($_SESSION['last_db_error'])): ?>
          <div class="alert alert-warning mt-2">DB Error: <?php echo htmlspecialchars($_SESSION['last_db_error']); unset($_SESSION['last_db_error']); ?></div>
        <?php endif; ?>
        <?php if (!empty($_SESSION['last_register_error'])): ?>
          <div class="alert alert-warning mt-2">Register Error: <?php echo htmlspecialchars($_SESSION['last_register_error']); unset($_SESSION['last_register_error']); ?></div>
        <?php endif; ?>
      </details>
    </div>
  <?php endif; ?>

  <!-- Create Case Modal -->
  <div class="modal fade" id="createCaseModal" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered">
      <div class="modal-content">
        <div class="modal-header">
          <h5 class="modal-title"><i class="bi bi-folder-plus me-2"></i>New Case</h5>
          <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
        </div>
        <div class="modal-body">
          <form>
            <div class="mb-3">
              <label class="form-label">Subject Handle</label>
              <input type="text" class="form-control" placeholder="@username" />
            </div>
            <div class="mb-3">
              <label class="form-label">Initial Summary</label>
              <textarea class="form-control" rows="3" placeholder="Short description…"></textarea>
            </div>
            <div class="row g-2">
              <div class="col-md-6">
                <label class="form-label">Sensitivity</label>
                <select class="form-select">
                  <option>Standard</option>
                  <option>Restricted</option>
                  <option>Sealed</option>
                </select>
              </div>
              <div class="col-md-6">
                <label class="form-label">Status</label>
                <select class="form-select">
                  <option>Open</option>
                  <option>In Review</option>
                  <option>Verified</option>
                  <option>Closed</option>
                </select>
              </div>
            </div>
          </form>
        </div>
        <div class="modal-footer">
          <button class="btn btn-outline-light" data-bs-dismiss="modal">Cancel</button>
          <button class="btn btn-primary"><i class="bi bi-save me-1"></i> Create</button>
        </div>
      </div>
    </div>
  </div>

  <!-- Upload Modal -->
  <div class="modal fade" id="uploadModal" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog modal-lg modal-dialog-centered">
      <div class="modal-content">
        <div class="modal-header">
          <h5 class="modal-title"><i class="bi bi-cloud-arrow-up me-2"></i>Upload Evidence</h5>
          <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
        </div>
        <div class="modal-body">
          <div class="alert alert-warning small"><i class="bi bi-shield-lock me-2"></i>Ensure personally identifiable information (PII) is handled lawfully. All uploads are hashed and timestamped.</div>
          <div class="dropzone" role="button" tabindex="0">
            <i class="bi bi-cloud-upload display-6 d-block"></i>
            <p class="mb-1">Drag & drop files here or click to browse</p>
            <small class="text-secondary">Max 1GB per file • Allowed: PNG, JPG, MP4, MOV, WAV, MP3, PDF, TXT, JSON</small>
          </div>
          <div class="mt-3 small text-secondary">Selected files (mock list)</div>
          <ul class="list-group list-group-flush">
            <li class="list-group-item bg-transparent text-white d-flex justify-content-between align-items-center">
              <span><i class="bi bi-file-earmark-image me-2"></i> screenshot_01.png</span>
              <span class="badge text-bg-dark border">12.4 MB</span>
            </li>
          </ul>
        </div>
        <div class="modal-footer">
          <button class="btn btn-outline-light" data-bs-dismiss="modal">Cancel</button>
          <button class="btn btn-primary"><i class="bi bi-arrow-right-circle me-1"></i> Continue</button>
        </div>
      </div>
    </div>
  </div>

  <!-- Auth Modal (Register / Login) -->
  <div class="modal fade" id="authModal" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered">
      <div class="modal-content">
        <div class="modal-header">
          <h5 class="modal-title"><i class="bi bi-shield-lock me-2"></i>Account Access</h5>
          <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
        </div>
        <div class="modal-body">
          <ul class="nav nav-tabs" id="authTabs" role="tablist">
            <li class="nav-item" role="presentation">
              <button class="nav-link active" id="login-tab" data-bs-toggle="tab" data-bs-target="#login-pane" type="button" role="tab" aria-controls="login-pane" aria-selected="true"><i class="bi bi-box-arrow-in-right me-1"></i> Login</button>
            </li>
            <li class="nav-item" role="presentation">
              <button class="nav-link" id="register-tab" data-bs-toggle="tab" data-bs-target="#register-pane" type="button" role="tab" aria-controls="register-pane" aria-selected="false"><i class="bi bi-person-plus me-1"></i> Register</button>
            </li>
          </ul>
          <div class="tab-content pt-3">
            <div class="tab-pane fade show active" id="login-pane" role="tabpanel" aria-labelledby="login-tab">
              <form method="post" action="">
                <input type="hidden" name="action" value="login">
                <?php csrf_field(); ?>
                <div class="mb-3">
                  <label class="form-label">Email</label>
                  <input type="email" name="email" class="form-control" placeholder="you@org.org" required />
                </div>
                <div class="mb-3">
                  <label class="form-label">Password</label>
                  <input type="password" name="password" class="form-control" placeholder="••••••••" minlength="8" required />
                </div>
                <div class="d-flex justify-content-between align-items-center">
                  <small class="text-secondary">Use your account email & password.</small>
                  <a class="small disabled" tabindex="-1" aria-disabled="true" href="#" title="Not available on public site">Forgot password?</a>
                </div>
                <div class="mt-3 d-grid">
                  <button class="btn btn-primary" type="submit"><i class="bi bi-box-arrow-in-right me-2"></i>Sign in</button>
                </div>
              </form>
            </div>
            <div class="tab-pane fade" id="register-pane" role="tabpanel" aria-labelledby="register-tab">
              <form method="post" action="">
                <input type="hidden" name="action" value="register">
                <?php csrf_field(); ?>
                <div class="mb-3">
                  <label class="form-label">Display Name</label>
                  <input type="text" name="display_name" class="form-control" placeholder="Your name" required />
                </div>
                <div class="mb-3">
                  <label class="form-label">Email</label>
                  <input type="email" name="email" class="form-control" placeholder="you@org.org" required />
                </div>
                <div class="mb-3">
                  <label class="form-label">Password</label>
                  <input type="password" name="password" class="form-control" placeholder="At least 8 characters" minlength="8" required />
                </div>
                <div class="mb-3">
                  <label class="form-label">Confirm Password</label>
                  <input type="password" name="password_confirm" class="form-control" placeholder="Repeat password" minlength="8" required />
                </div>
                <div class="form-check mb-2">
                  <input class="form-check-input" type="checkbox" value="1" id="agreeTos" name="agree" required>
                  <label class="form-check-label" for="agreeTos">
                    I agree to the <a href="#" data-bs-toggle="modal" data-bs-target="#tosModal">Terms</a> and acknowledge the <a href="#" data-bs-toggle="modal" data-bs-target="#privacyModal">Privacy Notice</a>.
                  </label>
                </div>
                <div class="mt-3 d-grid">
                  <button class="btn btn-success" type="submit"><i class="bi bi-person-plus me-2"></i>Create account</button>
                </div>
              </form>
            </div>
          </div>
        </div>
        <div class="modal-footer">
          <button class="btn btn-outline-light" data-bs-dismiss="modal">Close</button>
        </div>
      </div>
    </div>
  </div>

  <!-- Policy Modals (Privacy, Terms, Disclaimer) -->
  <div class="modal fade" id="privacyModal" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog modal-lg modal-dialog-scrollable">
      <div class="modal-content">
        <div class="modal-header"><h5 class="modal-title">Privacy Notice</h5><button class="btn-close" data-bs-dismiss="modal"></button></div>
        <div class="modal-body">
          <p class="small">This platform stores potentially sensitive material. Access is restricted to vetted users. All actions are logged. Do not upload content without lawful basis. Data minimization and redaction are required where appropriate.</p>
        </div>
        <div class="modal-footer"><button class="btn btn-primary" data-bs-dismiss="modal">Close</button></div>
      </div>
    </div>
  </div>
  <div class="modal fade" id="tosModal" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog modal-lg modal-dialog-scrollable">
      <div class="modal-content">
        <div class="modal-header"><h5 class="modal-title">Terms of Use</h5><button class="btn-close" data-bs-dismiss="modal"></button></div>
        <div class="modal-body">
          <p class="small">Users agree to lawful, ethical use. Distribution of unredacted materials is prohibited. Cooperation with legitimate legal requests is supported. Violations may result in suspension and reporting.</p>
        </div>
        <div class="modal-footer"><button class="btn btn-primary" data-bs-dismiss="modal">Close</button></div>
      </div>
    </div>
  </div>
  <div class="modal fade" id="disclaimerModal" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog modal-lg modal-dialog-scrollable">
      <div class="modal-content">
        <div class="modal-header"><h5 class="modal-title">Legal Disclaimer</h5><button class="btn-close" data-bs-dismiss="modal"></button></div>
        <div class="modal-body">
          <p class="small">Allegations documented here are claims and may be under investigation. Presumption of innocence applies. Content may be shared with appropriate authorities when required.</p>
        </div>
        <div class="modal-footer"><button class="btn btn-primary" data-bs-dismiss="modal">Close</button></div>
      </div>
    </div>
  </div>

  <?php $sqlError = $_SESSION['sql_error'] ?? ''; unset($_SESSION['sql_error']); ?>
  <div class="modal fade" id="sqlErrorModal" tabindex="-1" aria-labelledby="sqlErrorLabel" aria-hidden="true">
    <div class="modal-dialog modal-lg modal-dialog-centered modal-dialog-scrollable">
      <div class="modal-content">
        <div class="modal-header bg-danger-subtle">
          <h5 class="modal-title" id="sqlErrorLabel"><i class="bi bi-bug me-2"></i>Database / SQL Error</h5>
          <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
        </div>
        <div class="modal-body">
          <?php if ($sqlError): ?>
            <div class="alert alert-danger"><i class="bi bi-exclamation-octagon me-2"></i>An error occurred during authentication or registration. Details below:</div>
            <pre class="small mb-0" style="white-space: pre-wrap; word-wrap: break-word;">
<?php echo htmlspecialchars($sqlError); ?>
            </pre>
          <?php else: ?>
            <div class="text-secondary small">No SQL error information available.</div>
          <?php endif; ?>
        </div>
        <div class="modal-footer">
          <button type="button" class="btn btn-outline-light" data-bs-dismiss="modal">Close</button>
        </div>
      </div>
    </div>
  </div>

  <script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
  <script>
    // Theme toggle (respects Bootstrap 5.3 data-bs-theme)
    (function() {
      const key = 'tp-theme';
      const stored = localStorage.getItem(key);
      if (stored) document.documentElement.setAttribute('data-bs-theme', stored);
      document.getElementById('themeToggle').addEventListener('click', function(){
        const cur = document.documentElement.getAttribute('data-bs-theme');
        const next = cur === 'dark' ? 'light' : 'dark';
        document.documentElement.setAttribute('data-bs-theme', next);
        localStorage.setItem(key, next);
      });
      document.getElementById('year').textContent = new Date().getFullYear();
    })();

    // Mock: click on placeholder evidence to preview (toast)
    const toastContainer = document.createElement('div');
    toastContainer.className = 'toast-container position-fixed bottom-0 end-0 p-3';
    document.body.appendChild(toastContainer);
    function makeToast(msg){
      const el = document.createElement('div');
      el.className = 'toast align-items-center text-bg-dark border-0';
      el.role = 'status';
      el.innerHTML = `<div class="d-flex"><div class="toast-body">${msg}</div><button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button></div>`;
      toastContainer.appendChild(el);
      new bootstrap.Toast(el, { delay: 2000 }).show();
    }
    $(document).on('click', '.placeholder-tile', function(){ makeToast('Preview would open in a secure viewer.'); });

    // Accessibility helpers (focus outline only on keyboard)
    function handleFirstTab(e){ if(e.key==='Tab'){ document.body.classList.add('user-is-tabbing'); window.removeEventListener('keydown', handleFirstTab);} }
    window.addEventListener('keydown', handleFirstTab);
  </script>
  <script src="https://cdn.datatables.net/1.13.8/js/jquery.dataTables.min.js"></script>
  <script src="https://cdn.datatables.net/1.13.8/js/dataTables.bootstrap5.min.js"></script>
  <script src="https://cdn.datatables.net/responsive/2.5.0/js/dataTables.responsive.min.js"></script>
  <script src="https://cdn.datatables.net/responsive/2.5.0/js/responsive.bootstrap5.min.js"></script>
  <script>
    $(function(){
      const dt = $('#casesTable').DataTable({
        responsive: true,
        pageLength: 10,
        order: [[3, 'desc']],
        columnDefs: [
          { targets: [2,4,6], orderable: false }
        ],
        language: {
          search: "Filter:",
          lengthMenu: "Show _MENU_ cases",
          info: "_START_-_END_ of _TOTAL_ cases",
        }
      });
    });
  </script>
  <script>
    // Switch auth modal to requested tab
    document.addEventListener('click', function(e){
      const btn = e.target.closest('[data-auth-tab]');
      if (!btn) return;
      const tab = btn.getAttribute('data-auth-tab');
      setTimeout(()=>{
        const trigger = document.querySelector(tab === 'register' ? '#register-tab' : '#login-tab');
        if (trigger) new bootstrap.Tab(trigger).show();
      }, 150);
    });
  </script>
  <script>
    // Auto-open auth modal on server-side errors
    (function(){
      const openAuth = <?php echo json_encode($openAuth ?? ''); ?>;
      if (!openAuth) return;
      const m = new bootstrap.Modal(document.getElementById('authModal'));
      m.show();
      const trigger = document.querySelector(openAuth === 'register' ? '#register-tab' : '#login-tab');
      if (trigger) new bootstrap.Tab(trigger).show();
    })();
  </script>
  <script>
    // Auto-open SQL error modal if server captured a DB error
    (function(){
      const hasSqlError = <?php echo json_encode(isset($sqlError) && $sqlError !== ''); ?>;
      if (!hasSqlError) return;
      const m = new bootstrap.Modal(document.getElementById('sqlErrorModal'));
      m.show();
    })();
  </script>
</body>
</html>
