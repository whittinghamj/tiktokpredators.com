<?php

// --- Cross-subdomain session cookie for tiktokpredators.com and www.tiktokpredators.com
// Must be set BEFORE session_start()
$tp_cookie_domain = '.tiktokpredators.com'; // covers apex and www
$tp_cookie_path   = '/';
$tp_cookie_secure = (
    (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
    || (isset($_SERVER['SERVER_PORT']) && (int)$_SERVER['SERVER_PORT'] === 443)
) ? true : false; // secure on HTTPS; allow HTTP when not secure

$tp_cookie_params = [
    'lifetime' => 0,
    'path'     => $tp_cookie_path,
    'domain'   => $tp_cookie_domain,
    'secure'   => $tp_cookie_secure,
    'httponly' => true,
    'samesite' => 'Lax', // allows top-level nav across apex/www
];

if (PHP_VERSION_ID >= 70300) {
    session_set_cookie_params($tp_cookie_params);
} else {
    // PHP < 7.3 fallback (array form not supported)
    $legacyPath = $tp_cookie_path . '; samesite=' . $tp_cookie_params['samesite'];
    session_set_cookie_params(0, $legacyPath, $tp_cookie_domain, $tp_cookie_secure, true);
}

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

// Console log path
$CONSOLE_LOG_PATH = '/var/www/html/tiktokpredators.com/logs/console.log';

/**
 * Append a line to the console log using error_log() type 3 (append).
 * Format: [DD/MM/YYYY HH:MM] [ LEVEL ] - message
 */
function log_console(string $level, string $message) {
    $dest = $GLOBALS['CONSOLE_LOG_PATH'] ?? '/var/www/html/tiktokpredators.com/logs/console.log';
    $dir = dirname($dest);
    if (!is_dir($dir)) { @mkdir($dir, 0755, true); }
    $ts = date('d/m/Y H:i');
    $line = sprintf("[%s] [ %s ] - %s\n", $ts, strtoupper($level), $message);
    @error_log($line, 3, $dest);
}

// Flash helper
// Flash helper (also logs to console.log)
function flash(string $key, ?string $val = null){
    if ($val === null) {
        if (!empty($_SESSION['flash'][$key])) { $msg = $_SESSION['flash'][$key]; unset($_SESSION['flash'][$key]); return $msg; }
        return '';
    }
    $_SESSION['flash'][$key] = $val;
    // Log when setting a flash message
    if ($key === 'success') {
        // log_console('SUCCESS', $val);
    } elseif ($key === 'error') {
        // log_console('ERROR', $val);
    } else {
        // Optional: treat other flash keys as INFO
        // log_console('INFO', $key . ': ' . $val);
    }
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

/**
 * Allow the viewer who opened a case to manage it while status = Pending.
 * Returns true only if the current logged-in user created the case AND the case is still Pending.
 */
function can_manage_pending_case(PDO $pdo, int $caseId): bool {
    if ($caseId <= 0 || empty($_SESSION['user'])) { return false; }
    try {
        $s = $pdo->prepare('SELECT created_by, status FROM cases WHERE id = ? LIMIT 1');
        $s->execute([$caseId]);
        $r = $s->fetch();
        if ($r && (int)($r['created_by'] ?? 0) === (int)($_SESSION['user']['id'] ?? 0) && ($r['status'] ?? '') === 'Pending') {
            return true;
        }
    } catch (Throwable $e) {
        // noop
    }
    return false;
}
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

// --- Face / Evidence Scanner helpers (GD-based perceptual hashing + histogram) ---

/**
 * Cached DCT-II cosine table.
 */
function tp_scanner_dct_cos(int $sz): array {
    static $cache = [];
    if (!isset($cache[$sz])) {
        $t = [];
        for ($u = 0; $u < $sz; $u++) {
            for ($x = 0; $x < $sz; $x++) {
                $t[$u][$x] = cos(M_PI * $u * (2*$x+1) / (2.0*$sz));
            }
        }
        $cache[$sz] = $t;
    }
    return $cache[$sz];
}

/**
 * Prepare: resize a GdImage to 32×32 greyscale and return a flat pixel array.
 * Called ONCE per candidate — all hashes are derived from this array without
 * additional GD calls, reducing per-image GD operations from ~7 down to 1.
 */
function tp_scanner_prepare_pixels(GdImage $img): array {
    $sz = 32;
    $t = imagecreatetruecolor($sz, $sz);
    imagecopyresampled($t, $img, 0, 0, 0, 0, $sz, $sz, imagesx($img), imagesy($img));
    imagefilter($t, IMG_FILTER_GRAYSCALE);
    $p = [];
    for ($y = 0; $y < $sz; $y++) {
        for ($x = 0; $x < $sz; $x++) {
            $p[$y * $sz + $x] = (imagecolorat($t, $x, $y) >> 16) & 0xFF;
        }
    }
    imagedestroy($t);
    return $p; // 1024-element flat int array
}

/**
 * pHash from a pre-prepared 32×32 flat pixel array.
 * 8×8 DCT → 63-bit binary string (DC component dropped).
 */
function tp_scanner_phash_from_pixels(array $p): string {
    $sz = 32; $keep = 8;
    $cos = tp_scanner_dct_cos($sz);
    // Row DCT pass
    $r = [];
    for ($y = 0; $y < $sz; $y++) {
        $off = $y * $sz;
        for ($u = 0; $u < $sz; $u++) {
            $sum = 0.0;
            $cu = $cos[$u];
            for ($x = 0; $x < $sz; $x++) { $sum += $p[$off + $x] * $cu[$x]; }
            $r[$y][$u] = $sum * (($u === 0) ? 0.17677669529663689 /* sqrt(1/32) */ : 0.25); /* sqrt(2/32) */
        }
    }
    // Column DCT pass — top-left $keep×$keep block only
    $vals = [];
    for ($u = 0; $u < $keep; $u++) {
        for ($v = 0; $v < $keep; $v++) {
            $sum = 0.0;
            $cv = $cos[$v];
            for ($y = 0; $y < $sz; $y++) { $sum += $r[$y][$u] * $cv[$y]; }
            $vals[] = $sum * (($v === 0) ? 0.17677669529663689 : 0.25);
        }
    }
    array_shift($vals); // drop DC [0,0]
    $sorted = $vals; sort($sorted);
    $median = $sorted[(int)(count($sorted) / 2)];
    $hash = '';
    foreach ($vals as $val) { $hash .= ($val >= $median) ? '1' : '0'; }
    return $hash;
}

/**
 * dHash from a 32×32 flat pixel array (subsampled 9×8 for gradient direction).
 * Avoids any extra GD call.
 */
function tp_scanner_dhash_from_pixels(array $p): string {
    // Sample 9×8 grid from the 32×32 pixel array
    $h = '';
    for ($gy = 0; $gy < 8; $gy++) {
        $sy = (int)round($gy * 31 / 7);
        for ($gx = 0; $gx < 8; $gx++) {
            $sx  = (int)round($gx * 31 / 8);
            $sx1 = (int)round(($gx + 1) * 31 / 8);
            $l = $p[$sy * 32 + $sx];
            $r = $p[$sy * 32 + $sx1];
            $h .= ($l > $r) ? '1' : '0';
        }
    }
    return $h;
}

/**
 * aHash from a 32×32 flat pixel array (sub-averaged to 8×8 blocks).
 */
function tp_scanner_ahash_from_pixels(array $p): string {
    // Average down to 8×8 blocks (each block covers 4×4 pixels in 32×32)
    $block = 4;
    $blocks = [];
    $tot = $block * $block;
    for ($by = 0; $by < 8; $by++) {
        for ($bx = 0; $bx < 8; $bx++) {
            $sum = 0;
            for ($dy = 0; $dy < $block; $dy++) {
                $row = ($by * $block + $dy) * 32 + $bx * $block;
                for ($dx = 0; $dx < $block; $dx++) { $sum += $p[$row + $dx]; }
            }
            $blocks[] = $sum / $tot;
        }
    }
    $mean = array_sum($blocks) / 64;
    $h = '';
    foreach ($blocks as $v) { $h .= ($v >= $mean) ? '1' : '0'; }
    return $h;
}

/** Hamming similarity between two binary hash strings → 0.0–1.0 */
function tp_scanner_hamming_sim(string $a, string $b): float {
    $len = strlen($a);
    if ($len === 0) return 0.0;
    $dist = 0;
    for ($i = 0; $i < $len; $i++) { if (($b[$i] ?? '0') !== $a[$i]) $dist++; }
    return max(0.0, 1.0 - ($dist / $len));
}

/**
 * pHash from a GdImage directly (used for the query image & its center crop,
 * which are only computed once — not in any loop).
 */
function tp_scanner_phash(GdImage $img): string {
    return tp_scanner_phash_from_pixels(tp_scanner_prepare_pixels($img));
}

/**
 * Crop the central cx×cy fraction of an image — used on the query image only.
 */
function tp_scanner_center_crop(GdImage $img, float $cx = 0.6, float $cy = 0.7): GdImage {
    $ow = imagesx($img); $oh = imagesy($img);
    $cw = max(1, (int)round($ow * $cx));
    $ch = max(1, (int)round($oh * $cy));
    $ox = (int)round(($ow - $cw) / 2);
    $oy = (int)round(($oh - $ch) / 2);
    $out = imagecreatetruecolor($cw, $ch);
    imagecopy($out, $img, 0, 0, $ox, $oy, $cw, $ch);
    return $out;
}

/** Load a GD image from file path (any GD-supported format) */
function tp_scanner_load_image(string $path): ?GdImage {
    if (!is_file($path) || !is_readable($path)) return null;
    $sz = @filesize($path);
    if ($sz === false || $sz > 20 * 1024 * 1024) return null; // skip >20 MB files
    $data = @file_get_contents($path);
    if ($data === false || $data === '') return null;
    $img = @imagecreatefromstring($data);
    return ($img instanceof GdImage) ? $img : null;
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
log_console('ERROR', 'DB: ' . $e->getMessage());
    $_SESSION['sql_error'] = $e->getMessage();
log_console('ERROR', 'SQL: ' . $e->getMessage());
    flash('error', 'Database connection failed. Please check configuration.');
    $_SESSION['auth_tab'] = 'register';
}
  // --- Cases schema safety: ensure location column exists ---
  try {
    $col = $pdo->query("SHOW COLUMNS FROM cases LIKE 'location'");
    if (!$col || !$col->fetch()) {
      $pdo->exec("ALTER TABLE cases ADD COLUMN location VARCHAR(255) NULL AFTER person_name");
    }
  } catch (Throwable $e) {
    $_SESSION['sql_error'] = $_SESSION['sql_error'] ?? $e->getMessage();
  }
// --- Case events logging setup ---
try {
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS case_events (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
            case_id BIGINT UNSIGNED NOT NULL,
            event_type VARCHAR(64) NOT NULL,
            subject VARCHAR(255) NULL,
            detail TEXT NULL,
            ref_evidence_id BIGINT UNSIGNED NULL,
            ref_note_id BIGINT UNSIGNED NULL,
            created_by BIGINT UNSIGNED NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_case_id_created (case_id, created_at),
            INDEX idx_event_type (event_type),
            INDEX idx_ref_evidence (ref_evidence_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    ");
} catch (Throwable $e) {
    $_SESSION['sql_error'] = $_SESSION['sql_error'] ?? $e->getMessage();
}
// --- Removal requests table setup ---
try {
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS removal_requests (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
            full_name VARCHAR(255) NOT NULL,
            email VARCHAR(255) NOT NULL,
            phone VARCHAR(64) NULL,
            organization VARCHAR(255) NULL,
            target_url TEXT NOT NULL,
            justification TEXT NOT NULL,
            status ENUM('Pending','Declined','In Review','Approved / Closed') NOT NULL DEFAULT 'Pending',
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            INDEX idx_status_created (status, created_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    ");
} catch (Throwable $e) {
    $_SESSION['sql_error'] = $_SESSION['sql_error'] ?? $e->getMessage();
}
// --- Case views tracking setup ---
try {
  $pdo->exec(" 
    CREATE TABLE IF NOT EXISTS case_views (
      id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
      case_id BIGINT UNSIGNED NOT NULL,
      viewer_user_id BIGINT UNSIGNED NULL,
      viewer_role VARCHAR(16) NULL,
      is_authenticated TINYINT(1) NOT NULL DEFAULT 0,
      session_key CHAR(64) NULL,
      public_ip VARCHAR(45) NULL,
      forwarded_for VARCHAR(255) NULL,
      geo_ip VARCHAR(45) NULL,
      geo_continent_name VARCHAR(64) NULL,
      geo_continent_code CHAR(2) NULL,
      geo_country_name VARCHAR(128) NULL,
      geo_country CHAR(2) NULL,
      geo_region_code VARCHAR(16) NULL,
      geo_region VARCHAR(128) NULL,
      geo_city VARCHAR(128) NULL,
      geo_district VARCHAR(128) NULL,
      geo_postcode VARCHAR(32) NULL,
      geo_lat DECIMAL(10,6) NULL,
      geo_lon DECIMAL(10,6) NULL,
      geo_timezone VARCHAR(64) NULL,
      geo_utc_offset INT NULL,
      geo_currency VARCHAR(8) NULL,
      net_isp VARCHAR(255) NULL,
      net_org VARCHAR(255) NULL,
      net_as VARCHAR(255) NULL,
      net_as_name VARCHAR(255) NULL,
      net_reverse_dns VARCHAR(255) NULL,
      is_mobile TINYINT(1) NULL,
      is_proxy TINYINT(1) NULL,
      is_hosting TINYINT(1) NULL,
      geo_source VARCHAR(64) NULL,
      device_type VARCHAR(32) NULL,
      os_name VARCHAR(64) NULL,
      browser_name VARCHAR(64) NULL,
      browser_version VARCHAR(32) NULL,
      user_agent VARCHAR(1024) NULL,
      accept_language VARCHAR(255) NULL,
      referer VARCHAR(1024) NULL,
      request_uri VARCHAR(1024) NULL,
      request_method VARCHAR(16) NULL,
      viewed_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_case_id_viewed_at (case_id, viewed_at),
      INDEX idx_viewer_user (viewer_user_id),
      INDEX idx_public_ip (public_ip),
      INDEX idx_geo_ip (geo_ip),
      INDEX idx_geo_country (geo_country)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  ");

  // Safe schema migration for existing installations.
  $caseViewColumns = [
    'geo_ip' => "ALTER TABLE case_views ADD COLUMN geo_ip VARCHAR(45) NULL AFTER forwarded_for",
    'geo_continent_name' => "ALTER TABLE case_views ADD COLUMN geo_continent_name VARCHAR(64) NULL AFTER geo_ip",
    'geo_continent_code' => "ALTER TABLE case_views ADD COLUMN geo_continent_code CHAR(2) NULL AFTER geo_continent_name",
    'geo_country_name' => "ALTER TABLE case_views ADD COLUMN geo_country_name VARCHAR(128) NULL AFTER geo_continent_code",
    'geo_region_code' => "ALTER TABLE case_views ADD COLUMN geo_region_code VARCHAR(16) NULL AFTER geo_country",
    'geo_district' => "ALTER TABLE case_views ADD COLUMN geo_district VARCHAR(128) NULL AFTER geo_city",
    'geo_postcode' => "ALTER TABLE case_views ADD COLUMN geo_postcode VARCHAR(32) NULL AFTER geo_district",
    'geo_lat' => "ALTER TABLE case_views ADD COLUMN geo_lat DECIMAL(10,6) NULL AFTER geo_postcode",
    'geo_lon' => "ALTER TABLE case_views ADD COLUMN geo_lon DECIMAL(10,6) NULL AFTER geo_lat",
    'geo_timezone' => "ALTER TABLE case_views ADD COLUMN geo_timezone VARCHAR(64) NULL AFTER geo_lon",
    'geo_utc_offset' => "ALTER TABLE case_views ADD COLUMN geo_utc_offset INT NULL AFTER geo_timezone",
    'geo_currency' => "ALTER TABLE case_views ADD COLUMN geo_currency VARCHAR(8) NULL AFTER geo_utc_offset",
    'net_isp' => "ALTER TABLE case_views ADD COLUMN net_isp VARCHAR(255) NULL AFTER geo_currency",
    'net_org' => "ALTER TABLE case_views ADD COLUMN net_org VARCHAR(255) NULL AFTER net_isp",
    'net_as' => "ALTER TABLE case_views ADD COLUMN net_as VARCHAR(255) NULL AFTER net_org",
    'net_as_name' => "ALTER TABLE case_views ADD COLUMN net_as_name VARCHAR(255) NULL AFTER net_as",
    'net_reverse_dns' => "ALTER TABLE case_views ADD COLUMN net_reverse_dns VARCHAR(255) NULL AFTER net_as_name",
    'is_mobile' => "ALTER TABLE case_views ADD COLUMN is_mobile TINYINT(1) NULL AFTER net_reverse_dns",
    'is_proxy' => "ALTER TABLE case_views ADD COLUMN is_proxy TINYINT(1) NULL AFTER is_mobile",
    'is_hosting' => "ALTER TABLE case_views ADD COLUMN is_hosting TINYINT(1) NULL AFTER is_proxy",
  ];

  foreach ($caseViewColumns as $colName => $alterSql) {
    try {
      $col = $pdo->query("SHOW COLUMNS FROM case_views LIKE " . $pdo->quote($colName));
      if (!$col || !$col->fetch()) {
        $pdo->exec($alterSql);
      }
    } catch (Throwable $e) {
      $_SESSION['sql_error'] = $_SESSION['sql_error'] ?? $e->getMessage();
    }
  }

  try {
    $idx = $pdo->query("SHOW INDEX FROM case_views WHERE Key_name = 'idx_geo_ip'");
    if (!$idx || !$idx->fetch()) {
      $pdo->exec("ALTER TABLE case_views ADD INDEX idx_geo_ip (geo_ip)");
    }
  } catch (Throwable $e) {
    $_SESSION['sql_error'] = $_SESSION['sql_error'] ?? $e->getMessage();
  }
} catch (Throwable $e) {
  $_SESSION['sql_error'] = $_SESSION['sql_error'] ?? $e->getMessage();
}

function log_case_event(PDO $pdo, int $caseId, string $type, ?string $subject = null, ?string $detail = null, ?int $refEvidenceId = null, ?int $refNoteId = null): void {
    try {
        $stmt = $pdo->prepare("INSERT INTO case_events (case_id, event_type, subject, detail, ref_evidence_id, ref_note_id, created_by) VALUES (?, ?, ?, ?, ?, ?, ?)");
        $stmt->execute([$caseId, $type, $subject, $detail, $refEvidenceId, $refNoteId, $_SESSION['user']['id'] ?? null]);
    } catch (Throwable $e) {
        $_SESSION['sql_error'] = $_SESSION['sql_error'] ?? $e->getMessage();
    }
}

    function tp_header(string $name): string {
      $key = 'HTTP_' . strtoupper(str_replace('-', '_', $name));
      return trim((string)($_SERVER[$key] ?? ''));
    }

    function tp_client_ip(): array {
      $forwarded = tp_header('X-Forwarded-For');
      $candidates = [
        tp_header('CF-Connecting-IP'),
        tp_header('True-Client-IP'),
        tp_header('X-Real-IP'),
      ];
      if ($forwarded !== '') {
        $first = trim(explode(',', $forwarded)[0]);
        if ($first !== '') { $candidates[] = $first; }
      }
      $remoteAddr = trim((string)($_SERVER['REMOTE_ADDR'] ?? ''));
      if ($remoteAddr !== '') { $candidates[] = $remoteAddr; }

      $publicIp = '';
      foreach ($candidates as $ip) {
        if ($ip !== '' && filter_var($ip, FILTER_VALIDATE_IP)) {
          $publicIp = $ip;
          break;
        }
      }
      return [$publicIp, $forwarded];
    }

    function tp_parse_user_agent(string $ua): array {
      $u = strtolower($ua);

      $device = 'Desktop';
      if (preg_match('/bot|crawl|spider|slurp|bingpreview/i', $ua)) {
        $device = 'Bot';
      } elseif (preg_match('/ipad|tablet|kindle|silk|playbook/i', $ua) || (strpos($u, 'android') !== false && strpos($u, 'mobile') === false)) {
        $device = 'Tablet';
      } elseif (preg_match('/iphone|ipod|android|mobile|windows phone|opera mini/i', $ua)) {
        $device = 'Mobile';
      }

      $os = 'Unknown';
      if (strpos($u, 'windows nt') !== false) { $os = 'Windows'; }
      elseif (strpos($u, 'iphone') !== false || strpos($u, 'ipad') !== false || strpos($u, 'ipod') !== false) { $os = 'iOS'; }
      elseif (strpos($u, 'android') !== false) { $os = 'Android'; }
      elseif (strpos($u, 'mac os x') !== false || strpos($u, 'macintosh') !== false) { $os = 'macOS'; }
      elseif (strpos($u, 'cros') !== false) { $os = 'ChromeOS'; }
      elseif (strpos($u, 'linux') !== false) { $os = 'Linux'; }

      $browser = 'Unknown';
      $version = '';
      $patterns = [
        'Edge' => '/Edg\/([0-9\.]+)/i',
        'Opera' => '/(?:OPR|Opera)\/([0-9\.]+)/i',
        'Samsung Internet' => '/SamsungBrowser\/([0-9\.]+)/i',
        'Chrome' => '/Chrome\/([0-9\.]+)/i',
        'Firefox' => '/Firefox\/([0-9\.]+)/i',
        'Safari' => '/Version\/([0-9\.]+).*Safari/i',
        'Internet Explorer' => '/(?:MSIE\s([0-9\.]+)|Trident\/.*rv:([0-9\.]+))/i',
      ];
      foreach ($patterns as $name => $regex) {
        if (preg_match($regex, $ua, $m)) {
          $browser = $name;
          $version = $m[1] ?: ($m[2] ?? '');
          break;
        }
      }

      return [$device, $os, $browser, $version];
    }

    function tp_geo_from_headers(): array {
      $country = '';
      $region = '';
      $city = '';
      $source = '';

      $cfCountry = tp_header('CF-IPCountry');
      if ($cfCountry !== '') {
        $country = strtoupper(substr($cfCountry, 0, 2));
        $source = 'Cloudflare';
      }

      if ($country === '') {
        $awsCountry = tp_header('CloudFront-Viewer-Country');
        if ($awsCountry !== '') {
          $country = strtoupper(substr($awsCountry, 0, 2));
          $source = 'CloudFront';
        }
      }

      $region = tp_header('CloudFront-Viewer-Country-Region') ?: tp_header('X-AppEngine-Region');
      $city = tp_header('CloudFront-Viewer-City') ?: tp_header('X-AppEngine-City');

      return [$country, $region, $city, $source];
    }

    function tp_geo_lookup_api(string $ip): ?array {
      static $cache = [];

      $ip = trim($ip);
      if ($ip === '' || !filter_var($ip, FILTER_VALIDATE_IP)) {
        return null;
      }

      if (array_key_exists($ip, $cache)) {
        return $cache[$ip];
      }

      $isPublicIp = filter_var(
        $ip,
        FILTER_VALIDATE_IP,
        FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
      ) !== false;
      if (!$isPublicIp) {
        $cache[$ip] = null;
        return null;
      }

      $url = 'https://tiktokpredators.com/geoip.php?ip=' . rawurlencode($ip);
      $ch = curl_init();
      curl_setopt_array($ch, [
        CURLOPT_URL => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CONNECTTIMEOUT => 2,
        CURLOPT_TIMEOUT => 4,
        CURLOPT_FAILONERROR => false,
        CURLOPT_USERAGENT => 'tiktokpredators-case-view-geo/1.0',
      ]);

      $response = curl_exec($ch);
      $curlErr = curl_error($ch);
      $httpCode = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
      curl_close($ch);

      if ($response === false || $curlErr !== '' || $httpCode < 200 || $httpCode >= 300) {
        $cache[$ip] = null;
        return null;
      }

      $payload = json_decode($response, true);
      if (!is_array($payload) || empty($payload['success']) || !is_array($payload['data'] ?? null)) {
        $cache[$ip] = null;
        return null;
      }

      $data = $payload['data'];
      $cache[$ip] = [
        'geo_ip' => (string)($data['ip'] ?? $ip),
        'geo_continent_name' => trim((string)($data['continent']['name'] ?? '')),
        'geo_continent_code' => strtoupper(substr(trim((string)($data['continent']['code'] ?? '')), 0, 2)),
        'geo_country_name' => trim((string)($data['country']['name'] ?? '')),
        'geo_country' => strtoupper(substr(trim((string)($data['country']['code'] ?? '')), 0, 2)),
        'geo_region_code' => trim((string)($data['region']['code'] ?? '')),
        'geo_region' => trim((string)($data['region']['name'] ?? '')),
        'geo_city' => trim((string)($data['city'] ?? '')),
        'geo_district' => trim((string)($data['district'] ?? '')),
        'geo_postcode' => trim((string)($data['postcode'] ?? '')),
        'geo_lat' => isset($data['location']['lat']) ? (float)$data['location']['lat'] : null,
        'geo_lon' => isset($data['location']['lon']) ? (float)$data['location']['lon'] : null,
        'geo_timezone' => trim((string)($data['location']['timezone'] ?? '')),
        'geo_utc_offset' => isset($data['location']['utc_offset']) ? (int)$data['location']['utc_offset'] : null,
        'geo_currency' => trim((string)($data['currency'] ?? '')),
        'net_isp' => trim((string)($data['network']['isp'] ?? '')),
        'net_org' => trim((string)($data['network']['org'] ?? '')),
        'net_as' => trim((string)($data['network']['as'] ?? '')),
        'net_as_name' => trim((string)($data['network']['as_name'] ?? '')),
        'net_reverse_dns' => trim((string)($data['network']['reverse_dns'] ?? '')),
        'is_mobile' => isset($data['flags']['mobile']) ? ((bool)$data['flags']['mobile'] ? 1 : 0) : null,
        'is_proxy' => isset($data['flags']['proxy']) ? ((bool)$data['flags']['proxy'] ? 1 : 0) : null,
        'is_hosting' => isset($data['flags']['hosting']) ? ((bool)$data['flags']['hosting'] ? 1 : 0) : null,
        'geo_source' => 'geoip.php',
      ];

      return $cache[$ip];
    }

    function log_case_view(PDO $pdo, int $caseId): void {
      static $loggedCaseIds = [];
      if ($caseId < 0 || isset($loggedCaseIds[$caseId])) { return; }
      $loggedCaseIds[$caseId] = true;

      try {
        [$publicIp, $forwardedFor] = tp_client_ip();
        $ua = trim((string)($_SERVER['HTTP_USER_AGENT'] ?? ''));
        [$deviceType, $osName, $browserName, $browserVersion] = tp_parse_user_agent($ua);
        [$hdrGeoCountry, $hdrGeoRegion, $hdrGeoCity, $hdrGeoSource] = tp_geo_from_headers();
        $geo = tp_geo_lookup_api($publicIp);

        $geoIp = $publicIp;
        $geoCountry = $hdrGeoCountry;
        $geoRegion = $hdrGeoRegion;
        $geoCity = $hdrGeoCity;
        $geoSource = $hdrGeoSource;

        $geoContinentName = '';
        $geoContinentCode = '';
        $geoCountryName = '';
        $geoRegionCode = '';
        $geoDistrict = '';
        $geoPostcode = '';
        $geoLat = null;
        $geoLon = null;
        $geoTimezone = '';
        $geoUtcOffset = null;
        $geoCurrency = '';
        $netIsp = '';
        $netOrg = '';
        $netAs = '';
        $netAsName = '';
        $netReverseDns = '';
        $isMobile = null;
        $isProxy = null;
        $isHosting = null;

        if (is_array($geo)) {
          $geoIp = trim((string)($geo['geo_ip'] ?? $geoIp));
          $geoContinentName = trim((string)($geo['geo_continent_name'] ?? ''));
          $geoContinentCode = trim((string)($geo['geo_continent_code'] ?? ''));
          $geoCountryName = trim((string)($geo['geo_country_name'] ?? ''));
          $geoCountry = trim((string)($geo['geo_country'] ?? $geoCountry));
          $geoRegionCode = trim((string)($geo['geo_region_code'] ?? ''));
          $geoRegion = trim((string)($geo['geo_region'] ?? $geoRegion));
          $geoCity = trim((string)($geo['geo_city'] ?? $geoCity));
          $geoDistrict = trim((string)($geo['geo_district'] ?? ''));
          $geoPostcode = trim((string)($geo['geo_postcode'] ?? ''));
          $geoLat = $geo['geo_lat'];
          $geoLon = $geo['geo_lon'];
          $geoTimezone = trim((string)($geo['geo_timezone'] ?? ''));
          $geoUtcOffset = $geo['geo_utc_offset'];
          $geoCurrency = trim((string)($geo['geo_currency'] ?? ''));
          $netIsp = trim((string)($geo['net_isp'] ?? ''));
          $netOrg = trim((string)($geo['net_org'] ?? ''));
          $netAs = trim((string)($geo['net_as'] ?? ''));
          $netAsName = trim((string)($geo['net_as_name'] ?? ''));
          $netReverseDns = trim((string)($geo['net_reverse_dns'] ?? ''));
          $isMobile = isset($geo['is_mobile']) ? (int)$geo['is_mobile'] : null;
          $isProxy = isset($geo['is_proxy']) ? (int)$geo['is_proxy'] : null;
          $isHosting = isset($geo['is_hosting']) ? (int)$geo['is_hosting'] : null;
          $geoSource = trim((string)($geo['geo_source'] ?? $geoSource));
        }

        $viewerId = (int)($_SESSION['user']['id'] ?? 0);
        $viewerRole = trim((string)($_SESSION['user']['role'] ?? 'guest'));
        $isAuthed = !empty($_SESSION['user']) ? 1 : 0;
        $sessionKey = session_id() !== '' ? hash('sha256', session_id()) : null;

        $stmt = $pdo->prepare('INSERT INTO case_views (case_id, viewer_user_id, viewer_role, is_authenticated, session_key, public_ip, forwarded_for, geo_ip, geo_continent_name, geo_continent_code, geo_country_name, geo_country, geo_region_code, geo_region, geo_city, geo_district, geo_postcode, geo_lat, geo_lon, geo_timezone, geo_utc_offset, geo_currency, net_isp, net_org, net_as, net_as_name, net_reverse_dns, is_mobile, is_proxy, is_hosting, geo_source, device_type, os_name, browser_name, browser_version, user_agent, accept_language, referer, request_uri, request_method) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)');
        $stmt->execute([
          $caseId,
          $viewerId > 0 ? $viewerId : null,
          $viewerRole !== '' ? substr($viewerRole, 0, 16) : null,
          $isAuthed,
          $sessionKey,
          $publicIp !== '' ? substr($publicIp, 0, 45) : null,
          $forwardedFor !== '' ? substr($forwardedFor, 0, 255) : null,
          $geoIp !== '' ? substr($geoIp, 0, 45) : null,
          $geoContinentName !== '' ? substr($geoContinentName, 0, 64) : null,
          $geoContinentCode !== '' ? substr($geoContinentCode, 0, 2) : null,
          $geoCountryName !== '' ? substr($geoCountryName, 0, 128) : null,
          $geoCountry !== '' ? substr($geoCountry, 0, 2) : null,
          $geoRegionCode !== '' ? substr($geoRegionCode, 0, 16) : null,
          $geoRegion !== '' ? substr($geoRegion, 0, 128) : null,
          $geoCity !== '' ? substr($geoCity, 0, 128) : null,
          $geoDistrict !== '' ? substr($geoDistrict, 0, 128) : null,
          $geoPostcode !== '' ? substr($geoPostcode, 0, 32) : null,
          $geoLat,
          $geoLon,
          $geoTimezone !== '' ? substr($geoTimezone, 0, 64) : null,
          $geoUtcOffset,
          $geoCurrency !== '' ? substr($geoCurrency, 0, 8) : null,
          $netIsp !== '' ? substr($netIsp, 0, 255) : null,
          $netOrg !== '' ? substr($netOrg, 0, 255) : null,
          $netAs !== '' ? substr($netAs, 0, 255) : null,
          $netAsName !== '' ? substr($netAsName, 0, 255) : null,
          $netReverseDns !== '' ? substr($netReverseDns, 0, 255) : null,
          $isMobile,
          $isProxy,
          $isHosting,
          $geoSource !== '' ? substr($geoSource, 0, 64) : null,
          $deviceType,
          $osName,
          $browserName,
          $browserVersion !== '' ? substr($browserVersion, 0, 32) : null,
          $ua !== '' ? substr($ua, 0, 1024) : null,
          ($al = trim((string)($_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? ''))) !== '' ? substr($al, 0, 255) : null,
          ($ref = trim((string)($_SERVER['HTTP_REFERER'] ?? ''))) !== '' ? substr($ref, 0, 1024) : null,
          ($uri = trim((string)($_SERVER['REQUEST_URI'] ?? ''))) !== '' ? substr($uri, 0, 1024) : null,
          ($method = trim((string)($_SERVER['REQUEST_METHOD'] ?? 'GET'))) !== '' ? substr($method, 0, 16) : 'GET',
        ]);
      } catch (Throwable $e) {
        $_SESSION['sql_error'] = $_SESSION['sql_error'] ?? $e->getMessage();
      }
    }

    function get_case_view_count(PDO $pdo, int $caseId): int {
      if ($caseId <= 0) { return 0; }
      try {
        $s = $pdo->prepare('SELECT COUNT(*) AS cnt FROM case_views WHERE case_id = ?');
        $s->execute([$caseId]);
        $r = $s->fetch();
        return (int)($r['cnt'] ?? 0);
      } catch (Throwable $e) {
        return 0;
      }
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
            log_console('INFO', 'Login success for ' . ($user['email'] ?? 'unknown'));
        } else {
            $_SESSION['auth_attempts'] = (int)$_SESSION['auth_attempts'] + 1; $_SESSION['auth_last'] = time();
            flash('error', 'Incorrect email or password.');
            log_console('ERROR', 'Login failed for ' . $email);
            $_SESSION['auth_tab'] = 'login';
        }
    } catch (Throwable $e) {
        $_SESSION['sql_error'] = $e->getMessage();
log_console('ERROR', 'SQL: ' . $e->getMessage());
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
log_console('ERROR', 'REGISTER: ' . $e->getMessage());
        $_SESSION['sql_error'] = $e->getMessage();
log_console('ERROR', 'SQL: ' . $e->getMessage());
        flash('error', $public.' [ERR#'.$code.']');
        $_SESSION['auth_tab'] = 'register';
    }
    header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit;
}

// Handle admin add user (admin only)
if (($_POST['action'] ?? '') === 'admin_add_user') {
    throttle();
    if (!check_csrf()) { flash('error', 'Security check failed.'); header('Location: '. trim($_POST['redirect_url'] ?? '?view=users#users')); exit; }
    if (empty($_SESSION['user']) || (($_SESSION['user']['role'] ?? '') !== 'admin')) {
        flash('error', 'Unauthorized. Admins only.');
        header('Location: '. trim($_POST['redirect_url'] ?? '?view=users#users')); exit;
    }

    $email = trim($_POST['email'] ?? '');
    $displayName = trim($_POST['display_name'] ?? '');
    $password = $_POST['password'] ?? '';
    $confirm = $_POST['password_confirm'] ?? '';
    $role = trim($_POST['role'] ?? 'viewer');
    $isActive = isset($_POST['is_active']) ? 1 : 1; // default active

    $allowedRoles = ['admin','viewer'];

    $redir = trim($_POST['redirect_url'] ?? '?view=users#users');

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        flash('error', 'Please enter a valid email address.');
        header('Location: '. $redir); exit;
    }
    if ($displayName === '') {
        flash('error', 'Please enter a display name.');
        header('Location: '. $redir); exit;
    }
    if (strlen($password) < 8) {
        flash('error', 'Password must be at least 8 characters.');
        header('Location: '. $redir); exit;
    }
    if (!hash_equals($password, $confirm)) {
        flash('error', 'Passwords do not match.');
        header('Location: '. $redir); exit;
    }
    if (!in_array($role, $allowedRoles, true)) { $role = 'viewer'; }

    try {
        $stmt = $pdo->prepare('SELECT id FROM users WHERE email = ? LIMIT 1');
        $stmt->execute([$email]);
        if ($stmt->fetch()) {
            flash('error', 'That email is already registered.');
            header('Location: '. $redir); exit;
        }
        $hash = password_hash($password, PASSWORD_DEFAULT);
        $ins = $pdo->prepare('INSERT INTO users (email, display_name, password_hash, role, is_active, created_at) VALUES (?, ?, ?, ?, ?, NOW())');
        $ins->execute([$email, $displayName, $hash, $role, $isActive]);
        flash('success', 'User added successfully.');
    } catch (Throwable $e) {
        $_SESSION['sql_error'] = $e->getMessage();
log_console('ERROR', 'SQL: ' . $e->getMessage());
        $code = ($e instanceof PDOException && isset($e->errorInfo[1])) ? (int)$e->errorInfo[1] : 0;
        if ($code === 1062) {
            flash('error', 'That email is already registered.');
        } else {
            flash('error', 'Unable to add user.');
        }
    }
    header('Location: '. $redir); exit;
}

// Handle viewer submit case (viewer only)
if (($_POST['action'] ?? '') === 'viewer_submit_case') {
    throttle();
    if (!check_csrf()) {
        flash('error', 'Security check failed. Please refresh and try again.');
        $_SESSION['auth_tab'] = 'login';
        header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?') . '?view=submit_case#submit-case'); exit;
    }
    if (empty($_SESSION['user']) || (($_SESSION['user']['role'] ?? '') !== 'viewer')) {
        flash('error', 'You must be logged in as a viewer to submit a case.');
        header('Location: ?view=submit_case#submit-case'); exit;
    }

    // Collect & validate basic inputs
    $case_name = trim($_POST['case_name'] ?? '');
    $person_name = trim($_POST['person_name'] ?? '');
    $location = trim($_POST['location'] ?? '');
    $tiktok_username = trim(ltrim($_POST['tiktok_username'] ?? '', '@'));
    $initial_summary = trim($_POST['initial_summary'] ?? '');

    if ($case_name === '' || $initial_summary === '') {
        flash('error', 'Case name and summary are required.');
        $_SESSION['open_modal'] = '';
        $_SESSION['form_error'] = 'Case name and summary are required.';
        header('Location: ?view=submit_case#submit-case'); exit;
    }

    try {
        $case_code = generate_case_code($pdo);
        $stmt = $pdo->prepare('INSERT INTO cases (case_code, case_name, person_name, location, tiktok_username, initial_summary, sensitivity, status, created_by, opened_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())');
        $stmt->execute([
            $case_code,
            $case_name,
            ($person_name !== '' ? $person_name : null),
          ($location !== '' ? $location : null),
            ($tiktok_username !== '' ? $tiktok_username : null),
            $initial_summary,
            'Standard',
            'Pending',
            $_SESSION['user']['id'] ?? null
        ]);
        $case_id = (int)$pdo->lastInsertId();
        log_case_event($pdo, $case_id, 'case_created', $case_name, 'Viewer submitted case. Status set to Pending');

        // Optional person photo
        if (!empty($_FILES['person_photo']['name']) && $_FILES['person_photo']['error'] === UPLOAD_ERR_OK) {
            $pf = $_FILES['person_photo'];
            $pmime = $pf['type'] ?? '';
            $allowedImg = ['image/jpeg'=>'jpg','image/png'=>'png','image/webp'=>'webp'];
            $ext = $allowedImg[$pmime] ?? null;
            if (!$ext) { $det = @mime_content_type($pf['tmp_name']) ?: ''; $ext = $allowedImg[$det] ?? null; }
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

        flash('success', 'Case submitted for review. You can now add evidence to your case while it is Pending.');
        log_console('SUCCESS', 'Viewer submitted case ' . $case_code . ' by user_id ' . (int)($_SESSION['user']['id'] ?? 0));
        header('Location: ?view=case&code=' . urlencode($case_code) . '#case-view'); exit;
    } catch (Throwable $e) {
        $_SESSION['sql_error'] = $e->getMessage();
log_console('ERROR', 'SQL: ' . $e->getMessage());
        flash('error', 'Unable to submit case.');
        header('Location: ?view=submit_case#submit-case'); exit;
    }
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
    $location = trim($_POST['location'] ?? '');
    $tiktok_username = trim(ltrim($_POST['tiktok_username'] ?? '', '@'));
    $initial_summary = trim($_POST['initial_summary'] ?? '');
    $sensitivity = $_POST['sensitivity'] ?? '';
    $status = $_POST['status'] ?? '';

    $allowed_sensitivity = ['Standard','Restricted','Sealed'];
    $allowed_status = ['Pending','Open','In Review','Verified','Closed'];

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
        $stmt = $pdo->prepare('INSERT INTO cases (case_code, case_name, person_name, location, tiktok_username, initial_summary, sensitivity, status, created_by, opened_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())');
        $stmt->execute([
            $case_code,
            $case_name,
            ($person_name !== '' ? $person_name : null),
          ($location !== '' ? $location : null),
            ($tiktok_username !== '' ? $tiktok_username : null),
            $initial_summary,
            $sensitivity,
            $status,
            $_SESSION['user']['id'] ?? null
        ]);
        $case_id = (int)$pdo->lastInsertId();
        log_case_event($pdo, $case_id, 'case_created', $case_name, 'Case created with status '.$status.' and sensitivity '.$sensitivity);
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
        log_console('SUCCESS', 'Case created ' . $case_code . ' by user_id ' . (int)($_SESSION['user']['id'] ?? 0));
        // jump to full case view
        header('Location: '. strtok($_SERVER['REQUEST_URI'], '?') . '?view=case&code=' . urlencode($case_code) . '#case-view');
        exit;
    } catch (Throwable $e) {
        $_SESSION['open_modal'] = 'createCase';
        $_SESSION['sql_error'] = $e->getMessage();
log_console('ERROR', 'SQL: ' . $e->getMessage());
        flash('error', 'Unable to create case.');
    }
    header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit;
}

// Handle update case (admin only)
if (($_POST['action'] ?? '') === 'update_case') {
    throttle();
    if (!check_csrf()) { flash('error', 'Security check failed.'); header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit; }

    // Allow admins OR the viewer who opened the case while it's Pending
    $case_id = (int)($_POST['case_id'] ?? 0);
    $ownerCan = can_manage_pending_case($pdo, $case_id);
    if (empty($_SESSION['user']) || (!is_admin() && !$ownerCan)) {
        flash('error', 'Unauthorized.');
        header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit;
    }
    $case_code = trim($_POST['case_code'] ?? '');
    $case_name = trim($_POST['case_name'] ?? '');
    $person_name = trim($_POST['person_name'] ?? '');
    $location = trim($_POST['location'] ?? '');
    $tiktok_username = trim(ltrim($_POST['tiktok_username'] ?? '', '@'));
    $initial_summary = trim($_POST['initial_summary'] ?? '');
    $sensitivity = $_POST['sensitivity'] ?? '';
    $status = $_POST['status'] ?? '';

    $allowed_sensitivity = ['Standard','Restricted','Sealed'];
    $allowed_status = ['Pending','Open','In Review','Verified','Closed'];

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

    // Fetch current values to compute diffs
    $prev = [];
    try { $ps = $pdo->prepare('SELECT case_name, person_name, location, tiktok_username, initial_summary, sensitivity, status FROM cases WHERE id = ? LIMIT 1'); $ps->execute([$case_id]); $prev = $ps->fetch() ?: []; } catch (Throwable $e) {}

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
        $u = $pdo->prepare('UPDATE cases SET case_name = ?, person_name = ?, location = ?, tiktok_username = ?, initial_summary = ?, sensitivity = ?, status = ? WHERE id = ? LIMIT 1');
        $u->execute([
            $case_name,
            ($person_name !== '' ? $person_name : null),
          ($location !== '' ? $location : null),
            ($tiktok_username !== '' ? $tiktok_username : null),
            $initial_summary,
            $sensitivity,
            $status,
            $case_id
        ]);
        // Build diff summary
        $changes = [];
        $fields = ['case_name','person_name','location','tiktok_username','initial_summary','sensitivity','status'];
        $newVals = [
            'case_name' => $case_name,
            'person_name' => ($person_name !== '' ? $person_name : null),
          'location' => ($location !== '' ? $location : null),
            'tiktok_username' => ($tiktok_username !== '' ? $tiktok_username : null),
            'initial_summary' => $initial_summary,
            'sensitivity' => $sensitivity,
            'status' => $status
        ];
        foreach ($fields as $f) {
            $old = $prev[$f] ?? null; $new = $newVals[$f] ?? null;
            if ($old !== $new) {
                $shortOld = is_string($old) ? mb_strimwidth($old,0,60,'…','UTF-8') : (is_null($old)?'null':(string)$old);
                $shortNew = is_string($new) ? mb_strimwidth($new,0,60,'…','UTF-8') : (is_null($new)?'null':(string)$new);
                $changes[] = "$f: {$shortOld} → {$shortNew}";
            }
        }
        if ($changes) {
            log_case_event($pdo, $case_id, 'case_updated', $case_name !== '' ? $case_name : $case_code, 'Updated fields: '.implode('; ', $changes));
        }
        flash('success', 'Case updated.');
    } catch (Throwable $e) {
        $_SESSION['sql_error'] = $e->getMessage();
log_console('ERROR', 'SQL: ' . $e->getMessage());
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
        header('Location: ?view=case&code=' . urlencode($redir_code) . '#case-view'); exit;
    }

    try {
        $stmt = $pdo->prepare('INSERT INTO case_notes (case_id, note_text, created_by) VALUES (?, ?, ?)');
        $stmt->execute([$case_id, $note, $_SESSION['user']['id'] ?? null]);
        $notePreview = mb_strimwidth($note, 0, 160, '…','UTF-8');
        log_case_event($pdo, $case_id, 'note_added', 'Case note', $notePreview, null, null);
        flash('success', 'Note added.');
    } catch (Throwable $e) {
        $_SESSION['sql_error'] = $e->getMessage();
log_console('ERROR', 'SQL: ' . $e->getMessage());
        flash('error', 'Unable to add note.');
    }
    $redirUrl = trim($_POST['redirect_url'] ?? '');
    if ($redirUrl !== '') { header('Location: ' . $redirUrl); exit; }
    header('Location: ?view=case&code=' . urlencode($redir_code) . '#case-view'); exit;
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
        header('Location: ?view=case&code=' . urlencode($redir_code) . '#case-view'); exit;
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
        header('Location: ?view=case&code=' . urlencode($redir_code) . '#case-view'); exit;
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
        $newEvidenceId = (int)$pdo->lastInsertId();
        $notePreview = mb_strimwidth($note, 0, 160, '…','UTF-8');
        log_case_event($pdo, $case_id, 'evidence_added', $title, 'Type: other (note). '.$notePreview, $newEvidenceId, null);
        flash('success', 'Evidence note added.');
    } catch (Throwable $e) {
        $_SESSION['sql_error'] = $e->getMessage();
log_console('ERROR', 'SQL: ' . $e->getMessage());
        flash('error', 'Unable to add evidence note.');
    }
    if ($redir_url !== '') { header('Location: ' . $redir_url); exit; }
    header('Location: ?view=case&code=' . urlencode($redir_code) . '#case-view'); exit;
}

// Handle evidence upload (admin only)
if (($_POST['action'] ?? '') === 'upload_evidence') {
    throttle();
    if (!check_csrf()) { flash('error', 'Security check failed.'); header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit; }
    if (empty($_SESSION['user'])) { flash('error', 'Unauthorized.'); header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit; }
    $isAdminUser = (($_SESSION['user']['role'] ?? '') === 'admin');
    $isOwnerViewer = false;
    // Determine if viewer owns this case
    $case_id_check = (int)($_POST['case_id'] ?? 0);
    if (!$isAdminUser && $case_id_check > 0) {
        try {
            $cs = $pdo->prepare('SELECT created_by, status FROM cases WHERE id = ? LIMIT 1');
            $cs->execute([$case_id_check]);
            $crow = $cs->fetch();
            if ($crow && (int)($crow['created_by'] ?? 0) === (int)($_SESSION['user']['id'] ?? 0) && ($crow['status'] ?? '') === 'Pending') {
                $isOwnerViewer = true;
            }
        } catch (Throwable $e) {}
    }
    if (!$isAdminUser && !$isOwnerViewer) {
        flash('error', 'Unauthorized.'); header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit;
    }

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
            header('Location: ?view=case&code=' . urlencode($redir_code) . '#case-view'); exit;
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
        // Deduplicate by URL hash before insert
        try {
            $dupChk = $pdo->prepare('SELECT id, case_id, title FROM evidence WHERE (hash_sha256 = ? OR sha256_hex = ?) LIMIT 1');
            $dupChk->execute([$hash, $hash]);
            $dup = $dupChk->fetch();
            if ($dup) {
                flash('error', 'An identical URL evidence already exists (Evidence #'.(int)$dup['id'].').');
                $redirUrl = trim($_POST['redirect_url'] ?? '');
                if ($redirUrl !== '') { header('Location: ' . $redirUrl); exit; }
                header('Location: ?view=case&code=' . urlencode($redir_code) . '#case-view'); exit;
            }
        } catch (Throwable $e) {
            // no-op on dedupe check failure; continue to attempt insert
        }
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
            $newEvidenceId = (int)$pdo->lastInsertId();
            log_case_event($pdo, $case_id, 'evidence_added', ($title !== '' ? $title : $url), 'Type: url', $newEvidenceId, null);
            flash('success', 'URL evidence added.');
            log_console('SUCCESS', 'URL evidence added for case_id ' . $case_id . ' (' . ($title !== '' ? $title : $url) . ')');
        } catch (Throwable $e) {
            $_SESSION['sql_error'] = $e->getMessage();
            log_console('ERROR', 'SQL: ' . $e->getMessage());
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
                    $newEvidenceId = (int)$pdo->lastInsertId();
                    log_case_event($pdo, $case_id, 'evidence_added', ($title !== '' ? $title : $url), 'Type: url', $newEvidenceId, null);
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
        header('Location: ?view=case&code=' . urlencode($redir_code) . '#case-view'); exit;
    }

    if ($case_id <= 0 || ($type !== 'url' && empty($_FILES['evidence_file']['name']))) {
        flash('error', 'Please choose a file.');
        $redirUrl = trim($_POST['redirect_url'] ?? '');
        if ($redirUrl !== '') { header('Location: ' . $redirUrl); exit; }
        header('Location: ?view=case&code=' . urlencode($redir_code) . '#case-view'); exit;
    }

    $uploadDir = __DIR__ . '/uploads';
    if (!is_dir($uploadDir)) { @mkdir($uploadDir, 0755, true); }

    $f = $_FILES['evidence_file'];
    if ($f['error'] !== UPLOAD_ERR_OK) {
        flash('error', 'Upload failed with code: '. (int)$f['error']);
        $redirUrl = trim($_POST['redirect_url'] ?? '');
        if ($redirUrl !== '') { header('Location: ' . $redirUrl); exit; }
        header('Location: ?view=case&code=' . urlencode($redir_code) . '#case-view'); exit;
    }

    // New flow: temp move → hash → final unique name
    $safeName = preg_replace('/[^A-Za-z0-9_.\\-]/', '_', basename($f['name']));
    $origBase = pathinfo($safeName, PATHINFO_FILENAME);
    $origExt  = pathinfo($safeName, PATHINFO_EXTENSION);
    $origExt  = $origExt !== '' ? ('.' . strtolower($origExt)) : '';

    // 1) Move to a temporary unique path first
    $tmpRel = 'uploads/tmp_' . uniqid('', true);
    $tmpAbs = __DIR__ . '/' . $tmpRel;
    if (!move_uploaded_file($f['tmp_name'], $tmpAbs)) {
        flash('error', 'Unable to save uploaded file.');
        $redirUrl = trim($_POST['redirect_url'] ?? '');
        if ($redirUrl !== '') { header('Location: ' . $redirUrl); exit; }
        header('Location: ?view=case&code=' . urlencode($redir_code) . '#case-view'); exit;
    }

    // 2) Compute hash and build a final, unique filename
    $hash = hash_file('sha256', $tmpAbs);
    $uniq = date('Ymd_His') . '_' . bin2hex(random_bytes(4)); // timestamp + 8 hex chars
    $finalName = $origBase . '_' . $uniq . '_' . substr($hash, 0, 12) . $origExt;
    $destRel = 'uploads/' . $finalName;
    $destAbs = __DIR__ . '/' . $destRel;

    // 3) Move temp file into place with final unique name
    if (!@rename($tmpAbs, $destAbs)) {
        // Cleanup and abort if rename fails
        @unlink($tmpAbs);
        flash('error', 'Unable to finalize uploaded file.');
        $redirUrl = trim($_POST['redirect_url'] ?? '');
        if ($redirUrl !== '') { header('Location: ' . $redirUrl); exit; }
        header('Location: ?view=case&code=' . urlencode($redir_code) . '#case-view'); exit;
    }

    $mime = mime_content_type($destAbs) ?: ($f['type'] ?? 'application/octet-stream');
    $size = filesize($destAbs) ?: 0;
    $extLower = strtolower((string)pathinfo($safeName, PATHINFO_EXTENSION));

    // Enforce browser-compatible video containers for evidence type=video.
    if ($type === 'video') {
      $allowedVideoExts = ['mp4', 'webm', 'ogg', 'ogv', 'm4v'];
      $allowedVideoMimes = ['video/mp4', 'video/webm', 'video/ogg', 'application/ogg'];
      $mimeLower = strtolower((string)$mime);
      $extOk = in_array($extLower, $allowedVideoExts, true);
      $mimeOk = (strpos($mimeLower, 'video/') === 0) || in_array($mimeLower, $allowedVideoMimes, true);
      if (!$extOk || !$mimeOk) {
        if (is_file($destAbs)) { @unlink($destAbs); }
        flash('error', 'Unsupported video format. Please upload MP4, WebM, or OGG/OGV video files.');
        $redirUrl = trim($_POST['redirect_url'] ?? '');
        if ($redirUrl !== '') { header('Location: ' . $redirUrl); exit; }
        header('Location: ?view=case&code=' . urlencode($redir_code) . '#case-view'); exit;
      }
    }

    // $hash is already set above
    // Deduplicate by file content hash before insert
    try {
        $dupChk = $pdo->prepare('SELECT id, case_id, title FROM evidence WHERE (hash_sha256 = ? OR sha256_hex = ?) LIMIT 1');
        $dupChk->execute([$hash, $hash]);
        $dup = $dupChk->fetch();
        if ($dup) {
            // remove the file we just stored to keep FS clean
            if (is_file($destAbs)) { @unlink($destAbs); }
            flash('error', 'An identical file already exists (Evidence #'.(int)$dup['id'].'). Upload skipped.');
            $redirUrl = trim($_POST['redirect_url'] ?? '');
            if ($redirUrl !== '') { header('Location: ' . $redirUrl); exit; }
            header('Location: ?view=case&code=' . urlencode($redir_code) . '#case-view'); exit;
        }
    } catch (Throwable $e) {
        // If dedupe check fails, proceed to insert; DB unique index will still protect us
    }

    try {
        // Use global storage path and set uploaded_by and created_by to current user
        $stmt = $pdo->prepare('INSERT INTO evidence (case_id, type, title, filepath, storage_path, original_filename, mime_type, size_bytes, hash_sha256, sha256_hex, uploaded_by, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)');
        $stmt->execute([
            $case_id,
            $type,
            ($title !== '' ? $title : $finalName),
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
        $newEvidenceId = (int)$pdo->lastInsertId();
        log_case_event($pdo, $case_id, 'evidence_added', ($title !== '' ? $title : $finalName), 'Type: '.$type, $newEvidenceId, null);
        flash('success', 'Evidence uploaded.');
        log_console('SUCCESS', 'Evidence uploaded for case_id ' . $case_id . ' (' . ($title !== '' ? $title : $finalName) . ')');
    } catch (Throwable $e) {
        $_SESSION['sql_error'] = $e->getMessage();
log_console('ERROR', 'SQL: ' . $e->getMessage());
        flash('error', 'Unable to save evidence.');
    }
    $redirUrl = trim($_POST['redirect_url'] ?? '');
    if ($redirUrl !== '') { header('Location: ' . $redirUrl); exit; }
    header('Location: ?view=case&code=' . urlencode($redir_code) . '#case-view'); exit;
}

// Handle evidence AJAX upload (single file, returns JSON — used by multi-file uploader)
if (($_POST['action'] ?? '') === 'upload_evidence_ajax') {
    header('Content-Type: application/json');
    throttle();
    if (!check_csrf()) { echo json_encode(['ok'=>false,'error'=>'Security check failed.']); exit; }
    if (empty($_SESSION['user'])) { echo json_encode(['ok'=>false,'error'=>'Unauthorized.']); exit; }
    $isAdminUser = (($_SESSION['user']['role'] ?? '') === 'admin');
    $isOwnerViewer = false;
    $case_id_check = (int)($_POST['case_id'] ?? 0);
    if (!$isAdminUser && $case_id_check > 0) {
        try {
            $cs = $pdo->prepare('SELECT created_by, status FROM cases WHERE id = ? LIMIT 1');
            $cs->execute([$case_id_check]);
            $crow = $cs->fetch();
            if ($crow && (int)($crow['created_by'] ?? 0) === (int)($_SESSION['user']['id'] ?? 0) && ($crow['status'] ?? '') === 'Pending') {
                $isOwnerViewer = true;
            }
        } catch (Throwable $e) {}
    }
    if (!$isAdminUser && !$isOwnerViewer) { echo json_encode(['ok'=>false,'error'=>'Unauthorized.']); exit; }

    $case_id  = (int)($_POST['case_id'] ?? 0);
    $title    = trim($_POST['title'] ?? '');
    $type     = $_POST['type'] ?? 'other';
    $allowedTypes = ['image','video','audio','pdf','doc','other'];
    if (!in_array($type, $allowedTypes, true)) $type = 'other';

    if ($case_id <= 0 || empty($_FILES['evidence_file']['name'])) {
        echo json_encode(['ok'=>false,'error'=>'No file provided.']); exit;
    }

    $f = $_FILES['evidence_file'];
    if ($f['error'] !== UPLOAD_ERR_OK) {
        echo json_encode(['ok'=>false,'error'=>'Upload error code: '.(int)$f['error']]); exit;
    }

    $uploadDir = __DIR__ . '/uploads';
    if (!is_dir($uploadDir)) { @mkdir($uploadDir, 0755, true); }

    $safeName = preg_replace('/[^A-Za-z0-9_.\\-]/', '_', basename($f['name']));
    $origBase = pathinfo($safeName, PATHINFO_FILENAME);
    $origExt  = pathinfo($safeName, PATHINFO_EXTENSION);
    $origExt  = $origExt !== '' ? ('.' . strtolower($origExt)) : '';

    $tmpRel = 'uploads/tmp_' . uniqid('', true);
    $tmpAbs = __DIR__ . '/' . $tmpRel;
    if (!move_uploaded_file($f['tmp_name'], $tmpAbs)) {
        echo json_encode(['ok'=>false,'error'=>'Unable to save uploaded file.']); exit;
    }

    $hash    = hash_file('sha256', $tmpAbs);
    $uniq    = date('Ymd_His') . '_' . bin2hex(random_bytes(4));
    $finalName = $origBase . '_' . $uniq . '_' . substr($hash, 0, 12) . $origExt;
    $destRel = 'uploads/' . $finalName;
    $destAbs = __DIR__ . '/' . $destRel;

    if (!@rename($tmpAbs, $destAbs)) {
        @unlink($tmpAbs);
        echo json_encode(['ok'=>false,'error'=>'Unable to finalize uploaded file.']); exit;
    }

    $mime    = mime_content_type($destAbs) ?: ($f['type'] ?? 'application/octet-stream');
    $size    = filesize($destAbs) ?: 0;
    $extLower = strtolower((string)pathinfo($safeName, PATHINFO_EXTENSION));

    if ($type === 'video') {
        $allowedVideoExts  = ['mp4','webm','ogg','ogv','m4v'];
        $allowedVideoMimes = ['video/mp4','video/webm','video/ogg','application/ogg'];
        $mimeLower = strtolower((string)$mime);
        if (!in_array($extLower, $allowedVideoExts, true) || !(strpos($mimeLower,'video/') === 0 || in_array($mimeLower, $allowedVideoMimes, true))) {
            if (is_file($destAbs)) { @unlink($destAbs); }
            echo json_encode(['ok'=>false,'error'=>'Unsupported video format. Use MP4, WebM or OGG/OGV.']); exit;
        }
    }

    // Deduplicate
    try {
        $dupChk = $pdo->prepare('SELECT id FROM evidence WHERE (hash_sha256 = ? OR sha256_hex = ?) LIMIT 1');
        $dupChk->execute([$hash, $hash]);
        $dup = $dupChk->fetch();
        if ($dup) {
            if (is_file($destAbs)) { @unlink($destAbs); }
            echo json_encode(['ok'=>false,'error'=>'Duplicate file already exists (Evidence #'.(int)$dup['id'].').']); exit;
        }
    } catch (Throwable $e) {}

    try {
        $stmt = $pdo->prepare('INSERT INTO evidence (case_id, type, title, filepath, storage_path, original_filename, mime_type, size_bytes, hash_sha256, sha256_hex, uploaded_by, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)');
        $stmt->execute([
            $case_id, $type,
            ($title !== '' ? $title : $finalName),
            $destRel, $storagePath, $safeName, $mime, $size, $hash, $hash,
            $_SESSION['user']['id'] ?? null,
            $_SESSION['user']['id'] ?? null
        ]);
        $newEvidenceId = (int)$pdo->lastInsertId();
        log_case_event($pdo, $case_id, 'evidence_added', ($title !== '' ? $title : $finalName), 'Type: '.$type, $newEvidenceId, null);
        log_console('SUCCESS', 'AJAX evidence uploaded for case_id '.$case_id.' ('.$finalName.')');
        echo json_encode(['ok'=>true,'evidence_id'=>$newEvidenceId,'filename'=>$finalName]); exit;
    } catch (Throwable $e) {
        log_console('ERROR', 'AJAX upload SQL: '.$e->getMessage());
        echo json_encode(['ok'=>false,'error'=>'Database error: unable to save evidence.']); exit;
    }
}

// Handle update evidence (admin only)
if (($_POST['action'] ?? '') === 'update_evidence') {
    throttle();
    if (!check_csrf()) { flash('error', 'Security check failed.'); header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit; }

    $evidence_id = (int)($_POST['evidence_id'] ?? 0);
    $case_id = (int)($_POST['case_id'] ?? 0);
    $ownerCan = can_manage_pending_case($pdo, $case_id);
    if (empty($_SESSION['user']) || (!is_admin() && !$ownerCan)) {
        flash('error', 'Unauthorized.');
        header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit;
    }
    $title = trim($_POST['title'] ?? '');
    $type = $_POST['type'] ?? 'other';
    $allowedTypes = ['image','video','audio','pdf','doc','url','other'];
    if (!in_array($type, $allowedTypes, true)) $type = 'other';

    if ($evidence_id <= 0 || $case_id <= 0) { flash('error', 'Invalid evidence.'); $ru = trim($_POST['redirect_url'] ?? ''); if ($ru!==''){header('Location: '.$ru); exit;} header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit; }

    $prevEv = [];
    try { $ps = $pdo->prepare('SELECT title, type, filepath FROM evidence WHERE id = ? AND case_id = ? LIMIT 1'); $ps->execute([$evidence_id, $case_id]); $prevEv = $ps->fetch() ?: []; } catch (Throwable $e) {}
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
log_console('ERROR', 'SQL: ' . $e->getMessage());
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
        $changes = [];
        if (($prevEv['title'] ?? '') !== $title) { $changes[] = 'title: '.mb_strimwidth($prevEv['title'] ?? '',0,60,'…','UTF-8').' → '.mb_strimwidth($title,0,60,'…','UTF-8'); }
        if (($prevEv['type'] ?? '') !== $type) { $changes[] = 'type: '.($prevEv['type'] ?? '').' → '.$type; }
        if ($type === 'url' && ($prevEv['filepath'] ?? '') !== ($url ?? '')) { $changes[] = 'url updated'; }
        if ($changes) {
            log_case_event($pdo, $case_id, 'evidence_updated', $title !== '' ? $title : ($prevEv['title'] ?? ''), implode('; ', $changes), $evidence_id, null);
        }
        if ($type !== 'url') {
            flash('success', 'Evidence updated.');
        }
    } catch (Throwable $e) {
        $_SESSION['sql_error'] = $e->getMessage();
log_console('ERROR', 'SQL: ' . $e->getMessage());
        flash('error', 'Unable to update evidence.');
    }
    $ru = trim($_POST['redirect_url'] ?? ''); if ($ru!==''){header('Location: '.$ru); exit;} header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit;
}

// Handle delete evidence (admin only)
if (($_POST['action'] ?? '') === 'delete_evidence') {
    throttle();
    if (!check_csrf()) { flash('error', 'Security check failed.'); header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit; }

    $evidence_id = (int)($_POST['evidence_id'] ?? 0);
    $case_id = (int)($_POST['case_id'] ?? 0);
    $ownerCan = can_manage_pending_case($pdo, $case_id);
    if (empty($_SESSION['user']) || (!is_admin() && !$ownerCan)) {
        flash('error', 'Unauthorized.');
        header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit;
    }
    $ru = trim($_POST['redirect_url'] ?? '');

    if ($evidence_id <= 0 || $case_id <= 0) { flash('error', 'Invalid evidence.'); if($ru!==''){header('Location: '.$ru); exit;} header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit; }

    $evForLog = [];
    try { $sf = $pdo->prepare('SELECT title, type FROM evidence WHERE id = ? AND case_id = ? LIMIT 1'); $sf->execute([$evidence_id, $case_id]); $evForLog = $sf->fetch() ?: []; } catch (Throwable $e) {}
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
        log_case_event($pdo, $case_id, 'evidence_deleted', $evForLog['title'] ?? ('Evidence #'.$evidence_id), 'Type: '.($evForLog['type'] ?? ''), $evidence_id, null);
        // best-effort remove file
        if (!empty($abs) && is_file($abs) && strpos(realpath($abs), realpath(__DIR__ . '/uploads')) === 0) { @unlink($abs); }
        flash('success', 'Evidence deleted.');
    } catch (Throwable $e) {
        $_SESSION['sql_error'] = $e->getMessage();
log_console('ERROR', 'SQL: ' . $e->getMessage());
        flash('error', 'Unable to delete evidence.');
    }
    if($ru!==''){header('Location: '.$ru); exit;} header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit;
}

// Handle delete case (admin only)
if (($_POST['action'] ?? '') === 'delete_case') {
    throttle();
    if (!check_csrf()) { flash('error', 'Security check failed.'); header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit; }

    $case_id = (int)($_POST['case_id'] ?? 0);
    $case_code = trim($_POST['case_code'] ?? '');
    $ownerCan = can_manage_pending_case($pdo, $case_id);
    if (empty($_SESSION['user']) || (!is_admin() && !$ownerCan)) {
        flash('error', 'Unauthorized.');
        header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit;
    }

    if ($case_id <= 0) { flash('error', 'Invalid case.'); header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit; }

    $case_name_for_log = '';
    try { $s0 = $pdo->prepare('SELECT case_name FROM cases WHERE id = ? LIMIT 1'); $s0->execute([$case_id]); $r0 = $s0->fetch(); $case_name_for_log = $r0['case_name'] ?? ''; } catch (Throwable $e) {}
    log_case_event($pdo, $case_id, 'case_deleted', $case_name_for_log !== '' ? $case_name_for_log : $case_code, 'Case deleted');

    // Collect file paths for later removal
    $files = [];
    try {
        $s = $pdo->prepare('SELECT filepath FROM evidence WHERE case_id = ?');
        $s->execute([$case_id]);
        $files = $s->fetchAll();
    } catch (Throwable $e) { $_SESSION['sql_error'] = $e->getMessage();
log_console('ERROR', 'SQL: ' . $e->getMessage()); }

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
log_console('ERROR', 'SQL: ' . $e->getMessage());
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
// Handle save redaction mask (redaction mask handler)
if (($_POST['action'] ?? '') === 'save_redaction_mask') {
    throttle();
    if (!check_csrf()) { flash('error', 'Security check failed.'); header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit; }
    if (empty($_SESSION['user']) || (($_SESSION['user']['role'] ?? '') !== 'admin')) { flash('error', 'Unauthorized.'); header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit; }
    $evidence_id = (int)($_POST['evidence_id'] ?? 0);
    $mask_json = $_POST['mask_json'] ?? '';
    if ($evidence_id <= 0) { flash('error', 'Invalid evidence.'); header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit; }
    $decoded = json_decode($mask_json, true);
    $maskDir = __DIR__ . '/uploads/redactions';
    if (!is_dir($maskDir)) { @mkdir($maskDir, 0755, true); }
    $maskFile = $maskDir . '/mask_' . $evidence_id . '.json';
    $ok = @file_put_contents($maskFile, $mask_json);
    if ($ok === false) {
        flash('error', 'Unable to save redaction mask.');
    } else {
        $regions = is_array($decoded) ? count($decoded) : 0;
        // Determine case_id from evidence
        try {
            $q = $pdo->prepare('SELECT case_id, title FROM evidence WHERE id = ? LIMIT 1');
            $q->execute([$evidence_id]);
            $er = $q->fetch();
            if ($er) {
                log_case_event($pdo, (int)$er['case_id'], 'redactions_saved', $er['title'] ?? ('Evidence #'.$evidence_id), 'Regions: '.$regions, $evidence_id, null);
            }
        } catch (Throwable $e) {}
        flash('success', 'Redaction mask saved.');
    }
    $ru = trim($_POST['redirect_url'] ?? ''); if ($ru!==''){header('Location: '.$ru); exit;} header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit;
}
}

// Handle removal request submission (public)
if (($_POST['action'] ?? '') === 'submit_removal') {
    throttle();
    if (!check_csrf()) { flash('error', 'Security check failed.'); header('Location: ?view=removal#removal'); exit; }

    $full_name = trim($_POST['full_name'] ?? '');
    $email = trim($_POST['email'] ?? '');
    $phone = trim($_POST['phone'] ?? '');
    $org = trim($_POST['organization'] ?? '');
    $target_url = trim($_POST['target_url'] ?? '');
    $justification = trim($_POST['justification'] ?? '');

    if ($full_name === '' || !filter_var($email, FILTER_VALIDATE_EMAIL) || $target_url === '' || $justification === '') {
        flash('error', 'Please complete all required fields (Full name, valid Email, URL, and Justification).');
        header('Location: ?view=removal#removal'); exit;
    }

    try {
        $ins = $pdo->prepare('INSERT INTO removal_requests (full_name, email, phone, organization, target_url, justification, status) VALUES (?,?,?,?,?,?,"Pending")');
        $ins->execute([$full_name, $email, $phone !== '' ? $phone : null, $org !== '' ? $org : null, $target_url, $justification]);
        flash('success', 'Your request was submitted. Our admins will review it.');
        log_console('INFO', 'Removal request submitted for URL: ' . $target_url);
    } catch (Throwable $e) {
        $_SESSION['sql_error'] = $e->getMessage();
        log_console('ERROR', 'SQL: ' . $e->getMessage());
        flash('error', 'Unable to submit removal request.');
    }
    header('Location: ?view=removal#removal'); exit;
}

// Handle update removal request status (admin only)
if (($_POST['action'] ?? '') === 'update_removal_status') {
    throttle();
    if (!check_csrf()) { flash('error', 'Security check failed.'); header('Location: ?view=removal#removal'); exit; }
    if (!is_admin()) { flash('error', 'Unauthorized.'); header('Location: ?view=removal#removal'); exit; }

    $rid = (int)($_POST['removal_id'] ?? 0);
    $status = trim($_POST['status'] ?? 'Pending');
    $allowed = ['Pending','Declined','In Review','Approved / Closed'];
    if (!in_array($status, $allowed, true)) { $status = 'Pending'; }

    if ($rid <= 0) { flash('error', 'Invalid request.'); header('Location: ?view=removal#removal'); exit; }
    try {
        $u = $pdo->prepare('UPDATE removal_requests SET status = ? WHERE id = ? LIMIT 1');
        $u->execute([$status, $rid]);
        flash('success', 'Removal request status updated to ' . htmlspecialchars($status));
        log_console('SUCCESS', 'Removal request #' . $rid . ' status set to ' . $status);
    } catch (Throwable $e) {
        $_SESSION['sql_error'] = $e->getMessage();
        log_console('ERROR', 'SQL: ' . $e->getMessage());
        flash('error', 'Unable to update status.');
    }
    header('Location: ?view=removal#removal'); exit;
}

// Handle delete removal request (admin only)
if (($_POST['action'] ?? '') === 'delete_removal') {
    throttle();
    if (!check_csrf()) { flash('error', 'Security check failed.'); header('Location: ?view=removal#removal'); exit; }
    if (!is_admin()) { flash('error', 'Unauthorized.'); header('Location: ?view=removal#removal'); exit; }

    $rid = (int)($_POST['removal_id'] ?? 0);
    if ($rid <= 0) { flash('error', 'Invalid request.'); header('Location: ?view=removal#removal'); exit; }
    try {
        $d = $pdo->prepare('DELETE FROM removal_requests WHERE id = ? LIMIT 1');
        $d->execute([$rid]);
        flash('success', 'Removal request deleted.');
        log_console('SUCCESS', 'Removal request #' . $rid . ' deleted');
    } catch (Throwable $e) {
        $_SESSION['sql_error'] = $e->getMessage();
        log_console('ERROR', 'SQL: ' . $e->getMessage());
        flash('error', 'Unable to delete removal request.');
    }
    header('Location: ?view=removal#removal'); exit;
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
log_console('ERROR', 'SQL: ' . $e->getMessage());
        flash('error', 'Unable to delete user.');
    }
    header('Location: '. $ru); exit;
}

// --- Face / Evidence Scanner: POST handler ---
$scanResults = [];
$scanError   = '';
$scanDone    = false;

if (($view ?? '') === 'scanner' && $_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'face_scan') {
    throttle();
    if (!function_exists('imagecreatetruecolor')) {
        $scanError = 'Image processing (GD library) is not available on this server.';
    } elseif (!check_csrf()) {
        $scanError = 'Security check failed. Please refresh and try again.';
    } elseif (empty($_FILES['scan_image']['name']) || ($_FILES['scan_image']['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) {
        $scanError = 'Please upload a valid image file.';
    } elseif (($_FILES['scan_image']['size'] ?? 0) > 10 * 1024 * 1024) {
        $scanError = 'Image must be under 10 MB.';
    } else {
        $f = $_FILES['scan_image'];
        $detMime = @mime_content_type($f['tmp_name']) ?: '';
        $allowedMimes = ['image/jpeg','image/jpg','image/png','image/webp','image/gif','image/bmp'];
        if (!in_array($detMime, $allowedMimes, true)) {
            $scanError = 'Unsupported file type. Please upload a JPEG, PNG, WebP, or GIF image.';
        } else {
            $rawData  = @file_get_contents($f['tmp_name']);
            $queryImg = ($rawData !== false) ? @imagecreatefromstring($rawData) : false;
            if (!$queryImg || !($queryImg instanceof GdImage)) {
                $scanError = 'Could not decode the uploaded image. Please try a different file.';
            } else {
                // Warm cosine cache before loops
                tp_scanner_dct_cos(32);

                // ── Query-image features (computed once) ──────────────────────
                // Full pHash + center-crop pHash are computed from the query only.
                // Per-candidate we use the fast prepare_pixels path (1 GD op each).
                $qPixels = tp_scanner_prepare_pixels($queryImg);
                $qPhash  = tp_scanner_phash_from_pixels($qPixels);
                $qDhash  = tp_scanner_dhash_from_pixels($qPixels);
                $qAhash  = tp_scanner_ahash_from_pixels($qPixels);
                // Center-crop pHash for face-region sensitivity (query only)
                $qCrop   = tp_scanner_center_crop($queryImg);
                $qCPhash = tp_scanner_phash(($qCrop));
                imagedestroy($qCrop);
                imagedestroy($queryImg);

                $uploadsRoot = realpath(__DIR__ . '/uploads');
                $sensFilter  = is_admin() ? '' : "AND c.sensitivity != 'Sealed'";
                $scored      = [];

                // ── Scoring formula (weights sum to 1.0) ──────────────────────
                // pHash full   40% – DCT structural fingerprint
                // pHash crop   20% – query face-region vs candidate full image
                // dHash        25% – edge/gradient direction
                // aHash        15% – luminance structure
                // All candidate hashes derived from ONE 32×32 pixel array (no extra GD ops)

                // ── 1. Score person profile photos ────────────────────────────
                try {
                    $sensWhere2 = is_admin()
                        ? "WHERE status = 'Verified'"
                        : "WHERE status = 'Verified' AND sensitivity != 'Sealed'";
                    $pq = $pdo->query(
                        "SELECT case_code, case_name, person_name, tiktok_username, status, sensitivity, location
                         FROM cases $sensWhere2 ORDER BY id DESC"
                    );
                    foreach ($pq->fetchAll() as $pr) {
                        $photoRel = find_person_photo_url($pr['case_code']);
                        if ($photoRel === '') continue;
                        $cImg = tp_scanner_load_image(__DIR__ . '/' . $photoRel);
                        if (!$cImg) continue;
                        $cp    = tp_scanner_prepare_pixels($cImg); // 1 GD op
                        imagedestroy($cImg);
                        $score = 0.40 * tp_scanner_hamming_sim($qPhash,  tp_scanner_phash_from_pixels($cp))
                               + 0.20 * tp_scanner_hamming_sim($qCPhash, tp_scanner_phash_from_pixels($cp))
                               + 0.25 * tp_scanner_hamming_sim($qDhash,  tp_scanner_dhash_from_pixels($cp))
                               + 0.15 * tp_scanner_hamming_sim($qAhash,  tp_scanner_ahash_from_pixels($cp));
                        $pct = round($score * 100, 1);
                        $key = $pr['case_code'];
                        if (!isset($scored[$key]) || $scored[$key]['pct'] < $pct) {
                            $scored[$key] = [
                                'pct'             => $pct,
                                'case_code'       => $pr['case_code'],
                                'case_name'       => $pr['case_name'],
                                'person_name'     => $pr['person_name'],
                                'tiktok_username' => $pr['tiktok_username'],
                                'status'          => $pr['status'],
                                'sensitivity'     => $pr['sensitivity'],
                                'location'        => $pr['location'] ?? '',
                                'photo_url'       => $photoRel,
                                'match_source'    => 'profile_photo',
                                'evidence_id'     => null,
                                'evidence_title'  => '',
                            ];
                        }
                    }
                } catch (Throwable $ex) { /* non-fatal */ }

                // ── 2. Score image evidence files ─────────────────────────────
                try {
                    $sq = $pdo->query(
                        "SELECT e.id, e.filepath, e.mime_type, e.title,
                                c.case_code, c.case_name, c.person_name, c.tiktok_username,
                                c.status, c.sensitivity, c.location
                         FROM evidence e
                         JOIN cases c ON c.id = e.case_id
                         WHERE e.type = 'image'
                           AND e.mime_type LIKE 'image/%'
                           AND c.status = 'Verified'
                           $sensFilter
                         ORDER BY e.id DESC
                         LIMIT 400"
                    );
                    foreach ($sq->fetchAll() as $row) {
                        $absPath = __DIR__ . '/' . ltrim($row['filepath'], '/');
                        $absReal = @realpath($absPath);
                        if (!$absReal || !$uploadsRoot || strncmp($absReal, $uploadsRoot, strlen($uploadsRoot)) !== 0) {
                            continue;
                        }
                        $cImg = tp_scanner_load_image($absReal);
                        if (!$cImg) continue;
                        $cp    = tp_scanner_prepare_pixels($cImg); // 1 GD op
                        imagedestroy($cImg);
                        $score = 0.40 * tp_scanner_hamming_sim($qPhash,  tp_scanner_phash_from_pixels($cp))
                               + 0.20 * tp_scanner_hamming_sim($qCPhash, tp_scanner_phash_from_pixels($cp))
                               + 0.25 * tp_scanner_hamming_sim($qDhash,  tp_scanner_dhash_from_pixels($cp))
                               + 0.15 * tp_scanner_hamming_sim($qAhash,  tp_scanner_ahash_from_pixels($cp));
                        $pct      = round($score * 100, 1);
                        $key      = $row['case_code'];
                        $photoRel = find_person_photo_url($row['case_code']);
                        if (!isset($scored[$key]) || $scored[$key]['pct'] < $pct) {
                            $scored[$key] = [
                                'pct'            => $pct,
                                'case_code'      => $row['case_code'],
                                'case_name'      => $row['case_name'],
                                'person_name'    => $row['person_name'],
                                'tiktok_username'=> $row['tiktok_username'],
                                'status'         => $row['status'],
                                'sensitivity'    => $row['sensitivity'],
                                'location'       => $row['location'] ?? '',
                                'photo_url'      => $photoRel ?: ('?action=serve_evidence&id=' . (int)$row['id']),
                                'match_source'   => $photoRel ? 'evidence_with_photo' : 'evidence_image',
                                'evidence_id'    => (int)$row['id'],
                                'evidence_title' => $row['title'],
                            ];
                        }
                    }
                } catch (Throwable $ex) { /* non-fatal */ }

                // Sort descending, keep top 10 above 15%
                usort($scored, fn($a, $b) => $b['pct'] <=> $a['pct']);
                $scanResults = array_values(array_slice(
                    array_filter($scored, fn($r) => $r['pct'] >= 15.0), 0, 10
                ));
                $scanDone = true;
                log_console('INFO', 'Face scanner: scanned evidence+photos, ' . count($scanResults) . ' results >= 15%.');
            }
        }
    }
}

// Handle logout
if (isset($_GET['logout'])) {
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        // Clear session cookie for both apex and www on HTTP/HTTPS
        $tp_cookie_domain = '.tiktokpredators.com';
        $tp_cookie_path   = '/';
        // Expire both the non-secure and secure variants
        @setcookie(session_name(), '', time() - 42000, $tp_cookie_path, $tp_cookie_domain, false, true);
        @setcookie(session_name(), '', time() - 42000, $tp_cookie_path, $tp_cookie_domain, true,  true);
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
  <title>TikTokPredators — Case's & Evidence</title>
  <link rel="apple-touch-icon" sizes="57x57" href="/assets/favicon/apple-icon-57x57.png">
  <link rel="apple-touch-icon" sizes="60x60" href="/assets/favicon/apple-icon-60x60.png">
  <link rel="apple-touch-icon" sizes="72x72" href="/assets/favicon/apple-icon-72x72.png">
  <link rel="apple-touch-icon" sizes="76x76" href="/assets/favicon/apple-icon-76x76.png">
  <link rel="apple-touch-icon" sizes="114x114" href="/assets/favicon/apple-icon-114x114.png">
  <link rel="apple-touch-icon" sizes="120x120" href="/assets/favicon/apple-icon-120x120.png">
  <link rel="apple-touch-icon" sizes="144x144" href="/assets/favicon/apple-icon-144x144.png">
  <link rel="apple-touch-icon" sizes="152x152" href="/assets/favicon/apple-icon-152x152.png">
  <link rel="apple-touch-icon" sizes="180x180" href="/assets/favicon/apple-icon-180x180.png">
  <link rel="icon" type="image/png" sizes="192x192"  href="/assets/favicon/android-icon-192x192.png">
  <link rel="icon" type="image/png" sizes="32x32" href="/assets/favicon/favicon-32x32.png">
  <link rel="icon" type="image/png" sizes="96x96" href="/favicon-96x96.png">
  <link rel="icon" type="image/png" sizes="16x16" href="/assets/favicon/favicon-16x16.png">
  <link rel="manifest" href="/assets/favicon/manifest.json">
  <meta name="msapplication-TileColor" content="#ffffff">
  <meta name="msapplication-TileImage" content="/assets/favicon/ms-icon-144x144.png">
  <meta name="theme-color" content="#ffffff">
  <meta name="description" content="A public, auditable repository documenting abusive behaviour by TikTok accounts — case records, evidence, and verifiable proof to expose predators and support accountability." />
  <!-- Open Graph / Social sharing -->
  <meta property="og:title" content="TikTokPredators — Cases & Evidence" />
  <meta property="og:description" content="A public, auditable repository documenting abusive behaviour by TikTok accounts. We collect case records, evidence, and verifiable proof to expose predators and support accountability on the TikTok platform." />
  <meta property="og:type" content="website" />
  <meta property="og:url" content="https://tiktokpredators.com/" />
  <meta property="og:site_name" content="TikTokPredators" />
  <meta property="og:image" content="https://tiktokpredators.com/assets/og-image.png" />
  <meta name="twitter:card" content="summary_large_image" />
  <meta name="twitter:title" content="TikTokPredators — Cases & Evidence" />
  <meta name="twitter:description" content="A public, auditable repository documenting abusive behaviour by TikTok accounts. We collect case records, evidence, and verifiable proof to expose predators and support accountability on the TikTok platform." />
  <meta name="twitter:image" content="https://tiktokpredators.com/assets/og-image.png" />
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" />
  <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css" rel="stylesheet" />
  <link href="https://cdn.datatables.net/1.13.8/css/dataTables.bootstrap5.min.css" rel="stylesheet" />

  <!-- Bootstrap JS (required for modal/tabs) -->
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
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
    .evidence-modal #evPreview img {
      width: auto;
      max-width: 100%;
      max-height: 75vh;
      margin: 0 auto;
      object-fit: contain;
    }
    
    /* Restricted-mode media blurring (non-admins on Restricted cases) */
    footer a { color: inherit }
  </style>
</head>
<body>
  <!-- Ownership banner -->
  <div role="banner" style="background:#3a0f4a;color:#ffffff;font-weight:700;text-align:center;padding:10px 12px;">
    This site is owned and operated by Jamie Whittingham | <a href="https://www.tiktok.com/@jamiewhittinghamofficial" target="_blank" rel="noopener noreferrer" style="color:#ffffff;text-decoration:underline;">Mouldy Sausage</a>
  </div>

  <?php if ($msg = flash('success')): ?>
    <div class="alert alert-success border-0 rounded-0 mb-0 text-center"><?php echo $msg; ?></div>
  <?php endif; ?>


<!-- Auth Modal -->
<div class="modal fade" id="authModal" tabindex="-1" aria-hidden="true">
  <div class="modal-dialog modal-dialog-centered">
    <div class="modal-content">
      <div class="modal-header">
        <h5 class="modal-title"><i class="bi bi-person-lock me-2"></i>Account</h5>
        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
      </div>
      <div class="modal-body">

        <ul class="nav nav-tabs" id="authTabs" role="tablist">
          <li class="nav-item" role="presentation">
            <button class="nav-link active" id="tab-login" data-bs-toggle="tab" data-bs-target="#pane-login" type="button" role="tab" aria-controls="pane-login" aria-selected="true">
              <i class="bi bi-box-arrow-in-right me-1"></i> Login
            </button>
          </li>
          <li class="nav-item" role="presentation">
            <button class="nav-link" id="tab-register" data-bs-toggle="tab" data-bs-target="#pane-register" type="button" role="tab" aria-controls="pane-register" aria-selected="false">
              <i class="bi bi-person-plus me-1"></i> Register
            </button>
          </li>
        </ul>

        <div class="tab-content pt-3" id="authTabsContent">
          <!-- Login pane -->
          <div class="tab-pane fade show active" id="pane-login" role="tabpanel" aria-labelledby="tab-login" tabindex="0">
            <form method="post" action="">
              <input type="hidden" name="action" value="login">
              <?php csrf_field(); ?>
              <div class="mb-3">
                <label for="login_email" class="form-label">Email</label>
                <input type="email" class="form-control" id="login_email" name="email" placeholder="you@example.com" required>
              </div>
              <div class="mb-3">
                <label for="login_password" class="form-label">Password</label>
                <input type="password" class="form-control" id="login_password" name="password" minlength="8" required>
              </div>
              <div class="d-grid">
                <button type="submit" class="btn btn-primary">
                  <i class="bi bi-box-arrow-in-right me-1"></i> Sign in
                </button>
              </div>
            </form>
          </div>

          <!-- Register pane -->
          <div class="tab-pane fade" id="pane-register" role="tabpanel" aria-labelledby="tab-register" tabindex="0">
            <form method="post" action="">
              <input type="hidden" name="action" value="register">
              <?php csrf_field(); ?>
              <div class="mb-3">
                <label for="reg_display_name" class="form-label">Display Name</label>
                <input type="text" class="form-control" id="reg_display_name" name="display_name" required>
              </div>
              <div class="mb-3">
                <label for="reg_email" class="form-label">Email</label>
                <input type="email" class="form-control" id="reg_email" name="email" placeholder="you@example.com" required>
              </div>
              <div class="mb-3">
                <label for="reg_password" class="form-label">Password</label>
                <input type="password" class="form-control" id="reg_password" name="password" minlength="8" required>
              </div>
              <div class="mb-3">
                <label for="reg_password_confirm" class="form-label">Confirm Password</label>
                <input type="password" class="form-control" id="reg_password_confirm" name="password_confirm" minlength="8" required>
              </div>
              <div class="form-check mb-3">
                <input class="form-check-input" type="checkbox" value="1" id="reg_agree" name="agree" required>
                <label class="form-check-label" for="reg_agree">
                  I agree to the Terms and Privacy Policy
                </label>
              </div>
              <div class="d-grid">
                <button type="submit" class="btn btn-primary">
                  <i class="bi bi-person-plus me-1"></i> Create account
                </button>
              </div>
            </form>
          </div>
        </div>

      </div>
    </div>
  </div>
</div>

<!-- Open the auth modal on demand and select correct tab -->
<script>
(function(){
  var authModalEl = document.getElementById('authModal');
  if (authModalEl) {
    authModalEl.addEventListener('show.bs.modal', function (ev) {
      var trigger = ev.relatedTarget;
      var wanted = trigger && trigger.getAttribute('data-auth-tab');
      if (wanted === 'register') {
        var tabBtn = document.getElementById('tab-register');
        if (tabBtn) new bootstrap.Tab(tabBtn).show();
      } else if (wanted === 'login') {
        var tabBtn = document.getElementById('tab-login');
        if (tabBtn) new bootstrap.Tab(tabBtn).show();
      }
    });
  }
})();
</script>

<?php if (!empty($openAuth)): ?>
<script>
document.addEventListener('DOMContentLoaded', function(){
  var modalEl = document.getElementById('authModal');
  if (!modalEl) return;
  var modal = new bootstrap.Modal(modalEl);
  modal.show();
  <?php if ($openAuth === 'register'): ?>
    var tabBtn = document.getElementById('tab-register');
    if (tabBtn) new bootstrap.Tab(tabBtn).show();
  <?php else: ?>
    var tabBtn = document.getElementById('tab-login');
    if (tabBtn) new bootstrap.Tab(tabBtn).show();
  <?php endif; ?>
});
</script>
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
<?php if (is_logged_in()): ?>
  <li class="nav-item"><a class="nav-link <?php echo ($view==='pending')?'active':''; ?>" href="?view=pending#pending">Pending Cases</a></li>
<?php endif; ?>
<?php if (!empty($_SESSION['user']) && ($_SESSION['user']['role'] ?? '') === 'viewer'): ?>
  <li class="nav-item"><a class="nav-link <?php echo ($view==='submit_case')?'active':''; ?>" href="?view=submit_case#submit-case">Submit Case</a></li>
<?php endif; ?>
<?php if (is_admin()): ?>
  <li class="nav-item"><a class="nav-link <?php echo ($view==='users')?'active':''; ?>" href="?view=users#users">Users</a></li>
  <li class="nav-item"><a class="nav-link <?php echo ($view==='viewer_stats')?'active':''; ?>" href="?view=viewer_stats#viewer-stats">Viewer Stats</a></li>
  <li class="nav-item">
    <a class="nav-link" href="#" data-bs-toggle="modal" data-bs-target="#devModal">Dev</a>
  </li>
<?php endif; ?>
  <li class="nav-item"><a class="nav-link <?php echo ($view==='faq')?'active':''; ?>" href="?view=faq#faq">FAQ</a></li>
  <li class="nav-item"><a class="nav-link <?php echo ($view==='scanner')?'active':''; ?>" href="?view=scanner#scanner"><i class="bi bi-camera-fill me-1"></i>Face Scanner</a></li>
    
      </ul>
      <ul class="navbar-nav ms-auto mb-2 mb-lg-0 align-items-center">
        <?php if (is_logged_in()): ?>
          <li class="nav-item dropdown">
            <a class="nav-link dropdown-toggle d-flex align-items-center" href="#" role="button" data-bs-toggle="dropdown" aria-expanded="false">
              <i class="bi bi-person-circle me-2"></i>
              <span class="d-none d-md-inline"><?php echo htmlspecialchars($_SESSION['user']['email'] ?? ''); ?></span>
            </a>
            <ul class="dropdown-menu dropdown-menu-end">
              <li class="dropdown-header">
                <div class="fw-semibold"><?php echo htmlspecialchars($_SESSION['user']['display_name'] ?? ($_SESSION['user']['email'] ?? 'User')); ?></div>
                <div class="small text-secondary">Role: <?php echo htmlspecialchars($_SESSION['user']['role'] ?? 'viewer'); ?></div>
              </li>
              <?php if (is_admin()): ?>
              <li><hr class="dropdown-divider"></li>
              <li><a class="dropdown-item" href="#" data-bs-toggle="modal" data-bs-target="#devModal"><i class="bi bi-tools me-2"></i>Dev</a></li>
              <?php endif; ?>
              <li><hr class="dropdown-divider"></li>
              <li><a class="dropdown-item" href="?logout=1"><i class="bi bi-box-arrow-right me-2"></i>Logout</a></li>
            </ul>
          </li>
        <?php else: ?>
          <li class="nav-item me-2">
            <a class="btn btn-outline-light btn-sm" href="#" data-bs-toggle="modal" data-bs-target="#authModal" data-auth-tab="login"><i class="bi bi-box-arrow-in-right me-1"></i> Login</a>
          </li>
          <li class="nav-item">
            <a class="btn btn-primary btn-sm" href="#" data-bs-toggle="modal" data-bs-target="#authModal" data-auth-tab="register"><i class="bi bi-person-plus me-1"></i> Register</a>
          </li>
        <?php endif; ?>
      </ul>
      </div>
    </div>
  </nav>

  <?php if (($view ?? '') === 'removal_request'): ?>
  <?php
    if (!is_admin()) { header('Location: ?view=removal#removal'); exit; }
    $rid = (int)($_GET['id'] ?? 0);
    $req = null;
    if ($rid > 0) {
      try {
        $s = $pdo->prepare("SELECT id, full_name, email, phone, organization, target_url, justification, status, created_at, updated_at FROM removal_requests WHERE id = ? LIMIT 1");
        $s->execute([$rid]);
        $req = $s->fetch();
        $isLocked = ($req && $req['status'] === 'Approved / Closed');
      } catch (Throwable $e) {
        $_SESSION['sql_error'] = $_SESSION['sql_error'] ?? $e->getMessage();
      }
    }
    if (!$req) {
      flash('error', 'Removal request not found.');
      header('Location: ?view=removal#removal'); exit;
    }
  ?>
  <main class="container-xl my-4" id="removal-request">
    <div class="d-flex align-items-center justify-content-between mb-3">
      <h1 class="h4 mb-0"><i class="bi bi-eye me-2"></i>Removal Request #<?php echo (int)$req['id']; ?></h1>
      <div class="d-flex gap-2">
        <a href="?view=removal#removal" class="btn btn-outline-secondary"><i class="bi bi-arrow-left me-1"></i>Back to Requests</a>
        <form method="post" action="" onsubmit="return confirm('Delete this removal request?');">
          <input type="hidden" name="action" value="delete_removal">
          <?php csrf_field(); ?>
          <input type="hidden" name="removal_id" value="<?php echo (int)$req['id']; ?>">

          <?php if ($isLocked): ?>
              <button type="button" class="btn btn-outline-danger" disabled>
                  <i class="bi bi-trash me-1"></i>Delete
              </button>
          <?php else: ?>
              <button type="submit" class="btn btn-outline-danger">
                  <i class="bi bi-trash me-1"></i>Delete
              </button>
          <?php endif; ?>
      </form>

      </div>
    </div>

    <div class="row g-4">
      <div class="col-lg-7">
        <div class="card">
          <div class="card-header">
            <h2 class="h6 mb-0">Submitted Details</h2>
          </div>
          <div class="card-body">
            <div class="row g-3">
              <div class="col-md-6">
                <label class="form-label">Full name</label>
                <input type="text" class="form-control" value="<?php echo htmlspecialchars($req['full_name']); ?>" readonly>
              </div>
              <div class="col-md-6">
                <label class="form-label">Organization</label>
                <input type="text" class="form-control" value="<?php echo htmlspecialchars($req['organization'] ?? ''); ?>" readonly>
              </div>
              <div class="col-md-6">
                <label class="form-label">Email</label>
                <div><a href="mailto:<?php echo htmlspecialchars($req['email']); ?>"><?php echo htmlspecialchars($req['email']); ?></a></div>
              </div>
              <div class="col-md-6">
                <label class="form-label">Phone</label>
                <div><a href="<?php echo $req['phone'] ? 'tel:'.htmlspecialchars($req['phone']) : '#'; ?>"><?php echo htmlspecialchars($req['phone'] ?? ''); ?></a></div>
              </div>
              <div class="col-12">
                <label class="form-label">Target URL</label>
                <div><a href="<?php echo htmlspecialchars($req['target_url']); ?>" target="_blank" rel="noopener"><?php echo htmlspecialchars($req['target_url']); ?></a></div>
              </div>
              <div class="col-12">
                <label class="form-label">Justification</label>
                <textarea class="form-control" rows="8" readonly><?php echo htmlspecialchars($req['justification']); ?></textarea>
              </div>
            </div>
          </div>
          <div class="card-footer d-flex align-items-center justify-content-between">
            <small class="text-body-secondary">Created: <?php echo htmlspecialchars($req['created_at']); ?></small>
            <small class="text-body-secondary">Updated: <?php echo htmlspecialchars($req['updated_at']); ?></small>
          </div>
        </div>
      </div>

      <div class="col-lg-5">
        <div class="card">
          <div class="card-header">
            <h2 class="h6 mb-0">Admin Actions</h2>
          </div>
          <div class="card-body">
            <form method="post" action="" class="row g-3">
              <input type="hidden" name="action" value="update_removal_status">
              <?php csrf_field(); ?>
              <input type="hidden" name="removal_id" value="<?php echo (int)$req['id']; ?>">
              <div class="col-12">
                <label for="rr_status" class="form-label">Status</label>
                <select id="rr_status" class="form-select" name="status">
                  <?php
                    $opts = ['Pending','In Review','Declined','Approved / Closed'];
                    foreach ($opts as $opt) {
                      $sel = ($opt === ($req['status'] ?? 'Pending')) ? ' selected' : '';
                      echo '<option value="'.htmlspecialchars($opt).'"'.$sel.'>'.htmlspecialchars($opt).'</option>';
                    }
                  ?>
                </select>
              </div>
              <div class="col-12 d-flex gap-2">
                <button type="submit" class="btn btn-primary"><i class="bi bi-check2-circle me-1"></i>Update Status</button>
                <a href="?view=removal#removal" class="btn btn-outline-secondary">Cancel</a>
              </div>
            </form>
          </div>
        </div>

        <div class="card mt-3">
          <div class="card-header">
            <h2 class="h6 mb-0">Quick Links</h2>
          </div>
          <div class="card-body">
            <a href="<?php echo htmlspecialchars($req['target_url']); ?>" class="btn btn-outline-light w-100 mb-2" target="_blank" rel="noopener">
              <i class="bi bi-box-arrow-up-right me-1"></i> Open Target URL
            </a>
            <a href="mailto:<?php echo htmlspecialchars($req['email']); ?>" class="btn btn-outline-light w-100">
              <i class="bi bi-envelope me-1"></i> Email Submitter
            </a>
          </div>
        </div>
      </div>
    </div>
  </main>
<?php endif; ?>

<?php if ($view === 'removal'): ?>
  <main class="py-4" id="removal">
    <div class="container-xl">
      <?php if (!is_admin()): ?>
        <div class="row">
          <div class="col-lg-7 mx-auto">
            <div class="card glass mb-4">
              <div class="card-header d-flex align-items-center justify-content-between">
                <h5 class="mb-0"><i class="bi bi-shield-x me-2"></i>Takedown / Removal Request</h5>
              </div>
              <div class="card-body">
                <form method="post" action="">
                  <input type="hidden" name="action" value="submit_removal">
                  <?php csrf_field(); ?>
                  <div class="row g-3">
                    <div class="col-md-6">
                      <label class="form-label">Full name*</label>
                      <input type="text" name="full_name" class="form-control" required>
                    </div>
                    <div class="col-md-6">
                      <label class="form-label">Email*</label>
                      <input type="email" name="email" class="form-control" required>
                    </div>
                    <div class="col-md-6">
                      <label class="form-label">Phone</label>
                      <input type="text" name="phone" class="form-control" placeholder="Optional">
                    </div>
                    <div class="col-md-6">
                      <label class="form-label">Organization</label>
                      <input type="text" name="organization" class="form-control" placeholder="Optional">
                    </div>
                    <div class="col-12">
                      <label class="form-label">URL to the evidence or case*</label>
                      <input type="url" name="target_url" class="form-control" placeholder="https://tiktokpredators.com/?view=case&code=..." required>
                    </div>
                    <div class="col-12">
                      <label class="form-label">Justification*</label>
                      <textarea name="justification" rows="6" class="form-control" placeholder="Explain why this item should be reviewed or removed." required></textarea>
                    </div>
                  </div>
                  <div class="d-grid mt-3">
                    <button type="submit" class="btn btn-primary"><i class="bi bi-send me-1"></i> Submit request</button>
                  </div>
                </form>
              </div>
            </div>
          </div>
        </div>
      <?php endif; ?>

      <?php if (is_admin()): ?>
        <?php
          try {
              $reqs = $pdo->query("SELECT id, full_name, email, phone, organization, target_url, justification, status, created_at FROM removal_requests ORDER BY created_at DESC LIMIT 200")->fetchAll();
          } catch (Throwable $e) { $reqs = []; }
        ?>
        <div class="card glass">
          <div class="card-header d-flex align-items-center justify-content-between">
            <h5 class="mb-0"><i class="bi bi-inbox me-2"></i>Removal Requests</h5>
          </div>
          <div class="card-body">
            <?php if (!$reqs): ?>
              <div class="text-secondary">No removal requests yet.</div>
            <?php else: ?>
              <div class="table-responsive">
                <table class="table align-middle table-hover">
                  <thead>
                    <tr>
                      <th scope="col">#</th>
                      <th scope="col">Submitted</th>
                      <th scope="col">Name</th>
                      <th scope="col">Email</th>
                      <th scope="col">URL</th>
                      <th scope="col">Status</th>
                      <th scope="col" class="text-end">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    <?php foreach ($reqs as $r): ?>
                      <tr>
                        <td><?php echo (int)$r['id']; ?></td>
                        <td class="small text-secondary"><?php echo htmlspecialchars($r['created_at']); ?></td>
                        <td><?php echo htmlspecialchars($r['full_name']); ?></td>
                        <td><a href="mailto:<?php echo htmlspecialchars($r['email']); ?>"><?php echo htmlspecialchars($r['email']); ?></a></td>
                        <td class="text-truncate" style="max-width:280px;"><a href="<?php echo htmlspecialchars($r['target_url']); ?>" target="_blank" rel="noopener"><?php echo htmlspecialchars($r['target_url']); ?></a></td>
                        <td>
                            <?php
                            $status = $r['status'];
                            $badgeClass = 'secondary'; // default

                            switch ($status) {
                                case 'Pending':
                                    $badgeClass = 'warning'; // yellow
                                    break;
                                case 'In Review':
                                    $badgeClass = 'info'; // blue
                                    break;
                                case 'Declined':
                                    $badgeClass = 'danger'; // red
                                    break;
                                case 'Approved':
                                case 'Closed':
                                case 'Approved / Closed':
                                    $badgeClass = 'success'; // green
                                    break;
                            }
                            ?>
                            <span class="badge text-bg-<?php echo $badgeClass; ?>">
                                <?php echo htmlspecialchars($status); ?>
                            </span>
                        </td>
                        <td class="text-end">
                          <div class="btn-group">
                            <a class="btn btn-sm btn-outline-primary" href="?view=removal_request&amp;id=<?php echo (int)$r['id']; ?>#removal-request">
                              <i class="bi bi-eye me-1"></i>View
                            </a>
                            <?php $isLocked = (($row['status'] ?? $r['status'] ?? '') === 'Approved / Closed'); ?>

                            <form method="post" action="" onsubmit="return confirm('Delete this removal request?');">
                                <?php csrf_field(); ?>
                                <input type="hidden" name="action" value="delete_removal">
                                <input type="hidden" name="removal_id" value="<?php echo (int)$r['id']; ?>">

                                <?php if ($isLocked): ?>
                                    <button type="button" class="btn btn-danger btn-sm" disabled>
                                        <i class="bi bi-trash"></i> Delete
                                    </button>
                                <?php else: ?>
                                    <button type="submit" class="btn btn-danger btn-sm">
                                        <i class="bi bi-trash"></i> Delete
                                    </button>
                                <?php endif; ?>
                            </form>
                          </div>
                        </td>
                      </tr>
                    <?php endforeach; ?>
                  </tbody>
                </table>
              </div>

              <?php foreach ($reqs as $r): ?>
                <div class="modal fade" id="modalRemoval<?php echo (int)$r['id']; ?>" tabindex="-1" aria-hidden="true">
                  <div class="modal-dialog modal-lg modal-dialog-scrollable">
                    <div class="modal-content">
                      <div class="modal-header">
                        <h5 class="modal-title"><i class="bi bi-file-earmark-text me-2"></i>Removal Request #<?php echo (int)$r['id']; ?></h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                      </div>
                      <div class="modal-body">
                        <dl class="row mb-0">
                          <dt class="col-sm-3">Submitted</dt><dd class="col-sm-9"><?php echo htmlspecialchars($r['created_at']); ?></dd>
                          <dt class="col-sm-3">Full name</dt><dd class="col-sm-9"><?php echo htmlspecialchars($r['full_name']); ?></dd>
                          <dt class="col-sm-3">Email</dt><dd class="col-sm-9"><a href="mailto:<?php echo htmlspecialchars($r['email']); ?>"><?php echo htmlspecialchars($r['email']); ?></a></dd>
                          <dt class="col-sm-3">Phone</dt><dd class="col-sm-9"><?php echo htmlspecialchars($r['phone'] ?? ''); ?></dd>
                          <dt class="col-sm-3">Organization</dt><dd class="col-sm-9"><?php echo htmlspecialchars($r['organization'] ?? ''); ?></dd>
                          <dt class="col-sm-3">URL</dt><dd class="col-sm-9"><a href="<?php echo htmlspecialchars($r['target_url']); ?>" target="_blank" rel="noopener"><?php echo htmlspecialchars($r['target_url']); ?></a></dd>
                          <dt class="col-sm-3">Justification</dt><dd class="col-sm-9"><pre class="mb-0" style="white-space: pre-wrap;"><?php echo htmlspecialchars($r['justification']); ?></pre></dd>
                        </dl>
                      </div>
                      <div class="modal-footer d-flex align-items-center justify-content-between">
                        <div>Current status: <span class="badge text-bg-secondary"><?php echo htmlspecialchars($r['status']); ?></span></div>
                        <form method="post" action="">
                          <?php csrf_field(); ?>
                          <input type="hidden" name="action" value="update_removal_status">
                          <input type="hidden" name="removal_id" value="<?php echo (int)$r['id']; ?>">
                          <div class="input-group">
                            <label class="input-group-text" for="removalStatus<?php echo (int)$r['id']; ?>">Set status</label>
                            <select id="removalStatus<?php echo (int)$r['id']; ?>" name="status" class="form-select">
                              <?php foreach (['Pending','Declined','In Review','Approved / Closed'] as $opt): ?>
                                <option value="<?php echo $opt; ?>" <?php echo ($r['status'] === $opt ? 'selected' : ''); ?>><?php echo $opt; ?></option>
                              <?php endforeach; ?>
                            </select>
                            <button class="btn btn-primary" type="submit"><i class="bi bi-check2-circle me-1"></i>Update</button>
                          </div>
                        </form>
                      </div>
                    </div>
                  </div>
                </div>
              <?php endforeach; ?>
            <?php endif; ?>
          </div>
        </div>
      <?php endif; ?>
    </div>
  </main>
<?php endif; ?>
        </ul>
        
      </div>
    </div>
  </nav>

  <script>
  // Ensure Bootstrap dropdowns initialize even if data-api is disrupted
  document.addEventListener('DOMContentLoaded', function(){
    try {
      var triggers = document.querySelectorAll('[data-bs-toggle="dropdown"]');
      for (var i = 0; i < triggers.length; i++) {
        new bootstrap.Dropdown(triggers[i]);
      }
    } catch (e) { /* no-op */ }
  });
  </script>

  <?php
  // --- Owner Pending Case Edit Controls (viewer can edit like admin while Pending)
  if ($view === 'case') {
      $case_code_param = trim($_GET['code'] ?? '');
      if ($case_code_param !== '') {
          try {
              $stmt = $pdo->prepare('SELECT id, case_code, case_name, person_name, location, tiktok_username, initial_summary, sensitivity, status FROM cases WHERE case_code = ? LIMIT 1');
              $stmt->execute([$case_code_param]);
              $caseRow = $stmt->fetch();
          } catch (Throwable $e) { $caseRow = null; }
          if ($caseRow) {
              $ownerCanInline = can_manage_pending_case($pdo, (int)$caseRow['id']);
              if ($ownerCanInline) {
                  // Owner can edit while Pending — show compact edit form
                  ?>
                  <main class="py-3" id="owner-edit">
                    <div class="container-xl">
                      <div class="alert alert-info d-flex align-items-start glass">
                        <i class="bi bi-pencil-square me-2 fs-5"></i>
                        <div>
                          <div class="fw-semibold">You opened this case and it is currently <span class="text-warning">Pending</span>.</div>
                          <div class="small">You may edit the Case Details and manage evidence until an admin changes the status.</div>
                        </div>
                      </div>
                      <div class="card glass mb-4">
                        <div class="card-body">
                          <div class="d-flex align-items-center justify-content-between mb-2">
                            <h2 class="h6 mb-0"><i class="bi bi-sliders me-2"></i>Edit Case Details</h2>
                            <div class="d-flex gap-2">
                              <button class="btn btn-primary btn-sm" data-bs-toggle="modal" data-bs-target="#addEvidenceModal"><i class="bi bi-cloud-plus me-1"></i> Add Evidence</button>
                              <a class="btn btn-outline-light btn-sm" href="?view=case&amp;code=<?php echo urlencode($caseRow['case_code']); ?>#case-view"><i class="bi bi-arrow-repeat me-1"></i>Refresh</a>
                            </div>
                          </div>
                          <form method="post" action="" enctype="multipart/form-data" class="mt-2">
                            <input type="hidden" name="action" value="update_case">
                            <?php csrf_field(); ?>
                            <input type="hidden" name="case_id" value="<?php echo (int)$caseRow['id']; ?>">
                            <input type="hidden" name="case_code" value="<?php echo htmlspecialchars($caseRow['case_code']); ?>">
                            <div class="row">
                              <div class="col-md-6 mb-3">
                                <label class="form-label">Case Name</label>
                                <input type="text" name="case_name" class="form-control" value="<?php echo htmlspecialchars($caseRow['case_name'] ?? ''); ?>" required>
                              </div>
                              <div class="col-md-6 mb-3">
                                <label class="form-label">Person Name</label>
                                <input type="text" name="person_name" class="form-control" value="<?php echo htmlspecialchars($caseRow['person_name'] ?? ''); ?>">
                              </div>
                            </div>
                            <div class="row">
                              <div class="col-md-6 mb-3">
                                <label class="form-label">Location</label>
                                <input type="text" name="location" class="form-control" value="<?php echo htmlspecialchars($caseRow['location'] ?? ''); ?>" placeholder="City, region, or country">
                              </div>
                            </div>
                            <div class="row">
                              <div class="col-md-6 mb-3">
                                <label class="form-label">TikTok Username</label>
                                <div class="input-group">
                                  <span class="input-group-text">@</span>
                                  <input type="text" name="tiktok_username" class="form-control" value="<?php echo htmlspecialchars(ltrim((string)$caseRow['tiktok_username'], '@')); ?>">
                                </div>
                              </div>
                              <div class="col-md-6 mb-3">
                                <label class="form-label">Person Photo (optional)</label>
                                <input type="file" name="person_photo" class="form-control" accept="image/*">
                              </div>
                            </div>
                            <div class="mb-3">
                              <label class="form-label">Summary</label>
                              <textarea name="initial_summary" class="form-control" rows="4" required><?php echo htmlspecialchars($caseRow['initial_summary'] ?? ''); ?></textarea>
                            </div>
                            <div class="row">
                              <div class="col-md-6 mb-3">
                                <input type="hidden" name="sensitivity" value="Standard">
                              </div>
                              <div class="col-md-6 mb-3">
                                <input type="hidden" name="status" value="Pending">
                              </div>
                            </div>
                            <div class="d-flex gap-2">
                              <button type="submit" class="btn btn-primary"><i class="bi bi-save me-1"></i>Save Changes</button>
                              <a href="?view=case&amp;code=<?php echo urlencode($caseRow['case_code']); ?>#case-view" class="btn btn-outline-light">Cancel</a>
                            </div>
                          </form>
                        </div>
                      </div>
                      <?php
                      // --- Owner's own evidence list for this Pending case
                      try {
                          $myUid = (int)($_SESSION['user']['id'] ?? 0);
                          $evStmt = $pdo->prepare('SELECT id, title, type, filepath, created_at FROM evidence WHERE case_id = ? AND uploaded_by = ? ORDER BY created_at DESC');
                          $evStmt->execute([(int)$caseRow['id'], $myUid]);
                          $myEvidence = $evStmt->fetchAll() ?: [];
                      } catch (Throwable $e) { $myEvidence = []; }
                      if ($myEvidence):
                      ?>
                      <div class="card glass mb-4">
                        <div class="card-body">
                          <div class="d-flex align-items-center justify-content-between mb-2">
                            <h2 class="h6 mb-0"><i class="bi bi-collection me-2"></i>Your Evidence</h2>
                          </div>
                          <div class="table-responsive">
                            <table class="table table-sm align-middle mb-0">
                              <thead>
                                <tr>
                                  <th style="width:40%">Title</th>
                                  <th>Type</th>
                                  <th>Added</th>
                                  <th class="text-end" style="width:220px">Actions</th>
                                </tr>
                              </thead>
                              <tbody>
                                <?php foreach ($myEvidence as $ev): ?>
                                  <tr>
                                    <td><?php echo htmlspecialchars($ev['title'] ?? ('Evidence #'.$ev['id'])); ?></td>
                                    <td class="text-secondary"><?php echo htmlspecialchars($ev['type'] ?? 'other'); ?></td>
                                    <td class="text-secondary small"><?php echo htmlspecialchars($ev['created_at'] ?? ''); ?></td>
                                    <td class="text-end">
                                      <?php
                                      $isUrl = ($ev['type'] ?? '') === 'url';
                                      $viewHref = $isUrl ? ($ev['filepath'] ?? '#') : ('?action=serve_evidence&amp;id='.(int)$ev['id']);
                                      $viewAttrs = $isUrl ? ' target="_blank" rel="noopener"' : ' target="_blank"';
                                      ?>
                                      <!--
                                      <a href="<?php echo $viewHref; ?>"<?php echo $viewAttrs; ?> class="btn btn-outline-light btn-sm"><i class="bi bi-eye me-1"></i>View</a>
                                      <a href="#"
                                         class="btn btn-outline-light btn-sm"
                                         data-bs-toggle="modal"
                                         data-bs-target="#editEvidenceModal<?php echo (int)$ev['id']; ?>">
                                         <i class="bi bi-pencil me-1"></i>Edit
                                      </a>
                                      -->
                                      <form method="post" action="" class="d-inline" onsubmit="return confirm('Delete this evidence? This cannot be undone.');">
                                        <input type="hidden" name="action" value="delete_evidence">
                                        <?php csrf_field(); ?>
                                        <input type="hidden" name="evidence_id" value="<?php echo (int)$ev['id']; ?>">
                                        <input type="hidden" name="case_id" value="<?php echo (int)$caseRow['id']; ?>">
                                        <input type="hidden" name="redirect_url" value="?view=case&amp;code=<?php echo urlencode($caseRow['case_code']); ?>#case-view">
                                        <button type="submit" class="btn btn-danger btn-sm"><i class="bi bi-trash me-1"></i>Delete</button>
                                      </form>
                                    </td>
                                  </tr>
                                  <!-- Minimal inline Edit modal reusing update_evidence -->
                                  <div class="modal fade" id="editEvidenceModal<?php echo (int)$ev['id']; ?>" tabindex="-1" aria-hidden="true">
                                    <div class="modal-dialog modal-dialog-centered">
                                      <div class="modal-content">
                                        <div class="modal-header">
                                          <h5 class="modal-title"><i class="bi bi-pencil me-2"></i>Edit Evidence</h5>
                                          <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                                        </div>
                                        <form method="post" action="">
                                          <div class="modal-body">
                                            <input type="hidden" name="action" value="update_evidence">
                                            <?php csrf_field(); ?>
                                            <input type="hidden" name="evidence_id" value="<?php echo (int)$ev['id']; ?>">
                                            <input type="hidden" name="case_id" value="<?php echo (int)$caseRow['id']; ?>">
                                            <input type="hidden" name="redirect_url" value="?view=case&amp;code=<?php echo urlencode($caseRow['case_code']); ?>#case-view">
                                            <div class="mb-3">
                                              <label class="form-label">Title</label>
                                              <input type="text" name="title" class="form-control" value="<?php echo htmlspecialchars($ev['title'] ?? ''); ?>" required>
                                            </div>
                                            <div class="mb-3">
                                              <label class="form-label">Type</label>
                                              <select name="type" class="form-select">
                                                <?php
                                                $allowedTypes = ['image','video','audio','pdf','doc','url','other'];
                                                foreach ($allowedTypes as $t) {
                                                    $sel = (($ev['type'] ?? 'other') === $t) ? ' selected' : '';
                                                    echo '<option value="'.htmlspecialchars($t).'"'.$sel.'>'.htmlspecialchars(ucfirst($t)).'</option>';
                                                }
                                                ?>
                                              </select>
                                            </div>
                                            <div class="mb-3" id="owner-url-wrap-<?php echo (int)$ev['id']; ?>" style="<?php echo (($ev['type'] ?? '') === 'url') ? '' : 'display:none;'; ?>">
                                              <label class="form-label">Destination URL</label>
                                              <input type="url" name="url_value" class="form-control" value="<?php echo (($ev['type'] ?? '') === 'url') ? htmlspecialchars($ev['filepath'] ?? '') : ''; ?>" placeholder="https://example.com/page">
                                            </div>
                                          </div>
                                          <div class="modal-footer">
                                            <button type="button" class="btn btn-outline-light" data-bs-dismiss="modal">Cancel</button>
                                            <button type="submit" class="btn btn-primary"><i class="bi bi-save me-1"></i>Save</button>
                                          </div>
                                        </form>
                                      </div>
                                    </div>
                                  </div>
                                  <script>
                                  (function(){
                                    var modal = document.getElementById('editEvidenceModal<?php echo (int)$ev['id']; ?>');
                                    if (modal) {
                                      modal.addEventListener('shown.bs.modal', function(){
                                        var sel = modal.querySelector('select[name="type"]');
                                        var urlDiv = document.getElementById('owner-url-wrap-<?php echo (int)$ev['id']; ?>');
                                        if (sel && urlDiv) {
                                          sel.addEventListener('change', function(){
                                            if (this.value === 'url') { urlDiv.style.display = ''; }
                                            else { urlDiv.style.display = 'none'; }
                                          }, { once: true });
                                        }
                                      });
                                    }
                                  })();
                                  </script>
                                <?php endforeach; ?>
                              </tbody>
                            </table>
                          </div>
                        </div>
                      </div>
                      <?php else: ?>
                        <div class="card glass mb-4">
                          <div class="card-body">
                            <div class="small text-secondary">You haven't uploaded any evidence yet.</div>
                          </div>
                        </div>
                      <?php endif; ?>
                    </div>
                  </main>
                  <?php
              }
          }
      }
  }
  ?>



  <!-- Cases Grid + Right Rail -->
  <?php if ($view === 'cases'): ?>
  <?php log_case_view($pdo, 0); ?>
  <main class="py-4" id="cases">
    <div class="container-xl">
      <div class="row g-4">
        <div class="col-12 case-grid">
          <div class="d-flex align-items-center justify-content-between mb-2">
            <h2 class="h4 mb-0">Recent Cases</h2>
            <div class="d-flex align-items-center">
              <form class="d-none d-md-flex me-2" method="get" action="" role="search">
                <input type="hidden" name="view" value="cases">
                <input type="search" name="q" class="form-control form-control-sm" placeholder="Search names, usernames, summary…" value="<?php echo htmlspecialchars($_GET['q'] ?? ''); ?>" />
                <button type="submit" class="btn btn-outline-light btn-sm ms-1"><i class="bi bi-search"></i></button>
              </form>
              <div class="btn-group">
                <?php if (!empty($_SESSION['user']) && ($_SESSION['user']['role'] ?? '') === 'admin'): ?>
                  <button class="btn btn-primary btn-sm" data-bs-toggle="modal" data-bs-target="#createCaseModal"><i class="bi bi-folder-plus me-1"></i> Add Case</button>
                <?php elseif (!empty($_SESSION['user']) && ($_SESSION['user']['role'] ?? '') === 'viewer'): ?>
                  <a class="btn btn-primary btn-sm" href="?view=submit_case#submit-case"><i class="bi bi-folder-plus me-1"></i> Submit Case</a>
                <?php endif; ?>
              </div>
            </div>
          </div>
          <?php
          // --- SEARCH variable for search bar and results hint
          $search = trim($_GET['q'] ?? '');
          ?>
          <?php if (!empty($search)): ?>
            <div class="text-secondary small mb-2">Showing results for “<?php echo htmlspecialchars($search); ?>”.</div>
          <?php endif; ?>
          <div class="row g-3 row-cols-1 row-cols-md-2">
<?php
try {
  $search = trim($_GET['q'] ?? '');
  if ($search !== '') {
    $like = '%' . $search . '%';
    $stmt = $pdo->prepare("
      SELECT c.id, c.case_code, c.case_name, c.person_name, c.tiktok_username, c.initial_summary, c.status, c.sensitivity, c.opened_at,
             COALESCE(ev.cnt, 0) AS evidence_count,
             COALESCE(cv.cnt, 0) AS case_view_count,
             COALESCE(ev.last_added, c.opened_at) AS last_activity
      FROM cases c
      LEFT JOIN (
        SELECT case_id, COUNT(*) AS cnt, MAX(created_at) AS last_added
        FROM evidence
        GROUP BY case_id
      ) ev ON ev.case_id = c.id
      LEFT JOIN (
        SELECT case_id, COUNT(*) AS cnt
        FROM case_views
        GROUP BY case_id
      ) cv ON cv.case_id = c.id
      WHERE c.status <> 'Pending'
        AND (c.case_name LIKE ? OR c.person_name LIKE ? OR c.tiktok_username LIKE ? OR c.initial_summary LIKE ?)
      ORDER BY last_activity DESC
      LIMIT 1000
    ");
    $stmt->execute([$like, $like, $like, $like]);
    $rs = $stmt->fetchAll();
  } else {
    $sql = "SELECT c.id, c.case_code, c.case_name, c.person_name, c.tiktok_username, c.initial_summary, c.status, c.sensitivity, c.opened_at,
                   COALESCE(ev.cnt, 0) AS evidence_count,
                   COALESCE(cv.cnt, 0) AS case_view_count,
                   COALESCE(ev.last_added, c.opened_at) AS last_activity
            FROM cases c
            LEFT JOIN (
              SELECT case_id, COUNT(*) AS cnt, MAX(created_at) AS last_added
              FROM evidence
              GROUP BY case_id
            ) ev ON ev.case_id = c.id
            LEFT JOIN (
              SELECT case_id, COUNT(*) AS cnt
              FROM case_views
              GROUP BY case_id
            ) cv ON cv.case_id = c.id
            WHERE c.status <> 'Pending'
            ORDER BY last_activity DESC
            LIMIT 1000";
    $rs = $pdo->query($sql)->fetchAll();
  }
} catch (Throwable $e) {
  $_SESSION['sql_error'] = $e->getMessage();
log_console('ERROR', 'SQL: ' . $e->getMessage());
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
    $vwc   = (int)($row['case_view_count'] ?? 0);
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
      <?php } else { ?>
        <div class="placeholder-tile card-img-top">
          <div class="text">No Image</div>
        </div>
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
          <?php
        $badgeClass = 'dark'; // default

        switch ($status) {
            case 'Pending':
                $badgeClass = 'warning'; // yellow
                break;
            case 'Open':
                $badgeClass = 'primary'; // blue
                break;
            case 'In Review':
                $badgeClass = 'info'; // light blue
                break;
            case 'Verified':
                $badgeClass = 'success'; // green
                break;
            case 'Closed':
                $badgeClass = 'danger'; // red
                break;
        }
        ?>
        <span class="badge rounded-pill text-bg-<?php echo $badgeClass; ?> border">
            <?php echo htmlspecialchars($status); ?>
        </span>

        </div>
        <p class="small mt-3 mb-2 text-secondary"><?php echo htmlspecialchars($sum); ?></p>
        <div class="mt-2 d-flex gap-2 flex-wrap">
          <span class="badge text-bg-dark border"><i class="bi bi-files me-1"></i><?php echo $evc; ?> evidence</span>
          <span class="badge text-bg-dark border"><i class="bi bi-shield-lock me-1"></i><?php echo htmlspecialchars($sens); ?></span>
          <span class="badge text-bg-dark border" title="Last activity">
            <i class="bi bi-clock-history me-1"></i><?php echo htmlspecialchars(date('d M Y H:i', strtotime($last))); ?>
          </span>
          <span class="badge text-bg-dark border"><i class="bi bi-eye me-1"></i><?php echo $vwc; ?> views</span>
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

 

  <?php if ($view === 'submit_case'): ?>
  <main class="py-4" id="submit-case">
    <div class="container-xl">
      <div class="row g-4">
        <div class="col-12 col-lg-10 col-xl-8 mx-auto">
          <div class="card glass">
            <div class="card-body">
              <div class="d-flex align-items-center justify-content-between mb-2">
                <h2 class="h5 mb-0"><i class="bi bi-folder-plus me-2"></i>Submit a Case for Review</h2>
                <a class="btn btn-outline-light btn-sm" href="?view=cases#cases"><i class="bi bi-arrow-left me-1"></i> Back to Cases</a>
              </div>
              <?php if (empty($_SESSION['user']) || (($_SESSION['user']['role'] ?? '') !== 'viewer')): ?>
                <div class="alert alert-secondary mb-0">You must be logged in as a <strong>viewer</strong> to submit a case.</div>
              <?php else: ?>
                <?php if (!empty($formError)) : ?>
                  <div class="alert alert-danger"><?php echo htmlspecialchars($formError); ?></div>
                <?php endif; ?>
                <form method="post" action="" enctype="multipart/form-data" class="mt-3">
                  <input type="hidden" name="action" value="viewer_submit_case">
                  <?php csrf_field(); ?>
                  <div class="mb-3">
                    <label class="form-label">Case Name <span class="text-danger">*</span></label>
                    <input type="text" name="case_name" class="form-control" required>
                  </div>
                  <div class="row">
                    <div class="col-md-6 mb-3">
                      <label class="form-label">Person Name</label>
                      <input type="text" name="person_name" class="form-control">
                    </div>
                    <div class="col-md-6 mb-3">
                      <label class="form-label">Location</label>
                      <input type="text" name="location" class="form-control" placeholder="City, region, or country">
                    </div>
                  </div>
                  <div class="row">
                    <div class="col-md-6 mb-3">
                      <label class="form-label">TikTok Username</label>
                      <div class="input-group">
                        <span class="input-group-text">@</span>
                        <input type="text" name="tiktok_username" class="form-control" placeholder="username (optional)">
                      </div>
                    </div>
                  </div>
                  <div class="mb-3">
                    <label class="form-label">Summary <span class="text-danger">*</span></label>
                    <textarea name="initial_summary" class="form-control" rows="4" placeholder="Describe the concern and context." required></textarea>
                  </div>
                  <div class="mb-3">
                    <label class="form-label">Person Photo (optional)</label>
                    <input type="file" name="person_photo" class="form-control" accept="image/*">
                  </div>
                  <div class="alert alert-secondary small">
                    Submitting creates a <strong>Pending</strong> case visible only to admins. While your case is Pending, <em>you</em> can upload additional evidence. Admins will review and may change status.
                  </div>
                  <div class="d-grid">
                    <button class="btn btn-primary" type="submit"><i class="bi bi-cloud-upload me-1"></i> Submit Case</button>
                  </div>
                </form>
              <?php endif; ?>
            </div>
          </div>
        </div>
      </div>
    </div>
  </main>
  <?php endif; ?>

  <?php if ($view === 'pending'): ?>
  <main class="py-4" id="pending">
    <div class="container-xl">
      <div class="row g-4">
        <div class="col-12">
          <div class="card glass">
            <div class="card-body">
              <div class="d-flex align-items-center justify-content-between mb-3">
                <h2 class="h5 mb-0"><i class="bi bi-hourglass-split me-2"></i>Pending Cases</h2>
                <a class="btn btn-outline-light btn-sm" href="?view=cases#cases"><i class="bi bi-arrow-left me-1"></i> Back to Cases</a>
              </div>
  <?php
    // Build dataset based on role
    $rows = [];
    try {
        $baseSql = "
          SELECT c.id, c.case_code, c.case_name, c.person_name, c.status, c.created_by,
                 u.display_name AS creator_name,
                 COALESCE(ev.cnt, 0) AS evidence_count,
                 COALESCE(ev.last_added, c.opened_at) AS last_activity
          FROM cases c
          LEFT JOIN (
            SELECT case_id, COUNT(*) AS cnt, MAX(created_at) AS last_added
            FROM evidence
            GROUP BY case_id
          ) ev ON ev.case_id = c.id
          LEFT JOIN users u ON u.id = c.created_by
          WHERE c.status = 'Pending'
        ";
        if (is_admin()) {
            $sql = $baseSql . " ORDER BY last_activity DESC";
            $stmt = $pdo->prepare($sql);
            $stmt->execute();
        } else {
            // Viewer: only own pending cases
            $sql = $baseSql . " AND c.created_by = ? ORDER BY last_activity DESC";
            $stmt = $pdo->prepare($sql);
            $stmt->execute([ $_SESSION['user']['id'] ?? 0 ]);
        }
        $rows = $stmt->fetchAll();
    } catch (Throwable $e) {
        $_SESSION['sql_error'] = $e->getMessage();
log_console('ERROR', 'SQL: ' . $e->getMessage());
        $rows = [];
    }
  ?>
  <?php if ($rows && count($rows) > 0): ?>
              <div class="table-responsive">
                <table class="table table-sm align-middle mb-0">
                  <thead>
                    <tr>
                      <th style="width: 12rem;" class="text-nowrap">Case Code</th>
                      <th class="text-nowrap">Case Name</th>
                      <th class="text-nowrap">Submitted By</th>
                      <th style="width: 16rem;" class="text-nowrap">Subject</th>
                      <th style="width: 10rem;" class="text-nowrap">Evidence</th>
                      <th style="width: 14rem;" class="text-nowrap">Last Activity</th>
                      <th style="width: 18rem;" class="text-end text-nowrap">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                  <?php foreach ($rows as $r):
                      $code = $r['case_code'];
                      $name = $r['case_name'] ?: $code;
                      $person = $r['person_name'] ?: '';
                      $evc = (int)($r['evidence_count'] ?? 0);
                      $last = $r['last_activity'] ?? '';
                      $creatorName = trim($r['creator_name'] ?? '');
                  ?>
                    <tr>
                      <td class="text-nowrap"><span class="badge text-bg-dark border"><?php echo htmlspecialchars($code); ?></span></td>
                      <td class="fw-semibold text-nowrap"><?php echo htmlspecialchars($name); ?></td>
                      <td class="text-nowrap"><?php echo $creatorName !== '' ? htmlspecialchars($creatorName) : '—'; ?></td>
                      <td class="text-nowrap"><?php echo htmlspecialchars($person !== '' ? $person : '—'); ?></td>
                      <td class="text-nowrap"><?php echo $evc; ?></td>
                      <td class="text-nowrap"><?php echo htmlspecialchars($last ? date('d M Y H:i', strtotime($last)) : '—'); ?></td>
                      <td class="text-end text-nowrap">                        
                          <a class="btn btn-primary btn-sm" href="?view=case&code=<?php echo urlencode($code); ?>#case-view"><i class="bi bi-pencil-square me-1"></i>Edit</a>
                          <form method="post" action="" class="d-inline" onsubmit="return confirm('Delete this case and all evidence? This cannot be undone.');">
                            <input type="hidden" name="action" value="delete_case">
                            <?php csrf_field(); ?>
                            <input type="hidden" name="case_id" value="<?php echo (int)$r['id']; ?>">
                            <input type="hidden" name="case_code" value="<?php echo htmlspecialchars($code); ?>">
                            <button type="submit" class="btn btn-outline-danger btn-sm"><i class="bi bi-trash me-1"></i>Delete</button>
                          </form>
                        
                      </td>
                    </tr>
                  <?php endforeach; ?>
                  </tbody>
                </table>
              </div>
  <?php else: ?>
              <div class="alert alert-secondary mb-0">No pending cases to show.</div>
  <?php endif; ?>
            </div>
          </div>
        </div>
      </div>
    </div>
  </main>
  <?php endif; ?>

  <?php if ($view === 'faq'): ?>
  <main class="py-4" id="faq">
    <div class="container-xl">
      <div class="row g-4">
        <div class="col-12">
          <div class="card glass">
            <div class="card-body">
              <div class="d-flex align-items-center justify-content-between mb-2">
                <h2 class="h4 mb-0">Frequently Asked Questions</h2>
                <a class="btn btn-outline-light btn-sm" href="?view=cases#cases"><i class="bi bi-arrow-left me-1"></i> Back to Cases</a>
              </div>
              <p class="text-secondary small mb-4">This information is for general guidance about how we present and handle content on this site. It is not legal advice.</p>

              <div class="accordion" id="faqAccordion">
                <!-- DBS Checks -->
                <div class="accordion-item">
                  <h2 class="accordion-header" id="faq-dbs-heading">
                    <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#faq-dbs" aria-expanded="false" aria-controls="faq-dbs">
                      What are the different types of DBS checks in the UK?
                    </button>
                  </h2>
                  <div id="faq-dbs" class="accordion-collapse collapse" aria-labelledby="faq-dbs-heading" data-bs-parent="#faqAccordion">
                    <div class="accordion-body">
                      <p>DBS (Disclosure and Barring Service) checks are background checks used in England and Wales to help organisations make safer recruitment decisions. There are four main levels, each showing different information:</p>

                      <h6>Basic DBS Check</h6>
                      <ul>
                        <li><strong>Shows:</strong> Only unspent convictions held on the Police National Computer (PNC).</li>
                        <li><strong>Does not show:</strong> Spent convictions, cautions, reprimands, warnings, local police information, or barred list information.</li>
                        <li><strong>Who can apply:</strong> Any individual for themselves or via an employer.</li>
                        <li><strong>Typical uses:</strong> Roles where only basic honesty or integrity needs confirming, e.g. retail, delivery, some financial services.</li>
                      </ul>

                      <h6>Standard DBS Check</h6>
                      <ul>
                        <li><strong>Shows:</strong> Both spent and unspent convictions, cautions, reprimands and final warnings recorded on the PNC (subject to filtering rules).</li>
                        <li><strong>Does not show:</strong> Local police intelligence or barred list information.</li>
                        <li><strong>Who can request:</strong> Employers/organisations, not individuals, and only for roles legally entitled to this level.</li>
                        <li><strong>Typical uses:</strong> Accountants, legal professionals, security roles not involving vulnerable groups.</li>
                      </ul>

                      <h6>Enhanced DBS Check</h6>
                      <ul>
                        <li><strong>Shows:</strong> Everything a Standard check shows <em>plus</em> any relevant information held by local police forces (for example, investigations, allegations, or intelligence considered pertinent).</li>
                        <li><strong>Does not show:</strong> Barred list information unless specifically requested; information irrelevant to the role should be excluded by police disclosure officers.</li>
                        <li><strong>Who can request:</strong> Employers/organisations entitled by law, for roles working closely with children or vulnerable adults.</li>
                        <li><strong>Typical uses:</strong> Teachers, healthcare professionals, social workers, foster carers.</li>
                      </ul>

                      <h6>Enhanced DBS with Barred List Check</h6>
                      <ul>
                        <li><strong>Shows:</strong> Everything an Enhanced check shows <em>plus</em> a check against the children’s barred list, the adults’ barred list, or both, depending on the role.</li>
                        <li><strong>Does not show:</strong> Information beyond the scope of police records and barred lists; filtering rules still apply for old/minor convictions.</li>
                        <li><strong>Who can request:</strong> Only for positions legally classed as “regulated activity” with children and/or vulnerable adults.</li>
                        <li><strong>Typical uses:</strong> School teachers, childcare workers, medical staff providing direct care, care‑home workers.</li>
                      </ul>

                      <p class="small text-secondary">Filtering rules: Certain old and minor convictions/cautions are “filtered” and will not appear on Standard or Enhanced checks after a set period. The DBS filtering guidance defines exactly what is filtered and what is not.</p>
                    </div>
                  </div>
                </div>

                <!-- Sealed Cases -->
                <div class="accordion-item">
                  <h2 class="accordion-header" id="faq-sealed-heading">
                    <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#faq-sealed" aria-expanded="false" aria-controls="faq-sealed">
                      Why might a case be marked as “Sealed”?
                    </button>
                  </h2>
                  <div id="faq-sealed" class="accordion-collapse collapse" aria-labelledby="faq-sealed-heading" data-bs-parent="#faqAccordion">
                    <div class="accordion-body">
                      <p>We mark a case as <strong>Sealed</strong> when public access should be restricted. Typical reasons include:</p>
                      <ul>
                        <li>Active law‑enforcement investigation or court order limiting publication.</li>
                        <li>Risk of identifying victims, minors, or vulnerable persons.</li>
                        <li>Sensitive personal data (e.g., medical/educational records) that cannot be lawfully shared.</li>
                        <li>Takedown requests that meet our safety, privacy, or defamation policies.</li>
                      </ul>
                      <p class="small text-secondary">When sealed, we may hide or remove public content and limit visibility to authorised administrators.</p>
                    </div>
                  </div>
                </div>

                <!-- Evidence Policy -->
                <div class="accordion-item">
                  <h2 class="accordion-header" id="faq-evidence-heading">
                    <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#faq-evidence" aria-expanded="false" aria-controls="faq-evidence">
                      What types of evidence can be displayed, and what must be redacted?
                    </button>
                  </h2>
                  <div id="faq-evidence" class="accordion-collapse collapse" aria-labelledby="faq-evidence-heading" data-bs-parent="#faqAccordion">
                    <div class="accordion-body">
                      <p>We aim to share information responsibly. As a rule:</p>
                      <ul>
                        <li><strong>Allowed (subject to review):</strong> screenshots, images, PDFs, and links that document publicly visible behaviour relevant to a case.</li>
                        <li><strong>Must be redacted:</strong> addresses, phone numbers, emails, account IDs, IPs, exact locations, dates of birth, bank/payment details, or any data that can identify minors or private individuals who are not public figures.</li>
                        <li><strong>Not permitted:</strong> doxxing materials, stolen/hacked data, intimate images, malware, instructions for wrongdoing, or content under a valid takedown/court order.</li>
                      </ul>
                      <p>Where a case’s <em>Sensitivity</em> is set to <strong>Restricted</strong>, public viewers see server‑side blurred media, and some evidence may be withheld entirely.</p>
                      <p class="small text-secondary">We review reports and may remove or further redact materials to protect safety and comply with the law.</p>
                    </div>
                  </div>
                </div>

                <!-- Redaction & Blurring -->
                <div class="accordion-item">
                  <h2 class="accordion-header" id="faq-redaction-heading">
                    <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#faq-redaction" aria-expanded="false" aria-controls="faq-redaction">
                      How do you handle redaction and image/video blurring?
                    </button>
                  </h2>
                  <div id="faq-redaction" class="accordion-collapse collapse" aria-labelledby="faq-redaction-heading" data-bs-parent="#faqAccordion">
                    <div class="accordion-body">
                      <p>We combine <em>server‑side</em> blurring for restricted cases with manual redactions where necessary to remove sensitive details from images, documents, and logs. Public viewers cannot bypass server‑side protections to access unredacted files.</p>
                    </div>
                  </div>
                </div>

                <!-- Reporting and Takedowns -->
                <div class="accordion-item">
                  <h2 class="accordion-header" id="faq-report-heading">
                    <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#faq-report" aria-expanded="false" aria-controls="faq-report">
                      How can someone request a correction, removal, or takedown?
                    </button>
                  </h2>
                  <div id="faq-report" class="accordion-collapse collapse" aria-labelledby="faq-report-heading" data-bs-parent="#faqAccordion">
                    <div class="accordion-body">
                      <p>Please contact us via the site’s contact options with the case code, URLs, and a brief explanation. We will review within a reasonable timeframe and may request verification.</p>
                    </div>
                  </div>
                </div>

                <!-- Use of External Links -->
                <div class="accordion-item">
                  <h2 class="accordion-header" id="faq-links-heading">
                    <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#faq-links" aria-expanded="false" aria-controls="faq-links">
                      Do you host external links and social profiles?
                    </button>
                  </h2>
                  <div id="faq-links" class="accordion-collapse collapse" aria-labelledby="faq-links-heading" data-bs-parent="#faqAccordion">
                    <div class="accordion-body">
                      <p>We may include URLs as evidence to provide context. External sites can change without notice and are outside our control. We may replace links with screenshots where appropriate.</p>
                    </div>
                  </div>
                </div>
              </div>

              <div class="alert alert-secondary mt-4 mb-0 small">
                <i class="bi bi-shield-lock me-2"></i>
                <strong>Reminder:</strong> Content presented here is for transparency and safety. We balance public interest with privacy and legal responsibilities.
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </main>
  <?php endif; ?>

  <!-- ══════════════════════════════════════════════════════════
       Face / Evidence Scanner
  ══════════════════════════════════════════════════════════ -->
  <?php if ($view === 'scanner'): ?>
  <main class="py-4" id="scanner">
    <div class="container-xl">

      <!-- Page header -->
      <div class="d-flex align-items-center gap-3 mb-4">
        <div class="rounded-circle bg-primary bg-opacity-10 d-flex align-items-center justify-content-center" style="width:54px;height:54px;flex-shrink:0;">
          <i class="bi bi-camera-fill fs-3 text-primary"></i>
        </div>
        <div>
          <h1 class="h3 mb-0 fw-bold">Face &amp; Evidence Scanner</h1>
          <p class="text-secondary mb-0 small">Upload a photo to search for visual matches across all case evidence and profile photos.</p>
        </div>
      </div>

      <!-- Disclaimer -->
      <div class="alert alert-warning d-flex gap-2 mb-4" role="alert">
        <i class="bi bi-exclamation-triangle-fill fs-5 flex-shrink-0 mt-1"></i>
        <div>
          <strong>Similarity analysis — not definitive identification.</strong>
          Results are based on perceptual image hashing and colour histogram comparison.
          A high match percentage indicates visual similarity; it is <em>not</em> a confirmed identity match.
          Always corroborate findings through independent investigation.
          Sealed cases are excluded from public results.
        </div>
      </div>

      <!-- Upload form -->
      <div class="card glass mb-4">
        <div class="card-body">
          <h2 class="h5 mb-3"><i class="bi bi-upload me-2 text-primary"></i>Upload Image to Scan</h2>
          <form method="post" action="?view=scanner#scanner-results" enctype="multipart/form-data" id="scannerForm">
            <input type="hidden" name="action" value="face_scan">
            <?php csrf_field(); ?>

            <!-- Drag-drop zone -->
            <div class="dropzone mb-3 position-relative" id="scanDropzone" style="cursor:pointer;"
                 onclick="document.getElementById('scan_image_input').click()">
              <i class="bi bi-person-bounding-box display-4 d-block mb-2 text-primary"></i>
              <p class="mb-1 fw-semibold">Drag &amp; drop an image here, or click to browse</p>
              <small class="text-secondary">JPEG · PNG · WebP · GIF &nbsp;·&nbsp; Max 10 MB</small>
              <div id="scanPreviewWrap" class="mt-3 d-none">
                <img id="scanPreviewImg" src="" alt="Preview" class="rounded" style="max-height:200px;max-width:100%;object-fit:contain;">
                <p class="text-success small mt-1 mb-0" id="scanPreviewName"></p>
              </div>
            </div>
            <input type="file" name="scan_image" id="scan_image_input" accept="image/*" class="d-none" required>

            <?php if ($scanError !== ''): ?>
              <div class="alert alert-danger mb-3"><i class="bi bi-exclamation-circle me-2"></i><?php echo htmlspecialchars($scanError); ?></div>
            <?php endif; ?>

            <div class="d-flex gap-2 align-items-center">
              <button type="submit" class="btn btn-primary px-4" id="scanBtn">
                <i class="bi bi-search me-2"></i>Scan for Matches
              </button>
              <span class="text-secondary small">Images are processed server-side and never stored.</span>
            </div>
          </form>
        </div>
      </div>

      <!-- Results -->
      <?php if ($scanDone): ?>
      <div id="scanner-results">
        <div class="d-flex align-items-center justify-content-between mb-3">
          <h2 class="h5 mb-0"><i class="bi bi-bar-chart-steps me-2 text-primary"></i>
            <?php if (count($scanResults) > 0): ?>
              Top <?php echo count($scanResults); ?> potential match<?php echo count($scanResults) !== 1 ? 'es' : ''; ?> found
            <?php else: ?>
              No matches found above threshold
            <?php endif; ?>
          </h2>
          <?php if (count($scanResults) > 0): ?>
            <span class="badge bg-secondary">Sorted by highest similarity first</span>
          <?php endif; ?>
        </div>

        <?php if (count($scanResults) === 0): ?>
          <div class="card glass">
            <div class="card-body text-center py-5">
              <i class="bi bi-emoji-frown display-4 text-secondary d-block mb-3"></i>
              <p class="text-secondary mb-0">No visual matches were found above the 15% similarity threshold.<br>
              Try a clearer, well-lit front-facing photo for better results.</p>
            </div>
          </div>
        <?php else: ?>
          <div class="row g-3">
          <?php foreach ($scanResults as $idx => $res): ?>
            <?php
              $pct       = (float)$res['pct'];
              $badgeClass = $pct >= 65 ? 'bg-success' : ($pct >= 40 ? 'bg-warning text-dark' : 'bg-danger');
              $badgeLabel = $pct >= 65 ? 'High' : ($pct >= 40 ? 'Moderate' : 'Low');
              $photoUrl   = htmlspecialchars($res['photo_url'] ?? '');
              $caseLink   = '?view=case&code=' . urlencode($res['case_code']) . '#case-view';
              $statusBadge = match($res['status'] ?? '') {
                  'Verified'  => 'text-bg-success',
                  'Open'      => 'text-bg-primary',
                  'In Review' => 'text-bg-warning',
                  'Closed'    => 'text-bg-secondary',
                  default     => 'text-bg-secondary',
              };
            ?>
            <div class="col-12">
              <div class="card glass">
                <div class="card-body">
                  <div class="row g-3 align-items-center">

                    <!-- Rank badge -->
                    <div class="col-auto d-none d-md-block text-center" style="min-width:48px;">
                      <div class="fw-bold text-secondary" style="font-size:1.6rem;line-height:1;">#<?php echo $idx + 1; ?></div>
                    </div>

                    <!-- Profile/evidence photo -->
                    <div class="col-auto">
                      <?php if ($photoUrl !== ''): ?>
                        <a href="<?php echo $caseLink; ?>">
                          <img src="<?php echo $photoUrl; ?>"
                               alt="Case photo"
                               class="rounded"
                               style="width:90px;height:90px;object-fit:cover;border:2px solid rgba(124,77,255,.4);"
                               onerror="this.onerror=null;this.src='https://placehold.co/90x90/1a1a2e/666?text=No+Photo';">
                        </a>
                      <?php else: ?>
                        <div class="rounded d-flex align-items-center justify-content-center bg-secondary bg-opacity-25"
                             style="width:90px;height:90px;">
                          <i class="bi bi-person-fill fs-1 text-secondary"></i>
                        </div>
                      <?php endif; ?>
                    </div>

                    <!-- Case details -->
                    <div class="col">
                      <div class="d-flex flex-wrap align-items-center gap-2 mb-1">
                        <!-- Match percentage pill -->
                        <span class="badge <?php echo $badgeClass; ?> fs-6 px-3 py-1">
                          <?php echo number_format($pct, 1); ?>% — <?php echo $badgeLabel; ?> similarity
                        </span>
                        <span class="badge <?php echo $statusBadge; ?>"><?php echo htmlspecialchars($res['status'] ?? '—'); ?></span>
                        <?php if (($res['sensitivity'] ?? '') === 'Restricted'): ?>
                          <span class="badge bg-warning text-dark"><i class="bi bi-lock me-1"></i>Restricted</span>
                        <?php endif; ?>
                      </div>

                      <h3 class="h6 mb-1">
                        <a href="<?php echo $caseLink; ?>" class="text-decoration-none text-white">
                          <?php echo htmlspecialchars($res['case_name'] ?? '—'); ?>
                        </a>
                        <small class="text-secondary ms-2"><?php echo htmlspecialchars($res['case_code']); ?></small>
                      </h3>

                      <div class="row row-cols-auto g-3 small text-secondary mt-1">
                        <?php if (!empty($res['person_name'])): ?>
                        <div class="col">
                          <i class="bi bi-person me-1"></i>
                          <strong class="text-white"><?php echo htmlspecialchars($res['person_name']); ?></strong>
                        </div>
                        <?php endif; ?>
                        <?php if (!empty($res['tiktok_username'])): ?>
                        <div class="col">
                          <i class="bi bi-tiktok me-1"></i>@<?php echo htmlspecialchars($res['tiktok_username']); ?>
                        </div>
                        <?php endif; ?>
                        <?php if (!empty($res['location'])): ?>
                        <div class="col">
                          <i class="bi bi-geo-alt me-1"></i><?php echo htmlspecialchars($res['location']); ?>
                        </div>
                        <?php endif; ?>
                        <div class="col">
                          <i class="bi bi-tag me-1"></i>
                          <?php echo $res['match_source'] === 'profile_photo' ? 'Matched on profile photo' : 'Matched on evidence image'; ?>
                          <?php if (!empty($res['evidence_title']) && $res['match_source'] !== 'profile_photo'): ?>
                            — <em><?php echo htmlspecialchars(mb_strimwidth($res['evidence_title'], 0, 60, '…')); ?></em>
                          <?php endif; ?>
                        </div>
                      </div>
                    </div>

                    <!-- View case button -->
                    <div class="col-auto">
                      <a href="<?php echo $caseLink; ?>" class="btn btn-outline-primary btn-sm">
                        <i class="bi bi-box-arrow-up-right me-1"></i>View Case
                      </a>
                    </div>

                  </div><!-- /row -->
                </div><!-- /card-body -->
              </div><!-- /card -->
            </div><!-- /col-12 -->
          <?php endforeach; ?>
          </div><!-- /row -->
        <?php endif; ?>
      </div><!-- /scanner-results -->
      <?php endif; ?>

    </div><!-- /container -->
  </main>
  <?php endif; ?>

  <!-- Drag-drop + preview JS for scanner -->
  <script>
  (function () {
    var dz    = document.getElementById('scanDropzone');
    var input = document.getElementById('scan_image_input');
    var prev  = document.getElementById('scanPreviewImg');
    var wrap  = document.getElementById('scanPreviewWrap');
    var pname = document.getElementById('scanPreviewName');
    var btn   = document.getElementById('scanBtn');

    if (!dz || !input) return;

    function showPreview(file) {
      if (!file || !file.type.startsWith('image/')) return;
      var url = URL.createObjectURL(file);
      prev.src  = url;
      pname.textContent = file.name + ' (' + (file.size / 1024).toFixed(0) + ' KB)';
      wrap.classList.remove('d-none');
    }

    input.addEventListener('change', function () {
      if (this.files && this.files[0]) showPreview(this.files[0]);
    });

    dz.addEventListener('dragover', function (e) {
      e.preventDefault();
      dz.classList.add('border-primary');
    });
    dz.addEventListener('dragleave', function () {
      dz.classList.remove('border-primary');
    });
    dz.addEventListener('drop', function (e) {
      e.preventDefault();
      dz.classList.remove('border-primary');
      var files = e.dataTransfer.files;
      if (files && files[0]) {
        input.files = files;
        showPreview(files[0]);
      }
    });

    if (btn) {
      document.getElementById('scannerForm').addEventListener('submit', function () {
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner-border spinner-border-sm me-2" role="status"></span>Scanning…';
      });
    }
  })();
  </script>

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
log_console('ERROR', 'SQL: ' . $e->getMessage());
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
      <!-- Add User Modal -->
      <div class="modal fade" id="addUserModal" tabindex="-1" aria-hidden="true">
        <div class="modal-dialog modal-md modal-dialog-centered">
          <div class="modal-content">
            <div class="modal-header">
              <h5 class="modal-title"><i class="bi bi-person-plus me-2"></i>Add User</h5>
              <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
            </div>
            <form method="post" action="" id="addUserForm" autocomplete="off">
              <input type="hidden" name="action" value="admin_add_user">
              <?php csrf_field(); ?>
              <input type="hidden" name="redirect_url" value="?view=users#users">
              <div class="modal-body">
                <div class="mb-2">
                  <label class="form-label">Display Name</label>
                  <input type="text" name="display_name" class="form-control" placeholder="e.g. Jane Doe" required>
                </div>
                <div class="mb-2">
                  <label class="form-label">Email</label>
                  <input type="email" name="email" class="form-control" placeholder="name@example.com" required>
                </div>
                <div class="row g-2">
                  <div class="col-md-6">
                    <label class="form-label">Password</label>
                    <input type="password" name="password" class="form-control" minlength="8" required>
                  </div>
                  <div class="col-md-6">
                    <label class="form-label">Confirm Password</label>
                    <input type="password" name="password_confirm" class="form-control" minlength="8" required>
                  </div>
                </div>
                <div class="row g-2 mt-2">
                  <div class="col-md-6">
                    <label class="form-label">Account Role</label>
                    <select name="role" class="form-select" required>
                      <option value="viewer">Viewer</option>
                      <option value="admin">Admin</option>
                    </select>
                  </div>
                  <div class="col-md-6 d-flex align-items-end">
                    <div class="form-check">
                      <input class="form-check-input" type="checkbox" name="is_active" id="addUserActive" checked>
                      <label class="form-check-label" for="addUserActive">Active</label>
                    </div>
                  </div>
                </div>
              </div>
              <div class="modal-footer">
                <button type="button" class="btn btn-outline-light" data-bs-dismiss="modal">Cancel</button>
                <button type="submit" class="btn btn-primary"><i class="bi bi-save me-1"></i> Save User</button>
              </div>
            </form>
          </div>
        </div>
      </div>
    </div>
  </main>
  <?php endif; ?>

  <?php if ($view === 'viewer_stats'): ?>
  <main class="py-4" id="viewer-stats">
    <div class="container-xl">
      <div class="d-flex align-items-center justify-content-between mb-3">
        <h2 class="h4 mb-0">Viewer Statistics</h2>
        <a class="btn btn-outline-light btn-sm" href="?view=cases#cases"><i class="bi bi-arrow-left me-1"></i> Back to Cases</a>
      </div>

      <?php if (!is_admin()): ?>
        <div class="alert alert-danger"><i class="bi bi-shield-lock me-2"></i>Unauthorized. Admins only.</div>
      <?php else: ?>
        <?php
          $stats = [
            'total_views' => 0,
            'views_24h' => 0,
            'views_7d' => 0,
            'unique_cases' => 0,
            'unique_users' => 0,
            'unique_ips' => 0,
            'auth_views' => 0,
            'guest_views' => 0,
          ];
          $mostViewedCases = [];
          $recentViews = [];
          $topCountries = [];
          $topBrowsers = [];
          $topDevices = [];
          $topOperatingSystems = [];
          $topIps = [];

          try {
            $q = $pdo->query("SELECT
                COUNT(*) AS total_views,
                SUM(CASE WHEN viewed_at >= (NOW() - INTERVAL 1 DAY) THEN 1 ELSE 0 END) AS views_24h,
                SUM(CASE WHEN viewed_at >= (NOW() - INTERVAL 7 DAY) THEN 1 ELSE 0 END) AS views_7d,
                COUNT(DISTINCT CASE WHEN case_id > 0 THEN case_id END) AS unique_cases,
                COUNT(DISTINCT viewer_user_id) AS unique_users,
                COUNT(DISTINCT public_ip) AS unique_ips,
                SUM(CASE WHEN is_authenticated = 1 THEN 1 ELSE 0 END) AS auth_views,
                SUM(CASE WHEN is_authenticated = 0 THEN 1 ELSE 0 END) AS guest_views
              FROM case_views");
            $r = $q->fetch();
            if ($r) { $stats = array_merge($stats, $r); }
          } catch (Throwable $e) {
            $_SESSION['sql_error'] = $_SESSION['sql_error'] ?? $e->getMessage();
            log_console('ERROR', 'SQL: ' . $e->getMessage());
          }

          try {
            $q = $pdo->query("SELECT
                cv.case_id,
                CASE
                  WHEN cv.case_id = 0 THEN 'Home Page'
                  ELSE COALESCE(c.case_code, CONCAT('Case #', cv.case_id))
                END AS case_code,
                CASE
                  WHEN cv.case_id = 0 THEN 'Home Page'
                  ELSE COALESCE(c.case_name, 'Unknown Case')
                END AS case_name,
                COUNT(*) AS total_views,
                COUNT(DISTINCT cv.viewer_user_id) AS unique_users,
                COUNT(DISTINCT cv.public_ip) AS unique_ips,
                MAX(cv.viewed_at) AS last_viewed_at
              FROM case_views cv
              LEFT JOIN cases c ON c.id = cv.case_id
              GROUP BY cv.case_id, c.case_code, c.case_name
              ORDER BY total_views DESC, last_viewed_at DESC
              LIMIT 15");
            $mostViewedCases = $q->fetchAll() ?: [];
          } catch (Throwable $e) {
            $_SESSION['sql_error'] = $_SESSION['sql_error'] ?? $e->getMessage();
          }

          try {
            $q = $pdo->query("SELECT
                cv.id,
                cv.case_id,
                CASE
                  WHEN cv.case_id = 0 THEN 'Home Page'
                  ELSE COALESCE(c.case_code, CONCAT('Case #', cv.case_id))
                END AS case_code,
                CASE
                  WHEN cv.case_id = 0 THEN 'Home Page'
                  ELSE COALESCE(c.case_name, 'Unknown Case')
                END AS case_name,
                cv.viewer_user_id,
                u.email AS viewer_email,
                u.display_name AS viewer_display_name,
                cv.viewer_role,
                cv.is_authenticated,
                cv.public_ip,
                cv.forwarded_for,
                cv.geo_country,
                cv.geo_region,
                cv.geo_city,
                cv.geo_source,
                cv.device_type,
                cv.os_name,
                cv.browser_name,
                cv.browser_version,
                cv.accept_language,
                cv.referer,
                cv.request_uri,
                cv.request_method,
                cv.viewed_at
              FROM case_views cv
              LEFT JOIN cases c ON c.id = cv.case_id
              LEFT JOIN users u ON u.id = cv.viewer_user_id
              ORDER BY cv.viewed_at DESC
              LIMIT 250");
            $recentViews = $q->fetchAll() ?: [];
          } catch (Throwable $e) {
            $_SESSION['sql_error'] = $_SESSION['sql_error'] ?? $e->getMessage();
          }

          try {
            $q = $pdo->query("SELECT COALESCE(NULLIF(TRIM(geo_country), ''), 'Unknown') AS label, COUNT(*) AS cnt
              FROM case_views
              GROUP BY label
              ORDER BY cnt DESC
              LIMIT 10");
            $topCountries = $q->fetchAll() ?: [];
          } catch (Throwable $e) {}

          try {
            $q = $pdo->query("SELECT COALESCE(NULLIF(TRIM(CONCAT(browser_name, IF(browser_version IS NOT NULL AND browser_version != '', CONCAT(' ', browser_version), ''))), ''), 'Unknown') AS label, COUNT(*) AS cnt
              FROM case_views
              GROUP BY label
              ORDER BY cnt DESC
              LIMIT 10");
            $topBrowsers = $q->fetchAll() ?: [];
          } catch (Throwable $e) {}

          try {
            $q = $pdo->query("SELECT COALESCE(NULLIF(TRIM(device_type), ''), 'Unknown') AS label, COUNT(*) AS cnt
              FROM case_views
              GROUP BY label
              ORDER BY cnt DESC
              LIMIT 10");
            $topDevices = $q->fetchAll() ?: [];
          } catch (Throwable $e) {}

          try {
            $q = $pdo->query("SELECT COALESCE(NULLIF(TRIM(os_name), ''), 'Unknown') AS label, COUNT(*) AS cnt
              FROM case_views
              GROUP BY label
              ORDER BY cnt DESC
              LIMIT 10");
            $topOperatingSystems = $q->fetchAll() ?: [];
          } catch (Throwable $e) {}

          try {
            $q = $pdo->query("SELECT
                COALESCE(NULLIF(TRIM(public_ip), ''), 'Unknown') AS ip,
                COUNT(*) AS cnt,
                MAX(viewed_at) AS last_seen
              FROM case_views
              GROUP BY ip
              ORDER BY cnt DESC, last_seen DESC
              LIMIT 20");
            $topIps = $q->fetchAll() ?: [];
          } catch (Throwable $e) {}

          $totalViews = (int)($stats['total_views'] ?? 0);
          $authViews = (int)($stats['auth_views'] ?? 0);
          $guestViews = (int)($stats['guest_views'] ?? 0);
          $authPct = $totalViews > 0 ? round(($authViews / $totalViews) * 100, 1) : 0;
          $guestPct = $totalViews > 0 ? round(($guestViews / $totalViews) * 100, 1) : 0;
        ?>

        <div class="row g-3 mb-4">
          <div class="col-6 col-lg-3">
            <div class="card glass h-100"><div class="card-body">
              <div class="small text-secondary">Total Views</div>
              <div class="h4 mb-0"><?php echo number_format($totalViews); ?></div>
            </div></div>
          </div>
          <div class="col-6 col-lg-3">
            <div class="card glass h-100"><div class="card-body">
              <div class="small text-secondary">Views (24h)</div>
              <div class="h4 mb-0"><?php echo number_format((int)($stats['views_24h'] ?? 0)); ?></div>
            </div></div>
          </div>
          <div class="col-6 col-lg-3">
            <div class="card glass h-100"><div class="card-body">
              <div class="small text-secondary">Views (7d)</div>
              <div class="h4 mb-0"><?php echo number_format((int)($stats['views_7d'] ?? 0)); ?></div>
            </div></div>
          </div>
          <div class="col-6 col-lg-3">
            <div class="card glass h-100"><div class="card-body">
              <div class="small text-secondary">Cases Viewed</div>
              <div class="h4 mb-0"><?php echo number_format((int)($stats['unique_cases'] ?? 0)); ?></div>
            </div></div>
          </div>
          <div class="col-6 col-lg-3">
            <div class="card glass h-100"><div class="card-body">
              <div class="small text-secondary">Unique Logged-In Viewers</div>
              <div class="h4 mb-0"><?php echo number_format((int)($stats['unique_users'] ?? 0)); ?></div>
            </div></div>
          </div>
          <div class="col-6 col-lg-3">
            <div class="card glass h-100"><div class="card-body">
              <div class="small text-secondary">Unique Public IPs</div>
              <div class="h4 mb-0"><?php echo number_format((int)($stats['unique_ips'] ?? 0)); ?></div>
            </div></div>
          </div>
          <div class="col-6 col-lg-3">
            <div class="card glass h-100"><div class="card-body">
              <div class="small text-secondary">Authenticated Views</div>
              <div class="h4 mb-0"><?php echo number_format($authViews); ?></div>
              <div class="small text-secondary"><?php echo $authPct; ?>%</div>
            </div></div>
          </div>
          <div class="col-6 col-lg-3">
            <div class="card glass h-100"><div class="card-body">
              <div class="small text-secondary">Guest Views</div>
              <div class="h4 mb-0"><?php echo number_format($guestViews); ?></div>
              <div class="small text-secondary"><?php echo $guestPct; ?>%</div>
            </div></div>
          </div>
        </div>

        <div class="row g-4 mb-4">
          <div class="col-lg-7">
            <div class="card glass h-100">
              <div class="card-body">
                <h3 class="h6 mb-3">Most Viewed Cases</h3>
                <div class="table-responsive">
                  <table class="table table-sm align-middle mb-0">
                    <thead>
                      <tr>
                        <th>Case</th>
                        <th class="text-end">Views</th>
                        <th class="text-end">Unique Users</th>
                        <th class="text-end">Unique IPs</th>
                        <th>Last Viewed</th>
                      </tr>
                    </thead>
                    <tbody>
                      <?php if (!empty($mostViewedCases)): foreach ($mostViewedCases as $mv): ?>
                        <tr>
                          <td>
                            <?php if ((int)($mv['case_id'] ?? 0) === 0): ?>
                              <span class="fw-semibold">Home Page</span>
                              <div class="small text-secondary">Main dashboard</div>
                            <?php else: ?>
                              <a class="text-decoration-none" href="?view=case&code=<?php echo urlencode($mv['case_code'] ?? ''); ?>#case-view">
                                <?php echo htmlspecialchars($mv['case_name'] ?: ($mv['case_code'] ?? 'Case')); ?>
                              </a>
                              <div class="small text-secondary"><?php echo htmlspecialchars($mv['case_code'] ?? ''); ?></div>
                            <?php endif; ?>
                          </td>
                          <td class="text-end fw-semibold"><?php echo number_format((int)($mv['total_views'] ?? 0)); ?></td>
                          <td class="text-end"><?php echo number_format((int)($mv['unique_users'] ?? 0)); ?></td>
                          <td class="text-end"><?php echo number_format((int)($mv['unique_ips'] ?? 0)); ?></td>
                          <td class="small text-secondary"><?php echo htmlspecialchars($mv['last_viewed_at'] ?? ''); ?></td>
                        </tr>
                      <?php endforeach; else: ?>
                        <tr><td colspan="5" class="text-secondary">No case view data available yet.</td></tr>
                      <?php endif; ?>
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          </div>
          <div class="col-lg-5">
            <div class="card glass h-100">
              <div class="card-body">
                <h3 class="h6 mb-3">Top Public IPs</h3>
                <div class="table-responsive">
                  <table class="table table-sm align-middle mb-0">
                    <thead>
                      <tr>
                        <th>IP</th>
                        <th class="text-end">Views</th>
                        <th>Last Seen</th>
                      </tr>
                    </thead>
                    <tbody>
                      <?php if (!empty($topIps)): foreach ($topIps as $ip): ?>
                        <tr>
                          <td class="small"><?php echo htmlspecialchars($ip['ip'] ?? 'Unknown'); ?></td>
                          <td class="text-end fw-semibold"><?php echo number_format((int)($ip['cnt'] ?? 0)); ?></td>
                          <td class="small text-secondary"><?php echo htmlspecialchars($ip['last_seen'] ?? ''); ?></td>
                        </tr>
                      <?php endforeach; else: ?>
                        <tr><td colspan="3" class="text-secondary">No IP data available yet.</td></tr>
                      <?php endif; ?>
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          </div>
        </div>

        <div class="row g-4 mb-4">
          <div class="col-lg-3 col-md-6">
            <div class="card glass h-100">
              <div class="card-body">
                <h3 class="h6 mb-3">Countries</h3>
                <div class="table-responsive">
                  <table class="table table-sm align-middle mb-0">
                    <tbody>
                      <?php if (!empty($topCountries)): foreach ($topCountries as $x): ?>
                        <tr><td><?php echo htmlspecialchars($x['label'] ?? 'Unknown'); ?></td><td class="text-end fw-semibold"><?php echo number_format((int)($x['cnt'] ?? 0)); ?></td></tr>
                      <?php endforeach; else: ?>
                        <tr><td class="text-secondary">No data</td><td></td></tr>
                      <?php endif; ?>
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          </div>
          <div class="col-lg-3 col-md-6">
            <div class="card glass h-100">
              <div class="card-body">
                <h3 class="h6 mb-3">Browsers</h3>
                <div class="table-responsive">
                  <table class="table table-sm align-middle mb-0">
                    <tbody>
                      <?php if (!empty($topBrowsers)): foreach ($topBrowsers as $x): ?>
                        <tr><td><?php echo htmlspecialchars($x['label'] ?? 'Unknown'); ?></td><td class="text-end fw-semibold"><?php echo number_format((int)($x['cnt'] ?? 0)); ?></td></tr>
                      <?php endforeach; else: ?>
                        <tr><td class="text-secondary">No data</td><td></td></tr>
                      <?php endif; ?>
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          </div>
          <div class="col-lg-3 col-md-6">
            <div class="card glass h-100">
              <div class="card-body">
                <h3 class="h6 mb-3">Devices</h3>
                <div class="table-responsive">
                  <table class="table table-sm align-middle mb-0">
                    <tbody>
                      <?php if (!empty($topDevices)): foreach ($topDevices as $x): ?>
                        <tr><td><?php echo htmlspecialchars($x['label'] ?? 'Unknown'); ?></td><td class="text-end fw-semibold"><?php echo number_format((int)($x['cnt'] ?? 0)); ?></td></tr>
                      <?php endforeach; else: ?>
                        <tr><td class="text-secondary">No data</td><td></td></tr>
                      <?php endif; ?>
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          </div>
          <div class="col-lg-3 col-md-6">
            <div class="card glass h-100">
              <div class="card-body">
                <h3 class="h6 mb-3">Operating Systems</h3>
                <div class="table-responsive">
                  <table class="table table-sm align-middle mb-0">
                    <tbody>
                      <?php if (!empty($topOperatingSystems)): foreach ($topOperatingSystems as $x): ?>
                        <tr><td><?php echo htmlspecialchars($x['label'] ?? 'Unknown'); ?></td><td class="text-end fw-semibold"><?php echo number_format((int)($x['cnt'] ?? 0)); ?></td></tr>
                      <?php endforeach; else: ?>
                        <tr><td class="text-secondary">No data</td><td></td></tr>
                      <?php endif; ?>
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          </div>
        </div>

        <div class="card glass">
          <div class="card-body">
            <h3 class="h6 mb-3">Detailed Recent Viewer Activity (Last 250 views)</h3>
            <div class="table-responsive">
              <table id="recentViewerActivityTable" class="table table-sm align-middle">
                <thead>
                  <tr>
                    <th>Viewed At</th>
                    <th>Case</th>
                    <th>Viewer</th>
                    <th>Auth</th>
                    <th>Role</th>
                    <th>Public IP</th>
                    <th>Location</th>
                    <th>Device</th>
                    <th>Browser</th>
                    <th>OS</th>
                    <th>Referrer</th>
                  </tr>
                </thead>
                <tbody>
                  <?php if (!empty($recentViews)): foreach ($recentViews as $rv): ?>
                    <tr>
                      <td class="small"><?php echo htmlspecialchars($rv['viewed_at'] ?? ''); ?></td>
                      <td>
                        <?php if ((int)($rv['case_id'] ?? 0) === 0): ?>
                          <span class="fw-semibold">Home Page</span>
                          <div class="small text-secondary">Main dashboard</div>
                        <?php else: ?>
                          <a class="text-decoration-none" href="?view=case&code=<?php echo urlencode($rv['case_code'] ?? ''); ?>#case-view"><?php echo htmlspecialchars($rv['case_code'] ?? ''); ?></a>
                          <div class="small text-secondary"><?php echo htmlspecialchars($rv['case_name'] ?? ''); ?></div>
                        <?php endif; ?>
                      </td>
                      <td>
                        <?php if (!empty($rv['viewer_user_id'])): ?>
                          <div class="small fw-semibold"><?php echo htmlspecialchars($rv['viewer_display_name'] ?: ('User #'.$rv['viewer_user_id'])); ?></div>
                          <div class="small text-secondary"><?php echo htmlspecialchars($rv['viewer_email'] ?? ''); ?></div>
                        <?php else: ?>
                          <span class="small text-secondary">Anonymous / Guest</span>
                        <?php endif; ?>
                      </td>
                      <td><?php echo ((int)($rv['is_authenticated'] ?? 0) === 1) ? '<span class="badge bg-success-subtle border">Yes</span>' : '<span class="badge bg-secondary">No</span>'; ?></td>
                      <td class="small"><?php echo htmlspecialchars($rv['viewer_role'] ?? 'guest'); ?></td>
                      <td class="small"><?php echo htmlspecialchars($rv['public_ip'] ?? ''); ?></td>
                      <td class="small"><?php echo htmlspecialchars(trim(($rv['geo_country'] ?? '').' '.($rv['geo_region'] ?? '').' '.($rv['geo_city'] ?? '')) ?: 'Unknown'); ?></td>
                      <td class="small"><?php echo htmlspecialchars($rv['device_type'] ?? 'Unknown'); ?></td>
                      <td class="small"><?php echo htmlspecialchars(trim(($rv['browser_name'] ?? '').' '.($rv['browser_version'] ?? '')) ?: 'Unknown'); ?></td>
                      <td class="small"><?php echo htmlspecialchars($rv['os_name'] ?? 'Unknown'); ?></td>
                      <td class="small text-break" style="max-width: 260px;"><?php echo htmlspecialchars($rv['referer'] ?? ''); ?></td>
                    </tr>
                  <?php endforeach; else: ?>
                    <tr><td colspan="11" class="text-secondary">No viewer activity has been recorded yet.</td></tr>
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
      $viewCase = null; $viewCaseId = 0; $viewEv = []; $viewTotalViews = 0;
      if ($caseCode !== '') {
        try {
          $st = $pdo->prepare('SELECT id, case_code, case_name, person_name, location, tiktok_username, initial_summary, status, sensitivity, opened_at, created_by FROM cases WHERE case_code = ? LIMIT 1');
          $st->execute([$caseCode]);
          $viewCase = $st->fetch();
          $viewCaseId = (int)($viewCase['id'] ?? 0);
        } catch (Throwable $e) { $_SESSION['sql_error'] = $e->getMessage();
log_console('ERROR', 'SQL: ' . $e->getMessage()); }
        if ($viewCaseId > 0) {
          log_case_view($pdo, $viewCaseId);
          $viewTotalViews = get_case_view_count($pdo, $viewCaseId);
          try {
            $st2 = $pdo->prepare('SELECT id, type, title, filepath, mime_type, size_bytes, created_at FROM evidence WHERE case_id = ? ORDER BY created_at DESC');
            $st2->execute([$viewCaseId]);
            $viewEv = $st2->fetchAll();
          } catch (Throwable $e) { $_SESSION['sql_error'] = $e->getMessage();
log_console('ERROR', 'SQL: ' . $e->getMessage()); }
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
      // Capability: can this user add evidence?
      $tp_canAddEvidence = false;
      if (!empty($_SESSION['user'])) {
          if (($_SESSION['user']['role'] ?? '') === 'admin') {
              $tp_canAddEvidence = true;
          } elseif (!empty($viewCase) && (($viewCase['status'] ?? '') === 'Pending')) {
              $ownerId = (int)($viewCase['created_by'] ?? 0);
              $tp_canAddEvidence = ($ownerId > 0) && ($ownerId === (int)($_SESSION['user']['id'] ?? 0));
          }
      }
    ?>
    <section class="py-5 border-top" id="case-view">
      <div class="container-xl">
        <?php
          $tp_headerName = trim((string)($viewCase['person_name'] ?? ''));
          if ($tp_headerName === '') { $tp_headerName = trim((string)($viewCase['case_name'] ?? '')); }
          if ($tp_headerName === '') { $tp_headerName = 'Unknown'; }
          $tp_headerLocation = trim((string)($viewCase['location'] ?? ''));
          if ($tp_headerLocation === '') { $tp_headerLocation = 'Unknown Location'; }
        ?>
        <div class="d-flex align-items-center justify-content-between mb-3">
          <div>
            <h2 class="h4 mb-0"><?php echo htmlspecialchars($tp_headerName); ?> | <?php echo htmlspecialchars($tp_headerLocation); ?> | <?php echo htmlspecialchars($caseCode ?: ''); ?></h2>
            <?php if ($viewCaseId > 0): ?>
              <div class="small text-secondary">Total views: <?php echo (int)$viewTotalViews; ?></div>
            <?php endif; ?>
          </div>
          <div class="d-flex gap-2">
<?php if ($tp_canAddEvidence): ?>
            <button class="btn btn-primary btn-sm" data-bs-toggle="modal" data-bs-target="#addEvidenceModal"><i class="bi bi-cloud-plus me-1"></i> Add Evidence</button>
<?php endif; ?>
<?php if (!empty($_SESSION['user']) && (($_SESSION['user']['role'] ?? '') === 'admin')): ?>
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
        <!-- Case View Tabs -->
        <ul class="nav nav-tabs mt-3" id="caseViewTabs" role="tablist">
          <li class="nav-item" role="presentation">
            <button class="nav-link active" id="tab-evidence" data-bs-toggle="tab" data-bs-target="#case-evidence-panel" type="button" role="tab" aria-controls="case-evidence-panel" aria-selected="true">
              <i class="bi bi-collection me-1"></i> Evidence
            </button>
          </li>
          <li class="nav-item" role="presentation">
            <button class="nav-link" id="tab-timeline" data-bs-toggle="tab" data-bs-target="#case-timeline-panel" type="button" role="tab" aria-controls="case-timeline-panel" aria-selected="false">
              <i class="bi bi-clock-history me-1"></i> Case Timeline
            </button>
          </li>
        </ul>
        <div class="tab-content pt-3" id="caseViewTabContent">
          <!-- Timeline Pane -->
          <div class="tab-pane fade" id="case-timeline-panel" role="tabpanel" aria-labelledby="tab-timeline">
            <?php
            // Timeline builder: $timelineEvents
            $timelineEvents = [];
            // Add case opened event
            if (!empty($viewCase)) {
                $timelineEvents[] = [
                    'ts' => $viewCase['opened_at'] ?? '',
                    'type' => 'case_opened',
                    'label' => 'Case opened',
                    'detail' => mb_strimwidth(trim($viewCase['case_name'] ?? ''), 0, 180, '…', 'UTF-8'),
                    'meta' => '',
                    'evidence_id' => 0
                ];
            }
            // Add evidence events
            if ($viewEv && is_array($viewEv)) {
                foreach ($viewEv as $ev) {
                    $timelineEvents[] = [
                        'ts' => $ev['created_at'],
                        'type' => 'evidence',
                        'label' => 'Evidence',
                        'detail' => mb_strimwidth(trim($ev['title'] ?? ''), 0, 180, '…', 'UTF-8'),
                        'meta' => $ev['type'] ?? '',
                        'evidence_id' => (int)$ev['id']
                    ];
                }
            }
            // Add notes events
            try {
                if ($viewCaseId > 0) {
                    $nq = $pdo->prepare('SELECT id, note_text, created_at FROM case_notes WHERE case_id = ? ORDER BY created_at ASC');
                    $nq->execute([$viewCaseId]);
                    $rowsN = $nq->fetchAll();
                    foreach ($rowsN as $nrow) {
                        $timelineEvents[] = [
                            'ts' => $nrow['created_at'],
                            'type' => 'note',
                            'label' => 'Case note',
                            'detail' => mb_strimwidth(trim($nrow['note_text'] ?? ''), 0, 180, '…', 'UTF-8'),
                            'meta' => '',
                            'evidence_id' => 0
                        ];
                    }
                }
            } catch (Throwable $e) {}
            // Pull explicit case_events log
            try {
                if ($viewCaseId > 0) {
                    $ce = $pdo->prepare('SELECT event_type, subject, detail, ref_evidence_id, ref_note_id, created_at FROM case_events WHERE case_id = ? ORDER BY created_at ASC');
                    $ce->execute([$viewCaseId]);
                    $rowsCE = $ce->fetchAll();
                    foreach ($rowsCE as $ceRow) {
                        $labelMap = [
                            'case_created' => 'Case created',
                            'case_updated' => 'Case updated',
                            'case_deleted' => 'Case deleted',
                            'evidence_added' => 'Evidence added',
                            'evidence_updated' => 'Evidence updated',
                            'evidence_deleted' => 'Evidence deleted',
                            'note_added' => 'Case note added',
                            'redactions_saved' => 'Redactions saved'
                        ];
                        $lbl = $labelMap[$ceRow['event_type']] ?? ucfirst(str_replace('_',' ', $ceRow['event_type']));
                        $timelineEvents[] = [
                            'ts' => $ceRow['created_at'],
                            'type' => $ceRow['event_type'],
                            'label' => $lbl,
                            'detail' => mb_strimwidth(trim(($ceRow['subject'] ? $ceRow['subject'].': ' : '').($ceRow['detail'] ?? '')), 0, 180, '…', 'UTF-8'),
                            'meta' => '',
                            'evidence_id' => (int)($ceRow['ref_evidence_id'] ?? 0)
                        ];
                    }
                }
            } catch (Throwable $e) { $_SESSION['sql_error'] = $_SESSION['sql_error'] ?? $e->getMessage(); }
            // Sort by timestamp ascending
            // usort($timelineEvents, function($a, $b) {
                // return strtotime($a['ts']) <=> strtotime($b['ts']);
            // });
            usort($timelineEvents, function($a,$b){
              $ta = strtotime($a['ts'] ?? ''); 
              $tb = strtotime($b['ts'] ?? '');
              if ($ta === $tb) return 0;
              return ($ta > $tb) ? -1 : 1; // Newest first
            });
            ?>
            <?php if (!empty($timelineEvents)): ?>
              <div class="timeline">
                <?php foreach ($timelineEvents as $ev):
                  $when   = htmlspecialchars(date('d M Y H:i', strtotime($ev['ts'] ?? '')));
                  $label  = htmlspecialchars($ev['label'] ?? 'Event');
                  $detail = htmlspecialchars($ev['detail'] ?? '');
                  $meta   = htmlspecialchars($ev['meta'] ?? '');
                  $eid    = (int)($ev['evidence_id'] ?? 0);
                ?>
                  <div class="item">
                    <div class="d-flex justify-content-between">
                      <div>
                        <div class="fw-semibold">
                          <?php echo $label; ?>
                          <?php if ($meta): ?><span class="badge text-bg-dark border ms-1"><?php echo $meta; ?></span><?php endif; ?>
                        </div>
                        <?php if ($detail): ?><div class="text-secondary small"><?php echo $detail; ?></div><?php endif; ?>
                      </div>
                      <div class="text-secondary small"><?php echo $when; ?></div>
                    </div>
                  </div>
                <?php endforeach; ?>
              </div>
            <?php else: ?>
              <div class="alert alert-secondary">No timeline events yet.</div>
            <?php endif; ?>
          </div>
          <!-- Evidence Pane (open wrapper; existing evidence markup continues) -->
          <div class="tab-pane fade show active" id="case-evidence-panel" role="tabpanel" aria-labelledby="tab-evidence">
        <?php if ($tp_canAddEvidence): ?>
  <div class="modal fade" id="addEvidenceModal" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog modal-lg modal-dialog-centered">
      <div class="modal-content">
        <div class="modal-header">
          <h5 class="modal-title"><i class="bi bi-cloud-plus me-2"></i>Add Evidence</h5>
          <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
        </div>
        <div class="modal-body">
          <ul class="nav nav-tabs" id="addEvTabs" role="tablist">
            <li class="nav-item" role="presentation">
              <button class="nav-link active" id="ev-upload-tab" data-bs-toggle="tab" data-bs-target="#ev-upload-pane" type="button" role="tab">Upload Evidence</button>
            </li>
            <?php if (is_admin()): ?>
            <li class="nav-item" role="presentation">
              <button class="nav-link" id="ev-note-tab" data-bs-toggle="tab" data-bs-target="#ev-note-pane" type="button" role="tab">Add Note</button>
            </li>
            <?php endif; ?>
            <li class="nav-item" role="presentation">
              <button class="nav-link <?php echo is_admin() ? '' : 'ms-1'; ?>" id="ev-url-tab" data-bs-toggle="tab" data-bs-target="#ev-url-pane" type="button" role="tab">Add URL</button>
            </li>
          </ul>
          <div class="tab-content pt-3">
            <div class="tab-pane fade show active" id="ev-upload-pane" role="tabpanel">
              <!-- Multi-file evidence uploader -->
              <input type="hidden" id="evMultiCaseId" value="<?php echo (int)$viewCaseId; ?>">
              <input type="hidden" id="evMultiCsrf" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
              <!-- Drop zone -->
              <div class="dropzone mb-3 position-relative" id="evDropzone" style="cursor:pointer;" onclick="document.getElementById('evMultiFileInput').click()">
                <i class="bi bi-cloud-upload display-4 d-block mb-2 text-primary"></i>
                <p class="mb-1 fw-semibold">Drag &amp; drop files here, or click to browse</p>
                <small class="text-secondary">Images &nbsp;·&nbsp; Videos (MP4/WebM/OGG) &nbsp;·&nbsp; PDFs &nbsp;·&nbsp; Documents &nbsp;·&nbsp; Multiple files supported</small>
              </div>
              <input type="file" id="evMultiFileInput" multiple accept="image/*,video/mp4,video/webm,video/ogg,audio/*,application/pdf,.doc,.docx,.txt" class="d-none">
              <!-- Staged file list (shown after selection) -->
              <div id="evFileList" class="d-none">
                <p class="small text-secondary mb-2">Give each file a title/tag before uploading:</p>
                <div class="table-responsive">
                  <table class="table table-sm align-middle mb-2" id="evFileTable">
                    <thead class="table-dark">
                      <tr>
                        <th style="width:30%">File</th>
                        <th style="width:30%">Title / Tag</th>
                        <th style="width:18%">Type</th>
                        <th style="width:22%">Progress</th>
                      </tr>
                    </thead>
                    <tbody id="evFileListBody"></tbody>
                  </table>
                </div>
              </div>
              <div id="evUploadAllWrap" class="d-none text-end">
                <button type="button" class="btn btn-primary" id="evUploadAllBtn">
                  <i class="bi bi-cloud-arrow-up me-1"></i> Upload All
                </button>
              </div>
            </div>
            <?php if (is_admin()): ?>
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
            <?php endif; ?>
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
          <button class="btn btn-primary d-none" id="evModalUploadBtn" type="button" onclick="document.getElementById('evUploadAllBtn').click()"><i class="bi bi-cloud-arrow-up me-1"></i> Upload All</button>
          <?php if (is_admin()): ?>
          <button class="btn btn-success" type="submit" form="evNoteForm"><i class="bi bi-journal-plus me-1"></i> Save Note</button>
          <?php endif; ?>
          <button class="btn btn-info" type="submit" form="evUrlForm"><i class="bi bi-link-45deg me-1"></i> Save URL</button>
        </div>
      </div>
    </div>
  </div>
<?php endif; ?>
        <?php if ($viewCase): ?>
          <div class="row g-4">
            <div class="col-12">
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
                  <div class="row g-3 align-items-center">
                    <?php
                      $casePhoto = find_person_photo_url($caseCode);
                      if ($casePhoto !== '') {
                    ?>
                      <div class="col-auto d-flex align-items-center">
                        <img src="<?php echo htmlspecialchars($casePhoto); ?>" alt="" class="rounded" style="width:96px;height:96px;object-fit:cover;">
                      </div>
                    <?php } else { ?>
                      <div class="col-auto d-flex align-items-center">
                        <div class="rounded bg-secondary text-white d-flex align-items-center justify-content-center" style="width:96px;height:96px;object-fit:cover;">
                          <span class="small">No Image</span>
                        </div>
                      </div>
                    <?php } ?>
                    <div class="col">
                      <div class="row g-3 align-items-center">
                        <div class="col-sm-6 col-lg-3 mb-0">
                          <div class="small text-secondary">Case Name</div>
                          <div><?php echo htmlspecialchars($viewCase['case_name'] ?? ''); ?></div>
                        </div>
                        <div class="col-sm-6 col-lg-3 mb-0">
                          <div class="small text-secondary">Person Name</div>
                          <div><?php echo htmlspecialchars($viewCase['person_name'] ?? ''); ?></div>
                        </div>
                        <div class="col-sm-6 col-lg-3 mb-0">
                          <div class="small text-secondary">Location</div>
                          <div><?php echo ($viewCase['location'] ?? '') !== '' ? htmlspecialchars($viewCase['location']) : '<span class="text-secondary">—</span>'; ?></div>
                        </div>
                        <div class="col-sm-6 col-lg-3 mb-0">
                          <div class="small text-secondary">TikTok Username</div>
                          <div><?php echo $viewCase['tiktok_username'] ? '@'.htmlspecialchars($viewCase['tiktok_username']) : '<span class="text-secondary">—</span>'; ?></div>
                        </div>
                        <div class="col-sm-6 col-lg-3 mb-0">
                          <div class="small text-secondary">Status</div>
                          <div>
                            <?php
                              $status = $viewCase['status'];
                              $badgeClass = 'dark'; // default

                              switch ($status) {
                                  case 'Pending':
                                      $badgeClass = 'warning'; // yellow
                                      break;
                                  case 'Open':
                                      $badgeClass = 'primary'; // blue
                                      break;
                                  case 'In Review':
                                      $badgeClass = 'info'; // light blue
                                      break;
                                  case 'Verified':
                                      $badgeClass = 'success'; // green
                                      break;
                                  case 'Closed':
                                      $badgeClass = 'danger'; // red
                                      break;
                              }
                            ?>
                            <span class="badge text-bg-<?php echo $badgeClass; ?> border">
                                <?php echo htmlspecialchars($status); ?>
                            </span>
                        </div>
                        </div>
                        <div class="col-sm-6 col-lg-3 mb-0">
                          <div class="small text-secondary">Sensitivity</div>
                          <div><span class="badge text-bg-dark border"><?php echo htmlspecialchars($viewCase['sensitivity']); ?></span></div>
                        </div>
                        <div class="col-sm-6 col-lg-3 mb-0">
                          <div class="small text-secondary">Opened</div>
                          <div><?php echo htmlspecialchars($viewCase['opened_at']); ?></div>
                        </div>
                      </div>
                    </div>
                  </div>
                  <div class="small text-secondary">Summary</div>
                  <div class="mb-0"><?php echo nl2br(htmlspecialchars($viewCase['initial_summary'] ?? '')); ?></div>
                </div>
              </div>
            </div>
            <div class="col-12">
              <div class="card glass">
                <div class="card-body">
                  <div class="d-flex align-items-center justify-content-between mb-2">
                    <h3 class="h6 mb-0">Evidence</h3>
                  </div>
                  <div class="table-responsive">
                    <table class="table table-sm align-middle">
                      <thead>
                        <tr>
                          <th>Title</th>
                          <th>Tyle</th>
                          <th class="text-end">Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        <?php if ($viewEv) { foreach ($viewEv as $e) { ?>
                          <tr>
                            <td><?php echo htmlspecialchars($e['title']); ?></td>
                            <td><?php echo htmlspecialchars($e['type']); ?></td>
                            <td class="text-end">
                              <div class="d-inline-flex gap-1">
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
                                      <button type="button" class="btn btn-sm btn-outline-warning btn-edit-evidence" data-bs-toggle="modal" data-bs-target="#evidenceModal" data-id="<?php echo (int)$e['id']; ?>" data-case-id="<?php echo (int)$viewCaseId; ?>" data-src="<?php echo htmlspecialchars($e['filepath']); ?>" data-title="<?php echo htmlspecialchars($e['title']); ?>" data-type="<?php echo htmlspecialchars($e['type'] ?? 'other'); ?>" data-mime="<?php echo htmlspecialchars($e['mime_type']); ?>" data-admin="1">Edit</button>
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
              <div class="col-md-6">
                <label class="form-label">Location</label>
                <input type="text" name="location" class="form-control" value="<?php echo htmlspecialchars($viewCase['location'] ?? ''); ?>" placeholder="City, region, or country">
              </div>
            </div>
            <div class="row g-2 mt-2">
              <div class="col-md-3">
                <label class="form-label">Sensitivity</label>
                <select name="sensitivity" class="form-select" required>
                  <?php $sensOpts = ['Standard','Restricted','Sealed']; foreach ($sensOpts as $opt) { $sel = (($viewCase['sensitivity'] ?? '') === $opt) ? ' selected' : ''; echo '<option value="'.htmlspecialchars($opt).'"'.$sel.'>'.htmlspecialchars($opt)."</option>"; } ?>
                </select>
              </div>
              <div class="col-md-3">
                <label class="form-label">Status</label>
                <select name="status" class="form-select" required>
                  <?php $statOpts = ['Pending','Open','In Review','Verified','Closed']; foreach ($statOpts as $opt) { $sel = (($viewCase['status'] ?? '') === $opt) ? ' selected' : ''; echo '<option value="'.htmlspecialchars($opt).'"'.$sel.'>'.htmlspecialchars($opt)."</option>"; } ?>
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
      $caseRow = null; $caseId = 0; $adminCaseTotalViews = 0;
      try {
          $s = $pdo->prepare('SELECT id, case_code, case_name, person_name, location, tiktok_username, initial_summary, status, sensitivity, opened_at FROM cases WHERE case_code = ? LIMIT 1');
          $s->execute([$adminCaseCode]);
          $caseRow = $s->fetch();
          $caseId = (int)($caseRow['id'] ?? 0);
      } catch (Throwable $e) {
          $_SESSION['sql_error'] = $e->getMessage();
log_console('ERROR', 'SQL: ' . $e->getMessage());
      }
      if ($caseId > 0) {
        log_case_view($pdo, $caseId);
        $adminCaseTotalViews = get_case_view_count($pdo, $caseId);
      }
      // Fetch notes
      $notes = [];
      if ($caseId > 0) {
          try {
              $n = $pdo->prepare('SELECT cn.id, cn.note_text, cn.created_at, u.display_name FROM case_notes cn LEFT JOIN users u ON u.id = cn.created_by WHERE cn.case_id = ? ORDER BY cn.created_at DESC LIMIT 50');
              $n->execute([$caseId]);
              $notes = $n->fetchAll();
          } catch (Throwable $e) { $_SESSION['sql_error'] = $e->getMessage();
log_console('ERROR', 'SQL: ' . $e->getMessage()); }
      }
      // Fetch evidence
      $ev = [];
      if ($caseId > 0) {
          try {
              $evi = $pdo->prepare('SELECT id, type, title, filepath, mime_type, size_bytes, created_at FROM evidence WHERE case_id = ? ORDER BY created_at DESC LIMIT 100');
              $evi->execute([$caseId]);
              $ev = $evi->fetchAll();
          } catch (Throwable $e) { $_SESSION['sql_error'] = $e->getMessage();
log_console('ERROR', 'SQL: ' . $e->getMessage()); }
      }
  ?>
<section class="py-5 border-top" id="admin-case">
  <div class="container-xl">
    <?php
      $tp_adminHeaderName = trim((string)($caseRow['person_name'] ?? ''));
      if ($tp_adminHeaderName === '') { $tp_adminHeaderName = trim((string)($caseRow['case_name'] ?? '')); }
      if ($tp_adminHeaderName === '') { $tp_adminHeaderName = 'Unknown'; }
      $tp_adminHeaderLocation = trim((string)($caseRow['location'] ?? ''));
      if ($tp_adminHeaderLocation === '') { $tp_adminHeaderLocation = 'Unknown Location'; }
    ?>
    <div class="d-flex align-items-center justify-content-between mb-3">
      <div>
        <h2 class="h4 mb-0">Admin: <?php echo htmlspecialchars($tp_adminHeaderName); ?> | <?php echo htmlspecialchars($tp_adminHeaderLocation); ?> | <?php echo htmlspecialchars($adminCaseCode); ?></h2>
        <?php if ($caseId > 0): ?>
          <div class="small text-secondary">Total views: <?php echo (int)$adminCaseTotalViews; ?></div>
        <?php endif; ?>
      </div>
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
                  <div class="small text-secondary">Location</div>
                  <div class="mb-2"><?php echo ($caseRow['location'] ?? '') !== '' ? htmlspecialchars($caseRow['location']) : '<span class="text-secondary">—</span>'; ?></div>
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
            <!-- Multi-file uploader (admin panel) -->
            <input type="hidden" id="adminEvCaseId" value="<?php echo (int)$caseId; ?>">
            <input type="hidden" id="adminEvCsrf" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
            <div class="dropzone mb-3 position-relative" id="adminEvDropzone" style="cursor:pointer;" onclick="document.getElementById('adminEvFileInput').click()">
              <i class="bi bi-cloud-upload d-block mb-1 text-primary" style="font-size:2rem;"></i>
              <p class="mb-1 fw-semibold">Drag &amp; drop files here, or click to browse</p>
              <small class="text-secondary">Images · Videos (MP4/WebM/OGG) · PDFs · Docs · Audio &nbsp;·&nbsp; Multiple files supported</small>
            </div>
            <input type="file" id="adminEvFileInput" multiple accept="image/*,video/mp4,video/webm,video/ogg,audio/*,application/pdf,.doc,.docx,.txt" class="d-none">
            <div id="adminEvFileList" class="d-none">
              <p class="small text-secondary mb-2">Give each file a title/tag before uploading:</p>
              <div class="table-responsive">
                <table class="table table-sm align-middle mb-2" id="adminEvFileTable">
                  <thead class="table-dark">
                    <tr>
                      <th style="width:30%">File</th>
                      <th style="width:30%">Title / Tag</th>
                      <th style="width:18%">Type</th>
                      <th style="width:22%">Progress</th>
                    </tr>
                  </thead>
                  <tbody id="adminEvFileListBody"></tbody>
                </table>
              </div>
            </div>
            <div id="adminEvUploadAllWrap" class="d-none mb-3 text-end">
              <button type="button" class="btn btn-primary btn-sm" id="adminEvUploadAllBtn">
                <i class="bi bi-cloud-arrow-up me-1"></i> Upload All
              </button>
            </div>
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
                <thead><tr><th>Type</th><th>Title</th><th>Actions</th><th>MIME</th><th>Size</th><th>Added</th></tr></thead>
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
                  <div class="col-md-6">
                    <label class="form-label">Location</label>
                    <input type="text" name="location" class="form-control" value="<?php echo htmlspecialchars($caseRow['location'] ?? ''); ?>" placeholder="City, region, or country">
                  </div>
                </div>
                <div class="row g-2 mt-2">
                  <div class="col-md-3">
                    <label class="form-label">Sensitivity</label>
                    <select name="sensitivity" class="form-select" required>
                      <?php $sensOpts = ['Standard','Restricted','Sealed']; foreach ($sensOpts as $opt) { $sel = (($caseRow['sensitivity'] ?? '') === $opt) ? ' selected' : ''; echo '<option value="'.htmlspecialchars($opt).'"'.$sel.'>'.htmlspecialchars($opt)."</option>"; } ?>
                    </select>
                  </div>
                  <div class="col-md-3">
                    <label class="form-label">Status</label>
                    <select name="status" class="form-select" required>
                      <?php $statOpts = ['Pending','Open','In Review','Verified','Closed']; foreach ($statOpts as $opt) { $sel = (($caseRow['status'] ?? '') === $opt) ? ' selected' : ''; echo '<option value="'.htmlspecialchars($opt).'"'.$sel.'>'.htmlspecialchars($opt)."</option>"; } ?>
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
                <label class="form-label">Location</label>
                <input type="text" name="location" class="form-control" placeholder="City, region, or country">
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
                  <option value="Pending" selected>Pending</option>  
                  <option value="Open">Open</option>
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
  
  <!-- Dev Modal (admin only) -->
<?php if (is_admin()): ?>
<div class="modal fade" id="devModal" tabindex="-1" aria-hidden="true">
  <div class="modal-dialog modal-dialog-centered modal-lg">
    <div class="modal-content">
      <div class="modal-header">
        <h5 class="modal-title"><i class="bi bi-terminal me-2"></i>Developer Console</h5>
        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
      </div>
      <div class="modal-body">
        <?php
          ob_start(); print_r($_COOKIE);  $cookieDump  = ob_get_clean();
          ob_start(); print_r($_SESSION); $sessionDump = ob_get_clean();
        ?>
        <div class="mb-3">
          <h6 class="mb-2">$_COOKIE</h6>
          <pre class="small m-0"><?php echo htmlspecialchars($cookieDump); ?></pre>
        </div>
        <div class="mb-0">
          <h6 class="mb-2">$_SESSION</h6>
          <pre class="small m-0"><?php echo htmlspecialchars($sessionDump); ?></pre>
        </div>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-outline-light" data-bs-dismiss="modal">Close</button>
      </div>
    </div>
  </div>
</div>
<?php endif; ?>

  <script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
  <script src="https://cdn.datatables.net/1.13.8/js/jquery.dataTables.min.js"></script>
  <script src="https://cdn.datatables.net/1.13.8/js/dataTables.bootstrap5.min.js"></script>

  <script>
  document.addEventListener('DOMContentLoaded', function () {
    if (window.jQuery && window.jQuery.fn && typeof window.jQuery.fn.DataTable === 'function') {
      var activityTable = window.jQuery('#recentViewerActivityTable');
      if (activityTable.length) {
        activityTable.DataTable({
          pageLength: 25,
          lengthMenu: [[25, 50, 100, 250], [25, 50, 100, 250]],
          order: [[0, 'desc']]
        });
      }
    }

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
            preview.innerHTML = '<video controls playsinline preload="metadata" class="w-100 h-100"><source src="'+safeSrc+'" type="'+mime+'">Your browser does not support the HTML5 video element.</video>';
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

<!-- Global Footer -->
<footer class="border-top glass mt-5 py-3">
  <div class="container-xl d-flex flex-column flex-md-row justify-content-between align-items-center gap-2">
    <div class="small text-secondary">
      &copy; <?php echo date('Y'); ?> TikTokPredators. All rights reserved.
    </div>
    <div class="d-flex gap-3 small">
      <a href="?view=removal#removal" class="link-light text-decoration-none">Removal Requests</a>
      <a href="#" class="link-light text-decoration-none" data-bs-toggle="modal" data-bs-target="#privacyModal">Privacy</a>
      <a href="#" class="link-light text-decoration-none" data-bs-toggle="modal" data-bs-target="#termsModal">Terms</a>
    </div>
  </div>
</footer>

<!-- Privacy Policy Modal -->
<div class="modal fade" id="privacyModal" tabindex="-1" aria-hidden="true" aria-labelledby="privacyLabel">
  <div class="modal-dialog modal-lg modal-dialog-scrollable">
    <div class="modal-content">
      <div class="modal-header">
        <h5 class="modal-title" id="privacyLabel"><i class="bi bi-shield-lock me-2"></i>Privacy Policy</h5>
        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
      </div>
      <div class="modal-body">
        <p class="small text-secondary mb-3">
          This Privacy Policy explains how we collect, use, and protect information on this site. It is provided for transparency and does not constitute legal advice.
        </p>
        <h6>What we collect</h6>
        <ul>
          <li><strong>Account data:</strong> email, display name, role, and activity necessary to operate your account.</li>
          <li><strong>Case data:</strong> content you submit or upload (evidence, notes, metadata) for case management.</li>
          <li><strong>Technical data:</strong> server logs, IP addresses, and basic device information for security and abuse prevention.</li>
        </ul>
        <h6>How we use data</h6>
        <ul>
          <li>To provide and secure the platform, including audit and abuse prevention.</li>
          <li>To review and moderate case materials for compliance with our policies and applicable law.</li>
          <li>To respond to reports, takedown requests, or legal obligations.</li>
        </ul>
        <h6>Retention</h6>
        <p>We retain data as long as necessary for the purposes above or as required by law. We may anonymise or aggregate data for analytics and safety research.</p>
        <h6>Third parties</h6>
        <p>We may use hosting, storage, and analytics providers. We do not sell your personal information. Content subject to a lawful request may be shared with competent authorities.</p>
        <h6>Your choices</h6>
        <ul>
          <li>Request access, correction, or deletion of your account data where applicable.</li>
          <li>Request removal or further redaction of case materials that include your personal data (include case code/URLs).</li>
        </ul>
        <h6>Contact</h6>
        <p>For privacy inquiries, contact the site operators via the contact options listed on the homepage. Include your email and sufficient details for us to identify relevant records.</p>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-primary" data-bs-dismiss="modal">Close</button>
      </div>
    </div>
  </div>
</div>

<!-- Terms of Use Modal -->
<div class="modal fade" id="termsModal" tabindex="-1" aria-hidden="true" aria-labelledby="termsLabel">
  <div class="modal-dialog modal-lg modal-dialog-scrollable">
    <div class="modal-content">
      <div class="modal-header">
        <h5 class="modal-title" id="termsLabel"><i class="bi bi-file-earmark-text me-2"></i>Terms of Use</h5>
        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
      </div>
      <div class="modal-body">
        <p class="small text-secondary mb-3">By using this site you agree to these Terms.</p>
        <h6>Use of the Site</h6>
        <ul>
          <li>You must comply with all applicable laws and these Terms.</li>
          <li>Do not upload unlawful content, including doxxing materials, intimate images, malware, or anything that infringes rights.</li>
          <li>We may remove content, restrict access, or suspend accounts at our discretion to protect safety and comply with law.</li>
        </ul>
        <h6>Content and Evidence</h6>
        <ul>
          <li>Submitting content grants us a non-exclusive licence to host, process, display, and moderate that content for case management and public interest reporting.</li>
          <li>We may redact or blur sensitive information and may decline to publish certain materials.</li>
        </ul>
        <h6>Disclaimers</h6>
        <ul>
          <li>The site is provided on an “as-is” basis without warranties of any kind.</li>
          <li>We do not guarantee continuous availability or accuracy of third-party links.</li>
        </ul>
        <h6>Liability</h6>
        <p>To the maximum extent permitted by law, we are not liable for indirect or consequential losses. Nothing excludes liability that cannot be excluded by law.</p>
        <h6>Changes</h6>
        <p>We may update these Terms and the Privacy Policy. Continued use after changes means you accept the updated terms.</p>
        <h6>Contact</h6>
        <p>Questions about these Terms? Contact us via the options on the homepage.</p>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-primary" data-bs-dismiss="modal">Close</button>
      </div>
    </div>
  </div>
</div>
<!-- Multi-file Evidence Uploader JS -->
<script>
(function () {
  'use strict';

  // ── Helpers ────────────────────────────────────────────────────────────────

  function detectType(file) {
    var m = file.type || '';
    var ext = (file.name.split('.').pop() || '').toLowerCase();
    if (m.startsWith('image/'))  return 'image';
    if (m.startsWith('video/') || m === 'application/ogg') return 'video';
    if (m.startsWith('audio/'))  return 'audio';
    if (m === 'application/pdf' || ext === 'pdf') return 'pdf';
    if (['doc','docx'].includes(ext)) return 'doc';
    return 'other';
  }

  function fmtSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1048576) return (bytes / 1024).toFixed(0) + ' KB';
    return (bytes / 1048576).toFixed(1) + ' MB';
  }

  // Build the type <select> for a row
  function typeSelect(detected, rowId) {
    var types = ['image','video','audio','pdf','doc','other'];
    var labels = {image:'Image',video:'Video',audio:'Audio',pdf:'PDF',doc:'Document',other:'Other'};
    var s = '<select class="form-select form-select-sm" id="evType_'+rowId+'">';
    types.forEach(function(t){
      s += '<option value="'+t+'"'+(t===detected?' selected':'')+'>'+labels[t]+'</option>';
    });
    s += '</select>';
    return s;
  }

  // ── Generic uploader factory ────────────────────────────────────────────────
  // Wires up a dropzone/fileInput/fileListBody/uploadAllBtn combo.
  // config: { caseIdEl, csrfEl, dzEl, inputEl, listEl, listBodyEl, uploadAllWrapEl, uploadAllBtnEl,
  //           onAllDone }

  function initUploader(config) {
    var files = []; // [{file, rowId}]
    var rowCounter = 0;

    function populateList(newFiles) {
      for (var i = 0; i < newFiles.length; i++) {
        var f = newFiles[i];
        rowCounter++;
        var rid = rowCounter;
        files.push({ file: f, rowId: rid });
        var detected = detectType(f);
        var row = document.createElement('tr');
        row.id = 'evRow_' + rid;
        row.innerHTML =
          '<td class="text-truncate" style="max-width:140px;" title="'+escHtml(f.name)+'">'
            + '<span class="text-white small">'+escHtml(f.name)+'</span>'
            + '<br><span class="text-secondary" style="font-size:.75rem">'+fmtSize(f.size)+'</span>'
          + '</td>'
          + '<td><input type="text" class="form-control form-control-sm" id="evTitle_'+rid+'" placeholder="Title / tag" value="'+escHtml(f.name.replace(/\.[^.]+$/, ''))+'"></td>'
          + '<td>'+typeSelect(detected, rid)+'</td>'
          + '<td id="evStatus_'+rid+'">'
              + '<div class="progress" style="height:6px;"><div class="progress-bar" id="evProg_'+rid+'" style="width:0%"></div></div>'
              + '<span class="small text-secondary" id="evProgTxt_'+rid+'">Pending</span>'
          + '</td>';
        config.listBodyEl.appendChild(row);
      }
      config.listEl.classList.remove('d-none');
      config.uploadAllWrapEl.classList.remove('d-none');
      // Show footer button if it exists (modal context)
      var footerBtn = document.getElementById('evModalUploadBtn');
      if (footerBtn) footerBtn.classList.remove('d-none');
    }

    function escHtml(s) {
      return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    }

    function uploadFile(item, caseId, csrf, callback) {
      var rid = item.rowId;
      var progBar = document.getElementById('evProg_' + rid);
      var progTxt = document.getElementById('evProgTxt_' + rid);
      var titleEl = document.getElementById('evTitle_' + rid);
      var typeEl  = document.getElementById('evType_' + rid);

      progTxt.textContent = 'Uploading…';
      progTxt.className = 'small text-info';

      var fd = new FormData();
      fd.append('action', 'upload_evidence_ajax');
      fd.append('csrf_token', csrf);
      fd.append('case_id', caseId);
      fd.append('title', titleEl ? titleEl.value.trim() : '');
      fd.append('type', typeEl ? typeEl.value : 'other');
      fd.append('evidence_file', item.file, item.file.name);

      var xhr = new XMLHttpRequest();
      xhr.open('POST', '', true);

      xhr.upload.addEventListener('progress', function (e) {
        if (e.lengthComputable && progBar) {
          var pct = Math.round((e.loaded / e.total) * 100);
          progBar.style.width = pct + '%';
        }
      });

      xhr.addEventListener('load', function () {
        var data;
        try { data = JSON.parse(xhr.responseText); } catch(e) { data = {ok:false,error:'Invalid server response'}; }
        if (data.ok) {
          if (progBar) { progBar.style.width = '100%'; progBar.classList.add('bg-success'); }
          progTxt.textContent = 'Done ✓';
          progTxt.className = 'small text-success';
        } else {
          if (progBar) { progBar.classList.add('bg-danger'); }
          progTxt.textContent = 'Error: ' + (data.error || 'Unknown');
          progTxt.className = 'small text-danger';
        }
        callback(data.ok);
      });

      xhr.addEventListener('error', function () {
        if (progBar) progBar.classList.add('bg-danger');
        progTxt.textContent = 'Network error';
        progTxt.className = 'small text-danger';
        callback(false);
      });

      xhr.send(fd);
    }

    function startUploads() {
      var caseId = config.caseIdEl.value;
      var csrf   = config.csrfEl.value;
      config.uploadAllBtnEl.disabled = true;
      config.uploadAllBtnEl.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>Uploading…';

      var idx = 0;
      var successCount = 0;

      function next() {
        if (idx >= files.length) {
          config.uploadAllBtnEl.innerHTML = '<i class="bi bi-check-circle me-1"></i>Done ('+successCount+'/'+files.length+' uploaded)';
          config.uploadAllBtnEl.classList.remove('btn-primary');
          config.uploadAllBtnEl.classList.add('btn-success');
          if (config.onAllDone) config.onAllDone(successCount, files.length);
          return;
        }
        uploadFile(files[idx], caseId, csrf, function(ok) {
          if (ok) successCount++;
          idx++;
          next();
        });
      }
      next();
    }

    // Wire up input + drag/drop
    config.inputEl.addEventListener('change', function () {
      if (this.files && this.files.length) populateList(Array.from(this.files));
      this.value = '';
    });

    config.dzEl.addEventListener('dragover', function (e) { e.preventDefault(); this.classList.add('border-primary'); });
    config.dzEl.addEventListener('dragleave', function ()  { this.classList.remove('border-primary'); });
    config.dzEl.addEventListener('drop', function (e) {
      e.preventDefault();
      this.classList.remove('border-primary');
      var dropped = Array.from(e.dataTransfer.files);
      if (dropped.length) populateList(dropped);
    });

    config.uploadAllBtnEl.addEventListener('click', startUploads);
  }

  // ── Wire up modal uploader (case view) ─────────────────────────────────────
  var evCaseIdEl    = document.getElementById('evMultiCaseId');
  var evCsrfEl      = document.getElementById('evMultiCsrf');
  var evDz          = document.getElementById('evDropzone');
  var evInput       = document.getElementById('evMultiFileInput');
  var evList        = document.getElementById('evFileList');
  var evListBody    = document.getElementById('evFileListBody');
  var evUploadWrap  = document.getElementById('evUploadAllWrap');
  var evUploadBtn   = document.getElementById('evUploadAllBtn');

  if (evDz && evInput && evListBody && evUploadBtn) {
    initUploader({
      caseIdEl:        evCaseIdEl,
      csrfEl:          evCsrfEl,
      dzEl:            evDz,
      inputEl:         evInput,
      listEl:          evList,
      listBodyEl:      evListBody,
      uploadAllWrapEl: evUploadWrap,
      uploadAllBtnEl:  evUploadBtn,
      onAllDone: function(success, total) {
        // Reload the page after a short pause so the evidence list updates
        if (success > 0) {
          setTimeout(function () { window.location.reload(); }, 1200);
        }
      }
    });
  }

  // ── Wire up admin panel uploader ────────────────────────────────────────────
  var adminCaseIdEl    = document.getElementById('adminEvCaseId');
  var adminCsrfEl      = document.getElementById('adminEvCsrf');
  var adminDz          = document.getElementById('adminEvDropzone');
  var adminInput       = document.getElementById('adminEvFileInput');
  var adminList        = document.getElementById('adminEvFileList');
  var adminListBody    = document.getElementById('adminEvFileListBody');
  var adminUploadWrap  = document.getElementById('adminEvUploadAllWrap');
  var adminUploadBtn   = document.getElementById('adminEvUploadAllBtn');

  if (adminDz && adminInput && adminListBody && adminUploadBtn) {
    initUploader({
      caseIdEl:        adminCaseIdEl,
      csrfEl:          adminCsrfEl,
      dzEl:            adminDz,
      inputEl:         adminInput,
      listEl:          adminList,
      listBodyEl:      adminListBody,
      uploadAllWrapEl: adminUploadWrap,
      uploadAllBtnEl:  adminUploadBtn,
      onAllDone: function(success, total) {
        if (success > 0) {
          setTimeout(function () { window.location.reload(); }, 1200);
        }
      }
    });
  }

})();
</script>

  </body>
  </html>
