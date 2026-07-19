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
function check_csrf(){
    $submitted = $_POST['csrf_token'] ?? '';
    return is_string($submitted) && hash_equals((string)($_SESSION['csrf_token'] ?? ''), $submitted);
}

/** Read a scalar POST field without allowing arrays to reach string functions. */
function tp_post_string(string $key): string {
    $value = $_POST[$key] ?? '';
    return is_string($value) ? trim($value) : '';
}

/**
 * Reject malformed/control-character input and common code-execution probes.
 * Submitted text is still treated as data, stored through prepared statements,
 * and escaped when rendered; this is an additional abuse filter.
 */
function tp_valid_public_text(string $value, int $maxLength, bool $allowNewlines = false): bool {
    if ($value === '' || !mb_check_encoding($value, 'UTF-8')) { return false; }
    if (mb_strlen($value, 'UTF-8') > $maxLength) { return false; }

    $controlPattern = $allowNewlines
        ? '/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/'
        : '/[\x00-\x1F\x7F]/';
    if (preg_match($controlPattern, $value)) { return false; }

    return !preg_match(
        '/<\?(?:php|=)|\b(?:assert|eval|system|exec|shell_exec|passthru|base64_decode|gethostbyname)\s*\(|\bchr\s*\(\s*(?:hex\s*\()?/i',
        $value
    );
}

/** Only allow links an admin can safely open in a browser. */
function tp_valid_public_http_url(string $url): bool {
    if ($url === ''
        || strlen($url) > 2048
        || preg_match('/[\x00-\x20\x7F]/', $url)
        || !filter_var($url, FILTER_VALIDATE_URL)
    ) { return false; }
    $parts = parse_url($url);
    if (!is_array($parts)) { return false; }
    $scheme = strtolower((string)($parts['scheme'] ?? ''));
    $host = trim((string)($parts['host'] ?? ''));
    return in_array($scheme, ['http', 'https'], true)
        && $host !== ''
        && !isset($parts['user'])
        && !isset($parts['pass']);
}

/** Create one short-lived, session-bound addition challenge per public form. */
function tp_math_captcha_question(string $purpose): string {
    $challenge = $_SESSION['math_captcha'][$purpose] ?? null;
    if (!is_array($challenge)
        || !isset($challenge['left'], $challenge['right'], $challenge['answer'], $challenge['created_at'])
        || (time() - (int)$challenge['created_at']) > 900
    ) {
        $left = random_int(2, 9);
        $right = random_int(2, 9);
        $challenge = [
            'left' => $left,
            'right' => $right,
            'answer' => $left + $right,
            'created_at' => time(),
        ];
        $_SESSION['math_captcha'][$purpose] = $challenge;
    }
    return (int)$challenge['left'] . ' + ' . (int)$challenge['right'];
}

function tp_math_captcha_field(string $purpose): void {
    static $renderCount = 0;
    $renderCount++;
    $inputId = 'math_captcha_' . preg_replace('/[^a-z0-9_-]/i', '_', $purpose) . '_' . $renderCount;
    echo '<div class="mb-3">';
    echo '<label class="form-label" for="' . htmlspecialchars($inputId) . '">Security check: What is '
        . htmlspecialchars(tp_math_captcha_question($purpose)) . '?</label>';
    echo '<input type="text" class="form-control" id="' . htmlspecialchars($inputId)
        . '" name="captcha_answer" inputmode="numeric" pattern="[0-9]+" maxlength="3" autocomplete="off" required>';
    echo '</div>';
}

/** Validate and consume the challenge so an answer cannot be replayed. */
function tp_check_math_captcha(string $purpose): bool {
    $challenge = $_SESSION['math_captcha'][$purpose] ?? null;
    unset($_SESSION['math_captcha'][$purpose]);
    $submitted = $_POST['captcha_answer'] ?? '';
    if (!is_array($challenge) || !is_string($submitted)) { return false; }
    $submitted = trim($submitted);
    if ($submitted === '' || strlen($submitted) > 3 || !ctype_digit($submitted)) { return false; }
    if ((time() - (int)($challenge['created_at'] ?? 0)) > 900) { return false; }
    return (int)$submitted === (int)($challenge['answer'] ?? -1);
}

// VERY simple throttle (per-session)
$_SESSION['auth_attempts'] = $_SESSION['auth_attempts'] ?? 0;
$_SESSION['auth_last'] = $_SESSION['auth_last'] ?? 0;
function current_user_role(){ return $_SESSION['user']['role'] ?? 'guest'; }
function is_admin(){ return (current_user_role()==='admin'); }
function tp_mask_case_phone_number(?string $phoneNumber): string {
  $masked = trim((string)$phoneNumber);
  $digitsMasked = 0;
  for ($i = strlen($masked) - 1; $i >= 0 && $digitsMasked < 3; $i--) {
    if ($masked[$i] >= '0' && $masked[$i] <= '9') {
      $masked[$i] = '*';
      $digitsMasked++;
    }
  }
  return $masked;
}
function tp_case_phone_number_for_viewer(?string $phoneNumber): string {
  $phoneNumber = trim((string)$phoneNumber);
  return is_admin() ? $phoneNumber : tp_mask_case_phone_number($phoneNumber);
}
function tp_mask_case_location_house_number(?string $location): string {
  $location = trim((string)$location);
  return (string)preg_replace_callback(
    '/^(\d+[A-Za-z]?(?:\s*[-–—\/]\s*\d+[A-Za-z]?)*)(?=\s|,|$)/u',
    static function (array $match): string {
      return (string)preg_replace('/\d/', '*', $match[1]);
    },
    $location,
    1
  );
}
function tp_case_location_for_viewer(?string $location): string {
  $location = trim((string)$location);
  return is_admin() ? $location : tp_mask_case_location_house_number($location);
}
function tp_mask_case_event_field_values(string $detail, string $fieldName, callable $maskValue): string {
  return (string)preg_replace_callback(
    '/(' . preg_quote($fieldName, '/') . ':\s*)(.*?)(?=;\s*[a-z_]+:|$)/iu',
    static function (array $match) use ($maskValue): string {
      $values = preg_split('/(\s*→\s*)/u', $match[2], -1, PREG_SPLIT_DELIM_CAPTURE);
      if (!is_array($values)) { return $match[1] . $maskValue($match[2]); }
      foreach ($values as $index => $value) {
        if ($index % 2 === 0) { $values[$index] = $maskValue($value); }
      }
      return $match[1] . implode('', $values);
    },
    $detail
  );
}
function tp_case_event_detail_for_viewer(string $detail): string {
  if (is_admin()) { return $detail; }
  if (stripos($detail, 'phone_number:') !== false) {
    $detail = tp_mask_case_event_field_values($detail, 'phone_number', 'tp_mask_case_phone_number');
  }
  if (stripos($detail, 'location:') !== false) {
    $detail = tp_mask_case_event_field_values($detail, 'location', 'tp_mask_case_location_house_number');
  }
  return $detail;
}
function tp_is_main_admin(): bool {
  if (!is_admin()) { return false; }
  $userId = (int)($_SESSION['user']['id'] ?? 0);
  $userEmail = strtolower(trim((string)($_SESSION['user']['email'] ?? '')));
  $mainAdminId = (int)(getenv('MAIN_ADMIN_USER_ID') ?: 0);
  $mainAdminEmail = strtolower(trim((string)(getenv('MAIN_ADMIN_EMAIL') ?: '')));
  if ($mainAdminId > 0 && $userId === $mainAdminId) { return true; }
  if ($mainAdminEmail !== '' && $userEmail === $mainAdminEmail) { return true; }
  return $userId === 1;
}
function is_logged_in(){ return !empty($_SESSION['user']); }

function tp_normalize_account_username($input): string {
  $username = ltrim(trim((string)$input), '@');
  $username = preg_replace('/[^A-Za-z0-9._-]+/', '_', $username) ?? '';
  $username = trim($username, '._-');
  return mb_substr($username, 0, 120, 'UTF-8');
}

function tp_project_settings(PDO $pdo): array {
  static $cache = null;
  if ($cache !== null) { return $cache; }
  $cache = [
    'site_title' => 'TikTokPredators',
    'meta_data' => 'A public, auditable repository documenting abusive behaviour by TikTok accounts — case records, evidence, and verifiable proof to expose predators and support accountability.',
    'openai_api_key' => '',
    'discord_webhook_key' => '',
    'discord_webhooks' => '[]',
  ];
  try {
    $stmt = $pdo->query('SELECT setting_key, setting_value FROM project_settings');
    foreach ($stmt->fetchAll() as $row) {
      $key = (string)($row['setting_key'] ?? '');
      if ($key !== '') {
        $cache[$key] = (string)($row['setting_value'] ?? '');
      }
    }
  } catch (Throwable $e) {
    // fall back to defaults
  }
  return $cache;
}

function tp_project_setting(PDO $pdo, string $key, string $default = ''): string {
  $settings = tp_project_settings($pdo);
  return (string)($settings[$key] ?? $default);
}

function tp_discord_webhooks(PDO $pdo): array {
  $raw = tp_project_setting($pdo, 'discord_webhooks', '[]');
  $decoded = json_decode($raw, true);
  $hooks = [];
  if (is_array($decoded)) {
    foreach ($decoded as $item) {
      if (!is_array($item)) { continue; }
      $name = trim((string)($item['name'] ?? ''));
      $url = trim((string)($item['url'] ?? ''));
      $setAt = trim((string)($item['set_at'] ?? ''));
      $lastTestedAt = trim((string)($item['last_tested_at'] ?? ''));
      $lastTestStatus = trim((string)($item['last_test_status'] ?? ''));
      $lastTestMessage = trim((string)($item['last_test_message'] ?? ''));
      if ($url === '') { continue; }
      if (!filter_var($url, FILTER_VALIDATE_URL)) { continue; }
      $hooks[] = [
        'name' => $name,
        'url' => $url,
        'set_at' => $setAt,
        'last_tested_at' => $lastTestedAt,
        'last_test_status' => $lastTestStatus,
        'last_test_message' => $lastTestMessage,
      ];
    }
  }

  // Backward-compatible fallback for older single-webhook setting.
  if (count($hooks) === 0) {
    $legacy = trim(tp_project_setting($pdo, 'discord_webhook_key', ''));
    if ($legacy !== '' && filter_var($legacy, FILTER_VALIDATE_URL)) {
      $hooks[] = [
        'name' => 'Primary',
        'url' => $legacy,
        'set_at' => '',
        'last_tested_at' => '',
        'last_test_status' => '',
        'last_test_message' => '',
      ];
    }
  }
  return $hooks;
}

function tp_post_discord_webhook(string $webhookUrl, array $payload): array {
  $payloadJson = json_encode($payload);
  if ($payloadJson === false) {
    return [false, 0, 'Failed to encode payload'];
  }

  $ch = curl_init($webhookUrl);
  curl_setopt_array($ch, [
    CURLOPT_POST => true,
    CURLOPT_POSTFIELDS => $payloadJson,
    CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_TIMEOUT => 10,
  ]);
  $resp = curl_exec($ch);
  $httpCode = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
  $ok = ($httpCode >= 200 && $httpCode < 300);
  return [$ok, $httpCode, (string)$resp];
}

function tp_test_openai_api_key(string $apiKey): array {
  $apiKey = trim($apiKey);
  if ($apiKey === '') { return [false, 0, 'Enter an OpenAI API key first.']; }
  if (!function_exists('curl_init')) { return [false, 0, 'The server cURL extension is unavailable.']; }

  $ch = curl_init('https://api.openai.com/v1/models');
  curl_setopt_array($ch, [
    CURLOPT_HTTPGET => true,
    CURLOPT_HTTPHEADER => [
      'Authorization: Bearer ' . $apiKey,
      'Accept: application/json',
    ],
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_CONNECTTIMEOUT => 10,
    CURLOPT_TIMEOUT => 20,
    CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
  ]);
  $response = curl_exec($ch);
  $curlError = curl_error($ch);
  $httpCode = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);

  if ($response === false) {
    return [false, $httpCode, 'Unable to connect to OpenAI: ' . ($curlError !== '' ? $curlError : 'network error')];
  }
  if ($httpCode >= 200 && $httpCode < 300) {
    return [true, $httpCode, 'OpenAI connection succeeded. The API key is valid.'];
  }
  if ($httpCode === 401) { return [false, $httpCode, 'OpenAI rejected the API key. Check that it is complete and active.']; }
  if ($httpCode === 403) { return [false, $httpCode, 'The API key was recognised but does not have permission to list models.']; }
  if ($httpCode === 429) { return [false, $httpCode, 'OpenAI rate-limited the test. Check the project quota and try again.']; }
  return [false, $httpCode, 'OpenAI test failed with HTTP ' . ($httpCode > 0 ? $httpCode : 'unknown') . '.'];
}

function tp_ai_case_field_labels(): array {
  return [
    'case_name' => 'Case Name',
    'person_name' => 'Person Name',
    'location' => 'Location',
    'snapchat_username' => 'Snapchat Username',
    'tiktok_username' => 'TikTok Usernames',
    'initial_summary' => 'Summary',
    'case_tags' => 'Case Tags',
  ];
}

function tp_ai_case_current_values(PDO $pdo, array $case): array {
  $caseId = (int)($case['id'] ?? 0);
  $tiktok = $caseId > 0 ? get_case_tiktok_usernames($pdo, $caseId) : '';
  if ($tiktok === '') { $tiktok = normalize_tiktok_usernames($case['tiktok_username'] ?? ''); }
  $tags = $caseId > 0 ? get_case_tags($pdo, $caseId) : [];
  return [
    'case_name' => trim((string)($case['case_name'] ?? '')),
    'person_name' => trim((string)($case['person_name'] ?? '')),
    'location' => trim((string)($case['location'] ?? '')),
    'snapchat_username' => normalize_social_username($case['snapchat_username'] ?? ''),
    'tiktok_username' => $tiktok,
    'initial_summary' => trim((string)($case['initial_summary'] ?? '')),
    'case_tags' => implode(', ', array_keys($tags)),
  ];
}

function tp_ai_normalize_case_suggestion(string $field, string $value): string {
  $value = trim($value);
  if ($field === 'tiktok_username') { return normalize_tiktok_usernames($value); }
  if ($field === 'snapchat_username') { return normalize_social_username($value); }
  if ($field === 'case_tags') { return implode(', ', array_keys(tp_normalize_case_tags($value))); }

  $limits = [
    'case_name' => 255,
    'person_name' => 255,
    'location' => 255,
    'initial_summary' => 20000,
  ];
  $limit = (int)($limits[$field] ?? 1000);
  return mb_substr($value, 0, $limit, 'UTF-8');
}

/** Request structured, non-binding case edit suggestions from OpenAI. */
function tp_openai_case_builder_request(string $apiKey, string $model, array $caseContext): array {
  $apiKey = trim($apiKey);
  if ($apiKey === '') { return [false, [], 'OpenAI has not been configured in Project Settings.']; }
  if (!function_exists('curl_init')) { return [false, [], 'The server cURL extension is unavailable.']; }

  $fieldLabels = tp_ai_case_field_labels();
  $schema = [
    'type' => 'object',
    'properties' => [
      'overall_notes' => ['type' => 'string'],
      'suggestions' => [
        'type' => 'array',
        'maxItems' => 8,
        'items' => [
          'type' => 'object',
          'properties' => [
            'field' => ['type' => 'string', 'enum' => array_keys($fieldLabels)],
            'suggested_value' => ['type' => 'string'],
            'reason' => ['type' => 'string'],
          ],
          'required' => ['field', 'suggested_value', 'reason'],
          'additionalProperties' => false,
        ],
      ],
    ],
    'required' => ['overall_notes', 'suggestions'],
    'additionalProperties' => false,
  ];

  $payload = [
    'model' => $model,
    'store' => false,
    'instructions' => 'You are an editing assistant for a sensitive case-record system. Suggest only materially helpful edits for factual clarity, neutral wording, consistency, formatting, or privacy. Never invent facts, infer guilt, make legal conclusions, add allegations, or identify people from indirect clues. Do not suggest changing phone numbers, case status, sensitivity, ownership, identifiers, or evidence. Use only the allowed field names. Preserve every material fact and uncertainty. Case tags must be a comma-separated list selected only from allowed_case_tags. Return at most eight distinct suggestions. If no safe improvement is supported by the supplied record, return an empty suggestions array.',
    'input' => json_encode($caseContext, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
    'max_output_tokens' => 4000,
    'text' => [
      'format' => [
        'type' => 'json_schema',
        'name' => 'case_builder_suggestions',
        'schema' => $schema,
        'strict' => true,
      ],
    ],
  ];
  if ($payload['input'] === false) { return [false, [], 'Unable to prepare the case for AI review.']; }
  $payloadJson = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
  if ($payloadJson === false) { return [false, [], 'Unable to prepare the AI request.']; }

  $ch = curl_init('https://api.openai.com/v1/responses');
  curl_setopt_array($ch, [
    CURLOPT_POST => true,
    CURLOPT_POSTFIELDS => $payloadJson,
    CURLOPT_HTTPHEADER => [
      'Authorization: Bearer ' . $apiKey,
      'Content-Type: application/json',
      'Accept: application/json',
    ],
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_CONNECTTIMEOUT => 10,
    CURLOPT_TIMEOUT => 60,
    CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
  ]);
  $response = curl_exec($ch);
  $curlError = curl_error($ch);
  $httpCode = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
  if ($response === false) {
    return [false, [], 'Unable to connect to OpenAI: ' . ($curlError !== '' ? $curlError : 'network error')];
  }

  $decoded = json_decode((string)$response, true);
  if ($httpCode < 200 || $httpCode >= 300) {
    if ($httpCode === 401) { return [false, [], 'OpenAI rejected the configured API key.']; }
    if ($httpCode === 403) { return [false, [], 'The configured OpenAI project cannot use this model.']; }
    if ($httpCode === 429) { return [false, [], 'OpenAI rate-limited the request or the project has no available quota.']; }
    $apiMessage = is_array($decoded) ? trim((string)($decoded['error']['message'] ?? '')) : '';
    $safeMessage = $apiMessage !== '' ? mb_substr($apiMessage, 0, 240, 'UTF-8') : ('HTTP ' . ($httpCode > 0 ? $httpCode : 'unknown'));
    return [false, [], 'OpenAI could not analyse this case: ' . $safeMessage];
  }

  $outputText = '';
  $refusal = '';
  foreach (($decoded['output'] ?? []) as $item) {
    if (!is_array($item)) { continue; }
    foreach (($item['content'] ?? []) as $content) {
      if (!is_array($content)) { continue; }
      if (($content['type'] ?? '') === 'output_text') { $outputText .= (string)($content['text'] ?? ''); }
      if (($content['type'] ?? '') === 'refusal') { $refusal = trim((string)($content['refusal'] ?? '')); }
    }
  }
  if ($refusal !== '') { return [false, [], 'OpenAI declined to analyse this case. Review its content and try again.']; }
  if ($outputText === '') { return [false, [], 'OpenAI returned no case suggestions.']; }
  $result = json_decode($outputText, true);
  if (!is_array($result) || !isset($result['suggestions']) || !is_array($result['suggestions'])) {
    return [false, [], 'OpenAI returned an invalid suggestion format.'];
  }
  return [true, $result, ''];
}

/** Allow the original submitter to build or revise an unpublished case. */
function can_manage_case_submission(PDO $pdo, int $caseId): bool {
    if ($caseId <= 0 || empty($_SESSION['user'])) { return false; }
    try {
        $s = $pdo->prepare('SELECT created_by, status FROM cases WHERE id = ? LIMIT 1');
        $s->execute([$caseId]);
        $r = $s->fetch();
        $editableStatuses = ['Being Built', 'Pending', 'Rejected'];
        if ($r && (int)($r['created_by'] ?? 0) === (int)($_SESSION['user']['id'] ?? 0) && in_array(($r['status'] ?? ''), $editableStatuses, true)) {
            return true;
        }
    } catch (Throwable $e) {
        // noop
    }
    return false;
}

function tp_create_user_notification(PDO $pdo, int $userId, string $type, string $title, string $message, ?int $caseId = null): void {
  if ($userId <= 0) { return; }
  $stmt = $pdo->prepare('INSERT INTO user_notifications (user_id, notification_type, title, message, case_id) VALUES (?, ?, ?, ?, ?)');
  $stmt->execute([$userId, substr($type, 0, 64), substr($title, 0, 255), $message, $caseId]);
}

  function normalize_tiktok_usernames($input): string {
    if (is_array($input)) { $input = implode("\n", $input); }
    $raw = str_replace(["\r\n", "\r", ";"], "\n", trim((string)$input));
    if ($raw === '') { return ''; }
    $parts = preg_split('/[\s,]+/', $raw) ?: [];
    $names = [];
    $seen = [];
    foreach ($parts as $part) {
      $name = trim((string)$part);
      if ($name === '') { continue; }
      $name = preg_replace('~^https?://(?:www\.)?tiktok\.com/@?~i', '', $name);
      $name = ltrim((string)$name, '@');
      $name = preg_replace('/[?#\/].*$/', '', $name);
      $name = trim((string)$name);
      if ($name === '') { continue; }
      $key = mb_strtolower($name, 'UTF-8');
      if (isset($seen[$key])) { continue; }
      $seen[$key] = true;
      $names[] = $name;
    }
    return implode(', ', $names);
  }

  function tiktok_username_list($value): array {
    $normalized = normalize_tiktok_usernames($value);
    if ($normalized === '') { return []; }
    return array_values(array_filter(array_map('trim', explode(',', $normalized)), static function($name) {
      return $name !== '';
    }));
  }

  function render_tiktok_usernames($value, string $emptyHtml = '<span class="text-secondary">&mdash;</span>'): string {
    $names = tiktok_username_list($value);
    if (!$names) { return $emptyHtml; }
    $rendered = [];
    foreach ($names as $name) {
      $rendered[] = '@' . htmlspecialchars($name);
    }
    return implode(', ', $rendered);
  }

  function render_tiktok_usernames_lines($value, string $emptyHtml = '<span class="text-secondary">&mdash;</span>'): string {
    $names = tiktok_username_list($value);
    if (!$names) { return $emptyHtml; }
    $rendered = [];
    foreach ($names as $name) {
      $safeName = htmlspecialchars($name);
      $profileUrl = 'https://www.tiktok.com/@' . rawurlencode($name);
      $rendered[] = '<a class="text-decoration-none text-white d-inline-flex align-items-center gap-1" href="' . htmlspecialchars($profileUrl) . '" target="_blank" rel="noopener noreferrer"><i class="bi bi-tiktok small" aria-hidden="true"></i><span>@' . $safeName . '</span></a>';
    }
    return implode('<br>', $rendered);
  }

  function normalize_social_username($input): string {
    $name = trim((string)$input);
    if ($name === '') { return ''; }
    $name = preg_replace('~^https?://(?:www\.)?(?:snapchat\.com/add/|snapchat\.com/@?)~i', '', $name);
    $name = ltrim((string)$name, '@');
    $name = preg_replace('/[?#\/].*$/', '', $name);
    return trim((string)$name);
  }

  function get_case_tiktok_usernames(PDO $pdo, int $caseId): string {
    if ($caseId <= 0) { return ''; }
    try {
      $stmt = $pdo->prepare('SELECT username FROM case_tiktok_usernames WHERE case_id = ? ORDER BY sort_order ASC, id ASC');
      $stmt->execute([$caseId]);
      $names = [];
      foreach ($stmt->fetchAll() as $row) {
        $name = trim((string)($row['username'] ?? ''));
        if ($name !== '') { $names[] = $name; }
      }
      return implode(', ', $names);
    } catch (Throwable $e) {
      return '';
    }
  }

  function save_case_tiktok_usernames(PDO $pdo, int $caseId, $input): string {
    if ($caseId <= 0) { return ''; }
    $names = tiktok_username_list($input);
    $pdo->prepare('DELETE FROM case_tiktok_usernames WHERE case_id = ?')->execute([$caseId]);
    if ($names) {
      $stmt = $pdo->prepare('INSERT INTO case_tiktok_usernames (case_id, username, username_key, sort_order) VALUES (?, ?, ?, ?)');
      foreach ($names as $idx => $name) {
        $stmt->execute([$caseId, $name, mb_strtolower($name, 'UTF-8'), $idx]);
      }
    }
    return implode(', ', $names);
  }

  function backfill_case_tiktok_usernames(PDO $pdo): void {
    try {
      $rows = $pdo->query("SELECT id, tiktok_username FROM cases WHERE tiktok_username IS NOT NULL AND tiktok_username <> ''")->fetchAll();
      if (!$rows) { return; }
      $stmt = $pdo->prepare('INSERT IGNORE INTO case_tiktok_usernames (case_id, username, username_key, sort_order) VALUES (?, ?, ?, ?)');
      foreach ($rows as $row) {
        $caseId = (int)($row['id'] ?? 0);
        if ($caseId <= 0) { continue; }
        foreach (tiktok_username_list($row['tiktok_username'] ?? '') as $idx => $name) {
          $stmt->execute([$caseId, $name, mb_strtolower($name, 'UTF-8'), $idx]);
        }
      }
    } catch (Throwable $e) {
      $_SESSION['sql_error'] = $_SESSION['sql_error'] ?? $e->getMessage();
    }
  }

  function tp_case_tag_options(): array {
    return [
      'adult-predator' => 'Adult Predator',
      'child-predator' => 'Child Predator',
      'domestic-abuse' => 'Domestic Abuse',
      'scammer' => 'Scammer',
      'grooming' => 'Grooming',
      'sextortion' => 'Sextortion',
      'harassment' => 'Harassment',
      'stalking' => 'Stalking',
      'catfishing' => 'Catfishing',
      'impersonation' => 'Impersonation',
      'doxxing' => 'Doxxing',
      'financial-exploitation' => 'Financial Exploitation',
      'threats' => 'Threats',
    ];
  }

  function tp_normalize_case_tags($input): array {
    $rawTags = is_array($input) ? $input : preg_split('/[,\s]+/', (string)$input);
    $allowed = tp_case_tag_options();
    $tags = [];
    foreach (($rawTags ?: []) as $rawTag) {
      $slug = strtolower(trim((string)$rawTag));
      if ($slug === '' || !isset($allowed[$slug]) || isset($tags[$slug])) { continue; }
      $tags[$slug] = $allowed[$slug];
    }
    return $tags;
  }

  function get_case_tags(PDO $pdo, int $caseId): array {
    if ($caseId <= 0) { return []; }
    try {
      $stmt = $pdo->prepare('SELECT t.slug, t.label FROM case_tag_links ctl JOIN case_tags t ON t.id = ctl.tag_id WHERE ctl.case_id = ? ORDER BY t.label ASC');
      $stmt->execute([$caseId]);
      $tags = [];
      foreach ($stmt->fetchAll() as $row) {
        $slug = trim((string)($row['slug'] ?? ''));
        $label = trim((string)($row['label'] ?? ''));
        if ($slug !== '' && $label !== '') { $tags[$slug] = $label; }
      }
      return $tags;
    } catch (Throwable $e) {
      return [];
    }
  }

  function save_case_tags(PDO $pdo, int $caseId, $input): array {
    if ($caseId <= 0) { return []; }
    $tags = tp_normalize_case_tags($input);
    try {
      $pdo->prepare('DELETE FROM case_tag_links WHERE case_id = ?')->execute([$caseId]);
      if ($tags) {
        $selectTag = $pdo->prepare('SELECT id FROM case_tags WHERE slug = ? LIMIT 1');
        $insertLink = $pdo->prepare('INSERT IGNORE INTO case_tag_links (case_id, tag_id) VALUES (?, ?)');
        foreach ($tags as $slug => $label) {
          $selectTag->execute([$slug]);
          $tagRow = $selectTag->fetch();
          $tagId = (int)($tagRow['id'] ?? 0);
          if ($tagId > 0) { $insertLink->execute([$caseId, $tagId]); }
        }
      }
    } catch (Throwable $e) {
      $_SESSION['sql_error'] = $_SESSION['sql_error'] ?? $e->getMessage();
    }
    return $tags;
  }

  function render_case_tag_badges($tags, string $emptyHtml = ''): string {
    if (is_string($tags)) { $tags = tp_normalize_case_tags($tags); }
    if (!is_array($tags) || !$tags) { return $emptyHtml; }
    $html = [];
    foreach ($tags as $slug => $label) {
      $html[] = '<span class="badge text-bg-dark border"><i class="bi bi-tag me-1"></i>' . htmlspecialchars((string)$label) . '</span>';
    }
    return implode(' ', $html);
  }

  function render_case_tag_checkboxes($selected = []): string {
    static $renderCount = 0;
    $renderCount++;
    $selectedTags = tp_normalize_case_tags($selected);
    $html = '<div class="row g-2">';
    foreach (tp_case_tag_options() as $slug => $label) {
      $inputId = 'caseTag_' . $renderCount . '_' . preg_replace('/[^a-z0-9_]+/i', '_', $slug);
      $checked = isset($selectedTags[$slug]) ? ' checked' : '';
      $html .= '<div class="col-sm-6 col-lg-4"><div class="form-check">';
      $html .= '<input class="form-check-input" type="checkbox" name="case_tags[]" value="' . htmlspecialchars($slug) . '" id="' . htmlspecialchars($inputId) . '"' . $checked . '>';
      $html .= '<label class="form-check-label" for="' . htmlspecialchars($inputId) . '">' . htmlspecialchars($label) . '</label>';
      $html .= '</div></div>';
    }
    $html .= '</div>';
    return $html;
  }

  function render_case_tag_filter_options(string $selected = ''): string {
    $html = '<option value="">All Tags</option>';
    foreach (tp_case_tag_options() as $slug => $label) {
      $sel = ($selected === $slug) ? ' selected' : '';
      $html .= '<option value="' . htmlspecialchars($slug) . '"' . $sel . '>' . htmlspecialchars($label) . '</option>';
    }
    return $html;
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

function tp_request_scheme(): string {
    return (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
}

function tp_request_host(): string {
    $host = trim((string)($_SERVER['HTTP_HOST'] ?? 'tiktokpredators.com'));
    return $host !== '' ? $host : 'tiktokpredators.com';
}

function tp_absolute_url(string $pathOrUrl): string {
    $pathOrUrl = trim($pathOrUrl);
    if ($pathOrUrl === '') { return ''; }
    if (preg_match('~^https?://~i', $pathOrUrl)) { return $pathOrUrl; }
    return tp_request_scheme() . '://' . tp_request_host() . '/' . ltrim($pathOrUrl, '/');
}

function tp_social_summary(string $summary, string $fallback): string {
    $summary = trim(preg_replace('/\s+/', ' ', $summary) ?? '');
    if ($summary === '') { $summary = $fallback; }
    return mb_strimwidth($summary, 0, 300, '...', 'UTF-8');
}

function remove_person_photo(string $caseCode): bool {
    $caseCode = trim($caseCode);
    if ($caseCode === '') { return false; }
    $peopleDir = __DIR__ . '/uploads/people';
    $removed = false;
    foreach (['jpg','jpeg','png','webp'] as $ext) {
        $path = $peopleDir . '/' . $caseCode . '.' . $ext;
        if (is_file($path) && @unlink($path)) { $removed = true; }
    }
    return $removed;
}

/**
 * Post a Discord notification when a case is published (status → Verified).
 * Uses the Discord Webhook Embeds API.
 */
function notify_discord_case_verified(string $caseCode, string $caseName, string $personName, string $location, string $summary, string $photoRel): void {
  global $pdo;
  $webhooks = [];
  if (isset($pdo) && $pdo instanceof PDO) {
    $webhooks = tp_discord_webhooks($pdo);
  }
  if (count($webhooks) === 0) {
    return;
  }

    // Build the public case URL
    $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $host   = $_SERVER['HTTP_HOST'] ?? 'tiktokpredators.com';
    $caseUrl = $scheme . '://' . $host . '/?view=case&code=' . rawurlencode($caseCode);

    // Build absolute photo URL if one exists
    $imageUrl = '';
    if ($photoRel !== '') {
        $imageUrl = $scheme . '://' . $host . '/' . ltrim($photoRel, '/');
    }

    // Truncate summary for embed description
    $desc = mb_strlen($summary) > 300 ? mb_substr($summary, 0, 297) . '…' : $summary;

    $embed = [
        'title'       => '🚨 New Verified Case: ' . $caseName,
        'url'         => $caseUrl,
        'color'       => 0xE74C3C, // red
        'description' => $desc,
        'fields'      => [
            ['name' => 'Predator Name', 'value' => ($personName !== '' ? $personName : '—'), 'inline' => true],
            ['name' => 'Location',      'value' => ($location !== '' ? tp_mask_case_location_house_number($location) : '—'), 'inline' => true],
        ],
        'footer' => ['text' => 'TikTok Predators · ' . date('d M Y')],
    ];

    if ($imageUrl !== '') {
        $embed['image'] = ['url' => $imageUrl];
    }

    $payload = [
      'username'   => 'TikTok Predators',
      'avatar_url' => $scheme . '://' . $host . '/assets/favicon/android-chrome-192x192.png',
      'embeds'     => [$embed],
    ];

    foreach ($webhooks as $hook) {
      $webhookUrl = trim((string)($hook['url'] ?? ''));
      $hookName = trim((string)($hook['name'] ?? ''));
      if ($webhookUrl === '') { continue; }
      [$ok, $httpCode, $resp] = tp_post_discord_webhook($webhookUrl, $payload);

      if (!$ok) {
        log_console('WARN', 'Discord webhook ' . ($hookName !== '' ? '['.$hookName.'] ' : '') . 'returned HTTP ' . $httpCode . ': ' . (string)$resp);
      } else {
        log_console('INFO', 'Discord notification sent for case ' . $caseCode . ($hookName !== '' ? ' via ['.$hookName.']' : ''));
      }
    }
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
// --- Account usernames used for owner details and searchable ownership assignment ---
try {
  $usernameCol = $pdo->query("SHOW COLUMNS FROM users LIKE 'username'");
  if (!$usernameCol || !$usernameCol->fetch()) {
    $pdo->exec("ALTER TABLE users ADD COLUMN username VARCHAR(120) NULL AFTER display_name");
  }

  $usedUsernames = [];
  $existingUsernames = $pdo->query("SELECT id, username FROM users WHERE username IS NOT NULL AND username <> '' ORDER BY id")->fetchAll();
  foreach ($existingUsernames as $existingUsername) {
    $usedUsernames[strtolower((string)$existingUsername['username'])] = (int)$existingUsername['id'];
  }
  $missingUsernames = $pdo->query("SELECT id, email FROM users WHERE username IS NULL OR username = '' ORDER BY id")->fetchAll();
  $setUsername = $pdo->prepare('UPDATE users SET username = ? WHERE id = ? AND (username IS NULL OR username = \'\')');
  foreach ($missingUsernames as $missingUsername) {
    $userId = (int)$missingUsername['id'];
    $emailLocal = explode('@', (string)($missingUsername['email'] ?? ''), 2)[0] ?? '';
    $base = tp_normalize_account_username($emailLocal);
    if (mb_strlen($base, 'UTF-8') < 3) { $base = 'user' . $userId; }
    $candidate = $base;
    if (isset($usedUsernames[strtolower($candidate)])) { $candidate = mb_substr($base, 0, 105, 'UTF-8') . '-' . $userId; }
    $usedUsernames[strtolower($candidate)] = $userId;
    $setUsername->execute([$candidate, $userId]);
  }
  $usernameIndex = $pdo->query("SHOW INDEX FROM users WHERE Key_name = 'uq_users_username'");
  if (!$usernameIndex || !$usernameIndex->fetch()) {
    $pdo->exec('ALTER TABLE users ADD UNIQUE INDEX uq_users_username (username)');
  }
} catch (Throwable $e) {
  $_SESSION['sql_error'] = $_SESSION['sql_error'] ?? $e->getMessage();
}
// --- Account signup metadata and successful login history (admin-only display) ---
try {
  $userAuditColumns = [
    'signup_ip' => "ALTER TABLE users ADD COLUMN signup_ip VARCHAR(45) NULL",
    'signup_forwarded_for' => "ALTER TABLE users ADD COLUMN signup_forwarded_for VARCHAR(255) NULL",
    'signup_user_agent' => "ALTER TABLE users ADD COLUMN signup_user_agent VARCHAR(1024) NULL",
  ];
  foreach ($userAuditColumns as $columnName => $alterSql) {
    $column = $pdo->query("SHOW COLUMNS FROM users LIKE " . $pdo->quote($columnName));
    if (!$column || !$column->fetch()) { $pdo->exec($alterSql); }
  }
  $pdo->exec(<<<SQL
CREATE TABLE IF NOT EXISTS user_login_history (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  user_id BIGINT UNSIGNED NOT NULL,
  ip_address VARCHAR(45) NULL,
  forwarded_for VARCHAR(255) NULL,
  user_agent VARCHAR(1024) NULL,
  logged_in_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_user_login_history_user_time (user_id, logged_in_at),
  INDEX idx_user_login_history_ip (ip_address),
  INDEX idx_user_login_history_time (logged_in_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
SQL
  );
} catch (Throwable $e) {
  $_SESSION['sql_error'] = $_SESSION['sql_error'] ?? $e->getMessage();
}
// --- Project settings table setup ---
try {
  $pdo->exec(<<<SQL
CREATE TABLE IF NOT EXISTS project_settings (
  setting_key VARCHAR(64) NOT NULL PRIMARY KEY,
  setting_value LONGTEXT NULL,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
SQL
  );
  $defaultSettings = [
    'site_title' => 'TikTokPredators',
    'meta_data' => 'A public, auditable repository documenting abusive behaviour by TikTok accounts — case records, evidence, and verifiable proof to expose predators and support accountability.',
    'openai_api_key' => '',
    'discord_webhook_key' => '',
    'discord_webhooks' => '[]',
  ];
  $seed = $pdo->prepare('INSERT IGNORE INTO project_settings (setting_key, setting_value) VALUES (?, ?)');
  foreach ($defaultSettings as $settingKey => $settingValue) {
    $seed->execute([$settingKey, $settingValue]);
  }
} catch (Throwable $e) {
  $_SESSION['sql_error'] = $_SESSION['sql_error'] ?? $e->getMessage();
}
  // --- Cases schema safety: ensure location column exists and username field can hold multiple values ---
  try {
    $col = $pdo->query("SHOW COLUMNS FROM cases LIKE 'location'");
    if (!$col || !$col->fetch()) {
      $pdo->exec("ALTER TABLE cases ADD COLUMN location VARCHAR(255) NULL AFTER person_name");
    }
    $phoneCol = $pdo->query("SHOW COLUMNS FROM cases LIKE 'phone_number'");
    if (!$phoneCol || !$phoneCol->fetch()) {
      $pdo->exec("ALTER TABLE cases ADD COLUMN phone_number VARCHAR(64) NULL AFTER location");
    }
    $snapCol = $pdo->query("SHOW COLUMNS FROM cases LIKE 'snapchat_username'");
    if (!$snapCol || !$snapCol->fetch()) {
      $pdo->exec("ALTER TABLE cases ADD COLUMN snapchat_username VARCHAR(255) NULL AFTER phone_number");
    }
    $userCol = $pdo->query("SHOW COLUMNS FROM cases LIKE 'tiktok_username'");
    $userInfo = $userCol ? $userCol->fetch() : null;
    $userType = strtolower((string)($userInfo['Type'] ?? ''));
    if ($userInfo && strpos($userType, 'text') === false) {
      $pdo->exec("ALTER TABLE cases MODIFY COLUMN tiktok_username TEXT NULL");
    }
    $statusCol = $pdo->query("SHOW COLUMNS FROM cases LIKE 'status'");
    $statusInfo = $statusCol ? $statusCol->fetch() : null;
    $statusType = (string)($statusInfo['Type'] ?? '');
    $statusDefault = (string)($statusInfo['Default'] ?? '');
    if ($statusInfo && stripos($statusType, 'enum(') === 0 && (stripos($statusType, "'Being Built'") === false || stripos($statusType, "'Rejected'") === false || $statusDefault !== 'Being Built')) {
      $pdo->exec("ALTER TABLE cases MODIFY COLUMN status ENUM('Being Built','Pending','Open','In Review','Verified','Closed','Rejected') NOT NULL DEFAULT 'Being Built'");
    }
    $reviewColumns = [
      'rejection_reason' => "ALTER TABLE cases ADD COLUMN rejection_reason TEXT NULL AFTER status",
      'rejected_at' => "ALTER TABLE cases ADD COLUMN rejected_at DATETIME NULL AFTER rejection_reason",
      'rejected_by' => "ALTER TABLE cases ADD COLUMN rejected_by BIGINT UNSIGNED NULL AFTER rejected_at",
      'resubmitted_at' => "ALTER TABLE cases ADD COLUMN resubmitted_at DATETIME NULL AFTER rejected_by",
      'submitted_for_review_at' => "ALTER TABLE cases ADD COLUMN submitted_for_review_at DATETIME NULL AFTER resubmitted_at",
    ];
    foreach ($reviewColumns as $columnName => $alterSql) {
      $reviewCol = $pdo->query("SHOW COLUMNS FROM cases LIKE " . $pdo->quote($columnName));
      if (!$reviewCol || !$reviewCol->fetch()) { $pdo->exec($alterSql); }
    }
  } catch (Throwable $e) {
    $_SESSION['sql_error'] = $_SESSION['sql_error'] ?? $e->getMessage();
  }
// --- Case TikTok usernames relationship setup and legacy backfill ---
try {
    $pdo->exec("\n        CREATE TABLE IF NOT EXISTS case_tiktok_usernames (\n            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,\n            case_id BIGINT UNSIGNED NOT NULL,\n            username VARCHAR(255) NOT NULL,\n            username_key VARCHAR(255) NOT NULL,\n            sort_order INT UNSIGNED NOT NULL DEFAULT 0,\n            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,\n            UNIQUE KEY uq_case_username (case_id, username_key),\n            INDEX idx_case_sort (case_id, sort_order, id),\n            INDEX idx_username_key (username_key)\n        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;\n    ");
    backfill_case_tiktok_usernames($pdo);
} catch (Throwable $e) {
    $_SESSION['sql_error'] = $_SESSION['sql_error'] ?? $e->getMessage();
}
// --- Case tags setup ---
try {
  $legacyCaseTags = false;
  try {
    $legacyCol = $pdo->query("SHOW COLUMNS FROM case_tags LIKE 'slug'");
    $legacyCaseTags = (!$legacyCol || !$legacyCol->fetch());
  } catch (Throwable $e) {
    $legacyCaseTags = false;
  }
  if ($legacyCaseTags) {
    $legacyCount = 0;
    try { $legacyCount = (int)$pdo->query('SELECT COUNT(*) FROM case_tags')->fetchColumn(); } catch (Throwable $e) {}
    if ($legacyCount === 0) {
      $pdo->exec('DROP TABLE case_tags');
    } else {
      $pdo->exec('RENAME TABLE case_tags TO case_tags_legacy_' . date('YmdHis'));
    }
  }
  $pdo->exec("\n        CREATE TABLE IF NOT EXISTS case_tags (\n            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,\n            slug VARCHAR(64) NOT NULL,\n            label VARCHAR(128) NOT NULL,\n            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,\n            UNIQUE KEY uq_case_tag_slug (slug),\n            INDEX idx_case_tag_label (label)\n        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;\n    ");
  $pdo->exec("\n        CREATE TABLE IF NOT EXISTS case_tag_links (\n            case_id BIGINT UNSIGNED NOT NULL,\n            tag_id BIGINT UNSIGNED NOT NULL,\n            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,\n            PRIMARY KEY (case_id, tag_id),\n            INDEX idx_case_tag_links_tag (tag_id)\n        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;\n    ");
  try {
    $createdAtCol = $pdo->query("SHOW COLUMNS FROM case_tag_links LIKE 'created_at'");
    if (!$createdAtCol || !$createdAtCol->fetch()) {
      $pdo->exec('ALTER TABLE case_tag_links ADD COLUMN created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP');
    }
  } catch (Throwable $e) {}
  $tagSeed = $pdo->prepare('INSERT INTO case_tags (slug, label) VALUES (?, ?) ON DUPLICATE KEY UPDATE label = VALUES(label)');
  foreach (tp_case_tag_options() as $tagSlug => $tagLabel) {
    $tagSeed->execute([$tagSlug, $tagLabel]);
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
// --- Original case-submission network and geo metadata (admin-only display) ---
try {
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS case_submission_metadata (
            case_id BIGINT UNSIGNED NOT NULL PRIMARY KEY,
            submitted_by BIGINT UNSIGNED NULL,
            submitted_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            public_ip VARCHAR(45) NULL,
            forwarded_for VARCHAR(255) NULL,
            geo_json LONGTEXT NULL,
            user_agent VARCHAR(1024) NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_case_submission_user (submitted_by),
            INDEX idx_case_submission_ip (public_ip),
            INDEX idx_case_submission_at (submitted_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    ");
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS case_ownership_history (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
            case_id BIGINT UNSIGNED NOT NULL,
            previous_owner_id BIGINT UNSIGNED NULL,
            new_owner_id BIGINT UNSIGNED NOT NULL,
            changed_by BIGINT UNSIGNED NULL,
            changed_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_case_ownership_case (case_id, changed_at),
            INDEX idx_case_ownership_new_owner (new_owner_id),
            INDEX idx_case_ownership_changed_by (changed_by)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    ");
} catch (Throwable $e) {
    $_SESSION['sql_error'] = $_SESSION['sql_error'] ?? $e->getMessage();
}
// --- AI-assisted case builder runs and reviewable suggestions ---
try {
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS case_ai_runs (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
            case_id BIGINT UNSIGNED NOT NULL,
            requested_by BIGINT UNSIGNED NULL,
            model VARCHAR(128) NOT NULL,
            status ENUM('Processing','Completed','Failed') NOT NULL DEFAULT 'Processing',
            overall_notes TEXT NULL,
            error_message TEXT NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            completed_at DATETIME NULL,
            INDEX idx_case_ai_runs_case_created (case_id, created_at),
            INDEX idx_case_ai_runs_status (status)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    ");
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS case_ai_suggestions (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
            run_id BIGINT UNSIGNED NOT NULL,
            case_id BIGINT UNSIGNED NOT NULL,
            field_name VARCHAR(64) NOT NULL,
            current_value LONGTEXT NULL,
            suggested_value LONGTEXT NOT NULL,
            reason TEXT NOT NULL,
            decision ENUM('Pending','Approved','Rejected') NOT NULL DEFAULT 'Pending',
            decided_by BIGINT UNSIGNED NULL,
            decided_at DATETIME NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_case_ai_suggestions_run (run_id, id),
            INDEX idx_case_ai_suggestions_case_decision (case_id, decision),
            INDEX idx_case_ai_suggestions_decided_by (decided_by)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    ");
} catch (Throwable $e) {
    $_SESSION['sql_error'] = $_SESSION['sql_error'] ?? $e->getMessage();
}
// --- Persistent account notifications ---
try {
  $pdo->exec("
    CREATE TABLE IF NOT EXISTS user_notifications (
      id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
      user_id BIGINT UNSIGNED NOT NULL,
      notification_type VARCHAR(64) NOT NULL,
      title VARCHAR(255) NOT NULL,
      message TEXT NOT NULL,
      case_id BIGINT UNSIGNED NULL,
      is_read TINYINT(1) NOT NULL DEFAULT 0,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      read_at DATETIME NULL,
      INDEX idx_user_unread_created (user_id, is_read, created_at),
      INDEX idx_notification_case (case_id)
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
      ip_hash CHAR(64) NULL,
      referrer_host VARCHAR(255) NULL,
      is_same_site_referrer TINYINT(1) NULL,
      request_path VARCHAR(512) NULL,
      query_string VARCHAR(1024) NULL,
      language_primary VARCHAR(16) NULL,
      is_bot TINYINT(1) NOT NULL DEFAULT 0,
      bot_reason VARCHAR(255) NULL,
      analytics_score INT NOT NULL DEFAULT 0,
      alert_flags VARCHAR(512) NULL,
      screen_width INT UNSIGNED NULL,
      screen_height INT UNSIGNED NULL,
      viewport_width INT UNSIGNED NULL,
      viewport_height INT UNSIGNED NULL,
      client_timezone VARCHAR(64) NULL,
      client_timezone_offset INT NULL,
      client_platform VARCHAR(128) NULL,
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
      INDEX idx_ip_hash (ip_hash),
      INDEX idx_geo_ip (geo_ip),
      INDEX idx_geo_country (geo_country),
      INDEX idx_score_viewed_at (analytics_score, viewed_at)
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
    'ip_hash' => "ALTER TABLE case_views ADD COLUMN ip_hash CHAR(64) NULL AFTER is_hosting",
    'referrer_host' => "ALTER TABLE case_views ADD COLUMN referrer_host VARCHAR(255) NULL AFTER ip_hash",
    'is_same_site_referrer' => "ALTER TABLE case_views ADD COLUMN is_same_site_referrer TINYINT(1) NULL AFTER referrer_host",
    'request_path' => "ALTER TABLE case_views ADD COLUMN request_path VARCHAR(512) NULL AFTER is_same_site_referrer",
    'query_string' => "ALTER TABLE case_views ADD COLUMN query_string VARCHAR(1024) NULL AFTER request_path",
    'language_primary' => "ALTER TABLE case_views ADD COLUMN language_primary VARCHAR(16) NULL AFTER query_string",
    'is_bot' => "ALTER TABLE case_views ADD COLUMN is_bot TINYINT(1) NOT NULL DEFAULT 0 AFTER language_primary",
    'bot_reason' => "ALTER TABLE case_views ADD COLUMN bot_reason VARCHAR(255) NULL AFTER is_bot",
    'analytics_score' => "ALTER TABLE case_views ADD COLUMN analytics_score INT NOT NULL DEFAULT 0 AFTER bot_reason",
    'alert_flags' => "ALTER TABLE case_views ADD COLUMN alert_flags VARCHAR(512) NULL AFTER analytics_score",
    'screen_width' => "ALTER TABLE case_views ADD COLUMN screen_width INT UNSIGNED NULL AFTER alert_flags",
    'screen_height' => "ALTER TABLE case_views ADD COLUMN screen_height INT UNSIGNED NULL AFTER screen_width",
    'viewport_width' => "ALTER TABLE case_views ADD COLUMN viewport_width INT UNSIGNED NULL AFTER screen_height",
    'viewport_height' => "ALTER TABLE case_views ADD COLUMN viewport_height INT UNSIGNED NULL AFTER viewport_width",
    'client_timezone' => "ALTER TABLE case_views ADD COLUMN client_timezone VARCHAR(64) NULL AFTER viewport_height",
    'client_timezone_offset' => "ALTER TABLE case_views ADD COLUMN client_timezone_offset INT NULL AFTER client_timezone",
    'client_platform' => "ALTER TABLE case_views ADD COLUMN client_platform VARCHAR(128) NULL AFTER client_timezone_offset",
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
  foreach ([
    'idx_ip_hash' => 'ALTER TABLE case_views ADD INDEX idx_ip_hash (ip_hash)',
    'idx_score_viewed_at' => 'ALTER TABLE case_views ADD INDEX idx_score_viewed_at (analytics_score, viewed_at)',
  ] as $idxName => $idxSql) {
    try {
      $idx = $pdo->query("SHOW INDEX FROM case_views WHERE Key_name = " . $pdo->quote($idxName));
      if (!$idx || !$idx->fetch()) {
        $pdo->exec($idxSql);
      }
    } catch (Throwable $e) {
      $_SESSION['sql_error'] = $_SESSION['sql_error'] ?? $e->getMessage();
    }
  }
} catch (Throwable $e) {
  $_SESSION['sql_error'] = $_SESSION['sql_error'] ?? $e->getMessage();
}

// --- Case analytics alerts setup ---
try {
  $pdo->exec("
    CREATE TABLE IF NOT EXISTS case_analytics_alerts (
      id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
      case_id BIGINT UNSIGNED NOT NULL DEFAULT 0,
      alert_type VARCHAR(64) NOT NULL,
      severity ENUM('low','medium','high') NOT NULL DEFAULT 'low',
      title VARCHAR(255) NOT NULL,
      detail TEXT NULL,
      unique_key CHAR(64) NOT NULL,
      metric_value DECIMAL(12,2) NULL,
      threshold_value DECIMAL(12,2) NULL,
      first_seen_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      last_seen_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      occurrence_count INT UNSIGNED NOT NULL DEFAULT 1,
      is_resolved TINYINT(1) NOT NULL DEFAULT 0,
      resolved_at DATETIME NULL,
      resolved_by BIGINT UNSIGNED NULL,
      INDEX idx_case_last_seen (case_id, last_seen_at),
      INDEX idx_type_severity (alert_type, severity),
      INDEX idx_unresolved_seen (is_resolved, last_seen_at),
      UNIQUE KEY uq_case_alert_key (unique_key)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  ");
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

    /** Delete accounts while preserving submitted cases and detaching ownership references. */
    function tp_delete_user_accounts(PDO $pdo, array $userIds): int {
      $userIds = array_values(array_unique(array_filter(array_map('intval', $userIds), static fn (int $id): bool => $id > 0)));
      if (!$userIds) { return 0; }
      $placeholders = implode(',', array_fill(0, count($userIds), '?'));
      $startedTransaction = !$pdo->inTransaction();
      if ($startedTransaction) { $pdo->beginTransaction(); }

      try {
        $cleanupStatements = [
          'UPDATE cases SET created_by = NULL WHERE created_by IN (' . $placeholders . ')',
          'UPDATE evidence SET uploaded_by = NULL WHERE uploaded_by IN (' . $placeholders . ')',
          'UPDATE evidence SET created_by = NULL WHERE created_by IN (' . $placeholders . ')',
          'UPDATE case_notes SET created_by = NULL WHERE created_by IN (' . $placeholders . ')',
          'UPDATE case_events SET created_by = NULL WHERE created_by IN (' . $placeholders . ')',
          'UPDATE case_submission_metadata SET submitted_by = NULL WHERE submitted_by IN (' . $placeholders . ')',
          'UPDATE case_ownership_history SET previous_owner_id = NULL WHERE previous_owner_id IN (' . $placeholders . ')',
          'UPDATE case_ownership_history SET changed_by = NULL WHERE changed_by IN (' . $placeholders . ')',
          'DELETE FROM case_ownership_history WHERE new_owner_id IN (' . $placeholders . ')',
          'UPDATE case_ai_runs SET requested_by = NULL WHERE requested_by IN (' . $placeholders . ')',
          'UPDATE case_ai_suggestions SET decided_by = NULL WHERE decided_by IN (' . $placeholders . ')',
          'UPDATE case_analytics_alerts SET resolved_by = NULL WHERE resolved_by IN (' . $placeholders . ')',
          'DELETE FROM user_notifications WHERE user_id IN (' . $placeholders . ')',
          'DELETE FROM user_login_history WHERE user_id IN (' . $placeholders . ')',
        ];
        foreach ($cleanupStatements as $cleanupSql) {
          try {
            $cleanup = $pdo->prepare($cleanupSql);
            $cleanup->execute($userIds);
          } catch (Throwable $cleanupError) {
            log_console('WARN', 'User deletion cleanup skipped: ' . $cleanupError->getMessage());
          }
        }
        $delete = $pdo->prepare('DELETE FROM users WHERE id IN (' . $placeholders . ')');
        $delete->execute($userIds);
        $deletedCount = $delete->rowCount();
        if ($startedTransaction) { $pdo->commit(); }
        return $deletedCount;
      } catch (Throwable $e) {
        if ($startedTransaction && $pdo->inTransaction()) { $pdo->rollBack(); }
        throw $e;
      }
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

    function tp_record_case_submission_metadata(PDO $pdo, int $caseId, ?int $submittedBy = null, ?string $submittedAt = null): void {
      if ($caseId <= 0) { return; }
      try {
        [$publicIp, $forwardedFor] = tp_client_ip();
        [$headerCountry, $headerRegion, $headerCity, $headerSource] = tp_geo_from_headers();
        $geo = tp_geo_lookup_api($publicIp) ?? [];
        if (trim((string)($geo['geo_country'] ?? '')) === '') { $geo['geo_country'] = $headerCountry; }
        if (trim((string)($geo['geo_region'] ?? '')) === '') { $geo['geo_region'] = $headerRegion; }
        if (trim((string)($geo['geo_city'] ?? '')) === '') { $geo['geo_city'] = $headerCity; }
        if (trim((string)($geo['geo_source'] ?? '')) === '') { $geo['geo_source'] = $headerSource; }
        $geoJson = $geo ? json_encode($geo, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) : null;
        if ($geoJson === false) { $geoJson = null; }

        $stmt = $pdo->prepare('INSERT IGNORE INTO case_submission_metadata (case_id, submitted_by, submitted_at, public_ip, forwarded_for, geo_json, user_agent) VALUES (?, ?, COALESCE(?, NOW()), NULLIF(?, \'\'), NULLIF(?, \'\'), ?, NULLIF(?, \'\'))');
        $stmt->execute([
          $caseId,
          $submittedBy,
          $submittedAt,
          $publicIp,
          $forwardedFor,
          $geoJson,
          mb_substr(trim((string)($_SERVER['HTTP_USER_AGENT'] ?? '')), 0, 1024, 'UTF-8'),
        ]);
      } catch (Throwable $e) {
        $_SESSION['sql_error'] = $_SESSION['sql_error'] ?? $e->getMessage();
      }
    }

    function tp_url_host(string $url): string {
      $url = trim($url);
      if ($url === '') { return ''; }
      $host = (string)(parse_url($url, PHP_URL_HOST) ?: '');
      return strtolower(preg_replace('/^www\./i', '', trim($host)) ?? '');
    }

    function tp_primary_language(string $acceptLanguage): string {
      $acceptLanguage = trim($acceptLanguage);
      if ($acceptLanguage === '') { return ''; }
      $first = trim(explode(',', $acceptLanguage)[0] ?? '');
      $first = trim(explode(';', $first)[0] ?? '');
      return substr($first, 0, 16);
    }

    function tp_detect_bot(string $ua, string $acceptLanguage): array {
      $ua = trim($ua);
      if ($ua === '') { return [1, 'Missing user agent']; }
      $reasons = [];
      if (preg_match('/bot|crawl|spider|slurp|scanner|monitor|scrape|curl|wget|python-requests|httpclient|headless|phantom|selenium/i', $ua)) {
        $reasons[] = 'Automation keyword';
      }
      if (trim($acceptLanguage) === '' && !preg_match('/facebookexternalhit|discordbot|twitterbot|slackbot/i', $ua)) {
        $reasons[] = 'Missing accept-language';
      }
      return [count($reasons) > 0 ? 1 : 0, implode(', ', $reasons)];
    }

    function tp_view_risk_score(array $signals): array {
      $score = 0;
      $flags = [];

      if (!empty($signals['is_proxy'])) { $score += 35; $flags[] = 'proxy'; }
      if (!empty($signals['is_hosting'])) { $score += 25; $flags[] = 'hosting'; }
      if (!empty($signals['is_bot'])) { $score += 30; $flags[] = 'bot'; }
      if (!empty($signals['missing_referrer'])) { $score += 5; $flags[] = 'direct'; }
      if (!empty($signals['repeat_ip_case_views']) && (int)$signals['repeat_ip_case_views'] >= 10) { $score += 20; $flags[] = 'repeat-ip-case'; }
      if (!empty($signals['ip_distinct_cases']) && (int)$signals['ip_distinct_cases'] >= 5) { $score += 20; $flags[] = 'multi-case-ip'; }
      if (!empty($signals['case_hour_views']) && (int)$signals['case_hour_views'] >= 25) { $score += 15; $flags[] = 'case-spike'; }

      $score = min(100, $score);
      return [$score, implode(',', array_values(array_unique($flags)))];
    }

    function tp_record_case_analytics_alert(PDO $pdo, int $caseId, string $type, string $severity, string $title, string $detail, float $metricValue = 0, float $thresholdValue = 0, string $dedupeSuffix = ''): void {
      try {
        $severity = in_array($severity, ['low','medium','high'], true) ? $severity : 'low';
        $keyParts = [$caseId, $type, $severity, $dedupeSuffix !== '' ? $dedupeSuffix : date('Y-m-d-H')];
        $uniqueKey = hash('sha256', implode('|', $keyParts));
        $stmt = $pdo->prepare("INSERT INTO case_analytics_alerts (case_id, alert_type, severity, title, detail, unique_key, metric_value, threshold_value) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE last_seen_at = CURRENT_TIMESTAMP, occurrence_count = occurrence_count + 1, metric_value = VALUES(metric_value), threshold_value = VALUES(threshold_value), detail = VALUES(detail), is_resolved = 0, resolved_at = NULL");
        $stmt->execute([$caseId, $type, $severity, $title, $detail, $uniqueKey, $metricValue, $thresholdValue]);
      } catch (Throwable $e) {
        $_SESSION['sql_error'] = $_SESSION['sql_error'] ?? $e->getMessage();
      }
    }

    function tp_evaluate_case_view_alerts(PDO $pdo, int $caseId, array $viewSignals): void {
      if ($caseId <= 0) { return; }
      $ipHash = (string)($viewSignals['ip_hash'] ?? '');
      $ipLabel = (string)($viewSignals['public_ip'] ?? 'unknown IP');

      if (!empty($viewSignals['is_proxy'])) {
        tp_record_case_analytics_alert($pdo, $caseId, 'proxy_view', 'medium', 'Proxy viewer detected', 'A case view came from an IP flagged as proxy/VPN: ' . $ipLabel, 1, 1, 'proxy-' . $ipHash . '-' . date('Y-m-d'));
      }
      if (!empty($viewSignals['is_hosting'])) {
        tp_record_case_analytics_alert($pdo, $caseId, 'hosting_view', 'medium', 'Hosting network viewer detected', 'A case view came from a hosting/datacenter network: ' . $ipLabel, 1, 1, 'hosting-' . $ipHash . '-' . date('Y-m-d'));
      }
      if (!empty($viewSignals['is_bot'])) {
        $reason = trim((string)($viewSignals['bot_reason'] ?? ''));
        tp_record_case_analytics_alert($pdo, $caseId, 'bot_view', 'low', 'Likely automated viewer', 'A case view looked automated' . ($reason !== '' ? ': ' . $reason : '.') . ' IP: ' . $ipLabel, 1, 1, 'bot-' . $ipHash . '-' . date('Y-m-d'));
      }

      try {
        if ($ipHash !== '') {
          $stmt = $pdo->prepare('SELECT COUNT(*) FROM case_views WHERE case_id = ? AND ip_hash = ? AND viewed_at >= (NOW() - INTERVAL 1 HOUR)');
          $stmt->execute([$caseId, $ipHash]);
          $repeatCaseViews = (int)$stmt->fetchColumn();
          if ($repeatCaseViews >= 10) {
            tp_record_case_analytics_alert($pdo, $caseId, 'repeat_ip_case_views', 'high', 'Repeated views from one IP', $ipLabel . ' viewed this case ' . $repeatCaseViews . ' times in the last hour.', $repeatCaseViews, 10, 'repeat-ip-' . $ipHash . '-' . date('Y-m-d-H'));
          }

          $stmt = $pdo->prepare('SELECT COUNT(DISTINCT case_id) FROM case_views WHERE ip_hash = ? AND case_id > 0 AND viewed_at >= (NOW() - INTERVAL 1 HOUR)');
          $stmt->execute([$ipHash]);
          $distinctCases = (int)$stmt->fetchColumn();
          if ($distinctCases >= 5) {
            tp_record_case_analytics_alert($pdo, $caseId, 'multi_case_ip', 'medium', 'One IP viewing many cases', $ipLabel . ' viewed ' . $distinctCases . ' different cases in the last hour.', $distinctCases, 5, 'multi-case-' . $ipHash . '-' . date('Y-m-d-H'));
          }
        }

        $stmt = $pdo->prepare('SELECT COUNT(*) FROM case_views WHERE case_id = ? AND viewed_at >= (NOW() - INTERVAL 1 HOUR)');
        $stmt->execute([$caseId]);
        $caseHourViews = (int)$stmt->fetchColumn();

        $stmt = $pdo->prepare('SELECT COUNT(*) / 23 FROM case_views WHERE case_id = ? AND viewed_at >= (NOW() - INTERVAL 24 HOUR) AND viewed_at < (NOW() - INTERVAL 1 HOUR)');
        $stmt->execute([$caseId]);
        $previousHourlyAvg = (float)$stmt->fetchColumn();
        $spikeThreshold = max(25, $previousHourlyAvg * 3);
        if ($caseHourViews >= $spikeThreshold) {
          tp_record_case_analytics_alert($pdo, $caseId, 'traffic_spike', 'high', 'Case traffic spike', 'This case received ' . $caseHourViews . ' views in the last hour. Previous 23-hour average: ' . round($previousHourlyAvg, 1) . ' views/hour.', $caseHourViews, $spikeThreshold, 'spike-' . date('Y-m-d-H'));
        }
      } catch (Throwable $e) {
        $_SESSION['sql_error'] = $_SESSION['sql_error'] ?? $e->getMessage();
      }
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
        $ipHash = $publicIp !== '' ? hash('sha256', $publicIp . '|' . (string)(getenv('ANALYTICS_HASH_SALT') ?: '.tiktokpredators.com')) : null;
        $referer = trim((string)($_SERVER['HTTP_REFERER'] ?? ''));
        $referrerHost = tp_url_host($referer);
        $requestHost = tp_url_host(tp_request_scheme() . '://' . tp_request_host());
        $isSameSiteReferrer = ($referrerHost !== '' && $requestHost !== '' && $referrerHost === $requestHost) ? 1 : 0;
        $requestUri = trim((string)($_SERVER['REQUEST_URI'] ?? ''));
        $requestPath = (string)(parse_url($requestUri, PHP_URL_PATH) ?: '');
        $queryString = trim((string)($_SERVER['QUERY_STRING'] ?? ''));
        $acceptLanguage = trim((string)($_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? ''));
        $primaryLanguage = tp_primary_language($acceptLanguage);
        [$isBot, $botReason] = tp_detect_bot($ua, $acceptLanguage);

        $preRepeatCaseViews = 0;
        $preDistinctCases = 0;
        $preCaseHourViews = 0;
        try {
          if ($ipHash !== '') {
            $pre = $pdo->prepare('SELECT COUNT(*) FROM case_views WHERE case_id = ? AND ip_hash = ? AND viewed_at >= (NOW() - INTERVAL 1 HOUR)');
            $pre->execute([$caseId, $ipHash]);
            $preRepeatCaseViews = (int)$pre->fetchColumn();

            $pre = $pdo->prepare('SELECT COUNT(DISTINCT case_id) FROM case_views WHERE ip_hash = ? AND case_id > 0 AND viewed_at >= (NOW() - INTERVAL 1 HOUR)');
            $pre->execute([$ipHash]);
            $preDistinctCases = (int)$pre->fetchColumn();
          }
          $pre = $pdo->prepare('SELECT COUNT(*) FROM case_views WHERE case_id = ? AND viewed_at >= (NOW() - INTERVAL 1 HOUR)');
          $pre->execute([$caseId]);
          $preCaseHourViews = (int)$pre->fetchColumn();
        } catch (Throwable $e) {}

        [$analyticsScore, $alertFlags] = tp_view_risk_score([
          'is_proxy' => $isProxy,
          'is_hosting' => $isHosting,
          'is_bot' => $isBot,
          'missing_referrer' => $referer === '',
          'repeat_ip_case_views' => $preRepeatCaseViews + 1,
          'ip_distinct_cases' => $preDistinctCases + 1,
          'case_hour_views' => $preCaseHourViews + 1,
        ]);

        $stmt = $pdo->prepare('INSERT INTO case_views (case_id, viewer_user_id, viewer_role, is_authenticated, session_key, public_ip, forwarded_for, geo_ip, geo_continent_name, geo_continent_code, geo_country_name, geo_country, geo_region_code, geo_region, geo_city, geo_district, geo_postcode, geo_lat, geo_lon, geo_timezone, geo_utc_offset, geo_currency, net_isp, net_org, net_as, net_as_name, net_reverse_dns, is_mobile, is_proxy, is_hosting, ip_hash, referrer_host, is_same_site_referrer, request_path, query_string, language_primary, is_bot, bot_reason, analytics_score, alert_flags, geo_source, device_type, os_name, browser_name, browser_version, user_agent, accept_language, referer, request_uri, request_method) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)');
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
          $ipHash,
          $referrerHost !== '' ? substr($referrerHost, 0, 255) : null,
          $isSameSiteReferrer,
          $requestPath !== '' ? substr($requestPath, 0, 512) : null,
          $queryString !== '' ? substr($queryString, 0, 1024) : null,
          $primaryLanguage !== '' ? substr($primaryLanguage, 0, 16) : null,
          $isBot,
          $botReason !== '' ? substr($botReason, 0, 255) : null,
          $analyticsScore,
          $alertFlags !== '' ? substr($alertFlags, 0, 512) : null,
          $geoSource !== '' ? substr($geoSource, 0, 64) : null,
          $deviceType,
          $osName,
          $browserName,
          $browserVersion !== '' ? substr($browserVersion, 0, 32) : null,
          $ua !== '' ? substr($ua, 0, 1024) : null,
          $acceptLanguage !== '' ? substr($acceptLanguage, 0, 255) : null,
          $referer !== '' ? substr($referer, 0, 1024) : null,
          $requestUri !== '' ? substr($requestUri, 0, 1024) : null,
          ($method = trim((string)($_SERVER['REQUEST_METHOD'] ?? 'GET'))) !== '' ? substr($method, 0, 16) : 'GET',
        ]);
        $_SESSION['last_case_view_id'] = $_SESSION['last_case_view_id'] ?? [];
        $_SESSION['last_case_view_id'][(string)$caseId] = (int)$pdo->lastInsertId();
        tp_evaluate_case_view_alerts($pdo, $caseId, [
          'public_ip' => $publicIp,
          'ip_hash' => $ipHash,
          'is_proxy' => $isProxy,
          'is_hosting' => $isHosting,
          'is_bot' => $isBot,
          'bot_reason' => $botReason,
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
        $q = $pdo->prepare('SELECT e.id, e.filepath, e.mime_type, e.type, e.case_id, c.sensitivity, c.status AS case_status, c.created_by AS case_created_by FROM evidence e JOIN cases c ON c.id = e.case_id WHERE e.id = ? LIMIT 1');
        $q->execute([$eid]);
        $row = $q->fetch();
    } catch (Throwable $e) {
        http_response_code(500); exit('Server error');
    }
    if (!$row) { http_response_code(404); exit('Not found'); }
    $isReviewCaseOwner = !empty($_SESSION['user']) && (int)($row['case_created_by'] ?? 0) === (int)($_SESSION['user']['id'] ?? 0);
    $isPrivateReviewStatus = in_array(($row['case_status'] ?? ''), ['Being Built','Pending','Rejected'], true);
    if ($isPrivateReviewStatus && !is_admin() && !$isReviewCaseOwner) { http_response_code(404); exit('Not found'); }
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

if (($_POST['action'] ?? '') === 'update_view_client') {
  header('Content-Type: application/json; charset=utf-8');
  if (!check_csrf()) {
    http_response_code(403);
    echo json_encode(['success' => false, 'error' => 'Security check failed']);
    exit;
  }

  $caseId = (int)($_POST['case_id'] ?? 0);
  $lastViewId = (int)($_SESSION['last_case_view_id'][(string)$caseId] ?? 0);
  $sessionKey = session_id() !== '' ? hash('sha256', session_id()) : '';
  if ($lastViewId <= 0 || $sessionKey === '') {
    echo json_encode(['success' => false, 'error' => 'No matching view']);
    exit;
  }

  $screenWidth = max(0, min(100000, (int)($_POST['screen_width'] ?? 0)));
  $screenHeight = max(0, min(100000, (int)($_POST['screen_height'] ?? 0)));
  $viewportWidth = max(0, min(100000, (int)($_POST['viewport_width'] ?? 0)));
  $viewportHeight = max(0, min(100000, (int)($_POST['viewport_height'] ?? 0)));
  $timezone = substr(trim((string)($_POST['timezone'] ?? '')), 0, 64);
  $timezoneOffset = (int)($_POST['timezone_offset'] ?? 0);
  $platform = substr(trim((string)($_POST['platform'] ?? '')), 0, 128);

  try {
    $stmt = $pdo->prepare('UPDATE case_views SET screen_width = NULLIF(?, 0), screen_height = NULLIF(?, 0), viewport_width = NULLIF(?, 0), viewport_height = NULLIF(?, 0), client_timezone = NULLIF(?, \'\'), client_timezone_offset = ?, client_platform = NULLIF(?, \'\') WHERE id = ? AND case_id = ? AND session_key = ? AND viewed_at >= (NOW() - INTERVAL 15 MINUTE) LIMIT 1');
    $stmt->execute([$screenWidth, $screenHeight, $viewportWidth, $viewportHeight, $timezone, $timezoneOffset, $platform, $lastViewId, $caseId, $sessionKey]);
    echo json_encode(['success' => true, 'updated' => $stmt->rowCount()]);
  } catch (Throwable $e) {
    http_response_code(500);
    echo json_encode(['success' => false, 'error' => 'Update failed']);
  }
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
        $stmt = $pdo->prepare('SELECT id, email, display_name, username, password_hash, role FROM users WHERE email = ? AND is_active = 1');
        $stmt->execute([$email]);
        $user = $stmt->fetch();
        if ($user && password_verify($password, $user['password_hash'])) {
            session_regenerate_id(true);
            $_SESSION['user'] = [
              'id' => $user['id'],
              'email' => $user['email'],
              'display_name' => $user['display_name'] ?? '',
              'username' => $user['username'] ?? '',
              'role' => $user['role']
            ];
            $loginUpdate = $pdo->prepare('UPDATE users SET last_login_at = CURRENT_TIMESTAMP WHERE id = ?');
            $loginUpdate->execute([(int)$user['id']]);
            try {
                [$loginIp, $loginForwardedFor] = tp_client_ip();
                $loginForwardedFor = mb_check_encoding($loginForwardedFor, 'UTF-8') ? mb_substr($loginForwardedFor, 0, 255, 'UTF-8') : '';
                $loginUserAgentRaw = trim((string)($_SERVER['HTTP_USER_AGENT'] ?? ''));
                $loginUserAgent = mb_check_encoding($loginUserAgentRaw, 'UTF-8') ? mb_substr($loginUserAgentRaw, 0, 1024, 'UTF-8') : '';
                $loginHistory = $pdo->prepare('INSERT INTO user_login_history (user_id, ip_address, forwarded_for, user_agent, logged_in_at) VALUES (?, NULLIF(?, \'\'), NULLIF(?, \'\'), NULLIF(?, \'\'), CURRENT_TIMESTAMP)');
                $loginHistory->execute([(int)$user['id'], $loginIp, $loginForwardedFor, $loginUserAgent]);
            } catch (Throwable $auditError) {
                log_console('WARN', 'Unable to record login history for user #' . (int)$user['id'] . ': ' . $auditError->getMessage());
            }
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
    if (!tp_check_math_captcha('register')) {
        flash('error', 'Please answer the math security question correctly.');
        $_SESSION['auth_tab'] = 'register';
        header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit;
    }
    $email = tp_post_string('email');
    $displayName = tp_post_string('display_name');
    $username = tp_post_string('username');
    $password = is_string($_POST['password'] ?? null) ? $_POST['password'] : '';
    $confirm = is_string($_POST['password_confirm'] ?? null) ? $_POST['password_confirm'] : '';
    $agree = isset($_POST['agree']);

    if (strlen($email) > 254 || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        flash('error', 'Please enter a valid email address.');
        $_SESSION['auth_tab'] = 'register';
        header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit;
    }
    if (!tp_valid_public_text($displayName, 120)) {
        flash('error', 'Please enter a valid display name (maximum 120 characters).');
        $_SESSION['auth_tab'] = 'register';
        header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit;
    }
    if (!preg_match('/\A[A-Za-z0-9._-]{3,120}\z/D', $username)) {
        flash('error', 'Username must be 3–120 characters using only letters, numbers, dots, underscores, or hyphens.');
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
        $stmt = $pdo->prepare('SELECT id FROM users WHERE email = ? OR username = ? LIMIT 1');
        $stmt->execute([$email, $username]);
        if ($stmt->fetch()) {
            flash('error', 'That email address or username is already registered.');
            $_SESSION['auth_tab'] = 'register';
            header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit;
        }
        $hash = password_hash($password, PASSWORD_DEFAULT);
        [$signupIp, $signupForwardedFor] = tp_client_ip();
        $signupForwardedFor = mb_check_encoding($signupForwardedFor, 'UTF-8') ? mb_substr($signupForwardedFor, 0, 255, 'UTF-8') : '';
        $signupUserAgentRaw = trim((string)($_SERVER['HTTP_USER_AGENT'] ?? ''));
        $signupUserAgent = mb_check_encoding($signupUserAgentRaw, 'UTF-8') ? mb_substr($signupUserAgentRaw, 0, 1024, 'UTF-8') : '';
        $ins = $pdo->prepare('INSERT INTO users (email, display_name, username, password_hash, role, is_active, signup_ip, signup_forwarded_for, signup_user_agent) VALUES (?, ?, ?, ?, "viewer", 1, NULLIF(?, \'\'), NULLIF(?, \'\'), NULLIF(?, \'\'))');
        $ins->execute([$email, $displayName, $username, $hash, $signupIp, $signupForwardedFor, $signupUserAgent]);
        flash('success', 'Registration successful. You can now log in.');
    } catch (Throwable $e) {
        // Map common PDO errors to user-friendly messages, append safe error code
        $code = 0;
        if ($e instanceof PDOException && isset($e->errorInfo[1])) {
            $code = (int)$e->errorInfo[1];
        }
        $public = 'Unable to register right now.';
        if ($code === 1062) {
            $public = 'That email address or username is already registered.';
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
    $username = tp_normalize_account_username($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    $confirm = $_POST['password_confirm'] ?? '';
    $role = trim($_POST['role'] ?? 'viewer');
    $isActive = isset($_POST['is_active']) ? 1 : 0;

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
    if (mb_strlen($username, 'UTF-8') < 3) {
        flash('error', 'Please enter a username of at least 3 letters or numbers.');
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
        $stmt = $pdo->prepare('SELECT id FROM users WHERE email = ? OR username = ? LIMIT 1');
        $stmt->execute([$email, $username]);
        if ($stmt->fetch()) {
            flash('error', 'That email address or username is already registered.');
            header('Location: '. $redir); exit;
        }
        $hash = password_hash($password, PASSWORD_DEFAULT);
        $ins = $pdo->prepare('INSERT INTO users (email, display_name, username, password_hash, role, is_active, created_at) VALUES (?, ?, ?, ?, ?, ?, NOW())');
        $ins->execute([$email, $displayName, $username, $hash, $role, $isActive]);
        flash('success', 'User added successfully.');
    } catch (Throwable $e) {
        $_SESSION['sql_error'] = $e->getMessage();
log_console('ERROR', 'SQL: ' . $e->getMessage());
        $code = ($e instanceof PDOException && isset($e->errorInfo[1])) ? (int)$e->errorInfo[1] : 0;
        if ($code === 1062) {
            flash('error', 'That email address or username is already registered.');
        } else {
            flash('error', 'Unable to add user.');
        }
    }
    header('Location: '. $redir); exit;
}

// Test an OpenAI API key without saving or exposing it (main admin only).
if (($_POST['action'] ?? '') === 'test_openai_api_key') {
    throttle();
    $isAjax = (strtolower((string)($_SERVER['HTTP_X_REQUESTED_WITH'] ?? '')) === 'xmlhttprequest') || (($_POST['ajax'] ?? '') === '1');
    $respondJson = function (bool $ok, string $message, int $httpCode = 0): void {
      header('Content-Type: application/json');
      echo json_encode(['ok' => $ok, 'message' => $message, 'http_code' => $httpCode]);
      exit;
    };

    if (!check_csrf()) {
      if ($isAjax) { $respondJson(false, 'Security check failed.'); }
      flash('error', 'Security check failed.');
      header('Location: ?view=project_settings#project-settings'); exit;
    }
    if (!tp_is_main_admin()) {
      if ($isAjax) { $respondJson(false, 'Unauthorized. Main admin only.'); }
      flash('error', 'Unauthorized. Main admin only.');
      header('Location: ?view=project_settings#project-settings'); exit;
    }

    $openAiApiKey = trim((string)($_POST['openai_api_key'] ?? ''));
    [$ok, $httpCode, $message] = tp_test_openai_api_key($openAiApiKey);
    if ($isAjax) { $respondJson($ok, $message, $httpCode); }
    flash($ok ? 'success' : 'error', $message);
    header('Location: ?view=project_settings#project-settings'); exit;
}

// Handle webhook test (main admin only)
if (($_POST['action'] ?? '') === 'test_discord_webhook') {
    throttle();
    $isAjax = (strtolower((string)($_SERVER['HTTP_X_REQUESTED_WITH'] ?? '')) === 'xmlhttprequest') || (($_POST['ajax'] ?? '') === '1');
    $respondJson = function (bool $ok, string $message, array $extra = []) {
      header('Content-Type: application/json');
      echo json_encode(array_merge(['ok' => $ok, 'message' => $message], $extra));
      exit;
    };

    if (!check_csrf()) {
      if ($isAjax) { $respondJson(false, 'Security check failed.'); }
      flash('error', 'Security check failed.');
      header('Location: '. trim($_POST['redirect_url'] ?? '?view=project_settings#project-settings')); exit;
    }
    if (!tp_is_main_admin()) {
      if ($isAjax) { $respondJson(false, 'Unauthorized. Main admin only.'); }
      flash('error', 'Unauthorized. Main admin only.');
      header('Location: '. trim($_POST['redirect_url'] ?? '?view=project_settings#project-settings')); exit;
    }

    $webhookName = trim((string)($_POST['webhook_name'] ?? ''));
    $webhookUrl = trim((string)($_POST['webhook_url'] ?? ''));
    if ($webhookUrl === '' || !filter_var($webhookUrl, FILTER_VALIDATE_URL)) {
      if ($isAjax) { $respondJson(false, 'Please enter a valid webhook URL.'); }
      flash('error', 'Please enter a valid webhook URL.');
      header('Location: '. trim($_POST['redirect_url'] ?? '?view=project_settings#project-settings')); exit;
    }

    $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $host = $_SERVER['HTTP_HOST'] ?? 'tiktokpredators.com';
    $payload = [
      'username' => ($webhookName !== '' ? $webhookName : 'Webhook Test'),
      'avatar_url' => $scheme . '://' . $host . '/assets/favicon/android-chrome-192x192.png',
      'content' => 'Webhook test from ' . $host . ' at ' . date('Y-m-d H:i:s'),
    ];
    [$ok, $httpCode, $resp] = tp_post_discord_webhook($webhookUrl, $payload);
    $testedAt = date('c');
    $status = $ok ? 'success' : 'failed';
    $message = $ok ? 'Webhook test succeeded.' : ('Webhook test failed (HTTP ' . $httpCode . ').');

    try {
      $hooks = tp_discord_webhooks($pdo);
      $updated = false;
      foreach ($hooks as &$h) {
        if (trim((string)($h['url'] ?? '')) === $webhookUrl) {
          $h['last_tested_at'] = $testedAt;
          $h['last_test_status'] = $status;
          $h['last_test_message'] = substr((string)$resp, 0, 280);
          if (trim((string)($h['set_at'] ?? '')) === '') {
            $h['set_at'] = $testedAt;
          }
          $updated = true;
          break;
        }
      }
      unset($h);
      if ($updated) {
        $hooksJson = json_encode($hooks, JSON_UNESCAPED_SLASHES);
        if ($hooksJson === false) { $hooksJson = '[]'; }
        $stmt = $pdo->prepare('INSERT INTO project_settings (setting_key, setting_value, updated_at) VALUES (?, ?, NOW()) ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value), updated_at = NOW()');
        $stmt->execute(['discord_webhooks', $hooksJson]);
      }
    } catch (Throwable $e) {
      $_SESSION['sql_error'] = $_SESSION['sql_error'] ?? $e->getMessage();
    }

    if ($isAjax) {
      $respondJson($ok, $message, [
        'http_code' => $httpCode,
        'tested_at' => $testedAt,
        'status' => $status,
        'test_message' => substr((string)$resp, 0, 280),
      ]);
    }

    flash($ok ? 'success' : 'error', $message);
    header('Location: '. trim($_POST['redirect_url'] ?? '?view=project_settings#project-settings')); exit;
}

  // Handle project settings save (main admin only)
  if (($_POST['action'] ?? '') === 'save_project_settings') {
    throttle();
    if (!check_csrf()) { flash('error', 'Security check failed.'); header('Location: '. trim($_POST['redirect_url'] ?? '?view=project_settings#project-settings')); exit; }
    if (!tp_is_main_admin()) {
      flash('error', 'Unauthorized. Main admin only.');
      header('Location: '. trim($_POST['redirect_url'] ?? '?view=project_settings#project-settings')); exit;
    }

    $siteTitle = trim($_POST['site_title'] ?? '');
    $metaData = trim($_POST['meta_data'] ?? '');
    $openAiApiKey = trim((string)($_POST['openai_api_key'] ?? ''));
    $webhookNames = $_POST['discord_webhook_name'] ?? [];
    $webhookUrls = $_POST['discord_webhook_url'] ?? [];
    $redir = trim($_POST['redirect_url'] ?? '?view=project_settings#project-settings');

    if ($siteTitle === '') { $siteTitle = 'TikTokPredators'; }

    $discordWebhooks = [];
    if (!is_array($webhookNames)) { $webhookNames = []; }
    if (!is_array($webhookUrls)) { $webhookUrls = []; }
    $existingByUrl = [];
    try {
      foreach (tp_discord_webhooks($pdo) as $existingHook) {
        $u = trim((string)($existingHook['url'] ?? ''));
        if ($u === '') { continue; }
        $existingByUrl[$u] = [
          'set_at' => trim((string)($existingHook['set_at'] ?? '')),
          'last_tested_at' => trim((string)($existingHook['last_tested_at'] ?? '')),
          'last_test_status' => trim((string)($existingHook['last_test_status'] ?? '')),
          'last_test_message' => trim((string)($existingHook['last_test_message'] ?? '')),
        ];
      }
    } catch (Throwable $e) {
      // no-op
    }
    $max = max(count($webhookNames), count($webhookUrls));
    for ($i = 0; $i < $max; $i++) {
      $name = trim((string)($webhookNames[$i] ?? ''));
      $url = trim((string)($webhookUrls[$i] ?? ''));
      if ($url === '') { continue; }
      if (!filter_var($url, FILTER_VALIDATE_URL)) { continue; }
      $existingMeta = $existingByUrl[$url] ?? [];
      $setAt = trim((string)($existingMeta['set_at'] ?? ''));
      if ($setAt === '') { $setAt = date('c'); }
      $discordWebhooks[] = [
        'name' => $name,
        'url' => $url,
        'set_at' => $setAt,
        'last_tested_at' => trim((string)($existingMeta['last_tested_at'] ?? '')),
        'last_test_status' => trim((string)($existingMeta['last_test_status'] ?? '')),
        'last_test_message' => trim((string)($existingMeta['last_test_message'] ?? '')),
      ];
    }
    $discordWebhooksJson = json_encode($discordWebhooks, JSON_UNESCAPED_SLASHES);
    if ($discordWebhooksJson === false) { $discordWebhooksJson = '[]'; }
    $legacyWebhook = count($discordWebhooks) > 0 ? (string)$discordWebhooks[0]['url'] : '';

    try {
      $stmt = $pdo->prepare('INSERT INTO project_settings (setting_key, setting_value, updated_at) VALUES (?, ?, NOW()) ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value), updated_at = NOW()');
      $stmt->execute(['site_title', $siteTitle]);
      $stmt->execute(['meta_data', $metaData]);
      $stmt->execute(['openai_api_key', $openAiApiKey]);
      $stmt->execute(['discord_webhooks', $discordWebhooksJson]);
      $stmt->execute(['discord_webhook_key', $legacyWebhook]);
      flash('success', 'Project settings saved.');
    } catch (Throwable $e) {
      $_SESSION['sql_error'] = $e->getMessage();
      log_console('ERROR', 'SQL: ' . $e->getMessage());
      flash('error', 'Unable to save project settings.');
    }
    header('Location: '. $redir); exit;
  }

// Admin-only case ownership transfer.
if (($_POST['action'] ?? '') === 'transfer_case_ownership') {
    throttle();
    $caseCode = trim((string)($_POST['case_code'] ?? ''));
    $redirect = '?view=case&code=' . rawurlencode($caseCode) . '#case-owner-details';
    if (!check_csrf()) { flash('error', 'Security check failed.'); header('Location: ' . $redirect); exit; }
    if (!is_admin()) { flash('error', 'Only a site admin can change case ownership.'); header('Location: ' . $redirect); exit; }

    $caseId = (int)($_POST['case_id'] ?? 0);
    $newOwnerId = (int)($_POST['new_owner_id'] ?? 0);
    try {
      $pdo->beginTransaction();
      $caseStmt = $pdo->prepare('SELECT id, case_code, case_name, created_by, opened_at FROM cases WHERE id = ? FOR UPDATE');
      $caseStmt->execute([$caseId]);
      $case = $caseStmt->fetch();
      if (!$case) { throw new RuntimeException('Case not found.'); }
      $caseCode = (string)$case['case_code'];
      $redirect = '?view=case&code=' . rawurlencode($caseCode) . '#case-owner-details';

      $ownerStmt = $pdo->prepare('SELECT id, display_name, username, email FROM users WHERE id = ? AND is_active = 1 LIMIT 1');
      $ownerStmt->execute([$newOwnerId]);
      $newOwner = $ownerStmt->fetch();
      if (!$newOwner) { throw new RuntimeException('New owner not found or inactive.'); }
      $previousOwnerId = (int)($case['created_by'] ?? 0);
      if ($previousOwnerId === $newOwnerId) {
        $pdo->rollBack();
        flash('error', 'That user already owns this case.');
        header('Location: ' . $redirect); exit;
      }

      // Preserve the original submitter before changing the current owner on historical cases.
      $submissionStmt = $pdo->prepare('INSERT IGNORE INTO case_submission_metadata (case_id, submitted_by, submitted_at) VALUES (?, ?, COALESCE(?, NOW()))');
      $submissionStmt->execute([$caseId, $previousOwnerId > 0 ? $previousOwnerId : null, $case['opened_at'] ?? null]);

      $updateCase = $pdo->prepare('UPDATE cases SET created_by = ? WHERE id = ?');
      $updateCase->execute([$newOwnerId, $caseId]);
      $historyStmt = $pdo->prepare('INSERT INTO case_ownership_history (case_id, previous_owner_id, new_owner_id, changed_by) VALUES (?, ?, ?, ?)');
      $historyStmt->execute([$caseId, $previousOwnerId > 0 ? $previousOwnerId : null, $newOwnerId, (int)($_SESSION['user']['id'] ?? 0)]);
      log_case_event($pdo, $caseId, 'case_ownership_changed', 'Case ownership updated', 'Ownership was changed by a site administrator.');
      tp_create_user_notification(
        $pdo,
        $newOwnerId,
        'case_ownership_assigned',
        'A case has been assigned to you',
        'You are now the owner of ' . ((string)($case['case_name'] ?? '') !== '' ? (string)$case['case_name'] : $caseCode) . ' (' . $caseCode . ').',
        $caseId
      );
      $pdo->commit();
      flash('success', 'Case ownership transferred to ' . ((string)($newOwner['display_name'] ?? '') !== '' ? $newOwner['display_name'] : $newOwner['email']) . '.');
    } catch (Throwable $e) {
      if ($pdo->inTransaction()) { $pdo->rollBack(); }
      $_SESSION['sql_error'] = $_SESSION['sql_error'] ?? $e->getMessage();
      flash('error', 'Unable to change case ownership.');
    }
    header('Location: ' . $redirect); exit;
}

// Generate reviewable AI suggestions for an owned draft or, for admins, any case.
if (($_POST['action'] ?? '') === 'generate_ai_case_suggestions') {
    throttle();
    $caseCode = trim((string)($_POST['case_code'] ?? ''));
    $redirect = '?view=case&code=' . rawurlencode($caseCode) . '#ai-case-builder';
    if (!check_csrf()) { flash('error', 'Security check failed.'); header('Location: ' . $redirect); exit; }
    if (!is_logged_in()) { flash('error', 'You must be logged in to use the AI case builder.'); header('Location: ' . $redirect); exit; }

    $caseId = (int)($_POST['case_id'] ?? 0);
    try {
      $caseStmt = $pdo->prepare('SELECT id, case_code, case_name, person_name, location, snapchat_username, tiktok_username, initial_summary, status, created_by FROM cases WHERE id = ? LIMIT 1');
      $caseStmt->execute([$caseId]);
      $case = $caseStmt->fetch();
      if (!$case) { throw new RuntimeException('Case not found.'); }
      $caseCode = (string)$case['case_code'];
      $redirect = '?view=case&code=' . rawurlencode($caseCode) . '#ai-case-builder';

      $isOwnerDraft = (int)($case['created_by'] ?? 0) === (int)($_SESSION['user']['id'] ?? 0)
        && (string)($case['status'] ?? '') === 'Being Built';
      if (!is_admin() && !$isOwnerDraft) {
        flash('error', 'Only an admin, or the owner of a case being built, can run the AI case builder.');
        header('Location: ' . $redirect); exit;
      }

      $apiKey = trim(tp_project_setting($pdo, 'openai_api_key', ''));
      if ($apiKey === '') {
        flash('error', 'OpenAI has not been configured in Project Settings.');
        header('Location: ' . $redirect); exit;
      }
      $model = trim(tp_project_setting($pdo, 'openai_case_builder_model', 'gpt-5.4-mini'));
      if ($model === '') { $model = 'gpt-5.4-mini'; }

      $runStmt = $pdo->prepare("INSERT INTO case_ai_runs (case_id, requested_by, model, status) VALUES (?, ?, ?, 'Processing')");
      $runStmt->execute([$caseId, (int)($_SESSION['user']['id'] ?? 0), mb_substr($model, 0, 128, 'UTF-8')]);
      $runId = (int)$pdo->lastInsertId();

      $currentValues = tp_ai_case_current_values($pdo, $case);
      $safeValues = $currentValues;
      foreach ($safeValues as $field => $value) {
        $safeValues[$field] = mb_substr((string)$value, 0, $field === 'initial_summary' ? 12000 : 1000, 'UTF-8');
      }
      $evidenceMeta = [];
      $evidenceStmt = $pdo->prepare('SELECT type, title, created_at FROM evidence WHERE case_id = ? ORDER BY created_at DESC LIMIT 30');
      $evidenceStmt->execute([$caseId]);
      foreach ($evidenceStmt->fetchAll() as $evidenceRow) {
        $evidenceMeta[] = [
          'type' => mb_substr(trim((string)($evidenceRow['type'] ?? '')), 0, 64, 'UTF-8'),
          'title' => mb_substr(trim((string)($evidenceRow['title'] ?? '')), 0, 255, 'UTF-8'),
          'created_at' => (string)($evidenceRow['created_at'] ?? ''),
        ];
      }
      $context = [
        'case_code' => (string)$case['case_code'],
        'case_status' => (string)$case['status'],
        'editable_fields' => $safeValues,
        'allowed_case_tags' => tp_case_tag_options(),
        'evidence_metadata' => $evidenceMeta,
      ];

      [$ok, $result, $error] = tp_openai_case_builder_request($apiKey, $model, $context);
      if (!$ok) {
        $failedStmt = $pdo->prepare("UPDATE case_ai_runs SET status = 'Failed', error_message = ?, completed_at = NOW() WHERE id = ?");
        $failedStmt->execute([mb_substr($error, 0, 2000, 'UTF-8'), $runId]);
        flash('error', $error);
        header('Location: ' . $redirect); exit;
      }

      $labels = tp_ai_case_field_labels();
      $insertSuggestion = $pdo->prepare("INSERT INTO case_ai_suggestions (run_id, case_id, field_name, current_value, suggested_value, reason, decision) VALUES (?, ?, ?, ?, ?, ?, 'Pending')");
      $suggestionCount = 0;
      $seenFields = [];
      foreach (array_slice($result['suggestions'] ?? [], 0, 8) as $suggestion) {
        if (!is_array($suggestion)) { continue; }
        $field = trim((string)($suggestion['field'] ?? ''));
        if (!isset($labels[$field]) || isset($seenFields[$field])) { continue; }
        $suggestedValue = tp_ai_normalize_case_suggestion($field, (string)($suggestion['suggested_value'] ?? ''));
        $reason = mb_substr(trim((string)($suggestion['reason'] ?? '')), 0, 2000, 'UTF-8');
        $currentValue = (string)($currentValues[$field] ?? '');
        if ($suggestedValue === '' || $reason === '' || $suggestedValue === $currentValue) { continue; }
        $insertSuggestion->execute([$runId, $caseId, $field, $currentValue, $suggestedValue, $reason]);
        $seenFields[$field] = true;
        $suggestionCount++;
      }
      $overallNotes = mb_substr(trim((string)($result['overall_notes'] ?? '')), 0, 4000, 'UTF-8');
      $completeStmt = $pdo->prepare("UPDATE case_ai_runs SET status = 'Completed', overall_notes = ?, completed_at = NOW() WHERE id = ?");
      $completeStmt->execute([$overallNotes, $runId]);
      log_case_event($pdo, $caseId, 'ai_case_reviewed', 'AI case builder', $suggestionCount . ' suggestion(s) generated for admin review.');
      flash('success', $suggestionCount > 0
        ? ($suggestionCount . ' AI suggestion' . ($suggestionCount === 1 ? '' : 's') . ' ready for admin review.')
        : 'The AI review completed and found no safe changes to suggest.');
    } catch (Throwable $e) {
      if (!empty($runId)) {
        try {
          $failedStmt = $pdo->prepare("UPDATE case_ai_runs SET status = 'Failed', error_message = ?, completed_at = NOW() WHERE id = ?");
          $failedStmt->execute(['The AI review could not be completed.', (int)$runId]);
        } catch (Throwable $ignored) {}
      }
      $_SESSION['sql_error'] = $_SESSION['sql_error'] ?? $e->getMessage();
      flash('error', 'The AI review could not be completed.');
    }
    header('Location: ' . $redirect); exit;
}

// Admin approval/rejection is intentionally required for every AI suggestion.
if (($_POST['action'] ?? '') === 'decide_ai_case_suggestion') {
    throttle();
    $caseCode = trim((string)($_POST['case_code'] ?? ''));
    $redirect = '?view=case&code=' . rawurlencode($caseCode) . '#ai-case-builder';
    if (!check_csrf()) { flash('error', 'Security check failed.'); header('Location: ' . $redirect); exit; }
    if (!is_admin()) { flash('error', 'Only a site admin can approve or reject AI suggestions.'); header('Location: ' . $redirect); exit; }

    $suggestionId = (int)($_POST['suggestion_id'] ?? 0);
    $decision = strtolower(trim((string)($_POST['decision'] ?? '')));
    if (!in_array($decision, ['approve', 'reject'], true)) {
      flash('error', 'Invalid AI suggestion decision.'); header('Location: ' . $redirect); exit;
    }

    try {
      $pdo->beginTransaction();
      $suggestionStmt = $pdo->prepare('SELECT * FROM case_ai_suggestions WHERE id = ? FOR UPDATE');
      $suggestionStmt->execute([$suggestionId]);
      $suggestion = $suggestionStmt->fetch();
      if (!$suggestion) { throw new RuntimeException('Suggestion not found.'); }

      $caseStmt = $pdo->prepare('SELECT id, case_code, case_name, person_name, location, snapchat_username, tiktok_username, initial_summary, status, created_by FROM cases WHERE id = ? FOR UPDATE');
      $caseStmt->execute([(int)$suggestion['case_id']]);
      $case = $caseStmt->fetch();
      if (!$case) { throw new RuntimeException('Case not found.'); }
      $caseCode = (string)$case['case_code'];
      $redirect = '?view=case&code=' . rawurlencode($caseCode) . '#ai-case-builder';
      if (($suggestion['decision'] ?? '') !== 'Pending') {
        $pdo->rollBack();
        flash('error', 'This suggestion has already been decided.'); header('Location: ' . $redirect); exit;
      }

      $field = (string)($suggestion['field_name'] ?? '');
      $labels = tp_ai_case_field_labels();
      if (!isset($labels[$field])) { throw new RuntimeException('Unsupported suggestion field.'); }
      $userId = (int)($_SESSION['user']['id'] ?? 0);

      if ($decision === 'reject') {
        $updateSuggestion = $pdo->prepare("UPDATE case_ai_suggestions SET decision = 'Rejected', decided_by = ?, decided_at = NOW() WHERE id = ?");
        $updateSuggestion->execute([$userId, $suggestionId]);
        log_case_event($pdo, (int)$case['id'], 'ai_suggestion_rejected', $labels[$field], 'AI suggestion rejected.');
        $pdo->commit();
        flash('success', $labels[$field] . ' suggestion rejected.');
        header('Location: ' . $redirect); exit;
      }

      $currentValues = tp_ai_case_current_values($pdo, $case);
      $currentValue = (string)($currentValues[$field] ?? '');
      if ($currentValue !== (string)($suggestion['current_value'] ?? '')) {
        $pdo->rollBack();
        flash('error', 'The ' . $labels[$field] . ' field has changed since this suggestion was created. Run the AI case builder again before approving it.');
        header('Location: ' . $redirect); exit;
      }
      $suggestedValue = tp_ai_normalize_case_suggestion($field, (string)($suggestion['suggested_value'] ?? ''));
      if ($suggestedValue === '') { throw new RuntimeException('Suggestion value is empty.'); }

      if ($field === 'case_tags') {
        save_case_tags($pdo, (int)$case['id'], $suggestedValue);
      } elseif ($field === 'tiktok_username') {
        $savedTiktok = save_case_tiktok_usernames($pdo, (int)$case['id'], $suggestedValue);
        $updateCase = $pdo->prepare('UPDATE cases SET tiktok_username = ? WHERE id = ?');
        $updateCase->execute([$savedTiktok !== '' ? $savedTiktok : null, (int)$case['id']]);
      } else {
        $editableColumns = ['case_name', 'person_name', 'location', 'snapchat_username', 'initial_summary'];
        if (!in_array($field, $editableColumns, true)) { throw new RuntimeException('Unsupported suggestion field.'); }
        $updateCase = $pdo->prepare('UPDATE cases SET ' . $field . ' = ? WHERE id = ?');
        $updateCase->execute([$suggestedValue, (int)$case['id']]);
      }

      $updateSuggestion = $pdo->prepare("UPDATE case_ai_suggestions SET decision = 'Approved', decided_by = ?, decided_at = NOW() WHERE id = ?");
      $updateSuggestion->execute([$userId, $suggestionId]);
      log_case_event($pdo, (int)$case['id'], 'ai_suggestion_approved', $labels[$field], 'AI suggestion approved and applied.');
      $pdo->commit();
      flash('success', $labels[$field] . ' suggestion approved and applied.');
    } catch (Throwable $e) {
      if ($pdo->inTransaction()) { $pdo->rollBack(); }
      $_SESSION['sql_error'] = $_SESSION['sql_error'] ?? $e->getMessage();
      flash('error', 'Unable to process the AI suggestion.');
    }
    header('Location: ' . $redirect); exit;
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
    $phone_number = trim($_POST['phone_number'] ?? '');
    $snapchat_username = normalize_social_username($_POST['snapchat_username'] ?? '');
    $tiktok_username = normalize_tiktok_usernames($_POST['tiktok_username'] ?? '');
    $case_tags = tp_normalize_case_tags($_POST['case_tags'] ?? []);
    $initial_summary = trim($_POST['initial_summary'] ?? '');

    if ($case_name === '' || $initial_summary === '') {
        flash('error', 'Case name and summary are required.');
        $_SESSION['open_modal'] = '';
        $_SESSION['form_error'] = 'Case name and summary are required.';
        header('Location: ?view=submit_case#submit-case'); exit;
    }

    try {
        $case_code = generate_case_code($pdo);
        $stmt = $pdo->prepare('INSERT INTO cases (case_code, case_name, person_name, location, phone_number, snapchat_username, tiktok_username, initial_summary, sensitivity, status, created_by, opened_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())');
        $stmt->execute([
            $case_code,
            $case_name,
            ($person_name !== '' ? $person_name : null),
          ($location !== '' ? $location : null),
            ($phone_number !== '' ? $phone_number : null),
            ($snapchat_username !== '' ? $snapchat_username : null),
            ($tiktok_username !== '' ? $tiktok_username : null),
            $initial_summary,
            'Standard',
            'Being Built',
            $_SESSION['user']['id'] ?? null
        ]);
        $case_id = (int)$pdo->lastInsertId();
        save_case_tiktok_usernames($pdo, $case_id, $tiktok_username);
        save_case_tags($pdo, $case_id, array_keys($case_tags));
        tp_record_case_submission_metadata($pdo, $case_id, (int)($_SESSION['user']['id'] ?? 0));
        log_case_event($pdo, $case_id, 'case_created', $case_name, 'Viewer created case. Status set to Being Built');

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

        flash('success', 'Case created. Build the case and add evidence, then submit it for review when it is ready.');
        log_console('SUCCESS', 'Viewer created case ' . $case_code . ' by user_id ' . (int)($_SESSION['user']['id'] ?? 0));
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
    $phone_number = trim($_POST['phone_number'] ?? '');
    $snapchat_username = normalize_social_username($_POST['snapchat_username'] ?? '');
    $tiktok_username = normalize_tiktok_usernames($_POST['tiktok_username'] ?? '');
    $case_tags = tp_normalize_case_tags($_POST['case_tags'] ?? []);
    $initial_summary = trim($_POST['initial_summary'] ?? '');
    $sensitivity = $_POST['sensitivity'] ?? '';
    $status = 'Being Built';

    $allowed_sensitivity = ['Standard','Restricted','Sealed'];

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

    try {
        $case_code = generate_case_code($pdo);
        $stmt = $pdo->prepare('INSERT INTO cases (case_code, case_name, person_name, location, phone_number, snapchat_username, tiktok_username, initial_summary, sensitivity, status, created_by, opened_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())');
        $stmt->execute([
            $case_code,
            $case_name,
            ($person_name !== '' ? $person_name : null),
          ($location !== '' ? $location : null),
            ($phone_number !== '' ? $phone_number : null),
            ($snapchat_username !== '' ? $snapchat_username : null),
            ($tiktok_username !== '' ? $tiktok_username : null),
            $initial_summary,
            $sensitivity,
            $status,
            $_SESSION['user']['id'] ?? null
        ]);
        $case_id = (int)$pdo->lastInsertId();
        save_case_tiktok_usernames($pdo, $case_id, $tiktok_username);
        save_case_tags($pdo, $case_id, array_keys($case_tags));
        tp_record_case_submission_metadata($pdo, $case_id, (int)($_SESSION['user']['id'] ?? 0));
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
        flash('success', 'Case created as Being Built. Add the evidence and details, then submit it for review. ID: ' . htmlspecialchars($case_code));
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

// Reject a pending case without deleting its record or evidence (admin only).
if (($_POST['action'] ?? '') === 'reject_case') {
    throttle();
    if (!check_csrf()) {
        flash('error', 'Security check failed.');
        header('Location: ?view=pending#pending'); exit;
    }
    if (!is_admin()) {
        flash('error', 'Unauthorized. Admins only.');
        header('Location: ?view=pending#pending'); exit;
    }

    $case_id = (int)($_POST['case_id'] ?? 0);
    $case_code = trim((string)($_POST['case_code'] ?? ''));
    $rejection_reason = trim((string)($_POST['rejection_reason'] ?? ''));
    if ($case_id <= 0 || $case_code === '') {
        flash('error', 'Invalid case reference.');
        header('Location: ?view=pending#pending'); exit;
    }
    if ($rejection_reason === '') {
        flash('error', 'Please provide a reason for rejecting the case.');
        header('Location: ?view=pending#pending'); exit;
    }
    $rejection_reason = mb_substr($rejection_reason, 0, 2000, 'UTF-8');

    try {
        $caseStmt = $pdo->prepare('SELECT case_name, status, created_by FROM cases WHERE id = ? AND case_code = ? LIMIT 1');
        $caseStmt->execute([$case_id, $case_code]);
        $caseToReject = $caseStmt->fetch();
        if (!$caseToReject) {
            flash('error', 'Case not found.');
        } elseif (($caseToReject['status'] ?? '') === 'Rejected') {
            flash('success', 'Case is already rejected.');
        } elseif (($caseToReject['status'] ?? '') !== 'Pending') {
            flash('error', 'Only pending cases can be rejected.');
        } else {
            $pdo->beginTransaction();
            $rejectStmt = $pdo->prepare("UPDATE cases SET status = 'Rejected', rejection_reason = ?, rejected_at = NOW(), rejected_by = ?, resubmitted_at = NULL WHERE id = ? AND case_code = ? AND status = 'Pending' LIMIT 1");
            $rejectStmt->execute([$rejection_reason, (int)($_SESSION['user']['id'] ?? 0), $case_id, $case_code]);
            if ($rejectStmt->rowCount() === 1) {
                $caseName = trim((string)($caseToReject['case_name'] ?? ''));
                tp_create_user_notification(
                    $pdo,
                    (int)($caseToReject['created_by'] ?? 0),
                    'case_rejected',
                    'Case rejected: ' . $case_code,
                    'Your submitted case was rejected. Reason: ' . $rejection_reason . ' You can correct the case and resubmit it for review.',
                    $case_id
                );
                log_case_event($pdo, $case_id, 'case_rejected', $caseName !== '' ? $caseName : $case_code, 'Reason: ' . $rejection_reason);
                $pdo->commit();
                flash('success', 'Case rejected and the submitter has been notified.');
                log_console('SUCCESS', 'Case rejected: ' . $case_code . ' by admin user_id ' . (int)($_SESSION['user']['id'] ?? 0));
            } else {
                $pdo->rollBack();
                flash('error', 'Case status changed before it could be rejected.');
            }
        }
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) { $pdo->rollBack(); }
        $_SESSION['sql_error'] = $e->getMessage();
        log_console('ERROR', 'SQL: ' . $e->getMessage());
        flash('error', 'Unable to reject case.');
    }
    header('Location: ?view=pending#pending'); exit;
}

// Submit a draft or corrected rejected case to the admin review queue.
if (in_array(($_POST['action'] ?? ''), ['submit_case_for_review', 'resubmit_case'], true)) {
    throttle();
    if (!check_csrf()) {
        flash('error', 'Security check failed.');
        header('Location: ?view=pending#rejected-cases'); exit;
    }
    if (empty($_SESSION['user'])) {
        flash('error', 'You must be logged in to submit a case for review.');
        header('Location: ?view=pending#rejected-cases'); exit;
    }

    $case_id = (int)($_POST['case_id'] ?? 0);
    $case_code = trim((string)($_POST['case_code'] ?? ''));
    try {
        $pdo->beginTransaction();
        $caseStmt = $pdo->prepare('SELECT case_name, status, created_by FROM cases WHERE id = ? AND case_code = ? LIMIT 1 FOR UPDATE');
        $caseStmt->execute([$case_id, $case_code]);
        $caseToResubmit = $caseStmt->fetch();
        $isOriginalSubmitter = $caseToResubmit && (int)($caseToResubmit['created_by'] ?? 0) === (int)($_SESSION['user']['id'] ?? 0);
        if (!$caseToResubmit || (!is_admin() && !$isOriginalSubmitter)) {
            $pdo->rollBack();
            flash('error', 'Unauthorized. Only the original submitter or an administrator can submit this case for review.');
        } elseif (!in_array(($caseToResubmit['status'] ?? ''), ['Being Built', 'Rejected'], true)) {
            $pdo->rollBack();
            flash('error', 'Only cases being built or rejected cases can be submitted for review.');
        } else {
            $previousStatus = (string)$caseToResubmit['status'];
            $submissionTimestampSql = $previousStatus === 'Rejected'
                ? 'resubmitted_at = NOW()'
                : 'submitted_for_review_at = NOW(), resubmitted_at = NULL';
            $resubmitStmt = $pdo->prepare("UPDATE cases SET status = 'Pending', {$submissionTimestampSql} WHERE id = ? AND status = ? LIMIT 1");
            $resubmitStmt->execute([$case_id, $previousStatus]);
            if ($resubmitStmt->rowCount() !== 1) {
                $pdo->rollBack();
                flash('error', 'Case status changed before it could be submitted.');
                header('Location: ?view=pending#pending-review'); exit;
            }
            $caseName = trim((string)($caseToResubmit['case_name'] ?? ''));
            $eventType = $previousStatus === 'Rejected' ? 'case_resubmitted' : 'case_submitted_for_review';
            $eventDetail = $previousStatus === 'Rejected' ? 'Corrected case resubmitted for admin review' : 'Case submitted for admin review';
            log_case_event($pdo, $case_id, $eventType, $caseName !== '' ? $caseName : $case_code, $eventDetail);
            $pdo->commit();
            flash('success', $previousStatus === 'Rejected' ? 'Case resubmitted for review.' : 'Case submitted for review.');
            log_console('SUCCESS', 'Case submitted for review: ' . $case_code . ' by user_id ' . (int)($_SESSION['user']['id'] ?? 0));
        }
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) { $pdo->rollBack(); }
        $_SESSION['sql_error'] = $e->getMessage();
        log_console('ERROR', 'SQL: ' . $e->getMessage());
        flash('error', 'Unable to submit case for review.');
    }
    header('Location: ?view=pending#pending-review'); exit;
}

// Pull a published verified case back into the private Being Built workflow.
if (($_POST['action'] ?? '') === 'return_published_case_to_building') {
    throttle();
    if (!check_csrf()) {
        flash('error', 'Security check failed.');
        header('Location: ?view=pending#published-cases'); exit;
    }
    if (empty($_SESSION['user'])) {
        flash('error', 'You must be logged in to update this case.');
        header('Location: ?view=pending#published-cases'); exit;
    }

    $caseId = (int)($_POST['case_id'] ?? 0);
    $caseCode = trim((string)($_POST['case_code'] ?? ''));
    try {
        $pdo->beginTransaction();
        $caseStmt = $pdo->prepare('SELECT id, case_code, case_name, status, created_by FROM cases WHERE id = ? AND case_code = ? LIMIT 1 FOR UPDATE');
        $caseStmt->execute([$caseId, $caseCode]);
        $caseToBuild = $caseStmt->fetch();
        $isCaseOwner = $caseToBuild
            && (int)($caseToBuild['created_by'] ?? 0) > 0
            && (int)($caseToBuild['created_by'] ?? 0) === (int)($_SESSION['user']['id'] ?? 0);
        if (!$caseToBuild || (!is_admin() && !$isCaseOwner)) {
            $pdo->rollBack();
            flash('error', 'Only the case owner or a site admin can return this case to Being Built.');
        } elseif (($caseToBuild['status'] ?? '') !== 'Verified') {
            $pdo->rollBack();
            flash('error', 'Only verified published cases can be returned to Being Built.');
        } else {
            $updateStmt = $pdo->prepare("UPDATE cases SET status = 'Being Built', rejection_reason = NULL, rejected_at = NULL, rejected_by = NULL, resubmitted_at = NULL, closed_at = NULL WHERE id = ? AND status = 'Verified' LIMIT 1");
            $updateStmt->execute([$caseId]);
            if ($updateStmt->rowCount() !== 1) {
                $pdo->rollBack();
                flash('error', 'The case status changed before it could be returned to Being Built.');
            } else {
                $caseName = trim((string)($caseToBuild['case_name'] ?? ''));
                log_case_event($pdo, $caseId, 'case_returned_to_building', $caseName !== '' ? $caseName : $caseCode, 'Published case removed from public view and returned to Being Built for updates.');
                $ownerId = (int)($caseToBuild['created_by'] ?? 0);
                if (is_admin() && $ownerId > 0 && $ownerId !== (int)($_SESSION['user']['id'] ?? 0)) {
                    tp_create_user_notification(
                        $pdo,
                        $ownerId,
                        'case_returned_to_building',
                        'Case returned to Being Built: ' . $caseCode,
                        'A site admin removed this case from public view and returned it to Being Built so you can update its details or evidence before submitting it for approval again.',
                        $caseId
                    );
                }
                $pdo->commit();
                flash('success', 'Case removed from public view and returned to Being Built.');
                log_console('SUCCESS', 'Published case returned to Being Built: ' . $caseCode . ' by user_id ' . (int)($_SESSION['user']['id'] ?? 0));
            }
        }
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) { $pdo->rollBack(); }
        $_SESSION['sql_error'] = $e->getMessage();
        log_console('ERROR', 'SQL: ' . $e->getMessage());
        flash('error', 'Unable to return the case to Being Built.');
    }
    header('Location: ?view=pending#published-cases'); exit;
}

if (($_POST['action'] ?? '') === 'mark_notifications_read') {
    if (!check_csrf() || empty($_SESSION['user'])) {
        flash('error', 'Unable to update notifications.');
        header('Location: ?view=pending#pending'); exit;
    }
    try {
        $markRead = $pdo->prepare('UPDATE user_notifications SET is_read = 1, read_at = COALESCE(read_at, NOW()) WHERE user_id = ? AND is_read = 0');
        $markRead->execute([(int)($_SESSION['user']['id'] ?? 0)]);
    } catch (Throwable $e) {
        $_SESSION['sql_error'] = $e->getMessage();
    }
    header('Location: ?view=pending#pending'); exit;
}

// Handle update case (admin only)
if (($_POST['action'] ?? '') === 'update_case') {
    throttle();
    if (!check_csrf()) { flash('error', 'Security check failed.'); header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit; }

    // Allow admins or the original submitter while the case is Pending/Rejected.
    $case_id = (int)($_POST['case_id'] ?? 0);
    $ownerCan = can_manage_case_submission($pdo, $case_id);
    if (empty($_SESSION['user']) || (!is_admin() && !$ownerCan)) {
        flash('error', 'Unauthorized.');
        header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit;
    }
    $case_code = trim($_POST['case_code'] ?? '');
    $case_name = trim($_POST['case_name'] ?? '');
    $person_name = trim($_POST['person_name'] ?? '');
    $location = trim($_POST['location'] ?? '');
    $phone_number = trim($_POST['phone_number'] ?? '');
    $snapchat_username = normalize_social_username($_POST['snapchat_username'] ?? '');
    $tiktok_username = normalize_tiktok_usernames($_POST['tiktok_username'] ?? '');
    $case_tags = tp_normalize_case_tags($_POST['case_tags'] ?? []);
    $initial_summary = trim($_POST['initial_summary'] ?? '');
    $remove_person_photo = !empty($_POST['remove_person_photo']);
    $sensitivity = $_POST['sensitivity'] ?? '';
    $requestedStatus = is_string($_POST['status'] ?? null) ? trim($_POST['status']) : '';
    $skipVerifiedAnnouncement = is_admin() && $requestedStatus === 'Verified dont announce';
    // "Verified dont announce" is a one-time publishing action, not a stored
    // status. Persist the case as Verified so all normal public queries include it.
    $status = $skipVerifiedAnnouncement ? 'Verified' : $requestedStatus;

    $allowed_sensitivity = ['Standard','Restricted','Sealed'];
    $allowed_status = ['Being Built','Pending','Open','In Review','Verified','Closed','Rejected'];

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
    try { $ps = $pdo->prepare('SELECT case_name, person_name, location, phone_number, snapchat_username, tiktok_username, initial_summary, sensitivity, status FROM cases WHERE id = ? LIMIT 1'); $ps->execute([$case_id]); $prev = $ps->fetch() ?: []; $prev['tiktok_username'] = get_case_tiktok_usernames($pdo, $case_id) ?: ($prev['tiktok_username'] ?? ''); $prev['case_tags'] = implode(', ', get_case_tags($pdo, $case_id)); } catch (Throwable $e) {}

    if (is_admin() && in_array(($prev['status'] ?? ''), ['Being Built', 'Rejected'], true) && $status !== ($prev['status'] ?? '')) {
        flash('error', 'Use the Submit for Review button before moving this case to an approval or publishing status.');
        header('Location: ?view=case&code=' . urlencode($case_code) . '#case-view'); exit;
    }

    if (is_admin() && $status === 'Rejected' && ($prev['status'] ?? '') !== 'Rejected') {
        flash('error', 'Use the Reject Case button so a reason is recorded and the submitter is notified.');
        header('Location: ?view=case&code=' . urlencode($case_code) . '#case-view'); exit;
    }

    // Non-admin case owners only receive masked private fields. Keep the
    // originals when they save other changes without replacing those values.
    if (!is_admin()) {
        // Review submissions must use the dedicated submission workflow; never trust
        // a hidden status value supplied by a case owner.
        $status = (string)($prev['status'] ?? 'Pending');
        $previousLocation = trim((string)($prev['location'] ?? ''));
        $previousPhone = trim((string)($prev['phone_number'] ?? ''));
        if ($location === tp_mask_case_location_house_number($previousLocation)) {
            $location = $previousLocation;
        }
        if ($phone_number === tp_mask_case_phone_number($previousPhone)) {
            $phone_number = $previousPhone;
        }
    }

    if ($remove_person_photo) {
      remove_person_photo($case_code);
    }

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
        $u = $pdo->prepare('UPDATE cases SET case_name = ?, person_name = ?, location = ?, phone_number = ?, snapchat_username = ?, tiktok_username = ?, initial_summary = ?, sensitivity = ?, status = ? WHERE id = ? LIMIT 1');
        $u->execute([
            $case_name,
            ($person_name !== '' ? $person_name : null),
          ($location !== '' ? $location : null),
            ($phone_number !== '' ? $phone_number : null),
            ($snapchat_username !== '' ? $snapchat_username : null),
            ($tiktok_username !== '' ? $tiktok_username : null),
            $initial_summary,
            $sensitivity,
            $status,
            $case_id
        ]);
        $tiktok_username = save_case_tiktok_usernames($pdo, $case_id, $tiktok_username);
        $savedCaseTags = save_case_tags($pdo, $case_id, array_keys($case_tags));
        // Build diff summary
        $changes = [];
        $fields = ['case_name','person_name','location','phone_number','snapchat_username','tiktok_username','case_tags','initial_summary','sensitivity','status'];
        $newVals = [
            'case_name' => $case_name,
            'person_name' => ($person_name !== '' ? $person_name : null),
          'location' => ($location !== '' ? $location : null),
            'phone_number' => ($phone_number !== '' ? $phone_number : null),
            'snapchat_username' => ($snapchat_username !== '' ? $snapchat_username : null),
            'tiktok_username' => ($tiktok_username !== '' ? $tiktok_username : null),
            'case_tags' => implode(', ', $savedCaseTags),
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
        // Fire Discord notification if status just moved to Verified, unless the
        // admin explicitly selected the one-time no-announcement publishing option.
        $prevStatus = $prev['status'] ?? '';
        if ($status === 'Verified' && $prevStatus !== 'Verified') {
            if ($skipVerifiedAnnouncement) {
                log_case_event(
                    $pdo,
                    $case_id,
                    'discord_announcement_skipped',
                    $case_name !== '' ? $case_name : $case_code,
                    'Case published as Verified without sending Discord webhook announcements.'
                );
                log_console('INFO', 'Case published without Discord announcement: ' . $case_code);
            } else {
                $photoRel = find_person_photo_url($case_code);
                notify_discord_case_verified(
                    $case_code,
                    $case_name,
                    $person_name,
                    $location,
                    $initial_summary,
                    $photoRel
                );
            }
        }
        flash(
            'success',
            ($skipVerifiedAnnouncement && $prevStatus !== 'Verified')
                ? 'Case published as Verified without a Discord announcement.'
                : 'Case updated.'
        );
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
            if ($crow && (int)($crow['created_by'] ?? 0) === (int)($_SESSION['user']['id'] ?? 0) && in_array(($crow['status'] ?? ''), ['Being Built','Pending','Rejected'], true)) {
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
    $titleOnly = (string)($_POST['title_only'] ?? '') === '1';
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
            if ($crow && (int)($crow['created_by'] ?? 0) === (int)($_SESSION['user']['id'] ?? 0) && in_array(($crow['status'] ?? ''), ['Being Built','Pending','Rejected'], true)) {
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

// Handle evidence updates. Case creators may edit titles; admins retain full metadata editing.
if (($_POST['action'] ?? '') === 'update_evidence') {
    throttle();
    if (!check_csrf()) { flash('error', 'Security check failed.'); header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit; }

    $evidence_id = (int)($_POST['evidence_id'] ?? 0);
    $case_id = (int)($_POST['case_id'] ?? 0);
    $ru = trim($_POST['redirect_url'] ?? '');
    if ($evidence_id <= 0 || $case_id <= 0) { flash('error', 'Invalid evidence.'); if ($ru !== '') { header('Location: '.$ru); exit; } header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit; }

    $prevEv = [];
    try {
        $ps = $pdo->prepare('SELECT e.title, e.type, e.filepath, c.created_by AS case_created_by FROM evidence e JOIN cases c ON c.id = e.case_id WHERE e.id = ? AND e.case_id = ? LIMIT 1');
        $ps->execute([$evidence_id, $case_id]);
        $prevEv = $ps->fetch() ?: [];
    } catch (Throwable $e) {}
    $isCaseCreator = !empty($_SESSION['user'])
        && (int)($prevEv['case_created_by'] ?? 0) > 0
        && (int)($prevEv['case_created_by'] ?? 0) === (int)($_SESSION['user']['id'] ?? 0);
    if (!$prevEv || empty($_SESSION['user']) || (!is_admin() && !$isCaseCreator)) {
        flash('error', 'Unauthorized.');
        if ($ru !== '') { header('Location: '.$ru); exit; }
        header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit;
    }
    $title = trim($_POST['title'] ?? '');
    $type = $_POST['type'] ?? 'other';
    $allowedTypes = ['image','video','audio','pdf','doc','url','other'];
    if (!in_array($type, $allowedTypes, true)) $type = 'other';
    try {
        if (!is_admin() || $titleOnly) {
            $type = (string)($prevEv['type'] ?? 'other');
            $u = $pdo->prepare('UPDATE evidence SET title = ? WHERE id = ? AND case_id = ? LIMIT 1');
            $u->execute([$title, $evidence_id, $case_id]);
        } elseif ($type === 'url') {
            $url = trim($_POST['url_value'] ?? '');
            if ($url === '' || !filter_var($url, FILTER_VALIDATE_URL)) {
                flash('error', 'Please provide a valid URL.');
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
        if (is_admin() && !$titleOnly && ($prevEv['type'] ?? '') !== $type) { $changes[] = 'type: '.($prevEv['type'] ?? '').' → '.$type; }
        if (is_admin() && !$titleOnly && $type === 'url' && ($prevEv['filepath'] ?? '') !== ($url ?? '')) { $changes[] = 'url updated'; }
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
    if ($ru!==''){header('Location: '.$ru); exit;} header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit;
}

// Handle delete evidence (admin only)
if (($_POST['action'] ?? '') === 'delete_evidence') {
    throttle();
    if (!check_csrf()) { flash('error', 'Security check failed.'); header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit; }

    $evidence_id = (int)($_POST['evidence_id'] ?? 0);
    $case_id = (int)($_POST['case_id'] ?? 0);
    $ownerCan = can_manage_case_submission($pdo, $case_id);
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
    $ownerCan = can_manage_case_submission($pdo, $case_id);
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
        $d3 = $pdo->prepare('DELETE FROM case_tiktok_usernames WHERE case_id = ?');
        $d3->execute([$case_id]);
        $d4 = $pdo->prepare('DELETE FROM cases WHERE id = ? LIMIT 1');
        $d4->execute([$case_id]);
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
    if (!tp_check_math_captcha('removal')) {
        flash('error', 'Please answer the math security question correctly.');
        header('Location: ?view=removal#removal'); exit;
    }

    $full_name = tp_post_string('full_name');
    $email = tp_post_string('email');
    $phone = tp_post_string('phone');
    $org = tp_post_string('organization');
    $target_url = tp_post_string('target_url');
    $justification = tp_post_string('justification');

    $validRequest = tp_valid_public_text($full_name, 255)
        && strlen($email) <= 254
        && filter_var($email, FILTER_VALIDATE_EMAIL)
        && ($phone === '' || tp_valid_public_text($phone, 64))
        && ($org === '' || tp_valid_public_text($org, 255))
        && tp_valid_public_http_url($target_url)
        && tp_valid_public_text($justification, 5000, true);
    if (!$validRequest) {
        flash('error', 'Please enter valid request details and an http:// or https:// URL. Code-like or malformed input is not accepted.');
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
        $d = $pdo->prepare('DELETE FROM removal_requests WHERE id = ? AND status <> ? LIMIT 1');
        $d->execute([$rid, 'Approved / Closed']);
        if ($d->rowCount() > 0) {
            flash('success', 'Removal request deleted.');
            log_console('SUCCESS', 'Removal request #' . $rid . ' deleted');
        } else {
            flash('error', 'Removal request not found or it is Approved / Closed and cannot be deleted.');
        }
    } catch (Throwable $e) {
        $_SESSION['sql_error'] = $e->getMessage();
        log_console('ERROR', 'SQL: ' . $e->getMessage());
        flash('error', 'Unable to delete removal request.');
    }
    header('Location: ?view=removal#removal'); exit;
}

// Handle bulk delete removal requests (admin only)
if (($_POST['action'] ?? '') === 'bulk_delete_removals') {
    throttle();
    if (!check_csrf()) { flash('error', 'Security check failed.'); header('Location: ?view=removal#removal'); exit; }
    if (!is_admin()) { flash('error', 'Unauthorized.'); header('Location: ?view=removal#removal'); exit; }

    $submittedIds = $_POST['removal_ids'] ?? [];
    $removalIds = [];
    if (is_array($submittedIds)) {
        foreach ($submittedIds as $submittedId) {
            if (!is_string($submittedId) && !is_int($submittedId)) { continue; }
            $submittedId = (string)$submittedId;
            if (!ctype_digit($submittedId)) { continue; }
            $removalId = (int)$submittedId;
            if ($removalId > 0) { $removalIds[$removalId] = $removalId; }
            if (count($removalIds) >= 200) { break; }
        }
    }
    $removalIds = array_values($removalIds);

    if (!$removalIds) {
        flash('error', 'Select at least one removal request to delete.');
        header('Location: ?view=removal#removal'); exit;
    }

    try {
        $placeholders = implode(',', array_fill(0, count($removalIds), '?'));
        $params = array_merge($removalIds, ['Approved / Closed']);
        $d = $pdo->prepare('DELETE FROM removal_requests WHERE id IN (' . $placeholders . ') AND status <> ?');
        $d->execute($params);
        $deletedCount = $d->rowCount();
        $skippedCount = count($removalIds) - $deletedCount;

        if ($deletedCount > 0) {
            $message = $deletedCount . ' removal request' . ($deletedCount === 1 ? '' : 's') . ' deleted.';
            if ($skippedCount > 0) {
                $message .= ' ' . $skippedCount . ' locked or missing request' . ($skippedCount === 1 ? ' was' : 's were') . ' skipped.';
            }
            flash('success', $message);
            log_console('SUCCESS', 'Bulk deleted removal request IDs: ' . implode(',', $removalIds));
        } else {
            flash('error', 'None of the selected requests could be deleted. Approved / Closed requests are locked.');
        }
    } catch (Throwable $e) {
        $_SESSION['sql_error'] = $e->getMessage();
        log_console('ERROR', 'SQL: ' . $e->getMessage());
        flash('error', 'Unable to delete the selected removal requests.');
    }
    header('Location: ?view=removal#removal'); exit;
}

// Handle update user (admin only)
if (($_POST['action'] ?? '') === 'update_user') {
    throttle();
    if (!check_csrf()) { flash('error', 'Security check failed.'); header('Location: ?view=users#users'); exit; }
    if (!is_admin()) { flash('error', 'Unauthorized.'); header('Location: ?view=users#users'); exit; }

    $userId = (int)($_POST['user_id'] ?? 0);
    $email = tp_post_string('email');
    $displayName = tp_post_string('display_name');
    $username = tp_post_string('username');
    $role = tp_post_string('role');
    $isActive = isset($_POST['is_active']) ? 1 : 0;
    $newPassword = is_string($_POST['new_password'] ?? null) ? $_POST['new_password'] : '';
    $confirmPassword = is_string($_POST['password_confirm'] ?? null) ? $_POST['password_confirm'] : '';
    $returnToProfile = (($_POST['return_to_profile'] ?? '') === '1');
    $redirect = $returnToProfile && $userId > 0
        ? '?view=user_profile&id=' . $userId . '#user-profile'
        : '?view=users#users';

    if ($userId <= 0) { flash('error', 'Invalid user.'); header('Location: ?view=users#users'); exit; }
    if (strlen($email) > 254 || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        flash('error', 'Please enter a valid email address.'); header('Location: ' . $redirect); exit;
    }
    if (!tp_valid_public_text($displayName, 120)) {
        flash('error', 'Please enter a valid display name.'); header('Location: ' . $redirect); exit;
    }
    if (!preg_match('/\A[A-Za-z0-9._-]{3,120}\z/D', $username)) {
        flash('error', 'Username must be 3–120 characters using only letters, numbers, dots, underscores, or hyphens.');
        header('Location: ' . $redirect); exit;
    }
    if (!in_array($role, ['admin', 'viewer'], true)) { $role = 'viewer'; }
    if ($newPassword !== '' && strlen($newPassword) < 8) {
        flash('error', 'A new password must be at least 8 characters.'); header('Location: ' . $redirect); exit;
    }
    if ($newPassword !== '' && !hash_equals($newPassword, $confirmPassword)) {
        flash('error', 'New passwords do not match.'); header('Location: ' . $redirect); exit;
    }

    $isCurrentUser = $userId === (int)($_SESSION['user']['id'] ?? 0);
    if ($isCurrentUser) {
        $role = 'admin';
        $isActive = 1;
    }

    try {
        $exists = $pdo->prepare('SELECT id FROM users WHERE id = ? LIMIT 1');
        $exists->execute([$userId]);
        if (!$exists->fetch()) {
            flash('error', 'User not found.'); header('Location: ?view=users#users'); exit;
        }
        $duplicate = $pdo->prepare('SELECT id FROM users WHERE (email = ? OR username = ?) AND id <> ? LIMIT 1');
        $duplicate->execute([$email, $username, $userId]);
        if ($duplicate->fetch()) {
            flash('error', 'That email address or username is already registered.'); header('Location: ' . $redirect); exit;
        }

        if ($newPassword !== '') {
            $update = $pdo->prepare('UPDATE users SET email = ?, display_name = ?, username = ?, role = ?, is_active = ?, password_hash = ? WHERE id = ?');
            $update->execute([$email, $displayName, $username, $role, $isActive, password_hash($newPassword, PASSWORD_DEFAULT), $userId]);
        } else {
            $update = $pdo->prepare('UPDATE users SET email = ?, display_name = ?, username = ?, role = ?, is_active = ? WHERE id = ?');
            $update->execute([$email, $displayName, $username, $role, $isActive, $userId]);
        }
        if ($isCurrentUser) {
            $_SESSION['user']['email'] = $email;
            $_SESSION['user']['display_name'] = $displayName;
            $_SESSION['user']['username'] = $username;
            $_SESSION['user']['role'] = $role;
        }
        flash('success', 'User updated successfully.');
        log_console('SUCCESS', 'Admin updated user #' . $userId);
    } catch (Throwable $e) {
        $_SESSION['sql_error'] = $e->getMessage();
        log_console('ERROR', 'SQL: ' . $e->getMessage());
        flash('error', 'Unable to update user.');
    }
    header('Location: ' . $redirect); exit;
}

// Handle delete user (admin only)
if (($_POST['action'] ?? '') === 'delete_user') {
    throttle();
    if (!check_csrf()) { flash('error', 'Security check failed.'); header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit; }
    if (empty($_SESSION['user']) || (($_SESSION['user']['role'] ?? '') !== 'admin')) { flash('error', 'Unauthorized.'); header('Location: '. strtok($_SERVER['REQUEST_URI'], '?')); exit; }

    $user_id = (int)($_POST['user_id'] ?? 0);
    $ru = '?view=users#users';

    if ($user_id <= 0) { flash('error', 'Invalid user.'); header('Location: '. $ru); exit; }
    if (($user_id === (int)($_SESSION['user']['id'] ?? 0))) { flash('error', 'You cannot delete your own account.'); header('Location: '. $ru); exit; }

    try {
        $deletedCount = tp_delete_user_accounts($pdo, [$user_id]);
        if ($deletedCount > 0) {
            flash('success', 'User deleted.');
            log_console('SUCCESS', 'Admin deleted user #' . $user_id);
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

// Handle bulk delete users (admin only)
if (($_POST['action'] ?? '') === 'bulk_delete_users') {
    throttle();
    if (!check_csrf()) { flash('error', 'Security check failed.'); header('Location: ?view=users#users'); exit; }
    if (!is_admin()) { flash('error', 'Unauthorized.'); header('Location: ?view=users#users'); exit; }

    $submittedIds = $_POST['user_ids'] ?? [];
    $currentUserId = (int)($_SESSION['user']['id'] ?? 0);
    $userIds = [];
    if (is_array($submittedIds)) {
        foreach ($submittedIds as $submittedId) {
            if (!is_string($submittedId) && !is_int($submittedId)) { continue; }
            $submittedId = (string)$submittedId;
            if (!ctype_digit($submittedId)) { continue; }
            $userId = (int)$submittedId;
            if ($userId > 0 && $userId !== $currentUserId) { $userIds[$userId] = $userId; }
        }
    }
    $userIds = array_values($userIds);
    if (!$userIds) {
        flash('error', 'Select at least one user to delete. Your own account cannot be selected.');
        header('Location: ?view=users#users'); exit;
    }

    try {
        $deletedCount = tp_delete_user_accounts($pdo, $userIds);
        $skippedCount = count($userIds) - $deletedCount;
        if ($deletedCount > 0) {
            $message = $deletedCount . ' user account' . ($deletedCount === 1 ? '' : 's') . ' deleted.';
            if ($skippedCount > 0) { $message .= ' ' . $skippedCount . ' missing account' . ($skippedCount === 1 ? ' was' : 's were') . ' skipped.'; }
            flash('success', $message);
            log_console('SUCCESS', 'Admin bulk deleted user IDs: ' . implode(',', $userIds));
        } else {
            flash('error', 'None of the selected users could be deleted.');
        }
    } catch (Throwable $e) {
        $_SESSION['sql_error'] = $e->getMessage();
        log_console('ERROR', 'SQL: ' . $e->getMessage());
        flash('error', 'Unable to delete the selected users.');
    }
    header('Location: ?view=users#users'); exit;
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
                        ? "WHERE c.status = 'Verified'"
                        : "WHERE c.status = 'Verified' AND c.sensitivity != 'Sealed'";
                    $pq = $pdo->query(
                        "SELECT c.case_code, c.case_name, c.person_name, COALESCE(tu.usernames, c.tiktok_username) AS tiktok_username, c.status, c.sensitivity, c.location, c.phone_number, c.snapchat_username
                         FROM cases c
                         LEFT JOIN (
                           SELECT case_id, GROUP_CONCAT(username ORDER BY sort_order ASC, id ASC SEPARATOR ', ') AS usernames
                           FROM case_tiktok_usernames
                           GROUP BY case_id
                         ) tu ON tu.case_id = c.id
                         $sensWhere2 ORDER BY c.id DESC"
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
                                    c.case_code, c.case_name, c.person_name, COALESCE(tu.usernames, c.tiktok_username) AS tiktok_username,
                                c.status, c.sensitivity, c.location
                         FROM evidence e
                         JOIN cases c ON c.id = e.case_id
                             LEFT JOIN (
                               SELECT case_id, GROUP_CONCAT(username ORDER BY sort_order ASC, id ASC SEPARATOR ', ') AS usernames
                               FROM case_tiktok_usernames
                               GROUP BY case_id
                             ) tu ON tu.case_id = c.id
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

$tpSiteTitle = 'TikTokPredators';
$tpMetaDescription = 'A public, auditable repository documenting abusive behaviour by TikTok accounts — case records, evidence, and verifiable proof to expose predators and support accountability.';
$tpPageTitle = $tpSiteTitle . ' — Cases & Evidence';
$tpMetaUrl = tp_absolute_url('/');
$tpMetaType = 'website';
$tpMetaImage = tp_absolute_url('/assets/og-image.png');
$tpMetaImageAlt = $tpPageTitle;
$tpDiscordWebhooks = [];
$tpDiscordWebhookCount = 0;
$tpOpenAiApiKey = '';
if (isset($pdo) && $pdo instanceof PDO) {
    $tpSiteTitle = tp_project_setting($pdo, 'site_title', $tpSiteTitle);
    $tpMetaDescription = tp_project_setting($pdo, 'meta_data', $tpMetaDescription);
  $tpOpenAiApiKey = tp_project_setting($pdo, 'openai_api_key', '');
  $tpDiscordWebhooks = tp_discord_webhooks($pdo);
}
$tpPageTitle = $tpSiteTitle . ' — Cases & Evidence';
$tpMetaImageAlt = $tpPageTitle;

if ($view === 'case' && isset($pdo) && $pdo instanceof PDO) {
  $metaCaseCode = trim((string)($_GET['code'] ?? ''));
  if ($metaCaseCode !== '') {
    try {
      $metaStmt = $pdo->prepare('SELECT case_code, case_name, person_name, initial_summary, status, created_by FROM cases WHERE case_code = ? LIMIT 1');
      $metaStmt->execute([$metaCaseCode]);
      $metaCase = $metaStmt->fetch();
      $metaReviewOwner = $metaCase && is_logged_in() && (int)($metaCase['created_by'] ?? 0) === (int)($_SESSION['user']['id'] ?? 0);
      $metaIsPrivateReview = $metaCase && in_array(($metaCase['status'] ?? ''), ['Being Built','Pending','Rejected'], true);
      if ($metaCase && (!$metaIsPrivateReview || is_admin() || $metaReviewOwner)) {
        $metaCaseCode = (string)($metaCase['case_code'] ?? $metaCaseCode);
        $metaCaseName = trim((string)($metaCase['case_name'] ?? ''));
        $metaPersonName = trim((string)($metaCase['person_name'] ?? ''));
        $tpPageTitle = ($metaCaseName !== '' ? $metaCaseName : 'Case ' . $metaCaseCode) . ' — ' . $tpSiteTitle;
        $tpMetaDescription = tp_social_summary((string)($metaCase['initial_summary'] ?? ''), $tpMetaDescription);
        $tpMetaUrl = tp_absolute_url('/?view=case&code=' . rawurlencode($metaCaseCode));
        $tpMetaType = 'article';
        $metaPhoto = find_person_photo_url($metaCaseCode);
        if ($metaPhoto !== '') {
          $tpMetaImage = tp_absolute_url($metaPhoto);
        }
        if ($metaPersonName !== '' && $metaCaseName === '') {
          $tpPageTitle = $metaPersonName . ' — ' . $tpSiteTitle;
        }
        $tpMetaImageAlt = $tpPageTitle;
      }
    } catch (Throwable $e) {
      // Keep the default site metadata if the case lookup fails.
    }
  }
}
$tpDiscordWebhookCount = count($tpDiscordWebhooks);
if (count($tpDiscordWebhooks) === 0) {
  $tpDiscordWebhooks[] = ['name' => '', 'url' => ''];
}
$tpUserNotifications = [];
$tpUnreadNotificationCount = 0;
if (is_logged_in() && isset($pdo) && $pdo instanceof PDO) {
  try {
    $notificationUserId = (int)($_SESSION['user']['id'] ?? 0);
    $notificationCountStmt = $pdo->prepare('SELECT COUNT(*) FROM user_notifications WHERE user_id = ? AND is_read = 0');
    $notificationCountStmt->execute([$notificationUserId]);
    $tpUnreadNotificationCount = (int)$notificationCountStmt->fetchColumn();
    $notificationStmt = $pdo->prepare('SELECT n.id, n.title, n.message, n.is_read, n.created_at, c.case_code FROM user_notifications n LEFT JOIN cases c ON c.id = n.case_id WHERE n.user_id = ? ORDER BY n.created_at DESC LIMIT 8');
    $notificationStmt->execute([$notificationUserId]);
    $tpUserNotifications = $notificationStmt->fetchAll() ?: [];
  } catch (Throwable $e) {
    $_SESSION['sql_error'] = $_SESSION['sql_error'] ?? $e->getMessage();
  }
}
?>
<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title><?php echo htmlspecialchars($tpPageTitle); ?></title>
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
  <meta name="description" content="<?php echo htmlspecialchars($tpMetaDescription); ?>" />
  <!-- Open Graph / Social sharing -->
  <meta property="og:title" content="<?php echo htmlspecialchars($tpPageTitle); ?>" />
  <meta property="og:description" content="<?php echo htmlspecialchars($tpMetaDescription); ?>" />
  <meta property="og:type" content="<?php echo htmlspecialchars($tpMetaType); ?>" />
  <meta property="og:url" content="<?php echo htmlspecialchars($tpMetaUrl); ?>" />
  <meta property="og:site_name" content="<?php echo htmlspecialchars($tpSiteTitle); ?>" />
  <meta property="og:image" content="<?php echo htmlspecialchars($tpMetaImage); ?>" />
  <meta property="og:image:secure_url" content="<?php echo htmlspecialchars($tpMetaImage); ?>" />
  <meta property="og:image:alt" content="<?php echo htmlspecialchars($tpMetaImageAlt); ?>" />
  <meta name="twitter:card" content="summary_large_image" />
  <meta name="twitter:url" content="<?php echo htmlspecialchars($tpMetaUrl); ?>" />
  <meta name="twitter:title" content="<?php echo htmlspecialchars($tpPageTitle); ?>" />
  <meta name="twitter:description" content="<?php echo htmlspecialchars($tpMetaDescription); ?>" />
  <meta name="twitter:image" content="<?php echo htmlspecialchars($tpMetaImage); ?>" />
  <meta name="twitter:image:alt" content="<?php echo htmlspecialchars($tpMetaImageAlt); ?>" />
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" />
  <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css" rel="stylesheet" />
  <link href="https://cdn.datatables.net/1.13.8/css/dataTables.bootstrap5.min.css" rel="stylesheet" />
  <link href="https://cdn.jsdelivr.net/npm/select2@4.1.0-rc.0/dist/css/select2.min.css" rel="stylesheet" />
  <link href="https://cdn.jsdelivr.net/npm/select2-bootstrap-5-theme@1.3.0/dist/select2-bootstrap-5-theme.min.css" rel="stylesheet" />

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
    #case-view.case-outline-building .card.glass,
    #being-built > .card.glass {
      border: 2px solid #0d6efd !important;
      box-shadow: 0 0 0 .1rem rgba(13,110,253,.14);
    }
    #case-view.case-outline-pending .card.glass,
    #pending-review > .card.glass {
      border: 2px solid #ffc107 !important;
      box-shadow: 0 0 0 .1rem rgba(255,193,7,.14);
    }
    #case-view.case-outline-published .card.glass,
    #published-cases > .card.glass {
      border: 2px solid #198754 !important;
      box-shadow: 0 0 0 .1rem rgba(25,135,84,.14);
    }
    #case-view.case-outline-rejected .card.glass,
    #rejected-cases > .card.glass {
      border: 2px solid #dc3545 !important;
      box-shadow: 0 0 0 .1rem rgba(220,53,69,.14);
    }
    #case-owner-details .select2-container--bootstrap-5 .select2-selection,
    .select2-container--bootstrap-5 .select2-dropdown,
    .select2-container--bootstrap-5 .select2-search__field {
      background-color: #212529 !important;
      border-color: #495057 !important;
      color: #f8f9fa !important;
    }
    #case-owner-details .select2-container--bootstrap-5 .select2-selection__rendered,
    #case-owner-details .select2-container--bootstrap-5 .select2-selection__placeholder,
    .select2-container--bootstrap-5 .select2-results__option {
      color: #f8f9fa !important;
    }
    #case-owner-details .case-owner-transfer-form,
    #case-owner-details .case-owner-transfer-controls,
    #case-owner-details .case-owner-select-wrap {
      min-width: 0;
    }
    #case-owner-details .case-owner-transfer-form {
      width: 100%;
    }
    #case-owner-details .case-owner-select-wrap {
      flex: 1 1 auto;
      width: 100%;
    }
    #case-owner-details .case-owner-select-wrap .select2-container {
      min-width: 0;
      max-width: 100%;
    }
    #case-owner-details .case-owner-transfer-controls .btn {
      flex: 0 0 auto;
    }
    @media (min-width: 992px) {
      #case-owner-details .case-owner-transfer-form {
        flex: 1 1 auto;
        width: auto;
      }
    }
    .select2-container--bootstrap-5 .select2-results__option--selected {
      background-color: #343a40 !important;
    }
    .select2-container--bootstrap-5 .select2-results__option--highlighted {
      background-color: #495057 !important;
      color: #fff !important;
    }
    .select2-container--bootstrap-5 .select2-selection__clear,
    .select2-container--bootstrap-5 .select2-selection__choice__remove {
      color: #f8f9fa !important;
    }
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
    .webhook-row {
      display: grid;
      grid-template-columns: minmax(160px, 1fr) minmax(260px, 1.55fr) minmax(190px, auto) auto;
      gap: .5rem;
      align-items: center;
    }
    .webhook-meta {
      min-height: 42px;
      line-height: 1.25;
      white-space: nowrap;
    }
    .webhook-actions {
      display: flex;
      gap: .4rem;
      justify-content: flex-end;
    }
    .webhook-actions .btn {
      width: 42px;
      height: 42px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      padding: 0;
    }
    @media (max-width: 991.98px) {
      .webhook-row { grid-template-columns: 1fr; }
      .webhook-meta { white-space: normal; }
      .webhook-actions { justify-content: flex-start; }
    }
    
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
    <?php echo htmlspecialchars($tpSiteTitle); ?> is owned and operated by Jamie Whittingham | <a href="https://www.tiktok.com/@jamiewhittinghamofficial" target="_blank" rel="noopener noreferrer" style="color:#ffffff;text-decoration:underline;">Mouldy Sausage</a>
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
                <input type="text" class="form-control" id="reg_display_name" name="display_name" maxlength="120" required>
              </div>
              <div class="mb-3">
                <label for="reg_username" class="form-label">Username</label>
                <input type="text" class="form-control" id="reg_username" name="username" minlength="3" maxlength="120" pattern="[A-Za-z0-9._-]+" placeholder="your_username" required>
              </div>
              <div class="mb-3">
                <label for="reg_email" class="form-label">Email</label>
                <input type="email" class="form-control" id="reg_email" name="email" maxlength="254" placeholder="you@example.com" required>
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
              <?php tp_math_captcha_field('register'); ?>
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
      <a class="navbar-brand fw-bold" href="#"><i class="bi bi-shield-lock me-2 text-primary"></i> <?php echo htmlspecialchars($tpSiteTitle); ?></a>
      <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#topNav"><span class="navbar-toggler-icon"></span></button>
      <div class="collapse navbar-collapse" id="topNav">
<ul class="navbar-nav me-auto mb-2 mb-lg-0">
<li class="nav-item"><a class="nav-link <?php echo ($view==='cases')?'active':''; ?>" href="?view=cases#cases">Cases</a></li>
<?php if (is_logged_in()): ?>
  <li class="nav-item"><a class="nav-link <?php echo ($view==='pending')?'active':''; ?>" href="?view=pending#pending">Case Reviews</a></li>
<?php endif; ?>
<?php if (!empty($_SESSION['user']) && ($_SESSION['user']['role'] ?? '') === 'viewer'): ?>
  <li class="nav-item"><a class="nav-link <?php echo ($view==='submit_case')?'active':''; ?>" href="?view=submit_case#submit-case">Create Case</a></li>
<?php endif; ?>
<?php if (is_admin()): ?>
  <li class="nav-item"><a class="nav-link <?php echo in_array($view, ['users', 'user_profile'], true) ? 'active' : ''; ?>" href="?view=users#users">Users</a></li>
  <li class="nav-item"><a class="nav-link <?php echo ($view==='viewer_stats')?'active':''; ?>" href="?view=viewer_stats#viewer-stats">Viewer Stats</a></li>
  <?php if (tp_is_main_admin()): ?>
    <li class="nav-item"><a class="nav-link <?php echo ($view==='project_settings')?'active':''; ?>" href="?view=project_settings#project-settings">Project Settings</a></li>
  <?php endif; ?>
  <li class="nav-item">
    <a class="nav-link" href="#" data-bs-toggle="modal" data-bs-target="#devModal">Dev</a>
  </li>
<?php endif; ?>
  <li class="nav-item"><a class="nav-link <?php echo ($view==='faq')?'active':''; ?>" href="?view=faq#faq">FAQ</a></li>
  <li class="nav-item"><a class="nav-link <?php echo ($view==='scanner')?'active':''; ?>" href="?view=scanner#scanner"><i class="bi bi-camera-fill me-1"></i>Face Scanner</a></li>
    
      </ul>
      <ul class="navbar-nav ms-auto mb-2 mb-lg-0 align-items-center">
        <?php if (is_logged_in()): ?>
          <li class="nav-item dropdown me-2">
            <a class="nav-link position-relative" href="#" role="button" data-bs-toggle="dropdown" aria-expanded="false" aria-label="Account notifications">
              <i class="bi bi-bell"></i>
              <?php if ($tpUnreadNotificationCount > 0): ?>
                <span class="position-absolute top-0 start-100 translate-middle badge rounded-pill text-bg-danger"><?php echo min(99, $tpUnreadNotificationCount); ?></span>
              <?php endif; ?>
            </a>
            <ul class="dropdown-menu dropdown-menu-end p-0" style="width:min(92vw, 24rem); max-height:28rem; overflow:auto;">
              <li class="dropdown-header d-flex justify-content-between align-items-center px-3 py-2">
                <span>Notifications</span>
                <?php if ($tpUnreadNotificationCount > 0): ?>
                  <form method="post" action="" class="ms-2">
                    <input type="hidden" name="action" value="mark_notifications_read">
                    <?php csrf_field(); ?>
                    <button type="submit" class="btn btn-link btn-sm p-0">Mark all read</button>
                  </form>
                <?php endif; ?>
              </li>
              <?php if ($tpUserNotifications): foreach ($tpUserNotifications as $notification): ?>
                <li><hr class="dropdown-divider m-0"></li>
                <li>
                  <a class="dropdown-item text-wrap px-3 py-2<?php echo empty($notification['is_read']) ? ' bg-primary bg-opacity-10' : ''; ?>" href="<?php echo !empty($notification['case_code']) ? '?view=case&amp;code='.urlencode($notification['case_code']).'#case-view' : '?view=pending#pending'; ?>">
                    <div class="fw-semibold small"><?php echo htmlspecialchars($notification['title'] ?? 'Notification'); ?></div>
                    <div class="small text-secondary"><?php echo nl2br(htmlspecialchars($notification['message'] ?? '')); ?></div>
                    <div class="small text-secondary mt-1"><?php echo htmlspecialchars(date('d M Y H:i', strtotime($notification['created_at'] ?? 'now'))); ?></div>
                  </a>
                </li>
              <?php endforeach; else: ?>
                <li><span class="dropdown-item-text text-secondary small px-3 py-3">No notifications yet.</span></li>
              <?php endif; ?>
            </ul>
          </li>
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
    $reqTargetUrl = trim((string)($req['target_url'] ?? ''));
    $reqTargetUrlIsSafe = tp_valid_public_http_url($reqTargetUrl);
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
                <div>
                  <?php if ($reqTargetUrlIsSafe): ?>
                    <a href="<?php echo htmlspecialchars($reqTargetUrl); ?>" target="_blank" rel="noopener noreferrer"><?php echo htmlspecialchars($reqTargetUrl); ?></a>
                  <?php else: ?>
                    <span class="text-warning" title="This stored value is not a safe HTTP(S) URL."><?php echo htmlspecialchars($reqTargetUrl); ?></span>
                  <?php endif; ?>
                </div>
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
            <?php if ($reqTargetUrlIsSafe): ?>
              <a href="<?php echo htmlspecialchars($reqTargetUrl); ?>" class="btn btn-outline-light w-100 mb-2" target="_blank" rel="noopener noreferrer">
                <i class="bi bi-box-arrow-up-right me-1"></i> Open Target URL
              </a>
            <?php else: ?>
              <button type="button" class="btn btn-outline-warning w-100 mb-2" disabled>
                <i class="bi bi-exclamation-triangle me-1"></i> Unsafe URL blocked
              </button>
            <?php endif; ?>
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
                      <input type="text" name="full_name" class="form-control" maxlength="255" required>
                    </div>
                    <div class="col-md-6">
                      <label class="form-label">Email*</label>
                      <input type="email" name="email" class="form-control" maxlength="254" required>
                    </div>
                    <div class="col-md-6">
                      <label class="form-label">Phone</label>
                      <input type="text" name="phone" class="form-control" maxlength="64" placeholder="Optional">
                    </div>
                    <div class="col-md-6">
                      <label class="form-label">Organization</label>
                      <input type="text" name="organization" class="form-control" maxlength="255" placeholder="Optional">
                    </div>
                    <div class="col-12">
                      <label class="form-label">URL to the evidence or case*</label>
                      <input type="url" name="target_url" class="form-control" maxlength="2048" placeholder="https://tiktokpredators.com/?view=case&code=..." required>
                    </div>
                    <div class="col-12">
                      <label class="form-label">Justification*</label>
                      <textarea name="justification" rows="6" class="form-control" maxlength="5000" placeholder="Explain why this item should be reviewed or removed." required></textarea>
                    </div>
                  </div>
                  <div class="mt-3">
                    <?php tp_math_captcha_field('removal'); ?>
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
            <?php if ($reqs): ?>
              <form method="post" action="" id="bulkRemovalDeleteForm" class="m-0">
                <?php csrf_field(); ?>
                <input type="hidden" name="action" value="bulk_delete_removals">
                <button type="submit" class="btn btn-danger btn-sm" id="bulkRemovalDeleteButton" disabled>
                  <i class="bi bi-trash me-1"></i>Delete selected
                  <span class="badge text-bg-light ms-1" id="bulkRemovalSelectedCount">0</span>
                </button>
              </form>
            <?php endif; ?>
          </div>
          <div class="card-body">
            <?php if (!$reqs): ?>
              <div class="text-secondary">No removal requests yet.</div>
            <?php else: ?>
              <div class="table-responsive">
                <table class="table align-middle table-hover">
                  <thead>
                    <tr>
                      <th scope="col" style="width:2.5rem;">
                        <input type="checkbox" class="form-check-input" id="selectAllRemovalRequests" aria-label="Select all deletable removal requests">
                      </th>
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
                      <?php
                        $rowTargetUrl = trim((string)($r['target_url'] ?? ''));
                        $rowTargetUrlIsSafe = tp_valid_public_http_url($rowTargetUrl);
                        $isLocked = (($r['status'] ?? '') === 'Approved / Closed');
                      ?>
                      <tr>
                        <td>
                          <input
                            type="checkbox"
                            class="form-check-input removal-request-checkbox"
                            name="removal_ids[]"
                            value="<?php echo (int)$r['id']; ?>"
                            form="bulkRemovalDeleteForm"
                            aria-label="Select removal request #<?php echo (int)$r['id']; ?>"
                            <?php echo $isLocked ? 'disabled title="Approved / Closed requests cannot be deleted"' : ''; ?>
                          >
                        </td>
                        <td><?php echo (int)$r['id']; ?></td>
                        <td class="small text-secondary"><?php echo htmlspecialchars($r['created_at']); ?></td>
                        <td><?php echo htmlspecialchars($r['full_name']); ?></td>
                        <td><a href="mailto:<?php echo htmlspecialchars($r['email']); ?>"><?php echo htmlspecialchars($r['email']); ?></a></td>
                        <td class="text-truncate" style="max-width:280px;">
                          <?php if ($rowTargetUrlIsSafe): ?>
                            <a href="<?php echo htmlspecialchars($rowTargetUrl); ?>" target="_blank" rel="noopener noreferrer"><?php echo htmlspecialchars($rowTargetUrl); ?></a>
                          <?php else: ?>
                            <span class="text-warning" title="Unsafe URL blocked"><?php echo htmlspecialchars($rowTargetUrl); ?></span>
                          <?php endif; ?>
                        </td>
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
                <?php $rowTargetUrl = trim((string)($r['target_url'] ?? '')); $rowTargetUrlIsSafe = tp_valid_public_http_url($rowTargetUrl); ?>
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
                          <dt class="col-sm-3">URL</dt>
                          <dd class="col-sm-9">
                            <?php if ($rowTargetUrlIsSafe): ?>
                              <a href="<?php echo htmlspecialchars($rowTargetUrl); ?>" target="_blank" rel="noopener noreferrer"><?php echo htmlspecialchars($rowTargetUrl); ?></a>
                            <?php else: ?>
                              <span class="text-warning" title="Unsafe URL blocked"><?php echo htmlspecialchars($rowTargetUrl); ?></span>
                            <?php endif; ?>
                          </dd>
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
        <?php if ($reqs): ?>
          <script>
          (function () {
            var selectAll = document.getElementById('selectAllRemovalRequests');
            var checkboxes = Array.prototype.slice.call(document.querySelectorAll('.removal-request-checkbox:not(:disabled)'));
            var form = document.getElementById('bulkRemovalDeleteForm');
            var button = document.getElementById('bulkRemovalDeleteButton');
            var countBadge = document.getElementById('bulkRemovalSelectedCount');

            if (!selectAll || !form || !button || !countBadge) return;

            function updateBulkRemovalControls() {
              var selectedCount = checkboxes.filter(function (checkbox) { return checkbox.checked; }).length;
              countBadge.textContent = String(selectedCount);
              button.disabled = selectedCount === 0;
              selectAll.checked = checkboxes.length > 0 && selectedCount === checkboxes.length;
              selectAll.indeterminate = selectedCount > 0 && selectedCount < checkboxes.length;
              selectAll.disabled = checkboxes.length === 0;
            }

            selectAll.addEventListener('change', function () {
              checkboxes.forEach(function (checkbox) { checkbox.checked = selectAll.checked; });
              updateBulkRemovalControls();
            });
            checkboxes.forEach(function (checkbox) {
              checkbox.addEventListener('change', updateBulkRemovalControls);
            });
            form.addEventListener('submit', function (event) {
              var selectedCount = checkboxes.filter(function (checkbox) { return checkbox.checked; }).length;
              if (selectedCount === 0 || !confirm('Delete ' + selectedCount + ' selected removal request' + (selectedCount === 1 ? '' : 's') + '?')) {
                event.preventDefault();
              }
            });
            updateBulkRemovalControls();
          })();
          </script>
        <?php endif; ?>
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
  // --- Owner controls for unpublished cases (Being Built, Pending, or Rejected)
  if ($view === 'case') {
      $case_code_param = trim($_GET['code'] ?? '');
      if ($case_code_param !== '') {
          try {
              $stmt = $pdo->prepare('SELECT id, case_code, case_name, person_name, location, phone_number, snapchat_username, tiktok_username, initial_summary, sensitivity, status, rejection_reason, rejected_at FROM cases WHERE case_code = ? LIMIT 1');
              $stmt->execute([$case_code_param]);
              $caseRow = $stmt->fetch();
                if ($caseRow) { $caseRow['tiktok_username'] = get_case_tiktok_usernames($pdo, (int)$caseRow['id']) ?: ($caseRow['tiktok_username'] ?? ''); }
          } catch (Throwable $e) { $caseRow = null; }
          if ($caseRow) {
              $ownerCanInline = can_manage_case_submission($pdo, (int)$caseRow['id']);
              if ($ownerCanInline) {
                  $ownerCaseIsRejected = (($caseRow['status'] ?? '') === 'Rejected');
                  $ownerCaseIsBeingBuilt = (($caseRow['status'] ?? '') === 'Being Built');
                  ?>
                  <main class="py-3" id="owner-edit">
                    <div class="container-xl">
                      <div class="alert <?php echo $ownerCaseIsRejected ? 'alert-danger' : 'alert-info'; ?> d-flex align-items-start glass">
                        <i class="bi <?php echo $ownerCaseIsRejected ? 'bi-exclamation-circle' : 'bi-pencil-square'; ?> me-2 fs-5"></i>
                        <div>
                          <?php if ($ownerCaseIsRejected): ?>
                            <div class="fw-semibold">This case was rejected and needs changes before it can be reviewed again.</div>
                            <div class="mt-2"><strong>Admin reason:</strong> <?php echo nl2br(htmlspecialchars($caseRow['rejection_reason'] ?? 'No reason was recorded.')); ?></div>
                            <div class="small mt-2">Correct the case details and evidence, save your changes, then resubmit it for review.</div>
                          <?php elseif ($ownerCaseIsBeingBuilt): ?>
                            <div class="fw-semibold">This case is currently <span class="text-warning">Being Built</span>.</div>
                            <div class="small">Add the case details and evidence, save your changes, then submit it for review when it is ready.</div>
                          <?php else: ?>
                            <div class="fw-semibold">You opened this case and it is currently <span class="text-warning">Pending</span>.</div>
                            <div class="small">You may edit the case details and manage evidence while it is under review.</div>
                          <?php endif; ?>
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
                                <input type="text" name="location" class="form-control" value="<?php echo htmlspecialchars(tp_case_location_for_viewer($caseRow['location'] ?? '')); ?>" placeholder="City, region, or country">
                              </div>
                              <div class="col-md-6 mb-3">
                                <label class="form-label">Phone Number</label>
                                <input type="text" name="phone_number" class="form-control" value="<?php echo htmlspecialchars(tp_case_phone_number_for_viewer($caseRow['phone_number'] ?? '')); ?>" inputmode="tel">
                              </div>
                            </div>
                            <div class="row">
                              <div class="col-md-6 mb-3">
                                <label class="form-label">Snapchat Username</label>
                                <div class="input-group">
                                  <span class="input-group-text">@</span>
                                  <input type="text" name="snapchat_username" class="form-control" value="<?php echo htmlspecialchars($caseRow['snapchat_username'] ?? ''); ?>" placeholder="username">
                                </div>
                              </div>
                              <div class="col-md-6 mb-3">
                                <label class="form-label">TikTok Usernames</label>
                                <input type="text" name="tiktok_username" class="form-control" value="<?php echo htmlspecialchars(normalize_tiktok_usernames($caseRow['tiktok_username'] ?? '')); ?>" placeholder="username1, username2">
                              </div>
                              <div class="col-md-6 mb-3">
                                <label class="form-label">Person Photo (optional)</label>
                                <input type="file" name="person_photo" class="form-control" accept="image/*">
                                <?php if (find_person_photo_url($caseRow['case_code'] ?? '') !== ''): ?>
                                  <div class="form-check mt-2">
                                    <input class="form-check-input" type="checkbox" name="remove_person_photo" value="1" id="ownerRemovePersonPhoto">
                                    <label class="form-check-label" for="ownerRemovePersonPhoto">Remove current person photo</label>
                                  </div>
                                <?php endif; ?>
                              </div>
                            </div>
                            <div class="mb-3">
                              <label class="form-label">Summary</label>
                              <textarea name="initial_summary" class="form-control" rows="4" required><?php echo htmlspecialchars($caseRow['initial_summary'] ?? ''); ?></textarea>
                            </div>
                            <div class="mb-3">
                              <label class="form-label">Case Tags</label>
                              <?php echo render_case_tag_checkboxes(get_case_tags($pdo, (int)$caseRow['id'])); ?>
                            </div>
                            <div class="row">
                              <div class="col-md-6 mb-3">
                                <input type="hidden" name="sensitivity" value="Standard">
                              </div>
                              <div class="col-md-6 mb-3">
                                <input type="hidden" name="status" value="<?php echo htmlspecialchars($caseRow['status'] ?? 'Pending'); ?>">
                              </div>
                            </div>
                            <div class="d-flex gap-2">
                              <button type="submit" class="btn btn-primary"><i class="bi bi-save me-1"></i>Save Changes</button>
                              <a href="?view=case&amp;code=<?php echo urlencode($caseRow['case_code']); ?>#case-view" class="btn btn-outline-light">Cancel</a>
                            </div>
                          </form>
                          <?php if ($ownerCaseIsRejected || $ownerCaseIsBeingBuilt): ?>
                            <hr>
                            <form method="post" action="" onsubmit="return confirm('<?php echo $ownerCaseIsRejected ? 'Have you saved all corrections and are you ready to resubmit this case for admin review?' : 'Have you saved your changes and are you ready to submit this case for admin review?'; ?>');">
                              <input type="hidden" name="action" value="submit_case_for_review">
                              <?php csrf_field(); ?>
                              <input type="hidden" name="case_id" value="<?php echo (int)$caseRow['id']; ?>">
                              <input type="hidden" name="case_code" value="<?php echo htmlspecialchars($caseRow['case_code']); ?>">
                              <button type="submit" class="btn btn-success"><i class="bi <?php echo $ownerCaseIsRejected ? 'bi-arrow-repeat' : 'bi-send'; ?> me-1"></i><?php echo $ownerCaseIsRejected ? 'Resubmit for Review' : 'Submit for Review'; ?></button>
                              <span class="small text-secondary ms-2">Save your changes before submitting.</span>
                            </form>
                          <?php endif; ?>
                        </div>
                      </div>
                      <?php
                      // --- Owner's own evidence list for this review case
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
          <?php
          $search = trim($_GET['q'] ?? '');
          $tagFilter = strtolower(trim((string)($_GET['tag'] ?? '')));
          if (!isset(tp_case_tag_options()[$tagFilter])) { $tagFilter = ''; }
          ?>
          <div class="d-flex align-items-center justify-content-between mb-2">
            <h2 class="h4 mb-0">Recent Cases</h2>
            <div class="d-flex align-items-center">
              <form class="d-none d-md-flex me-2" method="get" action="" role="search">
                <input type="hidden" name="view" value="cases">
                <input type="search" name="q" class="form-control form-control-sm" placeholder="Search names, usernames, summary…" value="<?php echo htmlspecialchars($_GET['q'] ?? ''); ?>" />
                <select name="tag" class="form-select form-select-sm ms-1" style="min-width: 12rem;">
                  <?php echo render_case_tag_filter_options($tagFilter); ?>
                </select>
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
          <form class="d-flex d-md-none gap-1 mb-2" method="get" action="" role="search">
            <input type="hidden" name="view" value="cases">
            <input type="search" name="q" class="form-control form-control-sm" placeholder="Search cases…" value="<?php echo htmlspecialchars($search); ?>" />
            <select name="tag" class="form-select form-select-sm">
              <?php echo render_case_tag_filter_options($tagFilter); ?>
            </select>
            <button type="submit" class="btn btn-outline-light btn-sm"><i class="bi bi-search"></i></button>
          </form>
          <?php if ($search !== '' || $tagFilter !== ''): ?>
            <div class="text-secondary small mb-2">
              Showing results<?php if ($search !== ''): ?> for “<?php echo htmlspecialchars($search); ?>”<?php endif; ?><?php if ($tagFilter !== ''): ?> tagged <span class="text-white"><?php echo htmlspecialchars(tp_case_tag_options()[$tagFilter]); ?></span><?php endif; ?>.
              <a class="ms-1" href="?view=cases#cases">Clear filters</a>
            </div>
          <?php endif; ?>
          <div class="row g-3 row-cols-1 row-cols-md-2">
<?php
try {
  $whereParts = ["c.status NOT IN ('Being Built','Pending','Rejected')"];
  $queryParams = [];
  if ($search !== '') {
    $like = '%' . $search . '%';
    $whereParts[] = "(c.case_name LIKE ? OR c.person_name LIKE ? OR c.phone_number LIKE ? OR c.snapchat_username LIKE ? OR c.tiktok_username LIKE ? OR c.initial_summary LIKE ? OR EXISTS (SELECT 1 FROM case_tiktok_usernames ctu WHERE ctu.case_id = c.id AND ctu.username LIKE ?) OR EXISTS (SELECT 1 FROM case_tag_links ctl JOIN case_tags ct ON ct.id = ctl.tag_id WHERE ctl.case_id = c.id AND (ct.label LIKE ? OR ct.slug LIKE ?)))";
    array_push($queryParams, $like, $like, $like, $like, $like, $like, $like, $like, $like);
  }
  if ($tagFilter !== '') {
    $whereParts[] = "EXISTS (SELECT 1 FROM case_tag_links ctl_filter JOIN case_tags ct_filter ON ct_filter.id = ctl_filter.tag_id WHERE ctl_filter.case_id = c.id AND ct_filter.slug = ?)";
    $queryParams[] = $tagFilter;
  }
  $sql = "SELECT c.id, c.case_code, c.case_name, c.person_name, c.phone_number, c.snapchat_username, COALESCE(tu.usernames, c.tiktok_username) AS tiktok_username, c.initial_summary, c.status, c.sensitivity, c.opened_at,
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
          LEFT JOIN (
            SELECT case_id, GROUP_CONCAT(username ORDER BY sort_order ASC, id ASC SEPARATOR ', ') AS usernames
            FROM case_tiktok_usernames
            GROUP BY case_id
          ) tu ON tu.case_id = c.id
          WHERE " . implode(' AND ', $whereParts) . "
          ORDER BY last_activity DESC
          LIMIT 1000";
  $stmt = $pdo->prepare($sql);
  $stmt->execute($queryParams);
  $rs = $stmt->fetchAll();
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
    $tuser = $row['tiktok_username'] ? render_tiktok_usernames($row['tiktok_username'], '') : '';
    $sum   = trim($row['initial_summary'] ?? '');
    $sum   = $sum !== '' ? mb_strimwidth($sum, 0, 180, '…', 'UTF-8') : 'No summary provided.';
    $evc   = (int)($row['evidence_count'] ?? 0);
    $vwc   = (int)($row['case_view_count'] ?? 0);
    $status= $row['status'] ?? 'Open';
    $sens  = $row['sensitivity'] ?? 'Standard';
    $caseTags = get_case_tags($pdo, (int)($row['id'] ?? 0));
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
            case 'Rejected':
                $badgeClass = 'secondary';
                break;
        }
        ?>
        <span class="badge rounded-pill text-bg-<?php echo $badgeClass; ?> border">
            <?php echo htmlspecialchars($status); ?>
        </span>

        </div>
        <p class="small mt-3 mb-2 text-secondary"><?php echo htmlspecialchars($sum); ?></p>
        <?php if ($caseTags): ?>
          <div class="mb-2 d-flex gap-1 flex-wrap"><?php echo render_case_tag_badges($caseTags); ?></div>
        <?php endif; ?>
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
                <h2 class="h5 mb-0"><i class="bi bi-folder-plus me-2"></i>Create a Case</h2>
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
                      <label class="form-label">Phone Number</label>
                      <input type="text" name="phone_number" class="form-control" inputmode="tel">
                    </div>
                    <div class="col-md-6 mb-3">
                      <label class="form-label">Snapchat Username</label>
                      <div class="input-group">
                        <span class="input-group-text">@</span>
                        <input type="text" name="snapchat_username" class="form-control" placeholder="username (optional)">
                      </div>
                    </div>
                  </div>
                  <div class="row">
                    <div class="col-md-6 mb-3">
                      <label class="form-label">TikTok Usernames</label>
                      <input type="text" name="tiktok_username" class="form-control" placeholder="username1, username2 (optional)">
                    </div>
                  </div>
                  <div class="mb-3">
                    <label class="form-label">Summary <span class="text-danger">*</span></label>
                    <textarea name="initial_summary" class="form-control" rows="4" placeholder="Describe the concern and context." required></textarea>
                  </div>
                  <div class="mb-3">
                    <label class="form-label">Case Tags</label>
                    <?php echo render_case_tag_checkboxes(); ?>
                  </div>
                  <div class="mb-3">
                    <label class="form-label">Person Photo (optional)</label>
                    <input type="file" name="person_photo" class="form-control" accept="image/*">
                  </div>
                  <div class="alert alert-secondary small">
                    Creating a case starts it as <strong>Being Built</strong>. It remains private to you and administrators while you add details and evidence. Use <strong>Submit for Review</strong> when it is ready for an administrator.
                  </div>
                  <div class="d-grid">
                    <button class="btn btn-primary" type="submit"><i class="bi bi-folder-plus me-1"></i> Create Case</button>
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
        <?php
          $pendingTagFilter = strtolower(trim((string)($_GET['tag'] ?? '')));
          if (!isset(tp_case_tag_options()[$pendingTagFilter])) { $pendingTagFilter = ''; }
        ?>
        <div class="col-12">
          <div class="card glass">
            <div class="card-body">
              <div class="d-flex align-items-center justify-content-between gap-3 mb-3">
                <div>
                  <h1 class="h5 mb-1"><i class="bi bi-clipboard-check me-2"></i>Case Reviews</h1>
                  <p class="small text-secondary mb-0">Search Being Built, Pending Review, Approved / Published, and Rejected cases together.</p>
                </div>
                <a class="btn btn-outline-light btn-sm flex-shrink-0" href="?view=cases#cases"><i class="bi bi-arrow-left me-1"></i> Back to Cases</a>
              </div>
              <div class="d-flex flex-column flex-md-row align-items-md-end gap-2">
                <div class="flex-grow-1">
                  <label class="form-label small mb-1" for="caseReviewSearch">Search all case reviews</label>
                  <div class="input-group input-group-sm">
                    <span class="input-group-text"><i class="bi bi-search"></i></span>
                    <input type="search" class="form-control" id="caseReviewSearch" placeholder="Search case code, name, owner, subject, tag or rejection reason" autocomplete="off">
                  </div>
                </div>
                <form method="get" action="" class="d-flex align-items-end gap-2 flex-shrink-0">
                  <input type="hidden" name="view" value="pending">
                  <div>
                    <label class="form-label small mb-1" for="caseReviewTagFilter">Filter by tag</label>
                    <select name="tag" id="caseReviewTagFilter" class="form-select form-select-sm" style="min-width:12rem;">
                      <?php echo render_case_tag_filter_options($pendingTagFilter); ?>
                    </select>
                  </div>
                  <button type="submit" class="btn btn-outline-light btn-sm"><i class="bi bi-funnel me-1"></i>Filter</button>
                  <?php if ($pendingTagFilter !== ''): ?>
                    <a class="btn btn-outline-secondary btn-sm" href="?view=pending#pending" title="Clear tag filter"><i class="bi bi-x-lg"></i><span class="visually-hidden">Clear tag filter</span></a>
                  <?php endif; ?>
                </form>
              </div>
              <div class="small text-secondary mt-2" id="caseReviewSearchSummary" aria-live="polite"></div>
              <?php if ($pendingTagFilter !== ''): ?>
                <div class="small text-secondary mt-1">Filtering all sections by tag: <span class="text-white"><?php echo htmlspecialchars(tp_case_tag_options()[$pendingTagFilter]); ?></span>.</div>
              <?php endif; ?>
              <div class="alert alert-secondary mt-3 mb-0 d-none" id="caseReviewNoMatches">No cases match your search.</div>
            </div>
          </div>
        </div>
        <?php
          $beingBuiltRows = [];
          try {
            $beingBuiltSql = "
              SELECT c.id, c.case_code, c.case_name, c.person_name, c.created_by,
                     u.display_name AS creator_name,
                     COALESCE(ev.cnt, 0) AS evidence_count,
                     COALESCE(ev.last_added, c.opened_at) AS last_activity
              FROM cases c
              LEFT JOIN (
                SELECT case_id, COUNT(*) AS cnt, MAX(created_at) AS last_added
                FROM evidence GROUP BY case_id
              ) ev ON ev.case_id = c.id
              LEFT JOIN users u ON u.id = c.created_by
              WHERE c.status = 'Being Built'
            ";
            $beingBuiltParams = [];
            if ($pendingTagFilter !== '') {
              $beingBuiltSql .= " AND EXISTS (SELECT 1 FROM case_tag_links ctl_filter JOIN case_tags ct_filter ON ct_filter.id = ctl_filter.tag_id WHERE ctl_filter.case_id = c.id AND ct_filter.slug = ?)";
              $beingBuiltParams[] = $pendingTagFilter;
            }
            if (!is_admin()) {
              $beingBuiltSql .= ' AND c.created_by = ?';
              $beingBuiltParams[] = (int)($_SESSION['user']['id'] ?? 0);
            }
            $beingBuiltSql .= ' ORDER BY last_activity DESC';
            $beingBuiltStmt = $pdo->prepare($beingBuiltSql);
            $beingBuiltStmt->execute($beingBuiltParams);
            $beingBuiltRows = $beingBuiltStmt->fetchAll() ?: [];
          } catch (Throwable $e) {
            $_SESSION['sql_error'] = $e->getMessage();
          }
        ?>
        <div class="col-12" id="being-built" data-case-review-section data-case-review-status="building being built">
          <div class="card glass border-primary">
            <div class="card-body">
              <div class="d-flex align-items-center justify-content-between mb-3">
                <div>
                  <h2 class="h5 mb-1"><i class="bi bi-tools me-2 text-warning"></i>Being Built</h2>
                  <p class="small text-secondary mb-0"><?php echo is_admin() ? 'Cases still being prepared and not yet submitted for review.' : 'Build your case, add evidence, and submit it when it is ready for review.'; ?></p>
                </div>
                <span class="badge text-bg-warning">Being Built</span>
              </div>
              <?php if ($beingBuiltRows): ?>
                <div class="table-responsive">
                  <table class="table table-sm align-middle mb-0">
                    <thead><tr><th>Case</th><th>Created By</th><th>Subject</th><th>Tags</th><th>Evidence</th><th>Last Activity</th><th class="text-end">Actions</th></tr></thead>
                    <tbody>
                      <?php foreach ($beingBuiltRows as $builtCase):
                        $builtTags = get_case_tags($pdo, (int)$builtCase['id']);
                      ?>
                        <tr data-case-review-row>
                          <td><div class="fw-semibold"><?php echo htmlspecialchars($builtCase['case_name'] ?: $builtCase['case_code']); ?></div><div class="small text-secondary"><?php echo htmlspecialchars($builtCase['case_code']); ?></div></td>
                          <td><?php echo htmlspecialchars(trim((string)($builtCase['creator_name'] ?? '')) ?: '—'); ?></td>
                          <td><?php echo htmlspecialchars(trim((string)($builtCase['person_name'] ?? '')) ?: '—'); ?></td>
                          <td><?php echo render_case_tag_badges($builtTags, '<span class="text-secondary">&mdash;</span>'); ?></td>
                          <td><?php echo (int)($builtCase['evidence_count'] ?? 0); ?></td>
                          <td class="text-nowrap"><?php echo !empty($builtCase['last_activity']) ? htmlspecialchars(date('d M Y H:i', strtotime($builtCase['last_activity']))) : '—'; ?></td>
                          <td class="text-end text-nowrap">
                            <a class="btn btn-primary btn-sm" href="?view=case&amp;code=<?php echo urlencode($builtCase['case_code']); ?><?php echo is_admin() ? '#case-view' : '#owner-edit'; ?>"><i class="bi bi-pencil-square me-1"></i>Build / Edit</a>
                            <form method="post" action="" class="d-inline" onsubmit="return confirm('Submit this case for admin review now?');">
                              <input type="hidden" name="action" value="submit_case_for_review">
                              <?php csrf_field(); ?>
                              <input type="hidden" name="case_id" value="<?php echo (int)$builtCase['id']; ?>">
                              <input type="hidden" name="case_code" value="<?php echo htmlspecialchars($builtCase['case_code']); ?>">
                              <button type="submit" class="btn btn-success btn-sm"><i class="bi bi-send me-1"></i>Submit for Review</button>
                            </form>
                            <form method="post" action="" class="d-inline" onsubmit="return confirm('Delete this case and all evidence? This cannot be undone.');">
                              <input type="hidden" name="action" value="delete_case">
                              <?php csrf_field(); ?>
                              <input type="hidden" name="case_id" value="<?php echo (int)$builtCase['id']; ?>">
                              <input type="hidden" name="case_code" value="<?php echo htmlspecialchars($builtCase['case_code']); ?>">
                              <button type="submit" class="btn btn-outline-danger btn-sm"><i class="bi bi-trash me-1"></i>Delete</button>
                            </form>
                          </td>
                        </tr>
                      <?php endforeach; ?>
                    </tbody>
                  </table>
                </div>
              <?php else: ?>
                <div class="alert alert-secondary mb-0">No cases are currently being built.</div>
              <?php endif; ?>
            </div>
          </div>
        </div>
        <div class="col-12" id="pending-review" data-case-review-section data-case-review-status="pending pending review">
          <div class="card glass border-warning">
            <div class="card-body">
              <div class="d-flex align-items-center justify-content-between mb-3">
                <h2 class="h5 mb-0"><i class="bi bi-hourglass-split me-2"></i>Pending Review</h2>
                <span class="badge text-bg-warning">Pending</span>
              </div>
  <?php
    // Build dataset based on role
    $rows = [];
    try {
        $baseSql = "
          SELECT c.id, c.case_code, c.case_name, c.person_name, c.status, c.created_by, c.resubmitted_at, c.submitted_for_review_at,
                 u.display_name AS creator_name,
                 COALESCE(ev.cnt, 0) AS evidence_count,
                 GREATEST(COALESCE(ev.last_added, c.opened_at), COALESCE(c.resubmitted_at, c.opened_at), COALESCE(c.submitted_for_review_at, c.opened_at), c.opened_at) AS last_activity
          FROM cases c
          LEFT JOIN (
            SELECT case_id, COUNT(*) AS cnt, MAX(created_at) AS last_added
            FROM evidence
            GROUP BY case_id
          ) ev ON ev.case_id = c.id
          LEFT JOIN users u ON u.id = c.created_by
          WHERE c.status = 'Pending'
        ";
          $pendingParams = [];
          if ($pendingTagFilter !== '') {
            $baseSql .= " AND EXISTS (SELECT 1 FROM case_tag_links ctl_filter JOIN case_tags ct_filter ON ct_filter.id = ctl_filter.tag_id WHERE ctl_filter.case_id = c.id AND ct_filter.slug = ?)";
            $pendingParams[] = $pendingTagFilter;
          }
        if (is_admin()) {
            $sql = $baseSql . " ORDER BY last_activity DESC";
            $stmt = $pdo->prepare($sql);
            $stmt->execute($pendingParams);
        } else {
            // Viewer: only own pending cases
            $sql = $baseSql . " AND c.created_by = ? ORDER BY last_activity DESC";
            $stmt = $pdo->prepare($sql);
            $pendingParams[] = $_SESSION['user']['id'] ?? 0;
            $stmt->execute($pendingParams);
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
                    <tr data-case-review-row>
                      <th style="width: 12rem;" class="text-nowrap">Case Code</th>
                      <th class="text-nowrap">Case Name</th>
                      <th class="text-nowrap">Submitted By</th>
                      <th style="width: 16rem;" class="text-nowrap">Subject</th>
                      <th class="text-nowrap">Tags</th>
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
                        $pendingCaseTags = get_case_tags($pdo, (int)($r['id'] ?? 0));
                  ?>
                    <tr>
                      <td class="text-nowrap"><span class="badge text-bg-dark border"><?php echo htmlspecialchars($code); ?></span></td>
                      <td class="fw-semibold text-nowrap"><?php echo htmlspecialchars($name); ?><?php if (!empty($r['resubmitted_at'])): ?><span class="badge text-bg-info ms-1">Resubmitted</span><?php endif; ?></td>
                      <td class="text-nowrap"><?php echo $creatorName !== '' ? htmlspecialchars($creatorName) : '—'; ?></td>
                      <td class="text-nowrap"><?php echo htmlspecialchars($person !== '' ? $person : '—'); ?></td>
                      <td><?php echo render_case_tag_badges($pendingCaseTags, '<span class="text-secondary">&mdash;</span>'); ?></td>
                      <td class="text-nowrap"><?php echo $evc; ?></td>
                      <td class="text-nowrap"><?php echo htmlspecialchars($last ? date('d M Y H:i', strtotime($last)) : '—'); ?></td>
                      <td class="text-end text-nowrap">                        
                          <a class="btn btn-primary btn-sm" href="?view=case&code=<?php echo urlencode($code); ?>#case-view"><i class="bi bi-pencil-square me-1"></i><?php echo is_admin() ? 'Review' : 'Edit'; ?></a>
                          <?php if (is_admin()): ?>
                          <button type="button" class="btn btn-danger btn-sm btn-reject-case" data-bs-toggle="modal" data-bs-target="#rejectCaseModal" data-case-id="<?php echo (int)$r['id']; ?>" data-case-code="<?php echo htmlspecialchars($code); ?>" data-case-name="<?php echo htmlspecialchars($name); ?>"><i class="bi bi-x-circle me-1"></i>Reject</button>
                          <?php endif; ?>
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
        <div class="col-12" id="published-cases" data-case-review-section data-case-review-status="approved verified published">
          <div class="card glass border-success">
            <div class="card-body">
              <div class="d-flex align-items-center justify-content-between mb-3">
                <div>
                  <h2 class="h5 mb-1"><i class="bi bi-patch-check-fill me-2 text-success"></i>Approved / Verified / Published</h2>
                  <p class="small text-secondary mb-0"><?php echo is_admin() ? 'Cases that completed review, were verified, and are currently visible on the public site.' : 'Your cases that completed review, were verified, and are currently visible on the public site.'; ?></p>
                </div>
                <span class="badge text-bg-success">Published</span>
              </div>
              <?php
                $publishedRows = [];
                try {
                  $publishedSql = "
                    SELECT c.id, c.case_code, c.case_name, c.person_name, c.created_by, c.updated_at,
                           u.display_name AS creator_name,
                           COALESCE(ev.cnt, 0) AS evidence_count,
                           COALESCE(ev.last_added, c.updated_at, c.opened_at) AS last_activity
                    FROM cases c
                    LEFT JOIN (
                      SELECT case_id, COUNT(*) AS cnt, MAX(created_at) AS last_added
                      FROM evidence GROUP BY case_id
                    ) ev ON ev.case_id = c.id
                    LEFT JOIN users u ON u.id = c.created_by
                    WHERE c.status = 'Verified'
                  ";
                  $publishedParams = [];
                  if ($pendingTagFilter !== '') {
                    $publishedSql .= " AND EXISTS (SELECT 1 FROM case_tag_links ctl_filter JOIN case_tags ct_filter ON ct_filter.id = ctl_filter.tag_id WHERE ctl_filter.case_id = c.id AND ct_filter.slug = ?)";
                    $publishedParams[] = $pendingTagFilter;
                  }
                  if (!is_admin()) {
                    $publishedSql .= ' AND c.created_by = ?';
                    $publishedParams[] = (int)($_SESSION['user']['id'] ?? 0);
                  }
                  $publishedSql .= ' ORDER BY c.updated_at DESC, c.opened_at DESC';
                  $publishedStmt = $pdo->prepare($publishedSql);
                  $publishedStmt->execute($publishedParams);
                  $publishedRows = $publishedStmt->fetchAll() ?: [];
                } catch (Throwable $e) {
                  $_SESSION['sql_error'] = $e->getMessage();
                }
              ?>
              <?php if ($publishedRows): ?>
                <div class="table-responsive">
                  <table class="table table-sm align-middle mb-0">
                    <thead><tr><th>Case</th><th>Owner</th><th>Subject</th><th>Tags</th><th>Evidence</th><th>Published / Updated</th><th class="text-end">Actions</th></tr></thead>
                    <tbody>
                      <?php foreach ($publishedRows as $publishedCase):
                        $publishedTags = get_case_tags($pdo, (int)$publishedCase['id']);
                      ?>
                        <tr data-case-review-row>
                          <td><div class="fw-semibold"><?php echo htmlspecialchars($publishedCase['case_name'] ?: $publishedCase['case_code']); ?></div><div class="small text-secondary"><?php echo htmlspecialchars($publishedCase['case_code']); ?></div></td>
                          <td><?php echo htmlspecialchars(trim((string)($publishedCase['creator_name'] ?? '')) ?: '—'); ?></td>
                          <td><?php echo htmlspecialchars(trim((string)($publishedCase['person_name'] ?? '')) ?: '—'); ?></td>
                          <td><?php echo render_case_tag_badges($publishedTags, '<span class="text-secondary">&mdash;</span>'); ?></td>
                          <td><?php echo (int)($publishedCase['evidence_count'] ?? 0); ?></td>
                          <td class="text-nowrap"><?php echo !empty($publishedCase['updated_at']) ? htmlspecialchars(date('d M Y H:i', strtotime($publishedCase['updated_at']))) : '—'; ?></td>
                          <td class="text-end text-nowrap">
                            <a class="btn btn-outline-light btn-sm" href="?view=case&amp;code=<?php echo urlencode($publishedCase['case_code']); ?>#case-view"><i class="bi bi-eye me-1"></i>View</a>
                            <form method="post" action="" class="d-inline" onsubmit="return confirm('Remove this case from public view and return it to Being Built? It must be submitted and approved again before it will be published.');">
                              <input type="hidden" name="action" value="return_published_case_to_building">
                              <?php csrf_field(); ?>
                              <input type="hidden" name="case_id" value="<?php echo (int)$publishedCase['id']; ?>">
                              <input type="hidden" name="case_code" value="<?php echo htmlspecialchars($publishedCase['case_code']); ?>">
                              <button type="submit" class="btn btn-outline-warning btn-sm"><i class="bi bi-tools me-1"></i>Return to Building</button>
                            </form>
                          </td>
                        </tr>
                      <?php endforeach; ?>
                    </tbody>
                  </table>
                </div>
              <?php else: ?>
                <div class="alert alert-secondary mb-0">No verified published cases to show.</div>
              <?php endif; ?>
            </div>
          </div>
        </div>
        <div class="col-12" id="rejected-cases" data-case-review-section data-case-review-status="rejected requiring changes">
          <div class="card glass border-danger">
            <div class="card-body">
              <div class="d-flex align-items-center justify-content-between mb-3">
                <h2 class="h5 mb-0"><i class="bi bi-x-circle me-2 text-danger"></i><?php echo is_admin() ? 'Rejected Cases' : 'Cases Requiring Changes'; ?></h2>
                <span class="badge text-bg-danger">Rejected</span>
              </div>
              <p class="small text-secondary"><?php echo is_admin() ? 'Monitor rejected submissions, review the reason, and edit case details where needed.' : 'Correct the issues described by the administrator, save your changes, then resubmit the case for review.'; ?></p>
              <?php
                $rejectedRows = [];
                try {
                  $rejectedSql = "
                    SELECT c.id, c.case_code, c.case_name, c.person_name, c.created_by,
                           c.rejection_reason, c.rejected_at,
                           u.display_name AS creator_name,
                           COALESCE(ev.cnt, 0) AS evidence_count,
                           COALESCE(ev.last_added, c.rejected_at, c.opened_at) AS last_activity
                    FROM cases c
                    LEFT JOIN (
                      SELECT case_id, COUNT(*) AS cnt, MAX(created_at) AS last_added
                      FROM evidence GROUP BY case_id
                    ) ev ON ev.case_id = c.id
                    LEFT JOIN users u ON u.id = c.created_by
                    WHERE c.status = 'Rejected'
                  ";
                  $rejectedParams = [];
                  if ($pendingTagFilter !== '') {
                    $rejectedSql .= " AND EXISTS (SELECT 1 FROM case_tag_links ctl_filter JOIN case_tags ct_filter ON ct_filter.id = ctl_filter.tag_id WHERE ctl_filter.case_id = c.id AND ct_filter.slug = ?)";
                    $rejectedParams[] = $pendingTagFilter;
                  }
                  if (!is_admin()) {
                    $rejectedSql .= ' AND c.created_by = ?';
                    $rejectedParams[] = (int)($_SESSION['user']['id'] ?? 0);
                  }
                  $rejectedSql .= ' ORDER BY c.rejected_at DESC, last_activity DESC';
                  $rejectedStmt = $pdo->prepare($rejectedSql);
                  $rejectedStmt->execute($rejectedParams);
                  $rejectedRows = $rejectedStmt->fetchAll() ?: [];
                } catch (Throwable $e) {
                  $_SESSION['sql_error'] = $e->getMessage();
                }
              ?>
              <?php if ($rejectedRows): ?>
                <div class="table-responsive">
                  <table class="table table-sm align-middle mb-0">
                    <thead><tr><th>Case</th><th>Submitted By</th><th>Rejection Reason</th><th>Rejected</th><th>Evidence</th><th class="text-end">Actions</th></tr></thead>
                    <tbody>
                      <?php foreach ($rejectedRows as $rejectedCase): ?>
                        <tr data-case-review-row>
                          <td><div class="fw-semibold"><?php echo htmlspecialchars($rejectedCase['case_name'] ?: $rejectedCase['case_code']); ?></div><div class="small text-secondary"><?php echo htmlspecialchars($rejectedCase['case_code']); ?></div></td>
                          <td><?php echo htmlspecialchars(trim((string)($rejectedCase['creator_name'] ?? '')) ?: '—'); ?></td>
                          <td style="min-width:18rem; max-width:32rem;"><div class="text-wrap"><?php echo nl2br(htmlspecialchars($rejectedCase['rejection_reason'] ?? 'No reason recorded.')); ?></div></td>
                          <td class="text-nowrap"><?php echo !empty($rejectedCase['rejected_at']) ? htmlspecialchars(date('d M Y H:i', strtotime($rejectedCase['rejected_at']))) : '—'; ?></td>
                          <td><?php echo (int)($rejectedCase['evidence_count'] ?? 0); ?></td>
                          <td class="text-end text-nowrap">
                            <a class="btn btn-primary btn-sm" href="?view=case&amp;code=<?php echo urlencode($rejectedCase['case_code']); ?><?php echo is_admin() ? '#case-view' : '#owner-edit'; ?>"><i class="bi bi-pencil-square me-1"></i><?php echo is_admin() ? 'Review / Edit' : 'Fix Case'; ?></a>
                            <form method="post" action="" class="d-inline" onsubmit="return confirm('Have all corrections been saved and is this case ready to return to pending review?');">
                                <input type="hidden" name="action" value="submit_case_for_review">
                                <?php csrf_field(); ?>
                                <input type="hidden" name="case_id" value="<?php echo (int)$rejectedCase['id']; ?>">
                                <input type="hidden" name="case_code" value="<?php echo htmlspecialchars($rejectedCase['case_code']); ?>">
                                <button type="submit" class="btn btn-success btn-sm"><i class="bi bi-arrow-repeat me-1"></i><?php echo is_admin() ? 'Return to Pending' : 'Resubmit'; ?></button>
                              </form>
                          </td>
                        </tr>
                      <?php endforeach; ?>
                    </tbody>
                  </table>
                </div>
              <?php else: ?>
                <div class="alert alert-secondary mb-0">No rejected cases to show.</div>
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
                  'Rejected'  => 'text-bg-danger',
                  default     => 'text-bg-secondary',
              };
            ?>
            <div class="col-12">
              <div class="card glass">
                <div class="card-body">
                  <div class="row g-3 align-items-start">

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
                          <i class="bi bi-tiktok me-1"></i><?php echo render_tiktok_usernames($res['tiktok_username'], ''); ?>
                        </div>
                        <?php endif; ?>
                        <?php if (!empty($res['location'])): ?>
                        <div class="col">
                          <i class="bi bi-geo-alt me-1"></i><?php echo htmlspecialchars(tp_case_location_for_viewer($res['location'])); ?>
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

  <?php if ($view === 'user_profile'): ?>
  <main class="py-4" id="user-profile">
    <div class="container-xl">
      <?php if (!is_admin()): ?>
        <div class="alert alert-danger"><i class="bi bi-shield-lock me-2"></i>Unauthorized. Admins only.</div>
      <?php else: ?>
        <?php
          $profileUserId = (int)($_GET['id'] ?? 0);
          $profileUser = null;
          $profileCases = [];
          $profileLogins = [];
          $profileStatusCounts = [];
          $profileLoginPage = max(1, (int)($_GET['login_page'] ?? 1));
          $profileLoginsPerPage = 100;
          $profileLoginTotal = 0;
          $profileLoginTotalPages = 1;
          try {
            $profileStmt = $pdo->prepare("SELECT u.id, u.email, u.display_name, u.username, u.role, u.is_active, u.created_at, u.last_login_at, u.signup_ip, u.signup_forwarded_for, u.signup_user_agent,
                (SELECT COUNT(*) FROM user_login_history ulh WHERE ulh.user_id = u.id) AS login_count,
                (SELECT ulh.ip_address FROM user_login_history ulh WHERE ulh.user_id = u.id ORDER BY ulh.logged_in_at DESC, ulh.id DESC LIMIT 1) AS last_login_ip
              FROM users u WHERE u.id = ? LIMIT 1");
            $profileStmt->execute([$profileUserId]);
            $profileUser = $profileStmt->fetch() ?: null;

            if ($profileUser) {
              $profileLoginTotal = (int)($profileUser['login_count'] ?? 0);
              $profileLoginTotalPages = max(1, (int)ceil($profileLoginTotal / $profileLoginsPerPage));
              $profileLoginPage = min($profileLoginPage, $profileLoginTotalPages);
              $caseStmt = $pdo->prepare("SELECT c.id, c.case_code, c.case_name, c.person_name, c.status, c.sensitivity, c.created_by, c.opened_at, c.updated_at,
                    csm.submitted_by AS original_submitter_id,
                    (SELECT COUNT(*) FROM evidence e WHERE e.case_id = c.id) AS evidence_count
                  FROM cases c
                  LEFT JOIN case_submission_metadata csm ON csm.case_id = c.id
                  WHERE c.created_by = ? OR csm.submitted_by = ?
                  ORDER BY COALESCE(c.updated_at, c.opened_at) DESC");
              $caseStmt->execute([$profileUserId, $profileUserId]);
              $profileCases = $caseStmt->fetchAll() ?: [];
              foreach ($profileCases as $profileCase) {
                $caseStatus = (string)($profileCase['status'] ?? 'Unknown');
                $profileStatusCounts[$caseStatus] = ($profileStatusCounts[$caseStatus] ?? 0) + 1;
              }

              $profileLoginOffset = ($profileLoginPage - 1) * $profileLoginsPerPage;
              $loginStmt = $pdo->prepare('SELECT id, ip_address, forwarded_for, user_agent, logged_in_at FROM user_login_history WHERE user_id = ? ORDER BY logged_in_at DESC, id DESC LIMIT ' . $profileLoginsPerPage . ' OFFSET ' . $profileLoginOffset);
              $loginStmt->execute([$profileUserId]);
              $profileLogins = $loginStmt->fetchAll() ?: [];
            }
          } catch (Throwable $e) {
            $_SESSION['sql_error'] = $e->getMessage();
            log_console('ERROR', 'SQL: ' . $e->getMessage());
          }
          $profileIsCurrentUser = $profileUserId === (int)($_SESSION['user']['id'] ?? 0);
        ?>

        <div class="d-flex flex-column flex-md-row align-items-md-center justify-content-between gap-2 mb-3">
          <div>
            <h1 class="h4 mb-1"><i class="bi bi-person-vcard me-2"></i>User Profile</h1>
            <div class="text-secondary small">Account details, submitted cases, and successful login history.</div>
          </div>
          <a class="btn btn-outline-light btn-sm" href="?view=users#users"><i class="bi bi-arrow-left me-1"></i>Back to Users</a>
        </div>

        <?php if (!$profileUser): ?>
          <div class="alert alert-warning">User not found.</div>
        <?php else: ?>
          <div class="row g-4">
            <div class="col-lg-8">
              <div class="row g-3 mb-4">
                <div class="col-sm-6 col-xl-3"><div class="card glass h-100"><div class="card-body"><div class="text-secondary small">Submitted Cases</div><div class="display-6"><?php echo count($profileCases); ?></div></div></div></div>
                <div class="col-sm-6 col-xl-3"><div class="card glass h-100"><div class="card-body"><div class="text-secondary small">Verified Cases</div><div class="display-6"><?php echo (int)($profileStatusCounts['Verified'] ?? 0); ?></div></div></div></div>
                <div class="col-sm-6 col-xl-3"><div class="card glass h-100"><div class="card-body"><div class="text-secondary small">Recorded Logins</div><div class="display-6"><?php echo (int)($profileUser['login_count'] ?? 0); ?></div></div></div></div>
                <div class="col-sm-6 col-xl-3"><div class="card glass h-100"><div class="card-body"><div class="text-secondary small">Account</div><div class="mt-2"><?php echo (int)$profileUser['is_active'] === 1 ? '<span class="badge text-bg-success">Active</span>' : '<span class="badge text-bg-secondary">Disabled</span>'; ?></div></div></div></div>
              </div>

              <div class="card glass mb-4">
                <div class="card-header"><h2 class="h6 mb-0">Account Overview</h2></div>
                <div class="card-body">
                  <div class="row g-3">
                    <div class="col-sm-6"><span class="text-secondary d-block small">User ID</span><?php echo (int)$profileUser['id']; ?></div>
                    <div class="col-sm-6"><span class="text-secondary d-block small">Role</span><?php echo htmlspecialchars(ucfirst((string)$profileUser['role'])); ?></div>
                    <div class="col-sm-6"><span class="text-secondary d-block small">Display Name</span><?php echo htmlspecialchars((string)$profileUser['display_name']); ?></div>
                    <div class="col-sm-6"><span class="text-secondary d-block small">Username</span>@<?php echo htmlspecialchars((string)$profileUser['username']); ?></div>
                    <div class="col-sm-6"><span class="text-secondary d-block small">Email</span><?php echo htmlspecialchars((string)$profileUser['email']); ?></div>
                    <div class="col-sm-6"><span class="text-secondary d-block small">Signed Up</span><?php echo htmlspecialchars((string)($profileUser['created_at'] ?? 'Not recorded')); ?></div>
                    <div class="col-sm-6"><span class="text-secondary d-block small">Signup IP Address</span><span class="font-monospace"><?php echo htmlspecialchars((string)(($profileUser['signup_ip'] ?? '') !== '' ? $profileUser['signup_ip'] : 'Not recorded')); ?></span></div>
                    <div class="col-sm-6"><span class="text-secondary d-block small">Signup Forwarded IP Chain</span><span class="font-monospace small text-break"><?php echo htmlspecialchars((string)(($profileUser['signup_forwarded_for'] ?? '') !== '' ? $profileUser['signup_forwarded_for'] : 'Not recorded')); ?></span></div>
                    <div class="col-sm-6"><span class="text-secondary d-block small">Last Login</span><?php echo htmlspecialchars((string)(($profileUser['last_login_at'] ?? '') !== '' ? $profileUser['last_login_at'] : 'Never')); ?></div>
                    <div class="col-sm-6"><span class="text-secondary d-block small">Last Login IP</span><span class="font-monospace"><?php echo htmlspecialchars((string)(($profileUser['last_login_ip'] ?? '') !== '' ? $profileUser['last_login_ip'] : 'Not recorded')); ?></span></div>
                    <div class="col-12"><span class="text-secondary d-block small">Signup User Agent</span><span class="small text-break"><?php echo htmlspecialchars((string)(($profileUser['signup_user_agent'] ?? '') !== '' ? $profileUser['signup_user_agent'] : 'Not recorded')); ?></span></div>
                  </div>
                </div>
              </div>

              <div class="card glass mb-4">
                <div class="card-header d-flex align-items-center justify-content-between"><h2 class="h6 mb-0">Submitted Cases</h2><span class="badge text-bg-dark border"><?php echo count($profileCases); ?></span></div>
                <div class="card-body">
                  <?php if ($profileCases): ?>
                    <div class="table-responsive">
                      <table class="table table-sm align-middle mb-0">
                        <thead><tr><th>Case</th><th>Relationship</th><th>Status</th><th>Evidence</th><th>Updated</th><th class="text-end">Action</th></tr></thead>
                        <tbody>
                          <?php foreach ($profileCases as $profileCase): ?>
                            <?php
                              $isOriginalSubmitter = (int)($profileCase['original_submitter_id'] ?? 0) === $profileUserId;
                              $isCurrentOwner = (int)($profileCase['created_by'] ?? 0) === $profileUserId;
                              $relationship = $isOriginalSubmitter && $isCurrentOwner ? 'Submitted / Owner' : ($isOriginalSubmitter ? 'Original Submitter' : 'Current Owner');
                            ?>
                            <tr>
                              <td><div class="fw-semibold"><?php echo htmlspecialchars((string)($profileCase['case_name'] ?: $profileCase['case_code'])); ?></div><div class="small text-secondary"><?php echo htmlspecialchars((string)$profileCase['case_code']); ?></div></td>
                              <td><span class="badge text-bg-dark border"><?php echo htmlspecialchars($relationship); ?></span></td>
                              <td><?php echo htmlspecialchars((string)$profileCase['status']); ?></td>
                              <td><?php echo (int)($profileCase['evidence_count'] ?? 0); ?></td>
                              <td class="text-nowrap"><?php echo htmlspecialchars((string)($profileCase['updated_at'] ?? $profileCase['opened_at'] ?? '')); ?></td>
                              <td class="text-end"><a class="btn btn-outline-light btn-sm" href="?view=case&amp;code=<?php echo urlencode((string)$profileCase['case_code']); ?>#case-view"><i class="bi bi-eye me-1"></i>View</a></td>
                            </tr>
                          <?php endforeach; ?>
                        </tbody>
                      </table>
                    </div>
                  <?php else: ?>
                    <div class="text-secondary">No submitted or currently owned cases were found.</div>
                  <?php endif; ?>
                </div>
              </div>

              <div class="card glass">
                <div class="card-header d-flex align-items-center justify-content-between"><h2 class="h6 mb-0">Successful Login History</h2><span class="badge text-bg-dark border"><?php echo $profileLoginTotal; ?> total</span></div>
                <div class="card-body">
                  <?php if ($profileLogins): ?>
                    <div class="table-responsive">
                      <table class="table table-sm align-middle mb-0">
                        <thead><tr><th>Date / Time</th><th>IP Address</th><th>Forwarded IP Chain</th><th>User Agent</th></tr></thead>
                        <tbody>
                          <?php foreach ($profileLogins as $profileLogin): ?>
                            <tr>
                              <td class="text-nowrap"><?php echo htmlspecialchars((string)$profileLogin['logged_in_at']); ?></td>
                              <td class="font-monospace"><?php echo htmlspecialchars((string)(($profileLogin['ip_address'] ?? '') !== '' ? $profileLogin['ip_address'] : 'Not recorded')); ?></td>
                              <td class="font-monospace small text-break" style="max-width:18rem;"><?php echo htmlspecialchars((string)(($profileLogin['forwarded_for'] ?? '') !== '' ? $profileLogin['forwarded_for'] : '—')); ?></td>
                              <td class="small text-break" style="min-width:20rem;"><?php echo htmlspecialchars((string)(($profileLogin['user_agent'] ?? '') !== '' ? $profileLogin['user_agent'] : 'Not recorded')); ?></td>
                            </tr>
                          <?php endforeach; ?>
                        </tbody>
                      </table>
                    </div>
                    <?php if ($profileLoginTotalPages > 1): ?>
                      <nav class="d-flex align-items-center justify-content-between mt-3" aria-label="Login history pages">
                        <a class="btn btn-outline-light btn-sm <?php echo $profileLoginPage <= 1 ? 'disabled' : ''; ?>" href="?view=user_profile&amp;id=<?php echo $profileUserId; ?>&amp;login_page=<?php echo max(1, $profileLoginPage - 1); ?>#user-profile">Previous</a>
                        <span class="small text-secondary">Page <?php echo $profileLoginPage; ?> of <?php echo $profileLoginTotalPages; ?></span>
                        <a class="btn btn-outline-light btn-sm <?php echo $profileLoginPage >= $profileLoginTotalPages ? 'disabled' : ''; ?>" href="?view=user_profile&amp;id=<?php echo $profileUserId; ?>&amp;login_page=<?php echo min($profileLoginTotalPages, $profileLoginPage + 1); ?>#user-profile">Next</a>
                      </nav>
                    <?php endif; ?>
                  <?php else: ?>
                    <div class="text-secondary">No login history recorded yet. Tracking begins after this feature is deployed.</div>
                  <?php endif; ?>
                </div>
              </div>
            </div>

            <div class="col-lg-4">
              <div class="card glass position-sticky" style="top:5.5rem;">
                <div class="card-header"><h2 class="h6 mb-0"><i class="bi bi-pencil-square me-2"></i>Edit User</h2></div>
                <form method="post" action="" autocomplete="off">
                  <?php csrf_field(); ?>
                  <input type="hidden" name="action" value="update_user">
                  <input type="hidden" name="user_id" value="<?php echo (int)$profileUser['id']; ?>">
                  <input type="hidden" name="return_to_profile" value="1">
                  <div class="card-body vstack gap-3">
                    <div><label class="form-label">Display Name</label><input type="text" name="display_name" class="form-control" maxlength="120" value="<?php echo htmlspecialchars((string)$profileUser['display_name']); ?>" required></div>
                    <div><label class="form-label">Username</label><input type="text" name="username" class="form-control" minlength="3" maxlength="120" pattern="[A-Za-z0-9._-]+" value="<?php echo htmlspecialchars((string)$profileUser['username']); ?>" required></div>
                    <div><label class="form-label">Email</label><input type="email" name="email" class="form-control" maxlength="254" value="<?php echo htmlspecialchars((string)$profileUser['email']); ?>" required></div>
                    <div><label class="form-label">Role</label><select name="role" class="form-select" <?php echo $profileIsCurrentUser ? 'disabled' : ''; ?>><option value="viewer" <?php echo $profileUser['role'] === 'viewer' ? 'selected' : ''; ?>>Viewer</option><option value="admin" <?php echo $profileUser['role'] === 'admin' ? 'selected' : ''; ?>>Admin</option></select><?php if ($profileIsCurrentUser): ?><input type="hidden" name="role" value="admin"><div class="form-text">You cannot remove your own admin role.</div><?php endif; ?></div>
                    <div class="form-check"><input type="checkbox" name="is_active" value="1" class="form-check-input" id="profileUserActive" <?php echo (int)$profileUser['is_active'] === 1 ? 'checked' : ''; ?> <?php echo $profileIsCurrentUser ? 'disabled' : ''; ?>><label class="form-check-label" for="profileUserActive">Account active</label><?php if ($profileIsCurrentUser): ?><input type="hidden" name="is_active" value="1"><?php endif; ?></div>
                    <hr class="my-0">
                    <div><label class="form-label">New Password</label><input type="password" name="new_password" class="form-control" minlength="8" autocomplete="new-password"><div class="form-text">Leave blank to keep the current password.</div></div>
                    <div><label class="form-label">Confirm New Password</label><input type="password" name="password_confirm" class="form-control" minlength="8" autocomplete="new-password"></div>
                  </div>
                  <div class="card-footer d-flex justify-content-between gap-2">
                    <?php if (!$profileIsCurrentUser): ?>
                      <button type="submit" class="btn btn-outline-danger" form="deleteProfileUserForm"><i class="bi bi-person-x me-1"></i>Delete</button>
                    <?php else: ?><span></span><?php endif; ?>
                    <button type="submit" class="btn btn-primary"><i class="bi bi-save me-1"></i>Save User</button>
                  </div>
                </form>
                <?php if (!$profileIsCurrentUser): ?>
                  <form method="post" action="" id="deleteProfileUserForm" class="d-none" onsubmit="return confirm('Delete this user permanently? Submitted cases will be preserved without this account attached.');">
                    <?php csrf_field(); ?><input type="hidden" name="action" value="delete_user"><input type="hidden" name="user_id" value="<?php echo (int)$profileUser['id']; ?>"><input type="hidden" name="redirect_url" value="?view=users#users">
                  </form>
                <?php endif; ?>
              </div>
            </div>
          </div>
        <?php endif; ?>
      <?php endif; ?>
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
        <?php
          $users = [];
          try {
            $q = $pdo->query("SELECT u.id, u.email, u.display_name, u.username, u.role, u.is_active, u.created_at, u.last_login_at, u.signup_ip,
                (SELECT COUNT(DISTINCT c.id) FROM cases c LEFT JOIN case_submission_metadata csm ON csm.case_id = c.id WHERE c.created_by = u.id OR csm.submitted_by = u.id) AS case_count,
                (SELECT COUNT(*) FROM user_login_history ulh WHERE ulh.user_id = u.id) AS login_count,
                (SELECT ulh.ip_address FROM user_login_history ulh WHERE ulh.user_id = u.id ORDER BY ulh.logged_in_at DESC, ulh.id DESC LIMIT 1) AS last_login_ip
              FROM users u ORDER BY u.created_at DESC");
            $users = $q->fetchAll();
          } catch (Throwable $e) {
            $_SESSION['sql_error'] = $e->getMessage();
            log_console('ERROR', 'SQL: ' . $e->getMessage());
            $users = [];
          }
        ?>
        <div class="card glass">
          <div class="card-header d-flex flex-column flex-lg-row align-items-lg-center justify-content-between gap-2">
            <div class="input-group input-group-sm" style="max-width:28rem;">
              <span class="input-group-text"><i class="bi bi-search"></i></span>
              <input type="search" class="form-control" id="userSummarySearch" placeholder="Search users, email, username, IP…" aria-label="Search users">
            </div>
            <?php if ($users): ?>
              <form method="post" action="" id="bulkUserDeleteForm" class="m-0">
                <?php csrf_field(); ?>
                <input type="hidden" name="action" value="bulk_delete_users">
                <button type="submit" class="btn btn-danger btn-sm" id="bulkUserDeleteButton" disabled>
                  <i class="bi bi-person-x me-1"></i>Delete selected
                  <span class="badge text-bg-light ms-1" id="bulkUserSelectedCount">0</span>
                </button>
              </form>
            <?php endif; ?>
          </div>
          <div class="card-body">
            <div class="table-responsive">
              <table class="table table-sm align-middle">
                <thead>
                  <tr>
                    <th style="width:2.5rem;"><input type="checkbox" class="form-check-input" id="selectAllUsers" aria-label="Select all visible users except your account"></th>
                    <th>User</th>
                    <th>Email</th>
                    <th>Role / Status</th>
                    <th>Cases</th>
                    <th>Signup IP</th>
                    <th>Last Login</th>
                    <th class="text-end">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  <?php if ($users && count($users) > 0): foreach ($users as $u): ?>
                    <?php $isCurrentSummaryUser = (int)$u['id'] === (int)($_SESSION['user']['id'] ?? 0); ?>
                    <tr class="user-summary-row" data-user-search="<?php echo htmlspecialchars(strtolower(implode(' ', [(string)($u['id'] ?? ''), (string)($u['display_name'] ?? ''), (string)($u['username'] ?? ''), (string)($u['email'] ?? ''), (string)($u['role'] ?? ''), (string)($u['signup_ip'] ?? ''), (string)($u['last_login_ip'] ?? '')]))); ?>">
                      <td><input type="checkbox" class="form-check-input user-summary-checkbox" name="user_ids[]" value="<?php echo (int)$u['id']; ?>" form="bulkUserDeleteForm" aria-label="Select user #<?php echo (int)$u['id']; ?>" <?php echo $isCurrentSummaryUser ? 'disabled title="You cannot delete your own account"' : ''; ?>></td>
                      <td><div class="fw-semibold"><?php echo htmlspecialchars((string)($u['display_name'] ?? '')); ?><?php echo $isCurrentSummaryUser ? ' <span class="badge text-bg-info">You</span>' : ''; ?></div><div class="small text-secondary">#<?php echo (int)$u['id']; ?> · <?php echo ($u['username'] ?? '') !== '' ? '@' . htmlspecialchars((string)$u['username']) : 'No username'; ?></div></td>
                      <td><?php echo htmlspecialchars($u['email'] ?? ''); ?></td>
                      <td><span class="badge text-bg-dark border"><?php echo htmlspecialchars(ucfirst((string)($u['role'] ?? 'viewer'))); ?></span> <?php echo ((int)($u['is_active'] ?? 0) ? '<span class="badge bg-success">Active</span>' : '<span class="badge bg-secondary">Disabled</span>'); ?></td>
                      <td><span class="badge text-bg-dark border"><?php echo (int)($u['case_count'] ?? 0); ?></span></td>
                      <td class="font-monospace small"><?php echo htmlspecialchars((string)(($u['signup_ip'] ?? '') !== '' ? $u['signup_ip'] : 'Not recorded')); ?></td>
                      <td><div class="text-nowrap"><?php echo htmlspecialchars((string)(($u['last_login_at'] ?? '') !== '' ? $u['last_login_at'] : 'Never')); ?></div><div class="font-monospace small text-secondary"><?php echo htmlspecialchars((string)(($u['last_login_ip'] ?? '') !== '' ? $u['last_login_ip'] : 'No IP recorded')); ?></div></td>
                      <td class="text-end text-nowrap">
                        <a class="btn btn-sm btn-outline-light" href="?view=user_profile&amp;id=<?php echo (int)$u['id']; ?>#user-profile"><i class="bi bi-eye me-1"></i>View</a>
                        <button type="button" class="btn btn-sm btn-outline-primary edit-user-button" data-bs-toggle="modal" data-bs-target="#editUserModal" data-user-id="<?php echo (int)$u['id']; ?>" data-display-name="<?php echo htmlspecialchars((string)($u['display_name'] ?? '')); ?>" data-username="<?php echo htmlspecialchars((string)($u['username'] ?? '')); ?>" data-email="<?php echo htmlspecialchars((string)($u['email'] ?? '')); ?>" data-role="<?php echo htmlspecialchars((string)($u['role'] ?? 'viewer')); ?>" data-active="<?php echo (int)($u['is_active'] ?? 0); ?>" data-is-self="<?php echo $isCurrentSummaryUser ? '1' : '0'; ?>"><i class="bi bi-pencil-square me-1"></i>Edit</button>
                        <?php if (!$isCurrentSummaryUser): ?>
                          <form method="post" action="" class="d-inline" onsubmit="return confirm('Delete this user permanently? This cannot be undone.');">
                            <input type="hidden" name="action" value="delete_user">
                            <?php csrf_field(); ?>
                            <input type="hidden" name="user_id" value="<?php echo (int)$u['id']; ?>">
                            <input type="hidden" name="redirect_url" value="?view=users#users">
                            <button type="submit" class="btn btn-sm btn-outline-danger"><i class="bi bi-person-x me-1"></i>Delete</button>
                          </form>
                        <?php endif; ?>
                      </td>
                    </tr>
                  <?php endforeach; else: ?>
                    <tr><td colspan="8" class="text-secondary">No users found.</td></tr>
                  <?php endif; ?>
                </tbody>
              </table>
            </div>
            <div class="small text-secondary d-none" id="userSummaryNoResults">No users match this search.</div>
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
                  <label class="form-label">Username</label>
                  <input type="text" name="username" class="form-control" minlength="3" maxlength="120" pattern="[A-Za-z0-9._-]+" placeholder="jane_doe" required>
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

      <?php if (is_admin()): ?>
      <div class="modal fade" id="editUserModal" tabindex="-1" aria-hidden="true">
        <div class="modal-dialog modal-md modal-dialog-centered">
          <div class="modal-content">
            <div class="modal-header">
              <h5 class="modal-title"><i class="bi bi-pencil-square me-2"></i>Edit User</h5>
              <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
            </div>
            <form method="post" action="" id="editUserForm" autocomplete="off">
              <?php csrf_field(); ?>
              <input type="hidden" name="action" value="update_user">
              <input type="hidden" name="user_id" id="editUserId" value="">
              <div class="modal-body vstack gap-3">
                <div><label class="form-label" for="editUserDisplayName">Display Name</label><input type="text" name="display_name" id="editUserDisplayName" class="form-control" maxlength="120" required></div>
                <div><label class="form-label" for="editUserUsername">Username</label><input type="text" name="username" id="editUserUsername" class="form-control" minlength="3" maxlength="120" pattern="[A-Za-z0-9._-]+" required></div>
                <div><label class="form-label" for="editUserEmail">Email</label><input type="email" name="email" id="editUserEmail" class="form-control" maxlength="254" required></div>
                <div class="row g-2">
                  <div class="col-md-6"><label class="form-label" for="editUserRole">Role</label><select name="role" id="editUserRole" class="form-select"><option value="viewer">Viewer</option><option value="admin">Admin</option></select></div>
                  <div class="col-md-6 d-flex align-items-end"><div class="form-check mb-2"><input type="checkbox" name="is_active" value="1" class="form-check-input" id="editUserActive"><label class="form-check-label" for="editUserActive">Account active</label></div></div>
                </div>
                <div class="alert alert-info py-2 mb-0 d-none" id="editUserSelfNotice">Your own admin role and active status cannot be removed.</div>
                <hr class="my-0">
                <div><label class="form-label" for="editUserPassword">New Password</label><input type="password" name="new_password" id="editUserPassword" class="form-control" minlength="8" autocomplete="new-password"><div class="form-text">Leave blank to keep the current password.</div></div>
                <div><label class="form-label" for="editUserPasswordConfirm">Confirm New Password</label><input type="password" name="password_confirm" id="editUserPasswordConfirm" class="form-control" minlength="8" autocomplete="new-password"></div>
              </div>
              <div class="modal-footer">
                <button type="button" class="btn btn-outline-light" data-bs-dismiss="modal">Cancel</button>
                <button type="submit" class="btn btn-primary"><i class="bi bi-save me-1"></i>Save User</button>
              </div>
            </form>
          </div>
        </div>
      </div>
      <?php endif; ?>

      <script>
      (function () {
        var rows = Array.prototype.slice.call(document.querySelectorAll('.user-summary-row'));
        var search = document.getElementById('userSummarySearch');
        var noResults = document.getElementById('userSummaryNoResults');
        var selectAll = document.getElementById('selectAllUsers');
        var checkboxes = Array.prototype.slice.call(document.querySelectorAll('.user-summary-checkbox:not(:disabled)'));
        var bulkForm = document.getElementById('bulkUserDeleteForm');
        var bulkButton = document.getElementById('bulkUserDeleteButton');
        var countBadge = document.getElementById('bulkUserSelectedCount');

        function visibleCheckboxes() {
          return checkboxes.filter(function (checkbox) { return !checkbox.closest('tr').hidden; });
        }
        function updateBulkControls() {
          if (!selectAll || !bulkButton || !countBadge) return;
          var visible = visibleCheckboxes();
          var visibleSelected = visible.filter(function (checkbox) { return checkbox.checked; }).length;
          var totalSelected = checkboxes.filter(function (checkbox) { return checkbox.checked; }).length;
          countBadge.textContent = String(totalSelected);
          bulkButton.disabled = totalSelected === 0;
          selectAll.disabled = visible.length === 0;
          selectAll.checked = visible.length > 0 && visibleSelected === visible.length;
          selectAll.indeterminate = visibleSelected > 0 && visibleSelected < visible.length;
        }
        if (search) {
          search.addEventListener('input', function () {
            var term = search.value.trim().toLocaleLowerCase();
            var visibleCount = 0;
            rows.forEach(function (row) {
              var matches = term === '' || (row.getAttribute('data-user-search') || '').indexOf(term) !== -1;
              row.hidden = !matches;
              if (matches) visibleCount++;
            });
            if (noResults) noResults.classList.toggle('d-none', visibleCount !== 0);
            updateBulkControls();
          });
        }
        if (selectAll) {
          selectAll.addEventListener('change', function () {
            visibleCheckboxes().forEach(function (checkbox) { checkbox.checked = selectAll.checked; });
            updateBulkControls();
          });
        }
        checkboxes.forEach(function (checkbox) { checkbox.addEventListener('change', updateBulkControls); });
        if (bulkForm) {
          bulkForm.addEventListener('submit', function (event) {
            var selectedCount = checkboxes.filter(function (checkbox) { return checkbox.checked; }).length;
            if (selectedCount === 0 || !confirm('Delete ' + selectedCount + ' selected user account' + (selectedCount === 1 ? '' : 's') + '? Submitted cases will be preserved without those accounts attached.')) {
              event.preventDefault();
            }
          });
        }
        updateBulkControls();

        var editModal = document.getElementById('editUserModal');
        if (editModal) {
          editModal.addEventListener('show.bs.modal', function (event) {
            var button = event.relatedTarget;
            if (!button) return;
            var isSelf = button.getAttribute('data-is-self') === '1';
            document.getElementById('editUserId').value = button.getAttribute('data-user-id') || '';
            document.getElementById('editUserDisplayName').value = button.getAttribute('data-display-name') || '';
            document.getElementById('editUserUsername').value = button.getAttribute('data-username') || '';
            document.getElementById('editUserEmail').value = button.getAttribute('data-email') || '';
            var role = document.getElementById('editUserRole');
            var active = document.getElementById('editUserActive');
            role.value = button.getAttribute('data-role') || 'viewer';
            role.disabled = isSelf;
            active.checked = button.getAttribute('data-active') === '1';
            active.disabled = isSelf;
            document.getElementById('editUserSelfNotice').classList.toggle('d-none', !isSelf);
            document.getElementById('editUserPassword').value = '';
            document.getElementById('editUserPasswordConfirm').value = '';
          });
        }
      })();
      </script>
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
            'high_risk_views' => 0,
          ];
          $mostViewedCases = [];
          $recentViews = [];
          $recentAlerts = [];
          $unresolvedAlertCount = 0;
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
                SUM(CASE WHEN is_authenticated = 0 THEN 1 ELSE 0 END) AS guest_views,
                SUM(CASE WHEN analytics_score >= 70 THEN 1 ELSE 0 END) AS high_risk_views
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
                cv.net_isp,
                cv.net_org,
                cv.is_proxy,
                cv.is_hosting,
                cv.is_bot,
                cv.bot_reason,
                cv.analytics_score,
                cv.alert_flags,
                cv.referrer_host,
                cv.is_same_site_referrer,
                cv.request_path,
                cv.query_string,
                cv.language_primary,
                cv.screen_width,
                cv.screen_height,
                cv.viewport_width,
                cv.viewport_height,
                cv.client_timezone,
                cv.client_platform,
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
            $q = $pdo->query("SELECT COUNT(*) FROM case_analytics_alerts WHERE is_resolved = 0");
            $unresolvedAlertCount = (int)$q->fetchColumn();
          } catch (Throwable $e) {}

          try {
            $q = $pdo->query("SELECT
                caa.id,
                caa.case_id,
                caa.alert_type,
                caa.severity,
                caa.title,
                caa.detail,
                caa.metric_value,
                caa.threshold_value,
                caa.occurrence_count,
                caa.first_seen_at,
                caa.last_seen_at,
                COALESCE(c.case_code, CONCAT('Case #', caa.case_id)) AS case_code,
                COALESCE(c.case_name, 'Unknown Case') AS case_name
              FROM case_analytics_alerts caa
              LEFT JOIN cases c ON c.id = caa.case_id
              WHERE caa.is_resolved = 0
              ORDER BY FIELD(caa.severity, 'high', 'medium', 'low'), caa.last_seen_at DESC
              LIMIT 25");
            $recentAlerts = $q->fetchAll() ?: [];
          } catch (Throwable $e) {}

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
          $highRiskViews = (int)($stats['high_risk_views'] ?? 0);
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
          <div class="col-6 col-lg-3">
            <div class="card glass h-100"><div class="card-body">
              <div class="small text-secondary">High-Risk Views</div>
              <div class="h4 mb-0"><?php echo number_format($highRiskViews); ?></div>
              <div class="small text-secondary">Score 70+</div>
            </div></div>
          </div>
          <div class="col-6 col-lg-3">
            <div class="card glass h-100"><div class="card-body">
              <div class="small text-secondary">Open Analytics Alerts</div>
              <div class="h4 mb-0"><?php echo number_format($unresolvedAlertCount); ?></div>
              <div class="small text-secondary">Unresolved</div>
            </div></div>
          </div>
        </div>

        <div class="card glass mb-4">
          <div class="card-body">
            <h3 class="h6 mb-3">Case Analytics Alerts</h3>
            <div class="table-responsive">
              <table class="table table-sm align-middle mb-0">
                <thead>
                  <tr>
                    <th>Severity</th>
                    <th>Case</th>
                    <th>Alert</th>
                    <th class="text-end">Metric</th>
                    <th class="text-end">Count</th>
                    <th>Last Seen</th>
                  </tr>
                </thead>
                <tbody>
                  <?php if (!empty($recentAlerts)): foreach ($recentAlerts as $alert): ?>
                    <?php
                      $sev = (string)($alert['severity'] ?? 'low');
                      $sevClass = $sev === 'high' ? 'danger' : ($sev === 'medium' ? 'warning' : 'secondary');
                    ?>
                    <tr>
                      <td><span class="badge text-bg-<?php echo $sevClass; ?>"><?php echo htmlspecialchars(ucfirst($sev)); ?></span></td>
                      <td>
                        <a class="text-decoration-none" href="?view=case&amp;code=<?php echo urlencode($alert['case_code'] ?? ''); ?>#case-view"><?php echo htmlspecialchars($alert['case_code'] ?? ''); ?></a>
                        <div class="small text-secondary"><?php echo htmlspecialchars($alert['case_name'] ?? ''); ?></div>
                      </td>
                      <td>
                        <div class="fw-semibold"><?php echo htmlspecialchars($alert['title'] ?? ''); ?></div>
                        <div class="small text-secondary text-break"><?php echo htmlspecialchars($alert['detail'] ?? ''); ?></div>
                      </td>
                      <td class="text-end small"><?php echo htmlspecialchars((string)($alert['metric_value'] ?? '')); ?> / <?php echo htmlspecialchars((string)($alert['threshold_value'] ?? '')); ?></td>
                      <td class="text-end"><?php echo number_format((int)($alert['occurrence_count'] ?? 0)); ?></td>
                      <td class="small text-secondary"><?php echo htmlspecialchars($alert['last_seen_at'] ?? ''); ?></td>
                    </tr>
                  <?php endforeach; else: ?>
                    <tr><td colspan="6" class="text-secondary">No open analytics alerts yet.</td></tr>
                  <?php endif; ?>
                </tbody>
              </table>
            </div>
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
                    <th>Risk</th>
                    <th>Network</th>
                    <th>Client</th>
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
                      <td class="small">
                        <?php
                          $score = (int)($rv['analytics_score'] ?? 0);
                          $scoreClass = $score >= 70 ? 'danger' : ($score >= 40 ? 'warning' : 'secondary');
                        ?>
                        <span class="badge text-bg-<?php echo $scoreClass; ?>"><?php echo $score; ?></span>
                        <?php if (!empty($rv['alert_flags'])): ?><div class="text-secondary"><?php echo htmlspecialchars($rv['alert_flags']); ?></div><?php endif; ?>
                        <?php if (!empty($rv['bot_reason'])): ?><div class="text-secondary"><?php echo htmlspecialchars($rv['bot_reason']); ?></div><?php endif; ?>
                      </td>
                      <td class="small">
                        <?php echo htmlspecialchars(trim(($rv['net_isp'] ?? '').' '.($rv['net_org'] ?? '')) ?: 'Unknown'); ?>
                        <div class="text-secondary">
                          <?php if ((int)($rv['is_proxy'] ?? 0) === 1): ?><span class="badge text-bg-warning">Proxy</span><?php endif; ?>
                          <?php if ((int)($rv['is_hosting'] ?? 0) === 1): ?><span class="badge text-bg-warning">Hosting</span><?php endif; ?>
                          <?php if ((int)($rv['is_bot'] ?? 0) === 1): ?><span class="badge text-bg-secondary">Bot</span><?php endif; ?>
                        </div>
                      </td>
                      <td class="small">
                        <?php echo htmlspecialchars(trim(($rv['screen_width'] ?? '').'x'.($rv['screen_height'] ?? ''), 'x') ?: 'Unknown'); ?>
                        <div class="text-secondary"><?php echo htmlspecialchars(trim(($rv['viewport_width'] ?? '').'x'.($rv['viewport_height'] ?? ''), 'x')); ?></div>
                        <div class="text-secondary"><?php echo htmlspecialchars($rv['client_timezone'] ?? ''); ?></div>
                      </td>
                      <td class="small text-break" style="max-width: 260px;"><?php echo htmlspecialchars($rv['referer'] ?? ''); ?></td>
                    </tr>
                  <?php endforeach; else: ?>
                    <tr><td colspan="14" class="text-secondary">No viewer activity has been recorded yet.</td></tr>
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
      $viewCase = null; $viewCaseId = 0; $viewEv = []; $viewTotalViews = 0; $viewCaseTags = [];
      $viewOwner = []; $viewOriginalSubmitter = []; $viewSubmissionMeta = []; $viewSubmissionGeo = [];
      $viewOwnerCandidates = []; $viewOwnershipHistory = [];
      $viewAnalyticsSummary = [];
      $viewAnalyticsAlerts = [];
      $viewAnalyticsCountries = [];
      $viewAnalyticsRecentRisk = [];
      if ($caseCode !== '') {
        try {
          $st = $pdo->prepare('SELECT id, case_code, case_name, person_name, location, phone_number, snapchat_username, tiktok_username, initial_summary, status, sensitivity, rejection_reason, rejected_at, opened_at, created_by FROM cases WHERE case_code = ? LIMIT 1');
          $st->execute([$caseCode]);
          $viewCase = $st->fetch();
          $viewReviewOwner = $viewCase && is_logged_in() && (int)($viewCase['created_by'] ?? 0) === (int)($_SESSION['user']['id'] ?? 0);
          $viewIsPrivateReview = $viewCase && in_array(($viewCase['status'] ?? ''), ['Being Built','Pending','Rejected'], true);
          if ($viewCase && $viewIsPrivateReview && !is_admin() && !$viewReviewOwner) {
            $viewCase = null;
          }
          $viewCaseId = (int)($viewCase['id'] ?? 0);
          if ($viewCaseId > 0) { $viewCase['tiktok_username'] = get_case_tiktok_usernames($pdo, $viewCaseId) ?: ($viewCase['tiktok_username'] ?? ''); $viewCaseTags = get_case_tags($pdo, $viewCaseId); }

        } catch (Throwable $e) { $_SESSION['sql_error'] = $e->getMessage();
log_console('ERROR', 'SQL: ' . $e->getMessage()); }
        if ($viewCaseId > 0) {
          log_case_view($pdo, $viewCaseId);
          $viewTotalViews = get_case_view_count($pdo, $viewCaseId);
          if (is_admin()) {
            try {
              $ownerQuery = $pdo->prepare('SELECT id, email, display_name, username, role, is_active, created_at, last_login_at FROM users WHERE id = ? LIMIT 1');
              $ownerQuery->execute([(int)($viewCase['created_by'] ?? 0)]);
              $viewOwner = $ownerQuery->fetch() ?: [];

              $submissionQuery = $pdo->prepare('SELECT case_id, submitted_by, submitted_at, public_ip, forwarded_for, geo_json, user_agent FROM case_submission_metadata WHERE case_id = ? LIMIT 1');
              $submissionQuery->execute([$viewCaseId]);
              $viewSubmissionMeta = $submissionQuery->fetch() ?: [];
              $decodedGeo = json_decode((string)($viewSubmissionMeta['geo_json'] ?? ''), true);
              $viewSubmissionGeo = is_array($decodedGeo) ? $decodedGeo : [];

              $originalSubmitterId = (int)($viewSubmissionMeta['submitted_by'] ?? 0);
              if ($originalSubmitterId <= 0) { $originalSubmitterId = (int)($viewCase['created_by'] ?? 0); }
              if ($originalSubmitterId > 0) {
                $ownerQuery->execute([$originalSubmitterId]);
                $viewOriginalSubmitter = $ownerQuery->fetch() ?: [];
              }

              $candidateQuery = $pdo->query('SELECT id, email, display_name, username, role FROM users WHERE is_active = 1 ORDER BY display_name ASC, username ASC, email ASC');
              $viewOwnerCandidates = $candidateQuery->fetchAll() ?: [];

              $historyQuery = $pdo->prepare('SELECT h.changed_at, previous_user.display_name AS previous_name, previous_user.username AS previous_username, new_user.display_name AS new_name, new_user.username AS new_username, admin_user.display_name AS changed_by_name FROM case_ownership_history h LEFT JOIN users previous_user ON previous_user.id = h.previous_owner_id LEFT JOIN users new_user ON new_user.id = h.new_owner_id LEFT JOIN users admin_user ON admin_user.id = h.changed_by WHERE h.case_id = ? ORDER BY h.changed_at DESC, h.id DESC LIMIT 5');
              $historyQuery->execute([$viewCaseId]);
              $viewOwnershipHistory = $historyQuery->fetchAll() ?: [];
            } catch (Throwable $e) {
              $_SESSION['sql_error'] = $_SESSION['sql_error'] ?? $e->getMessage();
            }
            try {
              $aq = $pdo->prepare("SELECT
                  COUNT(*) AS total_views,
                  SUM(CASE WHEN viewed_at >= (NOW() - INTERVAL 24 HOUR) THEN 1 ELSE 0 END) AS views_24h,
                  COUNT(DISTINCT ip_hash) AS unique_ips,
                  SUM(CASE WHEN analytics_score >= 70 THEN 1 ELSE 0 END) AS high_risk_views,
                  SUM(CASE WHEN is_proxy = 1 THEN 1 ELSE 0 END) AS proxy_views,
                  SUM(CASE WHEN is_hosting = 1 THEN 1 ELSE 0 END) AS hosting_views,
                  SUM(CASE WHEN is_bot = 1 THEN 1 ELSE 0 END) AS bot_views,
                  MAX(analytics_score) AS max_score,
                  MAX(viewed_at) AS last_viewed_at
                FROM case_views WHERE case_id = ?");
              $aq->execute([$viewCaseId]);
              $viewAnalyticsSummary = $aq->fetch() ?: [];
            } catch (Throwable $e) {}
            try {
              $aq = $pdo->prepare("SELECT alert_type, severity, title, detail, metric_value, threshold_value, occurrence_count, first_seen_at, last_seen_at
                FROM case_analytics_alerts
                WHERE case_id = ? AND is_resolved = 0
                ORDER BY FIELD(severity, 'high', 'medium', 'low'), last_seen_at DESC
                LIMIT 10");
              $aq->execute([$viewCaseId]);
              $viewAnalyticsAlerts = $aq->fetchAll() ?: [];
            } catch (Throwable $e) {}
            try {
              $aq = $pdo->prepare("SELECT COALESCE(NULLIF(TRIM(geo_country), ''), 'Unknown') AS label, COUNT(*) AS cnt
                FROM case_views
                WHERE case_id = ?
                GROUP BY label
                ORDER BY cnt DESC
                LIMIT 8");
              $aq->execute([$viewCaseId]);
              $viewAnalyticsCountries = $aq->fetchAll() ?: [];
            } catch (Throwable $e) {}
            try {
              $aq = $pdo->prepare("SELECT viewed_at, public_ip, geo_country, geo_region, geo_city, net_isp, is_proxy, is_hosting, is_bot, bot_reason, analytics_score, alert_flags, referrer_host, device_type, browser_name, os_name
                FROM case_views
                WHERE case_id = ? AND analytics_score >= 40
                ORDER BY viewed_at DESC
                LIMIT 10");
              $aq->execute([$viewCaseId]);
              $viewAnalyticsRecentRisk = $aq->fetchAll() ?: [];
            } catch (Throwable $e) {}
          }
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
      $tp_isCaseOwner = false;
      $tp_canEditCaseEvidence = false;
      $tp_canRunAiBuilder = false;
      $tp_canViewAiBuilder = false;
      $tp_aiRuns = [];
      $tp_openAiConfigured = trim(tp_project_setting($pdo, 'openai_api_key', '')) !== '';
      if (!empty($_SESSION['user'])) {
          $tp_isCaseOwner = !empty($viewCase)
            && (int)($viewCase['created_by'] ?? 0) > 0
            && (int)($viewCase['created_by'] ?? 0) === (int)($_SESSION['user']['id'] ?? 0);
          if (($_SESSION['user']['role'] ?? '') === 'admin') {
              $tp_canAddEvidence = true;
              $tp_canEditCaseEvidence = !empty($viewCase);
              $tp_canRunAiBuilder = !empty($viewCase);
              $tp_canViewAiBuilder = !empty($viewCase);
          } elseif (!empty($viewCase) && in_array(($viewCase['status'] ?? ''), ['Being Built','Pending','Rejected'], true)) {
              $ownerId = (int)($viewCase['created_by'] ?? 0);
              $tp_canAddEvidence = ($ownerId > 0) && ($ownerId === (int)($_SESSION['user']['id'] ?? 0));
              $tp_canViewAiBuilder = $tp_isCaseOwner;
              $tp_canRunAiBuilder = $tp_isCaseOwner && (($viewCase['status'] ?? '') === 'Being Built');
          }
          if ($tp_isCaseOwner) { $tp_canEditCaseEvidence = true; }
      }
      if ($tp_canViewAiBuilder && $viewCaseId > 0) {
        try {
          $runQuery = $pdo->prepare('SELECT r.*, u.display_name AS requested_by_name FROM case_ai_runs r LEFT JOIN users u ON u.id = r.requested_by WHERE r.case_id = ? ORDER BY r.created_at DESC, r.id DESC LIMIT 5');
          $runQuery->execute([$viewCaseId]);
          $tp_aiRuns = $runQuery->fetchAll() ?: [];
          $suggestionQuery = $pdo->prepare('SELECT s.*, u.display_name AS decided_by_name FROM case_ai_suggestions s LEFT JOIN users u ON u.id = s.decided_by WHERE s.run_id = ? ORDER BY s.id ASC');
          foreach ($tp_aiRuns as &$tpAiRun) {
            $suggestionQuery->execute([(int)$tpAiRun['id']]);
            $tpAiRun['suggestions'] = $suggestionQuery->fetchAll() ?: [];
          }
          unset($tpAiRun);
        } catch (Throwable $e) {
          $_SESSION['sql_error'] = $_SESSION['sql_error'] ?? $e->getMessage();
          $tp_aiRuns = [];
        }
      }
    ?>
    <?php
      $tpCaseOutlineStatus = (string)($viewCase['status'] ?? '');
      $tpCaseOutlineClass = [
        'Being Built' => 'case-outline-building',
        'Pending' => 'case-outline-pending',
        'In Review' => 'case-outline-pending',
        'Open' => 'case-outline-published',
        'Verified' => 'case-outline-published',
        'Closed' => 'case-outline-published',
        'Rejected' => 'case-outline-rejected',
      ][$tpCaseOutlineStatus] ?? '';
    ?>
    <section class="py-5 border-top <?php echo htmlspecialchars($tpCaseOutlineClass); ?>" id="case-view">
      <div class="container-xl">
        <?php
          $tp_headerName = trim((string)($viewCase['person_name'] ?? ''));
          if ($tp_headerName === '') { $tp_headerName = trim((string)($viewCase['case_name'] ?? '')); }
          if ($tp_headerName === '') { $tp_headerName = 'Unknown'; }
          $tp_headerLocation = tp_case_location_for_viewer($viewCase['location'] ?? '');
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
            <?php if (in_array(($viewCase['status'] ?? ''), ['Being Built', 'Rejected'], true)): ?>
            <form method="post" action="" class="d-inline" onsubmit="return confirm('Submit this case for admin review now?');">
              <input type="hidden" name="action" value="submit_case_for_review">
              <?php csrf_field(); ?>
              <input type="hidden" name="case_id" value="<?php echo (int)$viewCaseId; ?>">
              <input type="hidden" name="case_code" value="<?php echo htmlspecialchars($caseCode); ?>">
              <button type="submit" class="btn btn-success btn-sm"><i class="bi bi-send me-1"></i><?php echo ($viewCase['status'] ?? '') === 'Rejected' ? 'Return to Pending Review' : 'Submit for Review'; ?></button>
            </form>
            <?php endif; ?>
            <?php if (($viewCase['status'] ?? '') === 'Pending'): ?>
            <button type="button" class="btn btn-danger btn-sm btn-reject-case" data-bs-toggle="modal" data-bs-target="#rejectCaseModal" data-case-id="<?php echo (int)$viewCaseId; ?>" data-case-code="<?php echo htmlspecialchars($caseCode); ?>" data-case-name="<?php echo htmlspecialchars($viewCase['case_name'] ?? $caseCode); ?>"><i class="bi bi-x-circle me-1"></i>Reject Case</button>
            <?php endif; ?>
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
        <?php if (is_admin() && $viewCaseId > 0):
          $ownerName = trim((string)($viewOwner['display_name'] ?? ''));
          $ownerEmail = trim((string)($viewOwner['email'] ?? ''));
          $ownerUsername = trim((string)($viewOwner['username'] ?? ''));
          $submitterName = trim((string)($viewOriginalSubmitter['display_name'] ?? ''));
          $submitterEmail = trim((string)($viewOriginalSubmitter['email'] ?? ''));
          $submitterUsername = trim((string)($viewOriginalSubmitter['username'] ?? ''));
          $submissionRecorded = !empty($viewSubmissionMeta);
          $submittedAt = trim((string)($viewSubmissionMeta['submitted_at'] ?? ($viewCase['opened_at'] ?? '')));
          $submitterDiffers = (int)($viewOriginalSubmitter['id'] ?? 0) > 0
            && (int)($viewOriginalSubmitter['id'] ?? 0) !== (int)($viewOwner['id'] ?? 0);
          $geoLocationParts = array_values(array_filter([
            trim((string)($viewSubmissionGeo['geo_city'] ?? '')),
            trim((string)($viewSubmissionGeo['geo_district'] ?? '')),
            trim((string)($viewSubmissionGeo['geo_region'] ?? '')),
            trim((string)($viewSubmissionGeo['geo_postcode'] ?? '')),
            trim((string)($viewSubmissionGeo['geo_country_name'] ?? ($viewSubmissionGeo['geo_country'] ?? ''))),
          ], static function ($value) { return $value !== ''; }));
          $coordinates = '';
          if (($viewSubmissionGeo['geo_lat'] ?? '') !== '' && ($viewSubmissionGeo['geo_lon'] ?? '') !== '') {
            $coordinates = (string)$viewSubmissionGeo['geo_lat'] . ', ' . (string)$viewSubmissionGeo['geo_lon'];
          }
        ?>
        <div class="card glass mb-3" id="case-owner-details">
          <div class="card-body">
            <div class="d-flex flex-column flex-lg-row justify-content-between gap-3 mb-3">
              <div>
                <h3 class="h6 mb-1"><i class="bi bi-person-badge me-1"></i> Case Ownership &amp; Submission Details</h3>
                <div class="small text-secondary">Visible to site admins only.</div>
              </div>
              <form method="post" action="" class="case-owner-transfer-form" onsubmit="return confirm('Transfer this case to the selected user? The selected user will become the case owner.');">
                <input type="hidden" name="action" value="transfer_case_ownership">
                <?php csrf_field(); ?>
                <input type="hidden" name="case_id" value="<?php echo (int)$viewCaseId; ?>">
                <input type="hidden" name="case_code" value="<?php echo htmlspecialchars($caseCode); ?>">
                <div class="case-owner-transfer-controls d-flex flex-column flex-sm-row align-items-sm-end gap-2">
                  <div class="case-owner-select-wrap">
                    <label class="form-label small mb-1" for="caseOwnerSelect">Change case owner</label>
                    <select class="form-select js-case-owner-select" id="caseOwnerSelect" name="new_owner_id" required>
                      <?php foreach ($viewOwnerCandidates as $candidate):
                        $candidateName = trim((string)($candidate['display_name'] ?? ''));
                        $candidateUsername = trim((string)($candidate['username'] ?? ''));
                        $candidateEmail = trim((string)($candidate['email'] ?? ''));
                      ?>
                        <option value="<?php echo (int)$candidate['id']; ?>" <?php echo (int)$candidate['id'] === (int)($viewCase['created_by'] ?? 0) ? 'selected' : ''; ?>><?php echo htmlspecialchars(($candidateName !== '' ? $candidateName : 'Unnamed user') . ($candidateUsername !== '' ? ' · @' . $candidateUsername : '') . ($candidateEmail !== '' ? ' · ' . $candidateEmail : '') . ' · ID ' . (int)$candidate['id']); ?></option>
                      <?php endforeach; ?>
                    </select>
                  </div>
                  <button class="btn btn-outline-warning" type="submit" aria-label="Change owner" title="Change owner"><i class="bi bi-arrow-left-right" aria-hidden="true"></i></button>
                </div>
              </form>
            </div>

            <div class="row g-3">
              <div class="col-xl-6 order-2">
                <div class="border rounded p-3 h-100">
                  <h4 class="h6 mb-3">Current Owner</h4>
                  <?php if ($viewOwner): ?>
                    <div class="row g-2 small">
                      <div class="col-sm-6"><span class="text-secondary d-block">Name</span><?php echo htmlspecialchars($ownerName !== '' ? $ownerName : 'Not recorded'); ?></div>
                      <div class="col-sm-6"><span class="text-secondary d-block">Username</span><?php echo $ownerUsername !== '' ? '@' . htmlspecialchars($ownerUsername) : 'Not recorded'; ?></div>
                      <div class="col-sm-6"><span class="text-secondary d-block">Email</span><?php if ($ownerEmail !== ''): ?><a href="mailto:<?php echo htmlspecialchars($ownerEmail); ?>"><?php echo htmlspecialchars($ownerEmail); ?></a><?php else: ?>Not recorded<?php endif; ?></div>
                      <div class="col-sm-3"><span class="text-secondary d-block">User ID</span><?php echo (int)$viewOwner['id']; ?></div>
                      <div class="col-sm-3"><span class="text-secondary d-block">Role</span><?php echo htmlspecialchars($viewOwner['role'] ?? ''); ?></div>
                      <div class="col-sm-4"><span class="text-secondary d-block">Account Status</span><?php echo (int)($viewOwner['is_active'] ?? 0) === 1 ? 'Active' : 'Disabled'; ?></div>
                      <div class="col-sm-4"><span class="text-secondary d-block">Account Created</span><?php echo htmlspecialchars($viewOwner['created_at'] ?? 'Not recorded'); ?></div>
                      <div class="col-sm-4"><span class="text-secondary d-block">Last Login</span><?php echo htmlspecialchars($viewOwner['last_login_at'] ?? 'Not recorded'); ?></div>
                    </div>
                  <?php else: ?>
                    <div class="text-secondary small">This case currently has no matching owner account.</div>
                  <?php endif; ?>
                </div>
              </div>

              <div class="col-xl-6 order-1">
                <div class="border rounded p-3 h-100">
                  <h4 class="h6 mb-3">Original Submission</h4>
                  <div class="row g-2 small">
                    <div class="col-sm-6"><span class="text-secondary d-block">Submitted By</span><?php echo htmlspecialchars($submitterName !== '' ? $submitterName : ($submitterEmail !== '' ? $submitterEmail : 'Not recorded')); ?></div>
                    <div class="col-sm-6"><span class="text-secondary d-block">Submitter Username</span><?php echo $submitterUsername !== '' ? '@' . htmlspecialchars($submitterUsername) : 'Not recorded'; ?></div>
                    <div class="col-sm-6"><span class="text-secondary d-block">Submitter Email</span><?php echo htmlspecialchars($submitterEmail !== '' ? $submitterEmail : 'Not recorded'); ?></div>
                    <div class="col-sm-6"><span class="text-secondary d-block"><?php echo $submissionRecorded ? 'Submitted At' : 'Case Opened'; ?></span><?php echo htmlspecialchars($submittedAt !== '' ? $submittedAt : 'Not recorded'); ?></div>
                    <div class="col-sm-6"><span class="text-secondary d-block">Submitting IP Address</span><?php echo htmlspecialchars(($viewSubmissionMeta['public_ip'] ?? '') !== '' ? $viewSubmissionMeta['public_ip'] : 'Not recorded'); ?></div>
                    <div class="col-sm-6"><span class="text-secondary d-block">Forwarded IP Chain</span><?php echo htmlspecialchars(($viewSubmissionMeta['forwarded_for'] ?? '') !== '' ? $viewSubmissionMeta['forwarded_for'] : 'Not recorded'); ?></div>
                  </div>
                  <?php if (!$submissionRecorded): ?>
                    <div class="alert alert-secondary small mt-3 mb-0">Submission IP and geo data were not recorded for this historical case. Later case-view analytics are not being presented as submission data.</div>
                  <?php endif; ?>
                </div>
              </div>

              <?php if ($submissionRecorded): ?>
              <div class="col-12 order-3">
                <div class="border rounded p-3">
                  <h4 class="h6 mb-3">Submission Geo &amp; Network Data</h4>
                  <div class="row g-2 small">
                    <div class="col-md-4 col-xl-3"><span class="text-secondary d-block">Location</span><?php echo htmlspecialchars($geoLocationParts ? implode(', ', $geoLocationParts) : 'Not recorded'); ?></div>
                    <div class="col-md-4 col-xl-3"><span class="text-secondary d-block">Continent</span><?php echo htmlspecialchars(trim((string)($viewSubmissionGeo['geo_continent_name'] ?? '')) ?: 'Not recorded'); ?></div>
                    <div class="col-md-4 col-xl-3"><span class="text-secondary d-block">Coordinates</span><?php echo htmlspecialchars($coordinates !== '' ? $coordinates : 'Not recorded'); ?></div>
                    <div class="col-md-4 col-xl-3"><span class="text-secondary d-block">Timezone</span><?php echo htmlspecialchars(trim((string)($viewSubmissionGeo['geo_timezone'] ?? '')) ?: 'Not recorded'); ?></div>
                    <div class="col-md-4 col-xl-3"><span class="text-secondary d-block">Currency</span><?php echo htmlspecialchars(trim((string)($viewSubmissionGeo['geo_currency'] ?? '')) ?: 'Not recorded'); ?></div>
                    <div class="col-md-4 col-xl-3"><span class="text-secondary d-block">ISP</span><?php echo htmlspecialchars(trim((string)($viewSubmissionGeo['net_isp'] ?? '')) ?: 'Not recorded'); ?></div>
                    <div class="col-md-4 col-xl-3"><span class="text-secondary d-block">Network Organisation</span><?php echo htmlspecialchars(trim((string)($viewSubmissionGeo['net_org'] ?? '')) ?: 'Not recorded'); ?></div>
                    <div class="col-md-4 col-xl-3"><span class="text-secondary d-block">Autonomous System</span><?php echo htmlspecialchars(trim((string)(($viewSubmissionGeo['net_as'] ?? '') . ' ' . ($viewSubmissionGeo['net_as_name'] ?? ''))) ?: 'Not recorded'); ?></div>
                    <div class="col-md-4 col-xl-3"><span class="text-secondary d-block">Reverse DNS</span><?php echo htmlspecialchars(trim((string)($viewSubmissionGeo['net_reverse_dns'] ?? '')) ?: 'Not recorded'); ?></div>
                    <div class="col-md-4 col-xl-3"><span class="text-secondary d-block">Geo Source</span><?php echo htmlspecialchars(trim((string)($viewSubmissionGeo['geo_source'] ?? '')) ?: 'Not recorded'); ?></div>
                    <div class="col-md-4 col-xl-3"><span class="text-secondary d-block">Connection Flags</span><?php echo !empty($viewSubmissionGeo['is_mobile']) ? 'Mobile ' : ''; ?><?php echo !empty($viewSubmissionGeo['is_proxy']) ? 'Proxy/VPN ' : ''; ?><?php echo !empty($viewSubmissionGeo['is_hosting']) ? 'Hosting ' : ''; ?><?php echo empty($viewSubmissionGeo['is_mobile']) && empty($viewSubmissionGeo['is_proxy']) && empty($viewSubmissionGeo['is_hosting']) ? 'None recorded' : ''; ?></div>
                    <div class="col-12"><span class="text-secondary d-block">User Agent</span><span class="text-break"><?php echo htmlspecialchars(($viewSubmissionMeta['user_agent'] ?? '') !== '' ? $viewSubmissionMeta['user_agent'] : 'Not recorded'); ?></span></div>
                  </div>
                </div>
              </div>
              <?php endif; ?>

              <?php if ($viewOwnershipHistory): ?>
              <div class="col-12 order-4">
                <details>
                  <summary class="small text-secondary" style="cursor:pointer;">Recent ownership changes</summary>
                  <ul class="small mt-2 mb-0">
                    <?php foreach ($viewOwnershipHistory as $history): ?>
                      <li><?php echo htmlspecialchars(($history['previous_name'] ?? 'Unassigned') . ' → ' . ($history['new_name'] ?? 'Unknown user') . ' on ' . ($history['changed_at'] ?? '') . (($history['changed_by_name'] ?? '') !== '' ? ' by ' . $history['changed_by_name'] : '')); ?></li>
                    <?php endforeach; ?>
                  </ul>
                </details>
              </div>
              <?php endif; ?>
            </div>
          </div>
        </div>
        <?php endif; ?>
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
                        $canViewReviewFeedback = is_admin() || (is_logged_in() && (int)($viewCase['created_by'] ?? 0) === (int)($_SESSION['user']['id'] ?? 0));
                        $labelMap = [
                            'case_created' => 'Case created',
                            'case_updated' => 'Case updated',
                            'case_deleted' => 'Case deleted',
                            'case_rejected' => 'Case rejected',
                            'case_resubmitted' => 'Case resubmitted',
                            'case_submitted_for_review' => 'Submitted for review',
                            'case_returned_to_building' => 'Returned to Being Built',
                            'evidence_added' => 'Evidence added',
                            'evidence_updated' => 'Evidence updated',
                            'evidence_deleted' => 'Evidence deleted',
                            'note_added' => 'Case note added',
                            'redactions_saved' => 'Redactions saved'
                        ];
                        $lbl = $labelMap[$ceRow['event_type']] ?? ucfirst(str_replace('_',' ', $ceRow['event_type']));
                        $caseEventDetail = trim(($ceRow['subject'] ? $ceRow['subject'].': ' : '').($ceRow['detail'] ?? ''));
                        if (($ceRow['event_type'] ?? '') === 'case_rejected' && !$canViewReviewFeedback) {
                            $caseEventDetail = trim((string)($ceRow['subject'] ?? ''));
                        }
                        $timelineEvents[] = [
                            'ts' => $ceRow['created_at'],
                            'type' => $ceRow['event_type'],
                            'label' => $lbl,
                            'detail' => mb_strimwidth(tp_case_event_detail_for_viewer($caseEventDetail), 0, 180, '…', 'UTF-8'),
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
                  <div class="row g-3 align-items-start">
                    <?php
                      $casePhoto = find_person_photo_url($caseCode);
                      if ($casePhoto !== '') {
                    ?>
                      <div class="col-auto d-flex align-items-start">
                        <img src="<?php echo htmlspecialchars($casePhoto); ?>" alt="" class="rounded" style="width:96px;height:96px;object-fit:cover;">
                      </div>
                    <?php } else { ?>
                      <div class="col-auto d-flex align-items-start">
                        <div class="rounded bg-secondary text-white d-flex align-items-center justify-content-center" style="width:96px;height:96px;object-fit:cover;">
                          <span class="small">No Image</span>
                        </div>
                      </div>
                    <?php } ?>
                    <div class="col">
                      <div class="row g-3 align-items-start">
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
                          <div><?php echo ($viewCase['location'] ?? '') !== '' ? htmlspecialchars(tp_case_location_for_viewer($viewCase['location'])) : '<span class="text-secondary">—</span>'; ?></div>
                        </div>
                        <div class="col-sm-6 col-lg-3 mb-0">
                          <div class="small text-secondary">Phone Number</div>
                          <div><?php echo ($viewCase['phone_number'] ?? '') !== '' ? htmlspecialchars(tp_case_phone_number_for_viewer($viewCase['phone_number'])) : '<span class="text-secondary">&mdash;</span>'; ?></div>
                        </div>
                        <div class="col-sm-6 col-lg-3 mb-0">
                          <div class="small text-secondary">Snapchat Username</div>
                          <div><?php echo ($viewCase['snapchat_username'] ?? '') !== '' ? '@'.htmlspecialchars($viewCase['snapchat_username']) : '<span class="text-secondary">&mdash;</span>'; ?></div>
                        </div>
                        <div class="col-sm-6 col-lg-3 mb-0">
                          <div class="small text-secondary">TikTok Usernames</div>
                          <div><?php echo render_tiktok_usernames_lines($viewCase['tiktok_username'] ?? ''); ?></div>
                        </div>
                        <div class="col-sm-6 col-lg-3 mb-0">
                          <div class="small text-secondary">Status</div>
                          <div>
                            <?php
                              $status = $viewCase['status'];
                              $badgeClass = 'dark'; // default

                              switch ($status) {
                                  case 'Being Built':
                                      $badgeClass = 'warning';
                                      break;
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
                                  case 'Rejected':
                                      $badgeClass = 'secondary';
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
                          <div class="small text-secondary">Case Tags</div>
                          <div><?php echo render_case_tag_badges($viewCaseTags, '<span class="text-secondary">&mdash;</span>'); ?></div>
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
            <?php if ($tp_canViewAiBuilder): ?>
            <div class="col-12" id="ai-case-builder">
              <div class="card glass">
                <div class="card-body">
                  <div class="d-flex flex-column flex-md-row align-items-md-center justify-content-between gap-3 mb-3">
                    <div>
                      <h3 class="h6 mb-1"><i class="bi bi-stars me-1"></i> AI-Assisted Case Builder</h3>
                      <div class="small text-secondary">Suggestions are itemised for human review. Nothing changes until a site admin approves that individual suggestion.</div>
                    </div>
                    <?php if ($tp_canRunAiBuilder && $tp_openAiConfigured): ?>
                      <form method="post" action="" class="ai-builder-run-form flex-shrink-0" onsubmit="var b=this.querySelector('.ai-builder-run-button');if(b){b.disabled=true;b.innerHTML='<span class=&quot;spinner-border spinner-border-sm me-1&quot; aria-hidden=&quot;true&quot;></span> Analysing case...';}">
                        <input type="hidden" name="action" value="generate_ai_case_suggestions">
                        <?php csrf_field(); ?>
                        <input type="hidden" name="case_id" value="<?php echo (int)$viewCaseId; ?>">
                        <input type="hidden" name="case_code" value="<?php echo htmlspecialchars($caseCode); ?>">
                        <button type="submit" class="btn btn-primary btn-sm ai-builder-run-button">
                          <i class="bi bi-stars me-1"></i> <?php echo $tp_aiRuns ? 'Run Again' : 'Run AI Case Builder'; ?>
                        </button>
                      </form>
                    <?php endif; ?>
                  </div>

                  <?php if (!$tp_openAiConfigured): ?>
                    <div class="alert alert-warning mb-3">
                      OpenAI is not configured.
                      <?php if (is_admin()): ?><a href="?view=project_settings#project-settings" class="alert-link">Add the API key in Project Settings</a>.<?php else: ?>Ask a site admin to configure it in Project Settings.<?php endif; ?>
                    </div>
                  <?php elseif (!$tp_canRunAiBuilder && !is_admin()): ?>
                    <div class="alert alert-secondary mb-3">The case owner can run this assistant while the case is Being Built. A site admin can run it again at any stage.</div>
                  <?php endif; ?>

                  <?php if (!$tp_aiRuns): ?>
                    <div class="border rounded p-3 text-secondary">No AI review has been run for this case yet.</div>
                  <?php else: ?>
                    <div class="d-flex flex-column gap-3">
                    <?php foreach ($tp_aiRuns as $tpAiRun):
                      $runStatus = (string)($tpAiRun['status'] ?? 'Processing');
                      $runBadge = $runStatus === 'Completed' ? 'success' : ($runStatus === 'Failed' ? 'danger' : 'warning');
                      $runSuggestions = is_array($tpAiRun['suggestions'] ?? null) ? $tpAiRun['suggestions'] : [];
                      $runDate = !empty($tpAiRun['created_at']) ? date('d M Y H:i', strtotime((string)$tpAiRun['created_at'])) : '';
                    ?>
                      <div class="border rounded p-3">
                        <div class="d-flex flex-wrap align-items-center justify-content-between gap-2 mb-2">
                          <div class="small">
                            <span class="badge text-bg-<?php echo $runBadge; ?> me-1"><?php echo htmlspecialchars($runStatus); ?></span>
                            <span class="text-secondary"><?php echo htmlspecialchars($runDate); ?></span>
                            <?php if (!empty($tpAiRun['requested_by_name'])): ?><span class="text-secondary"> &middot; Run by <?php echo htmlspecialchars($tpAiRun['requested_by_name']); ?></span><?php endif; ?>
                          </div>
                          <span class="small text-secondary">Model: <?php echo htmlspecialchars($tpAiRun['model'] ?? ''); ?></span>
                        </div>
                        <?php if ($runStatus === 'Failed'): ?>
                          <div class="alert alert-danger mb-0"><?php echo htmlspecialchars($tpAiRun['error_message'] ?? 'The AI review failed.'); ?></div>
                        <?php else: ?>
                          <?php if (trim((string)($tpAiRun['overall_notes'] ?? '')) !== ''): ?>
                            <div class="small text-secondary mb-3"><?php echo nl2br(htmlspecialchars($tpAiRun['overall_notes'])); ?></div>
                          <?php endif; ?>
                          <?php if (!$runSuggestions): ?>
                            <div class="small text-secondary">No changes were suggested in this review.</div>
                          <?php else: ?>
                            <ol class="list-group list-group-numbered">
                            <?php foreach ($runSuggestions as $tpSuggestion):
                              $fieldName = (string)($tpSuggestion['field_name'] ?? '');
                              $fieldLabel = tp_ai_case_field_labels()[$fieldName] ?? ucfirst(str_replace('_', ' ', $fieldName));
                              $suggestionDecision = (string)($tpSuggestion['decision'] ?? 'Pending');
                              $decisionBadge = $suggestionDecision === 'Approved' ? 'success' : ($suggestionDecision === 'Rejected' ? 'danger' : 'warning');
                              $beforeValue = (string)($tpSuggestion['current_value'] ?? '');
                              $afterValue = (string)($tpSuggestion['suggested_value'] ?? '');
                              if (!is_admin() && $fieldName === 'location') {
                                $beforeValue = tp_mask_case_location_house_number($beforeValue);
                                $afterValue = tp_mask_case_location_house_number($afterValue);
                              }
                            ?>
                              <li class="list-group-item bg-transparent text-light border-secondary ps-5 py-3">
                                <div class="d-flex flex-wrap justify-content-between align-items-center gap-2 mb-3">
                                  <div class="fw-semibold"><?php echo htmlspecialchars($fieldLabel); ?></div>
                                  <div>
                                    <span class="badge text-bg-<?php echo $decisionBadge; ?>"><?php echo htmlspecialchars($suggestionDecision); ?></span>
                                    <?php if ($suggestionDecision !== 'Pending' && !empty($tpSuggestion['decided_by_name'])): ?>
                                      <span class="small text-secondary ms-1">by <?php echo htmlspecialchars($tpSuggestion['decided_by_name']); ?></span>
                                    <?php endif; ?>
                                  </div>
                                </div>
                                <div class="row g-3 mb-4">
                                  <div class="col-md-6">
                                    <div class="small text-secondary mb-1">Before</div>
                                    <div class="border rounded p-3 bg-black bg-opacity-25" style="white-space:pre-wrap;overflow-wrap:anywhere;min-height:8rem;max-height:20rem;overflow:auto;"><?php echo $beforeValue !== '' ? htmlspecialchars($beforeValue) : '<span class="text-secondary">Empty</span>'; ?></div>
                                  </div>
                                  <div class="col-md-6">
                                    <div class="small text-secondary mb-1">Suggested change</div>
                                    <div class="border border-info rounded p-3 bg-info bg-opacity-10" style="white-space:pre-wrap;overflow-wrap:anywhere;min-height:8rem;max-height:20rem;overflow:auto;"><?php echo htmlspecialchars($afterValue); ?></div>
                                  </div>
                                </div>
                                <div class="small mb-3 pt-1"><span class="text-secondary d-block mb-1">Why:</span><span class="d-block"><?php echo nl2br(htmlspecialchars($tpSuggestion['reason'] ?? '')); ?></span></div>
                                <?php if ($suggestionDecision === 'Pending'): ?>
                                  <?php if (is_admin()): ?>
                                    <div class="d-flex flex-wrap gap-2">
                                      <form method="post" action="">
                                        <input type="hidden" name="action" value="decide_ai_case_suggestion">
                                        <?php csrf_field(); ?>
                                        <input type="hidden" name="suggestion_id" value="<?php echo (int)$tpSuggestion['id']; ?>">
                                        <input type="hidden" name="case_code" value="<?php echo htmlspecialchars($caseCode); ?>">
                                        <input type="hidden" name="decision" value="approve">
                                        <button type="submit" class="btn btn-success btn-sm"><i class="bi bi-check-lg me-1"></i> Approve Change</button>
                                      </form>
                                      <form method="post" action="" onsubmit="return confirm('Reject this AI suggestion?');">
                                        <input type="hidden" name="action" value="decide_ai_case_suggestion">
                                        <?php csrf_field(); ?>
                                        <input type="hidden" name="suggestion_id" value="<?php echo (int)$tpSuggestion['id']; ?>">
                                        <input type="hidden" name="case_code" value="<?php echo htmlspecialchars($caseCode); ?>">
                                        <input type="hidden" name="decision" value="reject">
                                        <button type="submit" class="btn btn-outline-danger btn-sm"><i class="bi bi-x-lg me-1"></i> Reject Change</button>
                                      </form>
                                    </div>
                                  <?php else: ?>
                                    <div class="small text-warning"><i class="bi bi-hourglass-split me-1"></i> Awaiting a site admin decision.</div>
                                  <?php endif; ?>
                                <?php endif; ?>
                              </li>
                            <?php endforeach; ?>
                            </ol>
                          <?php endif; ?>
                        <?php endif; ?>
                      </div>
                    <?php endforeach; ?>
                    </div>
                  <?php endif; ?>
                </div>
              </div>
            </div>
            <?php endif; ?>
            <?php if (is_admin()): ?>
            <div class="col-12">
              <div class="card glass">
                <div class="card-body">
                  <div class="d-flex align-items-center justify-content-between mb-3">
                    <h3 class="h6 mb-0"><i class="bi bi-activity me-1"></i> Case Analytics</h3>
                    <a class="btn btn-outline-light btn-sm" href="?view=viewer_stats#viewer-stats"><i class="bi bi-bar-chart me-1"></i> All Viewer Stats</a>
                  </div>
                  <div class="row g-3 mb-3">
                    <div class="col-6 col-lg-2"><div class="border rounded p-2 h-100"><div class="small text-secondary">24h Views</div><div class="h5 mb-0"><?php echo number_format((int)($viewAnalyticsSummary['views_24h'] ?? 0)); ?></div></div></div>
                    <div class="col-6 col-lg-2"><div class="border rounded p-2 h-100"><div class="small text-secondary">Unique IPs</div><div class="h5 mb-0"><?php echo number_format((int)($viewAnalyticsSummary['unique_ips'] ?? 0)); ?></div></div></div>
                    <div class="col-6 col-lg-2"><div class="border rounded p-2 h-100"><div class="small text-secondary">High Risk</div><div class="h5 mb-0"><?php echo number_format((int)($viewAnalyticsSummary['high_risk_views'] ?? 0)); ?></div></div></div>
                    <div class="col-6 col-lg-2"><div class="border rounded p-2 h-100"><div class="small text-secondary">Proxy</div><div class="h5 mb-0"><?php echo number_format((int)($viewAnalyticsSummary['proxy_views'] ?? 0)); ?></div></div></div>
                    <div class="col-6 col-lg-2"><div class="border rounded p-2 h-100"><div class="small text-secondary">Bot</div><div class="h5 mb-0"><?php echo number_format((int)($viewAnalyticsSummary['bot_views'] ?? 0)); ?></div></div></div>
                    <div class="col-6 col-lg-2"><div class="border rounded p-2 h-100"><div class="small text-secondary">Max Score</div><div class="h5 mb-0"><?php echo number_format((int)($viewAnalyticsSummary['max_score'] ?? 0)); ?></div></div></div>
                  </div>
                  <div class="row g-3">
                    <div class="col-lg-7">
                      <h4 class="h6 mb-2">Open Alerts</h4>
                      <div class="table-responsive">
                        <table class="table table-sm align-middle mb-0">
                          <thead><tr><th>Severity</th><th>Alert</th><th class="text-end">Metric</th><th>Last Seen</th></tr></thead>
                          <tbody>
                            <?php if (!empty($viewAnalyticsAlerts)): foreach ($viewAnalyticsAlerts as $alert): ?>
                              <?php $sev = (string)($alert['severity'] ?? 'low'); $sevClass = $sev === 'high' ? 'danger' : ($sev === 'medium' ? 'warning' : 'secondary'); ?>
                              <tr>
                                <td><span class="badge text-bg-<?php echo $sevClass; ?>"><?php echo htmlspecialchars(ucfirst($sev)); ?></span></td>
                                <td><div class="fw-semibold"><?php echo htmlspecialchars($alert['title'] ?? ''); ?></div><div class="small text-secondary text-break"><?php echo htmlspecialchars($alert['detail'] ?? ''); ?></div></td>
                                <td class="text-end small"><?php echo htmlspecialchars((string)($alert['metric_value'] ?? '')); ?> / <?php echo htmlspecialchars((string)($alert['threshold_value'] ?? '')); ?></td>
                                <td class="small text-secondary"><?php echo htmlspecialchars($alert['last_seen_at'] ?? ''); ?></td>
                              </tr>
                            <?php endforeach; else: ?>
                              <tr><td colspan="4" class="text-secondary">No open alerts for this case.</td></tr>
                            <?php endif; ?>
                          </tbody>
                        </table>
                      </div>
                    </div>
                    <div class="col-lg-5">
                      <h4 class="h6 mb-2">Top Countries</h4>
                      <div class="table-responsive mb-3">
                        <table class="table table-sm align-middle mb-0">
                          <tbody>
                            <?php if (!empty($viewAnalyticsCountries)): foreach ($viewAnalyticsCountries as $country): ?>
                              <tr><td><?php echo htmlspecialchars($country['label'] ?? 'Unknown'); ?></td><td class="text-end fw-semibold"><?php echo number_format((int)($country['cnt'] ?? 0)); ?></td></tr>
                            <?php endforeach; else: ?>
                              <tr><td class="text-secondary">No country data yet.</td><td></td></tr>
                            <?php endif; ?>
                          </tbody>
                        </table>
                      </div>
                    </div>
                  </div>
                  <h4 class="h6 mt-3 mb-2">Recent Risk Signals</h4>
                  <div class="table-responsive">
                    <table class="table table-sm align-middle mb-0">
                      <thead><tr><th>Viewed</th><th>IP</th><th>Location</th><th>Network</th><th>Device</th><th class="text-end">Score</th><th>Flags</th></tr></thead>
                      <tbody>
                        <?php if (!empty($viewAnalyticsRecentRisk)): foreach ($viewAnalyticsRecentRisk as $risk): ?>
                          <?php $score = (int)($risk['analytics_score'] ?? 0); $scoreClass = $score >= 70 ? 'danger' : ($score >= 40 ? 'warning' : 'secondary'); ?>
                          <tr>
                            <td class="small"><?php echo htmlspecialchars($risk['viewed_at'] ?? ''); ?></td>
                            <td class="small"><?php echo htmlspecialchars($risk['public_ip'] ?? ''); ?></td>
                            <td class="small"><?php echo htmlspecialchars(trim(($risk['geo_country'] ?? '').' '.($risk['geo_region'] ?? '').' '.($risk['geo_city'] ?? '')) ?: 'Unknown'); ?></td>
                            <td class="small"><?php echo htmlspecialchars($risk['net_isp'] ?? 'Unknown'); ?></td>
                            <td class="small"><?php echo htmlspecialchars(trim(($risk['device_type'] ?? '').' '.($risk['browser_name'] ?? '').' '.($risk['os_name'] ?? '')) ?: 'Unknown'); ?></td>
                            <td class="text-end"><span class="badge text-bg-<?php echo $scoreClass; ?>"><?php echo $score; ?></span></td>
                            <td class="small text-secondary"><?php echo htmlspecialchars(trim(($risk['alert_flags'] ?? '') . ' ' . ($risk['bot_reason'] ?? ''))); ?></td>
                          </tr>
                        <?php endforeach; else: ?>
                          <tr><td colspan="7" class="text-secondary">No risk signals above score 40 yet.</td></tr>
                        <?php endif; ?>
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>
            </div>
            <?php endif; ?>
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
                          <th>Type</th>
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
                                          data-title="<?php echo htmlspecialchars(is_logged_in() ? ($e['title'] ?? 'Note') : 'Evidence'); ?>">
                                    View
                                  </button>
                                  <?php if ($tp_canEditCaseEvidence): ?>
                                    <div class="btn-group ms-1">
                                      <button type="button" class="btn btn-sm btn-outline-warning btn-edit-evidence" data-bs-toggle="modal" data-bs-target="#evidenceModal" data-id="<?php echo (int)$e['id']; ?>" data-case-id="<?php echo (int)$viewCaseId; ?>" data-src="<?php echo htmlspecialchars($e['filepath']); ?>" data-title="<?php echo htmlspecialchars($e['title']); ?>" data-type="<?php echo htmlspecialchars($e['type'] ?? 'other'); ?>" data-mime="<?php echo htmlspecialchars($e['mime_type']); ?>">Edit</button>
                                      <?php if (is_admin()): ?>
                                      <form method="post" action="" class="d-inline" onsubmit="return confirm('Delete this evidence permanently?');">
                                        <input type="hidden" name="action" value="delete_evidence">
                                        <?php csrf_field(); ?>
                                        <input type="hidden" name="evidence_id" value="<?php echo (int)$e['id']; ?>">
                                        <input type="hidden" name="case_id" value="<?php echo (int)$viewCaseId; ?>">
                                        <input type="hidden" name="redirect_url" value="?view=case&amp;code=<?php echo urlencode($caseCode); ?>#case-view">
                                        <button type="submit" class="btn btn-sm btn-outline-danger">Delete</button>
                                      </form>
                                      <?php endif; ?>
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
                                      <?php if ($tp_canEditCaseEvidence): ?>
                                        <div class="btn-group ms-1">
                                          <button type="button" class="btn btn-sm btn-outline-warning btn-edit-evidence" data-bs-toggle="modal" data-bs-target="#evidenceModal"
                                                  data-id="<?php echo (int)$e['id']; ?>" data-case-id="<?php echo (int)$viewCaseId; ?>" data-src="<?php echo htmlspecialchars($e['filepath']); ?>" data-title="<?php echo htmlspecialchars($e['title']); ?>" data-type="<?php echo htmlspecialchars($e['type'] ?? 'other'); ?>" data-mime="<?php echo htmlspecialchars($e['mime_type']); ?>" data-url="1">
                                            Edit
                                          </button>
                                          <?php if (is_admin()): ?>
                                          <form method="post" action="" class="d-inline" onsubmit="return confirm('Delete this evidence permanently?');">
                                            <input type="hidden" name="action" value="delete_evidence">
                                            <?php csrf_field(); ?>
                                            <input type="hidden" name="evidence_id" value="<?php echo (int)$e['id']; ?>">
                                            <input type="hidden" name="case_id" value="<?php echo (int)$viewCaseId; ?>">
                                            <input type="hidden" name="redirect_url" value="?view=case&amp;code=<?php echo urlencode($caseCode); ?>#case-view">
                                            <button type="submit" class="btn btn-sm btn-outline-danger">Delete</button>
                                          </form>
                                          <?php endif; ?>
                                        </div>
                                      <?php endif; ?>
                                    <?php } else { ?>
                                      <button type="button" class="btn btn-sm btn-outline-light btn-view-evidence"
                                              data-bs-toggle="modal" data-bs-target="#evidenceModal"
                                              data-id="<?php echo (int)$e['id']; ?>"
                                              data-case-id="<?php echo (int)$viewCaseId; ?>"
                                              data-src="?action=serve_evidence&amp;id=<?php echo (int)$e['id']; ?>"
                                              data-title="<?php echo htmlspecialchars(is_logged_in() ? $e['title'] : 'Evidence'); ?>"
                                              data-type="<?php echo htmlspecialchars($e['type'] ?? 'other'); ?>"
                                              data-mime="<?php echo htmlspecialchars($e['mime_type']); ?>">
                                        View
                                    </button>
                                    <?php if ($tp_canEditCaseEvidence): ?>
                                      <div class="btn-group ms-1">
                                        <button type="button" class="btn btn-sm btn-outline-warning btn-edit-evidence" data-bs-toggle="modal" data-bs-target="#evidenceModal"
                                                data-id="<?php echo (int)$e['id']; ?>" data-case-id="<?php echo (int)$viewCaseId; ?>" data-src="?action=serve_evidence&amp;id=<?php echo (int)$e['id']; ?>" data-title="<?php echo htmlspecialchars($e['title']); ?>" data-type="<?php echo htmlspecialchars($e['type'] ?? 'other'); ?>" data-mime="<?php echo htmlspecialchars($e['mime_type']); ?>">
                                          Edit
                                        </button>
                                        <?php if (is_admin()): ?>
                                        <form method="post" action="" class="d-inline" onsubmit="return confirm('Delete this evidence permanently?');">
                                          <input type="hidden" name="action" value="delete_evidence">
                                          <?php csrf_field(); ?>
                                          <input type="hidden" name="evidence_id" value="<?php echo (int)$e['id']; ?>">
                                          <input type="hidden" name="case_id" value="<?php echo (int)$viewCaseId; ?>">
                                          <input type="hidden" name="redirect_url" value="?view=case&amp;code=<?php echo urlencode($caseCode); ?>#case-view">
                                          <button type="submit" class="btn btn-sm btn-outline-danger">Delete</button>
                                        </form>
                                        <?php endif; ?>
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
                <label class="form-label">TikTok Usernames</label>
                <input type="text" name="tiktok_username" class="form-control" value="<?php echo htmlspecialchars(normalize_tiktok_usernames($viewCase['tiktok_username'] ?? '')); ?>" placeholder="username1, username2">
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
              <div class="col-md-6">
                <label class="form-label">Phone Number</label>
                <input type="text" name="phone_number" class="form-control" value="<?php echo htmlspecialchars($viewCase['phone_number'] ?? ''); ?>" inputmode="tel">
              </div>
              <div class="col-md-6">
                <label class="form-label">Snapchat Username</label>
                <div class="input-group">
                  <span class="input-group-text">@</span>
                  <input type="text" name="snapchat_username" class="form-control" value="<?php echo htmlspecialchars($viewCase['snapchat_username'] ?? ''); ?>" placeholder="username">
                </div>
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
                  <?php
                    $currentStatus = (string)($viewCase['status'] ?? 'Being Built');
                    $statOpts = in_array($currentStatus, ['Being Built','Rejected'], true)
                      ? [$currentStatus]
                      : ['Being Built','Pending','Open','In Review','Verified','Verified dont announce','Closed'];
                    foreach ($statOpts as $opt) {
                      $sel = ($currentStatus === $opt) ? ' selected' : '';
                      $label = $opt === 'Verified dont announce' ? "Verified — Don't Announce" : $opt;
                      echo '<option value="'.htmlspecialchars($opt).'"'.$sel.'>'.htmlspecialchars($label)."</option>";
                    }
                  ?>
                </select>
              </div>
            </div>

            <div class="row g-2 mt-2">
              <div class="col-md-6">
                <label class="form-label">Update Person Photo</label>
                <input type="file" name="person_photo" class="form-control" accept="image/*">
                <small class="text-secondary">Leave blank to keep current</small>
                <?php if (find_person_photo_url($caseCode) !== ''): ?>
                  <div class="form-check mt-2">
                    <input class="form-check-input" type="checkbox" name="remove_person_photo" value="1" id="viewRemovePersonPhoto">
                    <label class="form-check-label" for="viewRemovePersonPhoto">Remove current person photo</label>
                  </div>
                <?php endif; ?>
              </div>
            </div>

            <div class="mt-3">
              <label class="form-label">Case Tags</label>
              <?php echo render_case_tag_checkboxes(get_case_tags($pdo, $viewCaseId)); ?>
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
      $caseRow = null; $caseId = 0; $adminCaseTotalViews = 0; $adminCaseTags = [];
      try {
          $s = $pdo->prepare('SELECT id, case_code, case_name, person_name, location, phone_number, snapchat_username, tiktok_username, initial_summary, status, sensitivity, opened_at FROM cases WHERE case_code = ? LIMIT 1');
          $s->execute([$adminCaseCode]);
          $caseRow = $s->fetch();
          $caseId = (int)($caseRow['id'] ?? 0);
            if ($caseId > 0) { $caseRow['tiktok_username'] = get_case_tiktok_usernames($pdo, $caseId) ?: ($caseRow['tiktok_username'] ?? ''); $adminCaseTags = get_case_tags($pdo, $caseId); }
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
                  <div class="small text-secondary">Phone Number</div>
                  <div class="mb-2"><?php echo ($caseRow['phone_number'] ?? '') !== '' ? htmlspecialchars($caseRow['phone_number']) : '<span class="text-secondary">&mdash;</span>'; ?></div>
                  <div class="small text-secondary">Snapchat Username</div>
                  <div class="mb-2"><?php echo ($caseRow['snapchat_username'] ?? '') !== '' ? '@'.htmlspecialchars($caseRow['snapchat_username']) : '<span class="text-secondary">&mdash;</span>'; ?></div>
                  <div class="small text-secondary">TikTok Usernames</div>
                  <div class="mb-2"><?php echo render_tiktok_usernames_lines($caseRow['tiktok_username'] ?? ''); ?></div>
                  <div class="small text-secondary">Status</div>
                  <div class="mb-2"><span class="badge text-bg-dark border"><?php echo htmlspecialchars($caseRow['status']); ?></span></div>
                  <div class="small text-secondary">Sensitivity</div>
                  <div class="mb-2"><span class="badge text-bg-dark border"><?php echo htmlspecialchars($caseRow['sensitivity']); ?></span></div>
                  <div class="small text-secondary">Case Tags</div>
                  <div class="mb-2"><?php echo render_case_tag_badges($adminCaseTags, '<span class="text-secondary">&mdash;</span>'); ?></div>
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
                    <label class="form-label">TikTok Usernames</label>
                    <input type="text" name="tiktok_username" class="form-control" value="<?php echo htmlspecialchars(normalize_tiktok_usernames($caseRow['tiktok_username'] ?? '')); ?>" placeholder="username1, username2">
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
                  <div class="col-md-6">
                    <label class="form-label">Phone Number</label>
                    <input type="text" name="phone_number" class="form-control" value="<?php echo htmlspecialchars($caseRow['phone_number'] ?? ''); ?>" inputmode="tel">
                  </div>
                  <div class="col-md-6">
                    <label class="form-label">Snapchat Username</label>
                    <div class="input-group">
                      <span class="input-group-text">@</span>
                      <input type="text" name="snapchat_username" class="form-control" value="<?php echo htmlspecialchars($caseRow['snapchat_username'] ?? ''); ?>" placeholder="username">
                    </div>
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
                      <?php
                        $currentStatus = (string)($caseRow['status'] ?? 'Being Built');
                        $statOpts = in_array($currentStatus, ['Being Built','Rejected'], true)
                          ? [$currentStatus]
                          : ['Being Built','Pending','Open','In Review','Verified','Verified dont announce','Closed'];
                        foreach ($statOpts as $opt) {
                          $sel = ($currentStatus === $opt) ? ' selected' : '';
                          $label = $opt === 'Verified dont announce' ? "Verified — Don't Announce" : $opt;
                          echo '<option value="'.htmlspecialchars($opt).'"'.$sel.'>'.htmlspecialchars($label)."</option>";
                        }
                      ?>
                    </select>
                  </div>
                </div>

                <div class="row g-2 mt-2">
                  <div class="col-md-6">
                    <label class="form-label">Update Person Photo</label>
                    <input type="file" name="person_photo" class="form-control" accept="image/*">
                    <small class="text-secondary">Leave blank to keep current</small>
                    <?php if (find_person_photo_url($caseRow['case_code'] ?? '') !== ''): ?>
                      <div class="form-check mt-2">
                        <input class="form-check-input" type="checkbox" name="remove_person_photo" value="1" id="adminRemovePersonPhoto">
                        <label class="form-check-label" for="adminRemovePersonPhoto">Remove current person photo</label>
                      </div>
                    <?php endif; ?>
                  </div>
                </div>

                <div class="mt-3">
                  <label class="form-label">Case Tags</label>
                  <?php echo render_case_tag_checkboxes(get_case_tags($pdo, (int)$caseId)); ?>
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

  <?php if ($view === 'project_settings'): ?>
    <?php if (!tp_is_main_admin()): ?>
      <section class="py-5 border-top" id="project-settings">
        <div class="container-xl">
          <div class="alert alert-danger"><i class="bi bi-shield-lock me-2"></i>Unauthorized. Main admin only.</div>
        </div>
      </section>
    <?php else: ?>
      <section class="py-5 border-top" id="project-settings">
        <div class="container-xl">
          <div class="d-flex align-items-center justify-content-between mb-3">
            <div>
              <h2 class="h4 mb-0">Project Settings</h2>
              <div class="text-secondary small">Visible only to the main admin account.</div>
            </div>
            <a class="btn btn-outline-light btn-sm" href="?view=users#users"><i class="bi bi-arrow-left me-1"></i> Back to Users</a>
          </div>

          <div class="row g-4">
            <div class="col-lg-8">
              <div class="card glass">
                <div class="card-body">
                  <form method="post" action="" class="vstack gap-3">
                    <input type="hidden" name="action" value="save_project_settings">
                    <?php csrf_field(); ?>
                    <input type="hidden" name="redirect_url" value="?view=project_settings#project-settings">

                    <div>
                      <label class="form-label">Site Title</label>
                      <input type="text" name="site_title" class="form-control" value="<?php echo htmlspecialchars($tpSiteTitle); ?>" placeholder="TikTokPredators">
                    </div>

                    <div>
                      <label class="form-label">Meta Data</label>
                      <textarea name="meta_data" class="form-control" rows="5" placeholder="Site description and SEO metadata"><?php echo htmlspecialchars($tpMetaDescription); ?></textarea>
                    </div>

                    <div>
                      <label class="form-label" for="openAiApiKey">OpenAI API Key</label>
                      <div class="input-group">
                        <input type="text" id="openAiApiKey" name="openai_api_key" class="form-control font-monospace" value="<?php echo htmlspecialchars($tpOpenAiApiKey); ?>" placeholder="sk-..." autocomplete="off" spellcheck="false">
                        <button type="button" class="btn btn-outline-info" id="testOpenAiKeyBtn"><i class="bi bi-broadcast me-1"></i>Test OpenAI</button>
                      </div>
                      <div class="form-text text-secondary">Stored in Platform Settings and displayed in plain text to the main admin account.</div>
                      <div class="small text-secondary mt-1" id="openAiTestStatus" role="status" aria-live="polite">Test not run.</div>
                    </div>

                    <div>
                      <div class="d-flex align-items-center justify-content-between mb-2">
                        <label class="form-label mb-0">Discord Webhooks</label>
                        <button type="button" class="btn btn-outline-light btn-sm" id="addWebhookRowBtn"><i class="bi bi-plus-lg me-1"></i>Add Webhook</button>
                      </div>
                      <div id="discordWebhookRows" class="vstack gap-2">
                        <?php foreach ($tpDiscordWebhooks as $hook): ?>
                          <div class="webhook-row">
                            <div>
                              <input type="text" name="discord_webhook_name[]" class="form-control" placeholder="Webhook name (e.g. Alerts)" value="<?php echo htmlspecialchars((string)($hook['name'] ?? '')); ?>">
                            </div>
                            <div>
                              <input type="url" name="discord_webhook_url[]" class="form-control" placeholder="https://discord.com/api/webhooks/..." value="<?php echo htmlspecialchars((string)($hook['url'] ?? '')); ?>">
                            </div>
                            <?php
                              $tpSetAtRaw = trim((string)($hook['set_at'] ?? ''));
                              $tpSetAtTs = $tpSetAtRaw !== '' ? strtotime($tpSetAtRaw) : false;
                            ?>
                            <?php $tpSetLabel = $tpSetAtTs ? ('Set: ' . date('Y-m-d H:i', $tpSetAtTs)) : 'Set: New'; ?>
                            <div class="webhook-meta small text-secondary" title="When this webhook was first set" data-set-label="<?php echo htmlspecialchars($tpSetLabel); ?>">
                              <?php
                                $tpLastRaw = trim((string)($hook['last_tested_at'] ?? ''));
                                $tpLastTs = $tpLastRaw !== '' ? strtotime($tpLastRaw) : false;
                                $tpLastStatus = trim((string)($hook['last_test_status'] ?? ''));
                                $tpLastMessage = trim((string)($hook['last_test_message'] ?? ''));
                                echo htmlspecialchars($tpSetLabel);
                                echo '<br>';
                                if ($tpLastTs) {
                                  $tpBadgeClass = 'text-bg-secondary';
                                  if ($tpLastStatus === 'success') { $tpBadgeClass = 'text-bg-success'; }
                                  if ($tpLastStatus === 'failed') { $tpBadgeClass = 'text-bg-danger'; }
                                  $tpStatusLabel = ($tpLastStatus !== '' ? $tpLastStatus : 'unknown');
                                  $tpMsgTitle = ($tpLastStatus === 'failed' && $tpLastMessage !== '')
                                    ? ' data-bs-toggle="tooltip" data-bs-placement="top" data-bs-title="' . htmlspecialchars($tpLastMessage) . '"'
                                    : '';
                                  echo 'Test: ' . htmlspecialchars(date('Y-m-d H:i', $tpLastTs)) . ' <span class="badge ' . $tpBadgeClass . '"' . $tpMsgTitle . '>' . htmlspecialchars($tpStatusLabel) . '</span>';
                                } else {
                                  echo 'Test: Never';
                                }
                              ?>
                            </div>
                            <div class="webhook-actions">
                              <button type="button" class="btn btn-outline-info test-webhook-row" title="Test"><i class="bi bi-broadcast me-0"></i></button>
                              <button type="button" class="btn btn-outline-danger remove-webhook-row" title="Remove"><i class="bi bi-x-lg"></i></button>
                            </div>
                          </div>
                        <?php endforeach; ?>
                      </div>
                      <div class="form-text text-secondary">Add one or more named Discord webhook URLs. Notifications are sent to all configured webhooks.</div>
                    </div>

                    <div class="d-flex justify-content-end gap-2">
                      <button type="submit" class="btn btn-primary"><i class="bi bi-save me-1"></i> Save Settings</button>
                    </div>
                  </form>
                </div>
              </div>
            </div>
            <div class="col-lg-4">
              <div class="card glass h-100">
                <div class="card-body">
                  <h3 class="h6 mb-3">Preview</h3>
                  <div class="small text-secondary mb-2">Current site title</div>
                  <div class="fw-semibold mb-3"><?php echo htmlspecialchars($tpSiteTitle); ?></div>
                  <div class="small text-secondary mb-2">Current meta description</div>
                  <div class="small mb-3"><?php echo htmlspecialchars($tpMetaDescription); ?></div>
                  <div class="small text-secondary mb-2">Discord webhooks configured</div>
                  <div class="fw-semibold"><?php echo (int)$tpDiscordWebhookCount; ?></div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>
      <script>
      (function () {
        var addBtn = document.getElementById('addWebhookRowBtn');
        var rows = document.getElementById('discordWebhookRows');
        var openAiTestBtn = document.getElementById('testOpenAiKeyBtn');
        var openAiKeyInput = document.getElementById('openAiApiKey');
        var openAiTestStatus = document.getElementById('openAiTestStatus');
        var csrfToken = <?php echo json_encode($_SESSION['csrf_token'] ?? ''); ?>;

        if (openAiTestBtn && openAiKeyInput && openAiTestStatus) {
          openAiTestBtn.addEventListener('click', function () {
            var apiKey = openAiKeyInput.value.trim();
            if (apiKey === '') {
              openAiTestStatus.className = 'small text-danger mt-1';
              openAiTestStatus.textContent = 'Enter an OpenAI API key first.';
              return;
            }

            var fd = new FormData();
            fd.append('action', 'test_openai_api_key');
            fd.append('csrf_token', csrfToken);
            fd.append('ajax', '1');
            fd.append('openai_api_key', apiKey);

            openAiTestBtn.disabled = true;
            openAiTestStatus.className = 'small text-info mt-1';
            openAiTestStatus.textContent = 'Testing OpenAI connection...';
            fetch(window.location.href, {
              method: 'POST',
              headers: { 'X-Requested-With': 'XMLHttpRequest' },
              body: fd
            }).then(function (res) {
              return res.json();
            }).then(function (data) {
              var succeeded = !!(data && data.ok);
              openAiTestStatus.className = 'small ' + (succeeded ? 'text-success' : 'text-danger') + ' mt-1';
              openAiTestStatus.textContent = (data && data.message) ? String(data.message) : 'OpenAI returned an unexpected response.';
            }).catch(function () {
              openAiTestStatus.className = 'small text-danger mt-1';
              openAiTestStatus.textContent = 'Unable to complete the OpenAI test request.';
            }).finally(function () {
              openAiTestBtn.disabled = false;
            });
          });
        }

        if (!addBtn || !rows) return;

        function initTooltips(scope) {
          if (typeof bootstrap === 'undefined' || !bootstrap.Tooltip) return;
          var root = scope || document;
          root.querySelectorAll('[data-bs-toggle="tooltip"]').forEach(function (el) {
            if (bootstrap.Tooltip.getInstance(el)) return;
            new bootstrap.Tooltip(el);
          });
        }

        function bindRemove(btn) {
          btn.addEventListener('click', function () {
            var row = btn.closest('.webhook-row');
            if (!row) return;
            if (rows.querySelectorAll('.webhook-row').length <= 1) {
              row.querySelector('input[name="discord_webhook_name[]"]').value = '';
              row.querySelector('input[name="discord_webhook_url[]"]').value = '';
              return;
            }
            row.remove();
          });
        }

        rows.querySelectorAll('.remove-webhook-row').forEach(bindRemove);

        function bindTest(btn) {
          function escHtml(str) {
            return String(str)
              .replace(/&/g, '&amp;')
              .replace(/</g, '&lt;')
              .replace(/>/g, '&gt;')
              .replace(/"/g, '&quot;')
              .replace(/'/g, '&#39;');
          }
          function statusBadge(status, msg) {
            var st = status || 'unknown';
            var cls = 'text-bg-secondary';
            if (st === 'success') cls = 'text-bg-success';
            if (st === 'failed') cls = 'text-bg-danger';
            var title = (st === 'failed' && msg)
              ? (' data-bs-toggle="tooltip" data-bs-placement="top" data-bs-title="' + escHtml(msg) + '"')
              : '';
            return '<span class="badge ' + cls + '"' + title + '>' + escHtml(st) + '</span>';
          }
          btn.addEventListener('click', function () {
            var row = btn.closest('.webhook-row');
            if (!row) return;
            var nameInput = row.querySelector('input[name="discord_webhook_name[]"]');
            var urlInput = row.querySelector('input[name="discord_webhook_url[]"]');
            var statusCell = row.querySelector('.webhook-meta[data-set-label]');
            var webhookName = nameInput ? nameInput.value.trim() : '';
            var webhookUrl = urlInput ? urlInput.value.trim() : '';
            if (webhookUrl === '') {
              if (statusCell) {
                var setLabelMissing = statusCell.getAttribute('data-set-label') || 'Set: New';
                statusCell.innerHTML = escHtml(setLabelMissing) + '<br>Test: Missing URL';
              }
              return;
            }

            var fd = new FormData();
            fd.append('action', 'test_discord_webhook');
            fd.append('csrf_token', csrfToken);
            fd.append('ajax', '1');
            fd.append('webhook_name', webhookName);
            fd.append('webhook_url', webhookUrl);
            fd.append('redirect_url', '?view=project_settings#project-settings');

            btn.disabled = true;
            if (statusCell) {
              var setLabelTesting = statusCell.getAttribute('data-set-label') || 'Set: New';
              statusCell.innerHTML = escHtml(setLabelTesting) + '<br>Test: Testing...';
            }
            fetch(window.location.href, {
              method: 'POST',
              headers: { 'X-Requested-With': 'XMLHttpRequest' },
              body: fd
            }).then(function (res) {
              return res.json();
            }).then(function (data) {
              var when = data && data.tested_at ? String(data.tested_at).replace('T', ' ').substring(0, 16) : 'Now';
              var st = data && data.status ? data.status : 'unknown';
              var testMsg = data && data.test_message ? String(data.test_message) : '';
              if (statusCell) {
                var setLabelDone = statusCell.getAttribute('data-set-label') || 'Set: New';
                statusCell.innerHTML = escHtml(setLabelDone) + '<br>Test: ' + escHtml(when) + ' ' + statusBadge(st, testMsg);
                initTooltips(statusCell);
              }
            }).catch(function () {
              if (statusCell) {
                var setLabelFailed = statusCell.getAttribute('data-set-label') || 'Set: New';
                statusCell.innerHTML = escHtml(setLabelFailed) + '<br>Test: ' + statusBadge('failed', 'Request failed');
                initTooltips(statusCell);
              }
            }).finally(function () {
              btn.disabled = false;
            });
          });
        }

        rows.querySelectorAll('.test-webhook-row').forEach(bindTest);

        addBtn.addEventListener('click', function () {
          var row = document.createElement('div');
          row.className = 'webhook-row';
          row.innerHTML = '' +
            '<div><input type="text" name="discord_webhook_name[]" class="form-control" placeholder="Webhook name (e.g. Alerts)"></div>' +
            '<div><input type="url" name="discord_webhook_url[]" class="form-control" placeholder="https://discord.com/api/webhooks/..."></div>' +
            '<div class="webhook-meta small text-secondary" title="When this webhook was first set" data-set-label="Set: New">Set: New<br>Test: Never</div>' +
            '<div class="webhook-actions"><button type="button" class="btn btn-outline-info test-webhook-row" title="Test"><i class="bi bi-broadcast me-0"></i></button><button type="button" class="btn btn-outline-danger remove-webhook-row" title="Remove"><i class="bi bi-x-lg"></i></button></div>';
          rows.appendChild(row);
          var btn = row.querySelector('.remove-webhook-row');
          if (btn) bindRemove(btn);
          var testBtn = row.querySelector('.test-webhook-row');
          if (testBtn) bindTest(testBtn);
        });

        initTooltips(rows);
      })();
      </script>
    <?php endif; ?>
  <?php endif; ?>

  <?php
    $tp_showEvidenceEditor = is_admin() || (($view ?? '') === 'case' && !empty($tp_canEditCaseEvidence));
    $tp_evidenceEditRedirect = (($view ?? '') === 'case' && !empty($caseCode))
      ? ('?view=case&code=' . rawurlencode($caseCode) . '#case-view')
      : (string)($_SERVER['REQUEST_URI'] ?? '/');
  ?>
  <!-- Global Evidence Viewer / Editor Modal -->
  <div class="modal fade evidence-modal" id="evidenceModal" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog modal-lg modal-fullscreen-md-down modal-dialog-centered modal-dialog-scrollable">
      <div class="modal-content">
        <div class="modal-header">
          <h5 class="modal-title"><i class="bi bi-file-earmark-text me-2"></i><span id="evModalTitle">Evidence</span></h5>
          <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
        </div>
        <div class="modal-body">
          <div class="row g-3">
            <div class="col-12" id="evPreviewColumn">
              <div id="evPreview" class="ratio ratio-16x9 bg-dark d-flex align-items-center justify-content-center rounded overflow-hidden">
                <div class="text-secondary small">No preview available</div>
              </div>
            </div>
            <?php if ($tp_showEvidenceEditor): ?>
            <div class="col-lg-4 d-none" id="evEditPanel">
              <div class="card glass">
                <div class="card-body">
                  <h6 class="mb-3">Edit Evidence Title</h6>
                  <form method="post" action="" id="evEditForm">
                    <input type="hidden" name="action" value="update_evidence">
                    <input type="hidden" name="title_only" value="1">
                    <?php csrf_field(); ?>
                    <input type="hidden" name="evidence_id" id="evId">
                    <input type="hidden" name="case_id" id="evCaseId">
                    <input type="hidden" name="redirect_url" value="<?php echo htmlspecialchars($tp_evidenceEditRedirect); ?>">
                    <div class="mb-2">
                      <label class="form-label">Title</label>
                      <input type="text" name="title" id="evTitle" class="form-control" required>
                    </div>
                    <input type="hidden" name="type" id="evType" value="other">
                    <div class="d-grid">
                      <button class="btn btn-primary" type="submit"><i class="bi bi-save me-1"></i> Save Title</button>
                    </div>
                  </form>
                </div>
              </div>
            </div>
            <?php endif; ?>
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
              <div class="col-md-6">
                <label class="form-label">Phone Number</label>
                <input type="text" name="phone_number" class="form-control" inputmode="tel">
              </div>
            </div>
            <div class="row g-2 mt-2">
              <div class="col-md-6">
                <label class="form-label">Snapchat Username</label>
                <div class="input-group">
                  <span class="input-group-text">@</span>
                  <input type="text" name="snapchat_username" class="form-control" placeholder="username (optional)">
                </div>
              </div>
              <div class="col-md-6">
                <label class="form-label">TikTok Usernames</label>
                <input type="text" name="tiktok_username" class="form-control" placeholder="username1, username2 (no @)">
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
                <label class="form-label">Initial Status</label>
                <input type="text" class="form-control" value="Being Built" readonly>
                <div class="form-text">Submit it for review after the case is ready.</div>
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
              <label class="form-label">Case Tags</label>
              <?php echo render_case_tag_checkboxes(); ?>
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
                  <input type="email" name="email" class="form-control" maxlength="254" placeholder="you@example.com" required>
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
                  <input type="text" name="display_name" class="form-control" maxlength="120" placeholder="Your name" required>
                </div>
                <div class="mb-2">
                  <label class="form-label">Username</label>
                  <input type="text" name="username" class="form-control" minlength="3" maxlength="120" pattern="[A-Za-z0-9._-]+" placeholder="your_username" required>
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
                <?php tp_math_captcha_field('register'); ?>
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
  <script src="https://cdn.jsdelivr.net/npm/select2@4.1.0-rc.0/dist/js/select2.min.js"></script>
  <script src="https://cdn.datatables.net/1.13.8/js/jquery.dataTables.min.js"></script>
  <script src="https://cdn.datatables.net/1.13.8/js/dataTables.bootstrap5.min.js"></script>

  <script>
  jQuery(function ($) {
    $('.js-case-owner-select').each(function () {
      $(this).select2({
        theme: 'bootstrap-5',
        width: '100%',
        placeholder: 'Search by name, username or email'
      });
    });
  });
  </script>

  <script>
  document.addEventListener('DOMContentLoaded', function () {
    (function () {
      var searchInput = document.getElementById('caseReviewSearch');
      if (!searchInput) return;

      var pageSize = 10;
      var rows = Array.prototype.slice.call(document.querySelectorAll('[data-case-review-row]'));
      var sections = Array.prototype.slice.call(document.querySelectorAll('[data-case-review-section]'));
      var summary = document.getElementById('caseReviewSearchSummary');
      var noMatches = document.getElementById('caseReviewNoMatches');

      rows.forEach(function (row) {
        var section = row.closest('[data-case-review-section]');
        var statusTerms = section ? (section.getAttribute('data-case-review-status') || '') : '';
        row.setAttribute('data-case-review-search', (statusTerms + ' ' + (row.textContent || '')).toLocaleLowerCase());
      });

      var sectionStates = sections.map(function (section) {
        var sectionRows = Array.prototype.slice.call(section.querySelectorAll('[data-case-review-row]'));
        var tableWrap = section.querySelector('.table-responsive');
        var pager = null;

        if (tableWrap && sectionRows.length > 0) {
          pager = document.createElement('div');
          pager.className = 'case-review-pagination d-flex flex-column flex-sm-row align-items-sm-center justify-content-between gap-2 mt-3 d-none';
          pager.innerHTML =
            '<div class="small text-secondary" data-case-page-summary></div>' +
            '<div class="d-flex align-items-center gap-2">' +
              '<div class="small text-secondary text-nowrap" data-case-page-number></div>' +
              '<div class="btn-group btn-group-sm" role="group" aria-label="Case section pagination">' +
                '<button type="button" class="btn btn-outline-light" data-case-page-prev><i class="bi bi-chevron-left me-1"></i>Previous</button>' +
                '<button type="button" class="btn btn-outline-light" data-case-page-next>Next<i class="bi bi-chevron-right ms-1"></i></button>' +
              '</div>' +
            '</div>';
          tableWrap.insertAdjacentElement('afterend', pager);
        }

        return {
          section: section,
          rows: sectionRows,
          page: 1,
          pager: pager,
          pageSummary: pager ? pager.querySelector('[data-case-page-summary]') : null,
          pageNumber: pager ? pager.querySelector('[data-case-page-number]') : null,
          previousButton: pager ? pager.querySelector('[data-case-page-prev]') : null,
          nextButton: pager ? pager.querySelector('[data-case-page-next]') : null
        };
      });

      function renderCaseReviewLists(resetPages) {
        var query = searchInput.value.trim().toLocaleLowerCase();
        var terms = query === '' ? [] : query.split(/\s+/).filter(Boolean);
        var matchingCount = 0;

        sectionStates.forEach(function (state) {
          if (resetPages) state.page = 1;

          var matchingRows = state.rows.filter(function (row) {
            var searchableText = row.getAttribute('data-case-review-search') || '';
            return terms.every(function (term) { return searchableText.indexOf(term) !== -1; });
          });
          matchingCount += matchingRows.length;

          var totalPages = Math.max(1, Math.ceil(matchingRows.length / pageSize));
          state.page = Math.min(Math.max(1, state.page), totalPages);
          var start = (state.page - 1) * pageSize;
          var end = Math.min(start + pageSize, matchingRows.length);
          var pageRows = new Set(matchingRows.slice(start, end));

          state.rows.forEach(function (row) {
            row.classList.toggle('d-none', !pageRows.has(row));
          });

          state.section.classList.toggle('d-none', terms.length > 0 && matchingRows.length === 0);

          if (state.pager) {
            state.pager.classList.toggle('d-none', matchingRows.length <= pageSize);
            if (state.pageSummary) {
              state.pageSummary.textContent = matchingRows.length > 0
                ? 'Showing ' + (start + 1) + '\u2013' + end + ' of ' + matchingRows.length + ' cases'
                : 'No matching cases';
            }
            if (state.pageNumber) state.pageNumber.textContent = 'Page ' + state.page + ' of ' + totalPages;
            if (state.previousButton) state.previousButton.disabled = state.page <= 1;
            if (state.nextButton) state.nextButton.disabled = state.page >= totalPages;
          }
        });

        if (summary) {
          summary.textContent = terms.length > 0
            ? 'Found ' + matchingCount + ' of ' + rows.length + ' cases across all review sections.'
            : rows.length + (rows.length === 1 ? ' case' : ' cases') + ' across all review sections.';
        }
        if (noMatches) noMatches.classList.toggle('d-none', terms.length === 0 || matchingCount > 0);
      }

      sectionStates.forEach(function (state) {
        if (state.previousButton) {
          state.previousButton.addEventListener('click', function () {
            if (state.page <= 1) return;
            state.page--;
            renderCaseReviewLists(false);
            state.section.scrollIntoView({ behavior: 'smooth', block: 'start' });
          });
        }
        if (state.nextButton) {
          state.nextButton.addEventListener('click', function () {
            state.page++;
            renderCaseReviewLists(false);
            state.section.scrollIntoView({ behavior: 'smooth', block: 'start' });
          });
        }
      });

      searchInput.addEventListener('input', function () { renderCaseReviewLists(true); });
      renderCaseReviewLists(true);
    })();

    (function () {
      var analyticsCaseId = <?php
        $tpAnalyticsCaseId = -1;
        if (($view ?? '') === 'cases') { $tpAnalyticsCaseId = 0; }
        elseif (($view ?? '') === 'case') { $tpAnalyticsCaseId = (int)($viewCaseId ?? 0); }
        elseif (!empty($adminCaseCode) && isset($caseId)) { $tpAnalyticsCaseId = (int)$caseId; }
        echo (int)$tpAnalyticsCaseId;
      ?>;
      if (analyticsCaseId < 0 || !window.FormData || !window.fetch) return;
      var fd = new FormData();
      fd.append('action', 'update_view_client');
      fd.append('csrf_token', <?php echo json_encode($_SESSION['csrf_token'] ?? ''); ?>);
      fd.append('case_id', String(analyticsCaseId));
      fd.append('screen_width', String((window.screen && window.screen.width) || 0));
      fd.append('screen_height', String((window.screen && window.screen.height) || 0));
      fd.append('viewport_width', String(window.innerWidth || document.documentElement.clientWidth || 0));
      fd.append('viewport_height', String(window.innerHeight || document.documentElement.clientHeight || 0));
      try { fd.append('timezone', Intl.DateTimeFormat().resolvedOptions().timeZone || ''); } catch (e) { fd.append('timezone', ''); }
      fd.append('timezone_offset', String(new Date().getTimezoneOffset()));
      fd.append('platform', String((navigator.userAgentData && navigator.userAgentData.platform) || navigator.platform || ''));
      fetch(window.location.href, {
        method: 'POST',
        headers: { 'X-Requested-With': 'XMLHttpRequest' },
        body: fd,
        credentials: 'same-origin',
        keepalive: true
      }).catch(function () {});
    })();

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
        var isEditMode = btn.classList.contains('btn-edit-evidence');
        var showEvidenceTitles = <?php echo is_logged_in() ? 'true' : 'false'; ?>;
  
        // Fallbacks
        if (!type && mime.indexOf('/') > -1) type = mime.split('/')[0];
        if (!title || title.trim() === '') {
          // Derive from filename as last resort
          try { title = src.split('/').pop(); } catch (e) { title = 'Evidence'; }
        }
  
        // Set header fields
        var titleEl = document.getElementById('evModalTitle');
        if (titleEl) titleEl.textContent = showEvidenceTitles ? title : 'Evidence';

        // Viewing is evidence-only. Editing is a separate creator/admin action.
        var previewColumn = document.getElementById('evPreviewColumn');
        var editPanel = document.getElementById('evEditPanel');
        if (previewColumn) {
          previewColumn.classList.toggle('col-lg-8', isEditMode && !!editPanel);
          previewColumn.classList.toggle('col-12', !isEditMode || !editPanel);
        }
        if (editPanel) editPanel.classList.toggle('d-none', !isEditMode);
  
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
        if (isEditMode && evId && evCaseId && evTitle && evType) {
          evId.value = id;
          evCaseId.value = caseId;
          evTitle.value = title;
          if (evType.tagName === 'SELECT' && evType.querySelector('option[value="'+type+'"]')) {
            evType.value = type;
          } else if (evType.tagName !== 'SELECT') {
            evType.value = type || 'other';
          }
        }
      });
  
      evModal.addEventListener('hidden.bs.modal', function () {
        var preview = document.getElementById('evPreview');
        if (preview) {
          preview.innerHTML = '<div class="text-secondary small">No preview available</div>';
          preview.classList.add('ratio','ratio-16x9');
        }
        var previewColumn = document.getElementById('evPreviewColumn');
        var editPanel = document.getElementById('evEditPanel');
        if (previewColumn) {
          previewColumn.classList.remove('col-lg-8');
          previewColumn.classList.add('col-12');
        }
        if (editPanel) editPanel.classList.add('d-none');
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
      &copy; <?php echo date('Y'); ?> <?php echo htmlspecialchars($tpSiteTitle); ?>. All rights reserved.
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

<?php if (is_admin()): ?>
<div class="modal fade" id="rejectCaseModal" tabindex="-1" aria-labelledby="rejectCaseModalLabel" aria-hidden="true">
  <div class="modal-dialog modal-dialog-centered">
    <div class="modal-content">
      <div class="modal-header">
        <h5 class="modal-title" id="rejectCaseModalLabel"><i class="bi bi-x-circle me-2 text-danger"></i>Reject Case</h5>
        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
      </div>
      <form method="post" action="" id="rejectCaseForm">
        <div class="modal-body">
          <input type="hidden" name="action" value="reject_case">
          <?php csrf_field(); ?>
          <input type="hidden" name="case_id" id="rejectCaseId" value="">
          <input type="hidden" name="case_code" id="rejectCaseCode" value="">
          <p class="mb-3">Reject <strong id="rejectCaseName">this case</strong>? The submitter will be notified and can correct and resubmit it.</p>
          <label class="form-label" for="rejectCaseReason">Reason for rejection <span class="text-danger">*</span></label>
          <textarea class="form-control" id="rejectCaseReason" name="rejection_reason" rows="5" maxlength="2000" placeholder="Explain clearly what must be corrected before this case can be approved." required></textarea>
          <div class="form-text">This reason will be shown to the original submitter.</div>
        </div>
        <div class="modal-footer">
          <button type="button" class="btn btn-outline-light" data-bs-dismiss="modal">Cancel</button>
          <button type="submit" class="btn btn-danger"><i class="bi bi-x-circle me-1"></i>Reject and Notify Submitter</button>
        </div>
      </form>
    </div>
  </div>
</div>
<script>
document.addEventListener('DOMContentLoaded', function () {
  var modal = document.getElementById('rejectCaseModal');
  if (!modal) return;
  modal.addEventListener('show.bs.modal', function (event) {
    var button = event.relatedTarget;
    if (!button) return;
    document.getElementById('rejectCaseId').value = button.getAttribute('data-case-id') || '';
    document.getElementById('rejectCaseCode').value = button.getAttribute('data-case-code') || '';
    document.getElementById('rejectCaseName').textContent = button.getAttribute('data-case-name') || button.getAttribute('data-case-code') || 'this case';
    document.getElementById('rejectCaseReason').value = '';
  });
});
</script>
<?php endif; ?>

  </body>
  </html>
