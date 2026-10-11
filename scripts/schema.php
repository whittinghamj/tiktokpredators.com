<?php
// Deployment-only schema upgrades. Never execute through HTTP.
if (PHP_SAPI !== 'cli' || !defined('TP_RUN_MIGRATIONS')) { http_response_code(404); exit; }
// --- Account roles: keep legacy analyst accounts and add moderator access ---
try {
  $roleCol = $pdo->query("SHOW COLUMNS FROM users LIKE 'role'");
  $roleInfo = $roleCol ? $roleCol->fetch() : null;
  $roleType = strtolower((string)($roleInfo['Type'] ?? ''));
  if ($roleInfo && strpos($roleType, 'enum(') === 0 && strpos($roleType, "'moderator'") === false) {
    $pdo->exec("ALTER TABLE users MODIFY COLUMN role ENUM('viewer','moderator','analyst','admin') NOT NULL DEFAULT 'viewer'");
  }
} catch (Throwable $e) {
  $_SESSION['sql_error'] = $_SESSION['sql_error'] ?? $e->getMessage();
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
  $defaultSettings = array_merge([
    'site_title' => 'TikTokPredators',
    'meta_data' => 'A public, auditable repository documenting abusive behaviour by TikTok accounts — case records, evidence, and verifiable proof to expose predators and support accountability.',
    'openai_api_key' => '',
    'discord_webhook_key' => '',
    'discord_webhooks' => '[]',
  ], tp_ollama_settings_defaults());
  $seed = $pdo->prepare('INSERT IGNORE INTO project_settings (setting_key, setting_value) VALUES (?, ?)');
  foreach ($defaultSettings as $settingKey => $settingValue) {
    $seed->execute([$settingKey, $settingValue]);
  }
} catch (Throwable $e) {
  $_SESSION['sql_error'] = $_SESSION['sql_error'] ?? $e->getMessage();
}
  // --- Cases schema safety: ensure profile fields exist and username fields have suitable storage ---
  try {
    $dateOfBirthCol = $pdo->query("SHOW COLUMNS FROM cases LIKE 'date_of_birth'");
    if (!$dateOfBirthCol || !$dateOfBirthCol->fetch()) {
      $pdo->exec("ALTER TABLE cases ADD COLUMN date_of_birth DATE NULL AFTER person_name");
    }
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
    $discordCol = $pdo->query("SHOW COLUMNS FROM cases LIKE 'discord_username'");
    if (!$discordCol || !$discordCol->fetch()) {
      $pdo->exec("ALTER TABLE cases ADD COLUMN discord_username VARCHAR(255) NULL AFTER snapchat_username");
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
// --- Evidence image display orientation (keeps the original upload immutable) ---
$tp_evidence_rotation_ready = false;
try {
  $evidenceRotationCol = $pdo->query("SHOW COLUMNS FROM evidence LIKE 'rotation_degrees'");
  if (!$evidenceRotationCol || !$evidenceRotationCol->fetch()) {
    $pdo->exec("ALTER TABLE evidence ADD COLUMN rotation_degrees SMALLINT UNSIGNED NOT NULL DEFAULT 0 AFTER size_bytes");
  }
  $tp_evidence_rotation_ready = true;
} catch (Throwable $e) {
  $_SESSION['sql_error'] = $_SESSION['sql_error'] ?? $e->getMessage();
}
// --- Evidence public derivatives (immutable original + current server-rendered redaction) ---
$tp_evidence_redactions_ready = false;
try {
  $pdo->exec(<<<SQL
CREATE TABLE IF NOT EXISTS evidence_redactions (
  evidence_id BIGINT UNSIGNED NOT NULL PRIMARY KEY,
  public_filepath VARCHAR(1024) NOT NULL,
  public_mime_type VARCHAR(127) NOT NULL,
  public_size_bytes BIGINT UNSIGNED NOT NULL DEFAULT 0,
  public_sha256 CHAR(64) NOT NULL,
  source_sha256 CHAR(64) NOT NULL,
  source_rotation SMALLINT UNSIGNED NOT NULL DEFAULT 0,
  source_width INT UNSIGNED NOT NULL,
  source_height INT UNSIGNED NOT NULL,
  mask_json LONGTEXT NOT NULL,
  region_count INT UNSIGNED NOT NULL DEFAULT 0,
  updated_by BIGINT UNSIGNED NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_evidence_redactions_updated_by (updated_by),
  INDEX idx_evidence_redactions_updated_at (updated_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
SQL
  );
  $tp_evidence_redactions_ready = true;
} catch (Throwable $e) {
  $_SESSION['sql_error'] = $_SESSION['sql_error'] ?? $e->getMessage();
  log_console('ERROR', 'Evidence redaction schema: ' . $e->getMessage());
  // A deployment may pre-create the table while denying runtime DDL. Confirm the
  // required columns with a read before deciding the feature is unavailable.
  try {
    $pdo->query('SELECT evidence_id, public_filepath, public_mime_type, public_size_bytes, public_sha256, source_sha256, source_rotation, source_width, source_height, mask_json, region_count, updated_by, created_at, updated_at FROM evidence_redactions LIMIT 0');
    $tp_evidence_redactions_ready = true;
  } catch (Throwable $ignored) {
    $tp_evidence_redactions_ready = false;
  }
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
            public_ip VARCHAR(45) NULL,
            forwarded_for VARCHAR(255) NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_case_id_created (case_id, created_at),
            INDEX idx_event_type (event_type),
            INDEX idx_ref_evidence (ref_evidence_id),
            INDEX idx_case_event_ip (public_ip)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    ");

    // Safe schema migration for installations created before event IP logging.
    $caseEventColumns = [
        'public_ip' => "ALTER TABLE case_events ADD COLUMN public_ip VARCHAR(45) NULL AFTER created_by",
        'forwarded_for' => "ALTER TABLE case_events ADD COLUMN forwarded_for VARCHAR(255) NULL AFTER public_ip",
    ];
    foreach ($caseEventColumns as $columnName => $alterSql) {
        $column = $pdo->query("SHOW COLUMNS FROM case_events LIKE " . $pdo->quote($columnName));
        if (!$column || !$column->fetch()) {
            $pdo->exec($alterSql);
        }
    }
    $caseEventIpIndex = $pdo->query("SHOW INDEX FROM case_events WHERE Key_name = 'idx_case_event_ip'");
    if (!$caseEventIpIndex || !$caseEventIpIndex->fetch()) {
        $pdo->exec('ALTER TABLE case_events ADD INDEX idx_case_event_ip (public_ip)');
    }
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
// Private Ollama reports deliberately live outside cases, so public case queries
// cannot accidentally select the report or chat history.
try {
  $pdo->exec("CREATE TABLE IF NOT EXISTS case_ollama_reports (
    case_id BIGINT UNSIGNED NOT NULL PRIMARY KEY,
    requested_version BIGINT UNSIGNED NOT NULL DEFAULT 1,
    processed_version BIGINT UNSIGNED NOT NULL DEFAULT 0,
    status ENUM('Queued','Processing','Ready','Partial','Failed') NOT NULL DEFAULT 'Queued',
    processing_token VARCHAR(64) NULL,
    report_text LONGTEXT NULL,
    report_json LONGTEXT NULL,
    model VARCHAR(255) NULL,
    error_message VARCHAR(1000) NULL,
    queued_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    generated_at DATETIME NULL,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_ollama_queue (status, queued_at)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
  $pdo->exec("CREATE TABLE IF NOT EXISTS case_ollama_messages (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    case_id BIGINT UNSIGNED NOT NULL,
    user_id BIGINT UNSIGNED NOT NULL,
    report_version BIGINT UNSIGNED NOT NULL,
    question TEXT NOT NULL,
    answer LONGTEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_ollama_chat (case_id, user_id, report_version, id)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
  // Existing cases are queued once; rerunning migrations preserves their reports.
  $pdo->exec('INSERT IGNORE INTO case_ollama_reports (case_id) SELECT id FROM cases');
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
// --- Catch a Pred public leaderboard ---
$tp_catch_pred_ready = false;
try {
  $pdo->exec(<<<SQL
CREATE TABLE IF NOT EXISTS catch_pred_scores (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  round_token_hash CHAR(64) NOT NULL,
  player_name VARCHAR(24) NOT NULL,
  score SMALLINT UNSIGNED NOT NULL,
  target_count SMALLINT UNSIGNED NOT NULL,
  duration_ms INT UNSIGNED NOT NULL,
  is_visible TINYINT(1) NOT NULL DEFAULT 1,
  created_by BIGINT UNSIGNED NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  moderated_by BIGINT UNSIGNED NULL,
  moderated_at DATETIME NULL,
  UNIQUE KEY uq_catch_pred_round (round_token_hash),
  INDEX idx_catch_pred_rank (is_visible, score, duration_ms, created_at),
  INDEX idx_catch_pred_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
SQL
  );
  $tp_catch_pred_ready = true;
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


// Composite indexes for bounded analytics and evidence queries.
foreach ([
  'case_views' => ['idx_ip_time_case' => '(ip_hash, viewed_at, case_id)', 'idx_case_ip_time' => '(case_id, ip_hash, viewed_at)'],
  'evidence' => ['idx_evidence_case_created' => '(case_id, created_at)'],
] as $table => $indexes) {
  foreach ($indexes as $name => $columns) {
    try {
      $check = $pdo->query("SHOW INDEX FROM `$table` WHERE Key_name = " . $pdo->quote($name));
      if (!$check->fetch()) { $pdo->exec("ALTER TABLE `$table` ADD INDEX `$name` $columns"); }
    } catch (Throwable $e) { $_SESSION['sql_error'] = $e->getMessage(); }
  }
}
