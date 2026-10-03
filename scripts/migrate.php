<?php
// Run with the same DB_DSN / DB_USER / DB_PASS environment as PHP-FPM.
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
define('TP_RUN_MIGRATIONS', true);
require dirname(__DIR__) . '/index.php';
