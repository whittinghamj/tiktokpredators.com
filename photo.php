<?php
// Use the application bootstrap so private case photos obey account/token access.
$_GET['action'] = 'serve_case_photo';
require __DIR__ . '/index.php';
