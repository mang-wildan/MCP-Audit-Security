<?php
// INERT FIXTURE: fake values only, exists to test secret redaction.
define('DB_NAME', 'wordpress');
define('DB_PASSWORD', 'fake-not-a-real-password');
define('AUTH_KEY', 'fake-auth-key-value-000');
$table_prefix = 'wp_';
require_once ABSPATH . 'wp-settings.php';
