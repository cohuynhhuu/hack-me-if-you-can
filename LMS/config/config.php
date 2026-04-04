<?php
/**
 * Database Configuration
 * Update these constants to match your environment.
 */
define('DB_HOST', 'localhost');
define('DB_NAME', 'lms_db');
define('DB_USER', 'root');
define('DB_PASS', '');
define('DB_CHARSET', 'utf8mb4');

/** Base URL (no trailing slash) */
define('BASE_URL', 'http://lms.local');

/** Application root path */
define('APP_ROOT', dirname(__DIR__));

/** Upload directory (relative to public/) */
define('UPLOAD_DIR', APP_ROOT . '/public/uploads/');

/** Maximum upload file size in bytes (10 MB) */
define('MAX_UPLOAD_SIZE', 10 * 1024 * 1024);

/** Allowed submission file extensions */
define('ALLOWED_SUBMISSION_TYPES', ['pdf', 'doc', 'docx', 'zip', 'py', 'txt']);
