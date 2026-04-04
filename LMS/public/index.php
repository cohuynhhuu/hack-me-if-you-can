<?php
/**
 * Front Controller / Entry Point
 */

// Load configuration
require_once dirname(__DIR__) . '/config/config.php';

// Start session securely
ini_set('session.cookie_httponly', '1');
ini_set('session.use_strict_mode', '1');
session_start();

// Load internationalisation helper
require_once APP_ROOT . '/app/core/Lang.php';
Lang::load();

// Load Router and bootstrap
require_once APP_ROOT . '/app/core/Router.php';
require_once APP_ROOT . '/app/core/App.php';

new App();
