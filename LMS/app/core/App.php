<?php
/**
 * Application Bootstrap
 */
class App
{
    public function __construct()
    {
        // Load core files
        require_once APP_ROOT . '/app/core/Database.php';
        require_once APP_ROOT . '/app/core/Model.php';
        require_once APP_ROOT . '/app/core/Controller.php';
        require_once APP_ROOT . '/app/core/Auth.php';

        $router = new Router();
        $router->dispatch();
    }
}
