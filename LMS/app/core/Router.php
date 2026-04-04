<?php
/**
 * Router
 * Parses the URL and dispatches to the appropriate Controller & method.
 *
 * URL format: /controller/method/param1/param2
 * Default:    AuthController::index()
 */
class Router
{
    private string $url;

    public function __construct()
    {
        $this->url = $this->parseUrl();
    }

    public function dispatch(): void
    {
        $parts = array_values(array_filter(explode('/', $this->url)));

        // Determine controller, method, params
        $controllerName = isset($parts[0])
            ? ucfirst(strtolower($parts[0])) . 'Controller'
            : 'AuthController';

        $method = isset($parts[1])
            ? preg_replace('/[^a-zA-Z0-9_]/', '', $parts[1])
            : 'index';

        $params = array_slice($parts, 2);

        $controllerFile = APP_ROOT . '/app/controllers/' . $controllerName . '.php';

        if (!file_exists($controllerFile)) {
            $this->notFound();
            return;
        }

        require_once $controllerFile;

        if (!class_exists($controllerName)) {
            $this->notFound();
            return;
        }

        $controller = new $controllerName();

        if (!method_exists($controller, $method)) {
            $this->notFound();
            return;
        }

        call_user_func_array([$controller, $method], $params);
    }

    private function parseUrl(): string
    {
        if (isset($_GET['url'])) {
            return rtrim(htmlspecialchars($_GET['url'], ENT_QUOTES, 'UTF-8'), '/');
        }
        return '';
    }

    private function notFound(): void
    {
        http_response_code(404);
        require_once APP_ROOT . '/app/views/errors/404.php';
    }
}
