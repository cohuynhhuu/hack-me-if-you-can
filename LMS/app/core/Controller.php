<?php
/**
 * Base Controller
 * Provides helpers for loading views, redirecting, and accessing session data.
 */
abstract class Controller
{
    /**
     * Render a view file with optional data passed as local variables.
     *
     * @param string $view  Dot-notation path, e.g. 'courses/index'
     * @param array  $data  Associative array of variables to extract into the view
     */
    protected function view(string $view, array $data = []): void
    {
        // Make data available inside the view
        extract($data);

        $viewPath = APP_ROOT . '/app/views/' . str_replace('.', '/', $view) . '.php';

        if (!file_exists($viewPath)) {
            http_response_code(500);
            die("View not found: {$view}");
        }

        require_once $viewPath;
    }

    /**
     * Redirect to a URL (relative to BASE_URL or absolute).
     */
    protected function redirect(string $url): void
    {
        // If not a full URL, prepend BASE_URL
        if (!str_starts_with($url, 'http')) {
            $url = BASE_URL . '/' . ltrim($url, '/');
        }
        header("Location: {$url}");
        exit;
    }

    /**
     * Return JSON response (for simple AJAX endpoints).
     */
    protected function json(mixed $data, int $status = 200): void
    {
        http_response_code($status);
        header('Content-Type: application/json');
        echo json_encode($data);
        exit;
    }

    /**
     * Flash a message into the session to display on the next request.
     */
    protected function flash(string $type, string $message): void
    {
        $_SESSION['flash'] = ['type' => $type, 'message' => $message];
    }

    /**
     * Load a model class and return an instance.
     */
    protected function model(string $modelName): object
    {
        $path = APP_ROOT . '/app/models/' . $modelName . '.php';
        require_once $path;
        return new $modelName();
    }
}
