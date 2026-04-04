<?php
require_once APP_ROOT . '/app/core/Controller.php';

class LangController extends Controller
{
    public function set(string $lang = 'en'): void
    {
        $allowed = ['en', 'vi'];
        $_SESSION['lang'] = in_array($lang, $allowed) ? $lang : 'en';

        // SSRF protection: only redirect back to same host
        $back   = $_SERVER['HTTP_REFERER'] ?? BASE_URL . '/dashboard/index';
        $host   = parse_url($back,    PHP_URL_HOST);
        $myHost = parse_url(BASE_URL, PHP_URL_HOST);
        if ($host !== $myHost) {
            $back = BASE_URL . '/dashboard/index';
        }

        $this->redirect($back);
    }
}
