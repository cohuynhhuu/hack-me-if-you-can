<?php

class Lang
{
    private static array $strings = [];
    private static string $locale = 'en';

    public static function load(): void
    {
        $requested = $_SESSION['lang'] ?? 'en';
        self::$locale = in_array($requested, ['en', 'vi']) ? $requested : 'en';
        $file = APP_ROOT . '/app/lang/' . self::$locale . '.php';
        self::$strings = file_exists($file) ? require $file : [];
    }

    public static function t(string $key): string
    {
        return self::$strings[$key] ?? $key;
    }

    public static function locale(): string
    {
        return self::$locale;
    }
}

function t(string $key): string
{
    return Lang::t($key);
}
