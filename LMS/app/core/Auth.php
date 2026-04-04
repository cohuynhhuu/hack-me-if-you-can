<?php
/**
 * Auth — Session-based authentication helper
 */
class Auth
{
    /** Check if a user is currently logged in. */
    public static function check(): bool
    {
        return isset($_SESSION['user_id']);
    }

    /** Get the current user's ID. */
    public static function id(): ?int
    {
        return $_SESSION['user_id'] ?? null;
    }

    /** Get the current user's role. */
    public static function role(): ?string
    {
        return $_SESSION['user_role'] ?? null;
    }

    /** Get the current user's name. */
    public static function name(): ?string
    {
        return $_SESSION['user_name'] ?? null;
    }

    /** Get the full current user array stored in session. */
    public static function user(): ?array
    {
        if (!self::check()) return null;
        return [
            'id'   => $_SESSION['user_id'],
            'name' => $_SESSION['user_name'],
            'role' => $_SESSION['user_role'],
        ];
    }

    /** Store user data in session after successful login. */
    public static function login(array $user): void
    {
        session_regenerate_id(true); // Prevent session fixation
        $_SESSION['user_id']   = (int)$user['id'];
        $_SESSION['user_name'] = $user['name'];
        $_SESSION['user_role'] = $user['role'];
    }

    /** Destroy session on logout. */
    public static function logout(): void
    {
        $_SESSION = [];
        if (ini_get('session.use_cookies')) {
            $params = session_get_cookie_params();
            setcookie(
                session_name(), '', time() - 42000,
                $params['path'], $params['domain'],
                $params['secure'], $params['httponly']
            );
        }
        session_destroy();
    }

    /**
     * Require authentication; redirect to login if not logged in.
     */
    public static function requireLogin(): void
    {
        if (!self::check()) {
            header('Location: ' . BASE_URL . '/auth/login');
            exit;
        }
    }

    /**
     * Require a specific role; redirect to dashboard if role doesn't match.
     */
    public static function requireRole(string ...$roles): void
    {
        self::requireLogin();
        if (!in_array(self::role(), $roles, true)) {
            header('Location: ' . BASE_URL . '/dashboard/index');
            exit;
        }
    }

    /** Check if the current user has a given role. */
    public static function hasRole(string ...$roles): bool
    {
        return in_array(self::role(), $roles, true);
    }
}
