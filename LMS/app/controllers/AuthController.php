<?php
require_once APP_ROOT . '/app/core/Controller.php';
require_once APP_ROOT . '/app/models/User.php';

/**
 * AuthController — Login, Register, Logout
 */
class AuthController extends Controller
{
    private User $userModel;

    public function __construct()
    {
        $this->userModel = new User();
    }

    /** GET /auth/login */
    public function login(): void
    {
        if (Auth::check()) {
            $this->redirect('dashboard/index');
        }
        $this->view('auth/login');
    }

    /** POST /auth/login */
    public function doLogin(): void
    {
        $email    = trim($_POST['email'] ?? '');
        $password = $_POST['password'] ?? '';

        // Basic validation
        if (empty($email) || empty($password)) {
            $this->flash('danger', 'Please fill in all fields.');
            $this->redirect('auth/login');
        }

        $user = $this->userModel->findByEmail($email);

        if (!$user || !password_verify($password, $user['password'])) {
            $this->flash('danger', 'Invalid email or password.');
            $this->redirect('auth/login');
        }

        Auth::login($user);
        $this->flash('success', 'Welcome back, ' . htmlspecialchars($user['name']) . '!');
        $this->redirect('dashboard/index');
    }

    /** GET /auth/register */
    public function register(): void
    {
        if (Auth::check()) {
            $this->redirect('dashboard/index');
        }
        $this->view('auth/register');
    }

    /** POST /auth/register */
    public function doRegister(): void
    {
        $name     = trim($_POST['name'] ?? '');
        $email    = trim($_POST['email'] ?? '');
        $password = $_POST['password'] ?? '';
        $confirm  = $_POST['password_confirm'] ?? '';
        $role     = $_POST['role'] ?? 'student';

        // Validate
        $errors = [];
        if (empty($name))                         $errors[] = 'Name is required.';
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) $errors[] = 'Valid email is required.';
        if (strlen($password) < 6)                $errors[] = 'Password must be at least 6 characters.';
        if ($password !== $confirm)               $errors[] = 'Passwords do not match.';
        if (!in_array($role, ['student', 'instructor'], true)) $role = 'student';

        if ($errors) {
            $this->flash('danger', implode(' ', $errors));
            $this->redirect('auth/register');
        }

        if ($this->userModel->emailExists($email)) {
            $this->flash('danger', 'That email is already registered.');
            $this->redirect('auth/register');
        }

        $this->userModel->create($name, $email, $password, $role);
        $this->flash('success', 'Account created. Please log in.');
        $this->redirect('auth/login');
    }

    /** GET /auth/logout */
    public function logout(): void
    {
        Auth::logout();
        $this->redirect('auth/login');
    }
}
