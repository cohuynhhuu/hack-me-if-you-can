<?php
require_once APP_ROOT . '/app/core/Controller.php';
require_once APP_ROOT . '/app/models/User.php';
require_once APP_ROOT . '/app/models/Course.php';
require_once APP_ROOT . '/app/models/Enrollment.php';

/**
 * AdminController — User management, system overview
 */
class AdminController extends Controller
{
    private User $userModel;
    private Course $courseModel;
    private Enrollment $enrollmentModel;

    public function __construct()
    {
        Auth::requireRole('admin');
        $this->userModel       = new User();
        $this->courseModel     = new Course();
        $this->enrollmentModel = new Enrollment();
    }

    /** GET /admin/index */
    public function index(): void
    {
        $users   = $this->userModel->getAll();
        $courses = $this->courseModel->getAll();
        $this->view('admin/index', compact('users', 'courses'));
    }

    /** POST /admin/createUser */
    public function createUser(): void
    {
        $name     = trim($_POST['name'] ?? '');
        $email    = trim($_POST['email'] ?? '');
        $password = $_POST['password'] ?? 'Password@123';
        $role     = $_POST['role'] ?? 'student';

        if (empty($name) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $this->flash('danger', 'Valid name and email are required.');
            $this->redirect('admin/index');
        }

        if (!in_array($role, ['student', 'instructor', 'admin'], true)) {
            $role = 'student';
        }

        if ($this->userModel->emailExists($email)) {
            $this->flash('danger', 'Email already in use.');
            $this->redirect('admin/index');
        }

        $this->userModel->create($name, $email, $password, $role);
        $this->flash('success', 'User created.');
        $this->redirect('admin/index');
    }

    /** POST /admin/deleteUser/{id} */
    public function deleteUser(int $id): void
    {
        if ($id === Auth::id()) {
            $this->flash('danger', 'You cannot delete your own account.');
            $this->redirect('admin/index');
        }
        $this->userModel->delete($id);
        $this->flash('success', 'User deleted.');
        $this->redirect('admin/index');
    }
}
