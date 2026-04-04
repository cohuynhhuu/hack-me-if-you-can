<?php
require_once APP_ROOT . '/app/core/Controller.php';
require_once APP_ROOT . '/app/models/Course.php';
require_once APP_ROOT . '/app/models/Enrollment.php';
require_once APP_ROOT . '/app/models/Forum.php';

/**
 * CourseController — CRUD + enrollment
 */
class CourseController extends Controller
{
    private Course $courseModel;
    private Enrollment $enrollmentModel;
    private Forum $forumModel;

    public function __construct()
    {
        Auth::requireLogin();
        $this->courseModel     = new Course();
        $this->enrollmentModel = new Enrollment();
        $this->forumModel      = new Forum();
    }

    /** GET /course/index — Course list */
    public function index(): void
    {
        $perPage = 12;
        $page    = max(1, (int)($_GET['page'] ?? 1));

        // Admin sees all languages; everyone else sees courses matching their selected language
        $lang  = Auth::hasRole('admin') ? null : Lang::locale();
        $total = $this->courseModel->countAll($lang);

        $totalPages = $total > 0 ? (int)ceil($total / $perPage) : 1;
        $page       = min($page, $totalPages);
        $offset     = ($page - 1) * $perPage;

        $courses = $this->courseModel->getPaginated($lang, $offset, $perPage);

        // Enrich each course with enrollment count and (student) enrollment status
        foreach ($courses as &$c) {
            $c['student_count'] = $this->enrollmentModel->countByCourse($c['id']);
            if (Auth::hasRole('student')) {
                $c['is_enrolled'] = $this->enrollmentModel->isEnrolled(Auth::id(), $c['id']);
            }
        }

        $this->view('courses/index', [
            'courses'     => $courses,
            'currentLang' => Lang::locale(),
            'page'        => $page,
            'totalPages'  => $totalPages,
            'total'       => $total,
            'perPage'     => $perPage,
        ]);
    }

    /** GET /course/detail/{id} — Course detail page */
    public function detail(int $id): void
    {
        $course = $this->courseModel->findById($id);
        if (!$course) {
            $this->flash('danger', 'Course not found.');
            $this->redirect('course/index');
        }

        require_once APP_ROOT . '/app/models/Material.php';
        require_once APP_ROOT . '/app/models/Assignment.php';
        require_once APP_ROOT . '/app/models/Quiz.php';

        $materialModel   = new Material();
        $assignmentModel = new Assignment();
        $quizModel       = new Quiz();

        $materials   = $materialModel->getByCourse($id);
        $assignments = $assignmentModel->getByCourse($id);
        $quizzes     = $quizModel->getByCourse($id);
        $students    = $this->enrollmentModel->getStudentsByCourse($id);
        $forum       = $this->forumModel->findByCourse($id);

        $isEnrolled = Auth::hasRole('student')
            ? $this->enrollmentModel->isEnrolled(Auth::id(), $id)
            : true; // instructors/admin always see full detail

        $this->view('courses/detail', compact(
            'course', 'materials', 'assignments', 'quizzes',
            'students', 'forum', 'isEnrolled'
        ));
    }

    /** GET /course/create */
    public function create(): void
    {
        Auth::requireRole('instructor', 'admin');
        $this->view('courses/create');
    }

    /** POST /course/store */
    public function store(): void
    {
        Auth::requireRole('instructor', 'admin');

        $title       = trim($_POST['title'] ?? '');
        $description = trim($_POST['description'] ?? '');
        $category    = trim($_POST['category'] ?? '');
        $language    = $_POST['language'] ?? Lang::locale();

        if (empty($title)) {
            $this->flash('danger', 'Course title is required.');
            $this->redirect('course/create');
        }

        $courseId = $this->courseModel->create(
            Auth::id(), $title, $description, $category, $language
        );

        // Auto-create a forum for the new course
        $this->forumModel->create($courseId, $title . ' - Discussion');

        $this->flash('success', 'Course created successfully.');
        $this->redirect('course/detail/' . $courseId);
    }

    /** GET /course/edit/{id} */
    public function edit(int $id): void
    {
        Auth::requireRole('instructor', 'admin');
        $course = $this->courseModel->findById($id);
        if (!$course) {
            $this->flash('danger', 'Course not found.');
            $this->redirect('course/index');
        }
        $this->view('courses/edit', ['course' => $course]);
    }

    /** POST /course/update/{id} */
    public function update(int $id): void
    {
        Auth::requireRole('instructor', 'admin');

        $title       = trim($_POST['title'] ?? '');
        $description = trim($_POST['description'] ?? '');
        $category    = trim($_POST['category'] ?? '');
        $status      = $_POST['status'] ?? 'active';
        $language    = $_POST['language'] ?? 'en';

        if (empty($title)) {
            $this->flash('danger', 'Course title is required.');
            $this->redirect('course/edit/' . $id);
        }

        if (!in_array($status, ['active', 'inactive', 'archived'], true)) {
            $status = 'active';
        }

        $this->courseModel->update($id, $title, $description, $category, $status, $language);
        $this->flash('success', 'Course updated.');
        $this->redirect('course/detail/' . $id);
    }

    /** POST /course/delete/{id} */
    public function delete(int $id): void
    {
        Auth::requireRole('instructor', 'admin');
        $this->courseModel->delete($id);
        $this->flash('success', 'Course deleted.');
        $this->redirect('course/index');
    }

    /** POST /course/enroll/{id} — Student enrolls */
    public function enroll(int $courseId): void
    {
        Auth::requireRole('student');
        if (!$this->enrollmentModel->isEnrolled(Auth::id(), $courseId)) {
            $this->enrollmentModel->enroll(Auth::id(), $courseId);
            $this->flash('success', 'You have enrolled in the course.');
        } else {
            $this->flash('info', 'You are already enrolled.');
        }
        $this->redirect('course/detail/' . $courseId);
    }

    /** POST /course/unenroll/{id} — Student unenrolls */
    public function unenroll(int $courseId): void
    {
        Auth::requireRole('student');
        $this->enrollmentModel->unenroll(Auth::id(), $courseId);
        $this->flash('success', 'You have unenrolled from the course.');
        $this->redirect('course/index');
    }
}
