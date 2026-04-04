<?php
require_once APP_ROOT . '/app/core/Controller.php';
require_once APP_ROOT . '/app/models/User.php';
require_once APP_ROOT . '/app/models/Course.php';
require_once APP_ROOT . '/app/models/Enrollment.php';
require_once APP_ROOT . '/app/models/Submission.php';
require_once APP_ROOT . '/app/models/QuizResult.php';
require_once APP_ROOT . '/app/models/Assignment.php';
require_once APP_ROOT . '/app/models/Message.php';

/**
 * DashboardController — Role-aware analytics dashboard
 */
class DashboardController extends Controller
{
    private Course $courseModel;
    private Enrollment $enrollmentModel;
    private Submission $submissionModel;
    private QuizResult $quizResultModel;
    private Assignment $assignmentModel;
    private User $userModel;
    private Message $messageModel;

    public function __construct()
    {
        Auth::requireLogin();
        $this->courseModel     = new Course();
        $this->enrollmentModel = new Enrollment();
        $this->submissionModel = new Submission();
        $this->quizResultModel = new QuizResult();
        $this->assignmentModel = new Assignment();
        $this->userModel       = new User();
        $this->messageModel    = new Message();
    }

    /** GET /dashboard/index */
    public function index(): void
    {
        $role = Auth::role();

        if ($role === 'admin') {
            $this->adminDashboard();
        } elseif ($role === 'instructor') {
            $this->instructorDashboard();
        } else {
            $this->studentDashboard();
        }
    }

    /* -------------------------------------------------- */
    /*  Student Dashboard                                  */
    /* -------------------------------------------------- */
    private function studentDashboard(): void
    {
        $studentId = Auth::id();
        $db = \Database::getInstance();

        // Enrolled courses
        $courses = $this->courseModel->getEnrolledByStudent($studentId);

        // Recent quiz results
        $quizResults = $this->quizResultModel->getByStudent($studentId);

        // Assignment submissions
        $submissions = $this->submissionModel->getByStudent($studentId);

        // Stats
        $completedQuizzes      = count($quizResults);
        $submittedAssignments  = count($submissions);
        $avgScore = null;
        if ($completedQuizzes > 0) {
            $total = array_sum(array_map(
                fn($r) => $r['max_score'] > 0 ? round($r['score'] / $r['max_score'] * 100, 1) : 0,
                $quizResults
            ));
            $avgScore = round($total / $completedQuizzes, 1);
        }

        // Progress per course: graded submissions / total assignments
        $progress = [];
        foreach ($courses as $c) {
            $total  = count($this->assignmentModel->getByCourse($c['id']));
            $done   = $this->submissionModel->countGradedByStudentAndCourse($studentId, $c['id']);
            $progress[$c['id']] = [
                'total'   => $total,
                'done'    => $done,
                'percent' => $total > 0 ? round($done / $total * 100) : 0,
            ];
        }

        // Recent submissions with assignment + course title
        $stmt = $db->prepare(
            'SELECT s.submitted_at, s.grade, a.title AS assignment_title, c.title AS course_title
             FROM submissions s
             JOIN assignments a ON a.id = s.assignment_id
             JOIN courses c ON c.id = a.course_id
             WHERE s.student_id = ?
             ORDER BY s.submitted_at DESC LIMIT 5'
        );
        $stmt->execute([$studentId]);
        $recentSubmissions = $stmt->fetchAll();

        // Unread messages
        $unreadCount = $this->messageModel->countUnread($studentId);

        // Chart data: scores per quiz
        $quizChartLabels = [];
        $quizChartData   = [];
        foreach ($quizResults as $r) {
            $quizChartLabels[] = $r['quiz_title'] ?? 'Quiz';
            $quizChartData[]   = $r['max_score'] > 0
                ? round($r['score'] / $r['max_score'] * 100, 1)
                : 0;
        }

        $this->view('dashboard/index', compact(
            'courses', 'progress', 'unreadCount',
            'completedQuizzes', 'submittedAssignments', 'avgScore',
            'recentSubmissions', 'quizChartLabels', 'quizChartData'
        ));
    }

    /* -------------------------------------------------- */
    /*  Instructor Dashboard                               */
    /* -------------------------------------------------- */
    private function instructorDashboard(): void
    {
        $instructorId = Auth::id();
        $courses      = $this->courseModel->getByInstructor($instructorId);
        $db = \Database::getInstance();

        // Build flat courseStats array with keys the view expects
        $courseStats    = [];
        $pendingGrading = 0;
        $totalQuizzes   = 0;

        foreach ($courses as $c) {
            $courseId = $c['id'];

            $enrollmentCount = $this->enrollmentModel->countByCourse($courseId);

            // Average quiz score
            $stmt = $db->prepare(
                'SELECT AVG(qr.score / NULLIF(qr.max_score, 0) * 100)
                 FROM quiz_results qr
                 JOIN quizzes q ON q.id = qr.quiz_id
                 WHERE q.course_id = ?'
            );
            $stmt->execute([$courseId]);
            $avg = $stmt->fetchColumn();
            $avgQuizScore = $avg !== false ? round((float)$avg, 1) : null;

            // Pending ungraded submissions
            $stmt2 = $db->prepare(
                'SELECT COUNT(*) FROM submissions s
                 JOIN assignments a ON a.id = s.assignment_id
                 WHERE a.course_id = ? AND s.grade IS NULL'
            );
            $stmt2->execute([$courseId]);
            $pendingSubmissions = (int)$stmt2->fetchColumn();
            $pendingGrading += $pendingSubmissions;

            // Quiz count
            $stmt3 = $db->prepare('SELECT COUNT(*) FROM quizzes WHERE course_id = ?');
            $stmt3->execute([$courseId]);
            $totalQuizzes += (int)$stmt3->fetchColumn();

            $courseStats[] = [
                'id'                  => $c['id'],
                'title'               => $c['title'],
                'enrollment_count'    => $enrollmentCount,
                'avg_quiz_score'      => $avgQuizScore,
                'pending_submissions' => $pendingSubmissions,
            ];
        }

        // Chart data
        $enrollChartLabels = array_column($courseStats, 'title');
        $enrollChartData   = array_column($courseStats, 'enrollment_count');

        $unreadCount = $this->messageModel->countUnread($instructorId);

        $this->view('dashboard/index', compact(
            'courses', 'courseStats', 'unreadCount',
            'pendingGrading', 'totalQuizzes',
            'enrollChartLabels', 'enrollChartData'
        ));
    }

    /* -------------------------------------------------- */
    /*  Admin Dashboard                                    */
    /* -------------------------------------------------- */
    private function adminDashboard(): void
    {
        $totalUsers       = $this->userModel->count();
        $totalStudents    = $this->userModel->count('student');
        $totalInstructors = $this->userModel->count('instructor');
        $totalCourses     = $this->courseModel->count();
        $totalEnrollments = $this->enrollmentModel->countTotal();

        $db = \Database::getInstance();

        // Top 5 courses with instructor name + student count
        $topCourses = $db->query(
            'SELECT c.id, c.title, u.name AS instructor_name, COUNT(e.id) AS student_count
             FROM courses c
             LEFT JOIN users u ON u.id = c.instructor_id
             LEFT JOIN enrollments e ON e.course_id = c.id
             GROUP BY c.id, c.title, u.name
             ORDER BY student_count DESC
             LIMIT 5'
        )->fetchAll();

        // Chart: all courses by enrollment
        $allForChart = $db->query(
            'SELECT c.title, COUNT(e.id) AS student_count
             FROM courses c
             LEFT JOIN enrollments e ON e.course_id = c.id
             GROUP BY c.id, c.title
             ORDER BY student_count DESC'
        )->fetchAll();
        $enrollChartLabels = array_column($allForChart, 'title');
        $enrollChartData   = array_column($allForChart, 'student_count');

        $unreadCount = $this->messageModel->countUnread(Auth::id());

        $this->view('dashboard/index', compact(
            'totalUsers', 'totalStudents', 'totalInstructors',
            'totalCourses', 'totalEnrollments',
            'topCourses', 'enrollChartLabels', 'enrollChartData',
            'unreadCount'
        ));
    }
}
