<?php
require_once APP_ROOT . '/app/core/Controller.php';
require_once APP_ROOT . '/app/models/Assignment.php';
require_once APP_ROOT . '/app/models/Submission.php';
require_once APP_ROOT . '/app/models/Course.php';

/**
 * AssignmentController — Create assignments, submit work, grade
 */
class AssignmentController extends Controller
{
    private Assignment $assignmentModel;
    private Submission $submissionModel;
    private Course $courseModel;

    public function __construct()
    {
        Auth::requireLogin();
        $this->assignmentModel = new Assignment();
        $this->submissionModel = new Submission();
        $this->courseModel     = new Course();
    }

    /** GET /assignment/view/{id} — View assignment + submissions (instructor) or submission form (student) */
    public function view(int $id): void
    {
        $assignment = $this->assignmentModel->findById($id);
        if (!$assignment) {
            $this->flash('danger', 'Assignment not found.');
            $this->redirect('course/index');
        }

        $course = $this->courseModel->findById($assignment['course_id']);

        if (Auth::hasRole('student')) {
            $submission = $this->submissionModel->findByStudentAndAssignment(Auth::id(), $id);
            $this->view('assignments/submit', compact('assignment', 'course', 'submission'));
        } else {
            $submissions = $this->submissionModel->getByAssignment($id);
            $this->view('assignments/view', compact('assignment', 'course', 'submissions'));
        }
    }

    /** POST /assignment/create — Instructor creates assignment */
    public function create(): void
    {
        Auth::requireRole('instructor', 'admin');

        $courseId    = (int)($_POST['course_id'] ?? 0);
        $title       = trim($_POST['title'] ?? '');
        $description = trim($_POST['description'] ?? '');
        $dueDate     = trim($_POST['due_date'] ?? '') ?: null;
        $maxScore    = (int)($_POST['max_score'] ?? 100);

        if (!$courseId || empty($title)) {
            $this->flash('danger', 'Course and title are required.');
            $this->redirect('course/detail/' . $courseId);
        }

        $this->assignmentModel->create($courseId, $title, $description, $dueDate, $maxScore);
        $this->flash('success', 'Assignment created.');
        $this->redirect('course/detail/' . $courseId);
    }

    /** POST /assignment/delete/{id} */
    public function delete(int $id): void
    {
        Auth::requireRole('instructor', 'admin');
        $a = $this->assignmentModel->findById($id);
        if ($a) {
            $this->assignmentModel->delete($id);
            $this->flash('success', 'Assignment deleted.');
            $this->redirect('course/detail/' . $a['course_id']);
        }
        $this->redirect('course/index');
    }

    /** POST /assignment/submit/{id} — Student submits file */
    public function submit(int $id): void
    {
        Auth::requireRole('student');

        $assignment = $this->assignmentModel->findById($id);
        if (!$assignment) {
            $this->flash('danger', 'Assignment not found.');
            $this->redirect('course/index');
        }

        // Check if already submitted
        if ($this->submissionModel->findByStudentAndAssignment(Auth::id(), $id)) {
            $this->flash('info', 'You have already submitted this assignment.');
            $this->redirect('assignment/view/' . $id);
        }

        // File upload
        if (!isset($_FILES['submission_file']) || $_FILES['submission_file']['error'] !== UPLOAD_ERR_OK) {
            $this->flash('danger', 'File upload failed.');
            $this->redirect('assignment/view/' . $id);
        }

        $file    = $_FILES['submission_file'];
        $origName = basename($file['name']);
        $ext     = strtolower(pathinfo($origName, PATHINFO_EXTENSION));
        $allowed = ALLOWED_SUBMISSION_TYPES;

        if (!in_array($ext, $allowed, true)) {
            $this->flash('danger', 'File type not allowed. Allowed: ' . implode(', ', $allowed));
            $this->redirect('assignment/view/' . $id);
        }

        if ($file['size'] > MAX_UPLOAD_SIZE) {
            $this->flash('danger', 'File exceeds 10 MB limit.');
            $this->redirect('assignment/view/' . $id);
        }

        $dir = UPLOAD_DIR . 'submissions/';
        if (!is_dir($dir)) {
            mkdir($dir, 0755, true);
        }

        $newName = 'sub_' . Auth::id() . '_' . $id . '_' . uniqid() . '.' . $ext;
        $dest    = $dir . $newName;

        if (!move_uploaded_file($file['tmp_name'], $dest)) {
            $this->flash('danger', 'Could not save file.');
            $this->redirect('assignment/view/' . $id);
        }

        $this->submissionModel->create($id, Auth::id(), 'uploads/submissions/' . $newName);
        $this->flash('success', 'Assignment submitted successfully.');
        $this->redirect('assignment/view/' . $id);
    }

    /** POST /assignment/grade/{submissionId} — Instructor grades submission */
    public function grade(int $submissionId): void
    {
        Auth::requireRole('instructor', 'admin');

        $grade    = (float)($_POST['grade'] ?? 0);
        $feedback = trim($_POST['feedback'] ?? '');

        $submission = $this->submissionModel->findById($submissionId);
        if (!$submission) {
            $this->flash('danger', 'Submission not found.');
            $this->redirect('course/index');
        }

        $this->submissionModel->grade($submissionId, $grade, $feedback ?: null);
        $this->flash('success', 'Submission graded.');
        $this->redirect('assignment/view/' . $submission['assignment_id']);
    }
}
