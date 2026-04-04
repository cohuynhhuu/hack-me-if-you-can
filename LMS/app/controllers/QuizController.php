<?php
require_once APP_ROOT . '/app/core/Controller.php';
require_once APP_ROOT . '/app/models/Quiz.php';
require_once APP_ROOT . '/app/models/QuizQuestion.php';
require_once APP_ROOT . '/app/models/QuizResult.php';
require_once APP_ROOT . '/app/models/Course.php';

/**
 * QuizController — Create, take, and score quizzes
 */
class QuizController extends Controller
{
    private Quiz $quizModel;
    private QuizQuestion $questionModel;
    private QuizResult $resultModel;
    private Course $courseModel;

    public function __construct()
    {
        Auth::requireLogin();
        $this->quizModel     = new Quiz();
        $this->questionModel = new QuizQuestion();
        $this->resultModel   = new QuizResult();
        $this->courseModel   = new Course();
    }

    /** GET /quiz/take/{quizId} — Student takes quiz */
    public function take(int $quizId): void
    {
        Auth::requireRole('student');

        $quiz = $this->quizModel->findById($quizId);
        if (!$quiz) {
            $this->flash('danger', 'Quiz not found.');
            $this->redirect('course/index');
        }

        // Check if already attempted
        $existing = $this->resultModel->findByStudentAndQuiz(Auth::id(), $quizId);
        if ($existing) {
            $this->redirect('quiz/result/' . $quizId);
        }

        $questions = $this->questionModel->getByQuiz($quizId);
        $course    = $this->courseModel->findById($quiz['course_id']);

        $this->view('quizzes/take', compact('quiz', 'questions', 'course'));
    }

    /** POST /quiz/submit/{quizId} — Auto-grade and save result */
    public function submitQuiz(int $quizId): void
    {
        Auth::requireRole('student');

        $quiz = $this->quizModel->findById($quizId);
        if (!$quiz) {
            $this->flash('danger', 'Quiz not found.');
            $this->redirect('course/index');
        }

        // Prevent double submission
        if ($this->resultModel->findByStudentAndQuiz(Auth::id(), $quizId)) {
            $this->redirect('quiz/result/' . $quizId);
        }

        $questions = $this->questionModel->getByQuiz($quizId);
        $maxScore  = $this->questionModel->totalPoints($quizId);
        $score     = 0;
        $answers   = [];

        foreach ($questions as $q) {
            $key    = 'q_' . $q['id'];
            $chosen = isset($_POST[$key]) ? (int)$_POST[$key] : -1;
            $answers[$q['id']] = $chosen;
            if ($chosen === (int)$q['correct_answer']) {
                $score += (int)$q['points'];
            }
        }

        $this->resultModel->save($quizId, Auth::id(), $score, $maxScore, $answers);
        $this->redirect('quiz/result/' . $quizId);
    }

    /** GET /quiz/result/{quizId} — Show score + correct answers */
    public function result(int $quizId): void
    {
        $quiz   = $this->quizModel->findById($quizId);
        $result = $this->resultModel->findByStudentAndQuiz(Auth::id(), $quizId);

        if (!$quiz || !$result) {
            $this->flash('danger', 'Result not found.');
            $this->redirect('course/index');
        }

        $questions = $this->questionModel->getByQuiz($quizId);
        $course    = $this->courseModel->findById($quiz['course_id']);

        $this->view('quizzes/result', compact('quiz', 'result', 'questions', 'course'));
    }

    /** GET /quiz/manage/{quizId} — Instructor views submissions */
    public function manage(int $quizId): void
    {
        Auth::requireRole('instructor', 'admin');
        $quiz    = $this->quizModel->findById($quizId);
        $results = $this->resultModel->getByQuiz($quizId);
        $course  = $this->courseModel->findById($quiz['course_id']);
        $this->view('quizzes/manage', compact('quiz', 'results', 'course'));
    }

    /** POST /quiz/create — Instructor creates quiz + questions */
    public function create(): void
    {
        Auth::requireRole('instructor', 'admin');

        $courseId    = (int)($_POST['course_id'] ?? 0);
        $title       = trim($_POST['title'] ?? '');
        $description = trim($_POST['description'] ?? '');
        $timeLimit   = isset($_POST['time_limit']) && $_POST['time_limit'] !== '' ? (int)$_POST['time_limit'] : null;

        if (!$courseId || empty($title)) {
            $this->flash('danger', 'Course and title are required.');
            $this->redirect('course/detail/' . $courseId);
        }

        $quizId = $this->quizModel->create($courseId, $title, $description, $timeLimit);

        // Save questions if provided
        $questionTexts  = $_POST['question_text'] ?? [];
        $optionsAll     = $_POST['options'] ?? [];
        $correctAnswers = $_POST['correct_answer'] ?? [];

        foreach ($questionTexts as $i => $qText) {
            $qText = trim($qText);
            if (empty($qText)) continue;

            $opts    = $optionsAll[$i] ?? [];
            $correct = isset($correctAnswers[$i]) ? (int)$correctAnswers[$i] : 0;

            $this->questionModel->create($quizId, $qText, $opts, $correct, 1, $i + 1);
        }

        $this->flash('success', 'Quiz created successfully.');
        $this->redirect('course/detail/' . $courseId);
    }

    /** POST /quiz/delete/{id} */
    public function delete(int $id): void
    {
        Auth::requireRole('instructor', 'admin');
        $q = $this->quizModel->findById($id);
        if ($q) {
            $this->quizModel->delete($id);
            $this->flash('success', 'Quiz deleted.');
            $this->redirect('course/detail/' . $q['course_id']);
        }
        $this->redirect('course/index');
    }
}
