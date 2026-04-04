<?php
/**
 * QuizResult Model
 */
class QuizResult extends Model
{
    /** Find a student's result for a specific quiz. */
    public function findByStudentAndQuiz(int $studentId, int $quizId): ?array
    {
        $stmt = $this->db->prepare(
            'SELECT * FROM quiz_results WHERE student_id = ? AND quiz_id = ? ORDER BY taken_at DESC LIMIT 1'
        );
        $stmt->execute([$studentId, $quizId]);
        $row = $stmt->fetch();
        if ($row) {
            $row['answers'] = json_decode($row['answers'], true);
        }
        return $row ?: null;
    }

    /** Get all results for a quiz (instructor view). */
    public function getByQuiz(int $quizId): array
    {
        $stmt = $this->db->prepare(
            'SELECT qr.*, u.name AS student_name
             FROM quiz_results qr
             JOIN users u ON u.id = qr.student_id
             WHERE qr.quiz_id = ?
             ORDER BY qr.score DESC'
        );
        $stmt->execute([$quizId]);
        return $stmt->fetchAll();
    }

    /** Get all quiz results for a student. */
    public function getByStudent(int $studentId): array
    {
        $stmt = $this->db->prepare(
            'SELECT qr.*, q.title AS quiz_title, c.title AS course_title
             FROM quiz_results qr
             JOIN quizzes q ON q.id = qr.quiz_id
             JOIN courses c ON c.id = q.course_id
             WHERE qr.student_id = ?
             ORDER BY qr.taken_at DESC'
        );
        $stmt->execute([$studentId]);
        return $stmt->fetchAll();
    }

    /** Save a quiz attempt result. */
    public function save(int $quizId, int $studentId, float $score, float $maxScore, array $answers): int
    {
        $stmt = $this->db->prepare(
            'INSERT INTO quiz_results (quiz_id, student_id, score, max_score, answers)
             VALUES (?, ?, ?, ?, ?)'
        );
        $stmt->execute([$quizId, $studentId, $score, $maxScore, json_encode($answers)]);
        return (int)$this->db->lastInsertId();
    }

    /** Get average score percentage for a quiz. */
    public function averageScore(int $quizId): float
    {
        $stmt = $this->db->prepare(
            'SELECT AVG(score / NULLIF(max_score, 0) * 100) FROM quiz_results WHERE quiz_id = ?'
        );
        $stmt->execute([$quizId]);
        return round((float)$stmt->fetchColumn(), 1);
    }
}
