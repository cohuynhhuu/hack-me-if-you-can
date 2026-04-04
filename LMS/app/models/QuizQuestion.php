<?php
/**
 * QuizQuestion Model
 */
class QuizQuestion extends Model
{
    /** Get all questions for a quiz, ordered by sort_order. */
    public function getByQuiz(int $quizId): array
    {
        $stmt = $this->db->prepare(
            'SELECT * FROM quiz_questions WHERE quiz_id = ? ORDER BY sort_order ASC'
        );
        $stmt->execute([$quizId]);
        $rows = $stmt->fetchAll();

        // Decode JSON options
        foreach ($rows as &$row) {
            $row['options'] = json_decode($row['options'], true);
        }
        return $rows;
    }

    /** Find a single question by ID. */
    public function findById(int $id): ?array
    {
        $stmt = $this->db->prepare('SELECT * FROM quiz_questions WHERE id = ? LIMIT 1');
        $stmt->execute([$id]);
        $row = $stmt->fetch();
        if ($row) {
            $row['options'] = json_decode($row['options'], true);
        }
        return $row ?: null;
    }

    /** Add a question to a quiz. */
    public function create(int $quizId, string $questionText, array $options, int $correctAnswer, int $points, int $sortOrder): int
    {
        $stmt = $this->db->prepare(
            'INSERT INTO quiz_questions (quiz_id, question_text, options, correct_answer, points, sort_order)
             VALUES (?, ?, ?, ?, ?, ?)'
        );
        $stmt->execute([$quizId, $questionText, json_encode($options), $correctAnswer, $points, $sortOrder]);
        return (int)$this->db->lastInsertId();
    }

    /** Delete a question. */
    public function delete(int $id): bool
    {
        $stmt = $this->db->prepare('DELETE FROM quiz_questions WHERE id = ?');
        return $stmt->execute([$id]);
    }

    /** Count total points available in a quiz. */
    public function totalPoints(int $quizId): int
    {
        $stmt = $this->db->prepare('SELECT COALESCE(SUM(points), 0) FROM quiz_questions WHERE quiz_id = ?');
        $stmt->execute([$quizId]);
        return (int)$stmt->fetchColumn();
    }
}
