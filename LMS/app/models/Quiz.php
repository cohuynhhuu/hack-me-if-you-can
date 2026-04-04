<?php
/**
 * Quiz Model
 */
class Quiz extends Model
{
    /** Get all quizzes for a course. */
    public function getByCourse(int $courseId): array
    {
        $stmt = $this->db->prepare('SELECT * FROM quizzes WHERE course_id = ? ORDER BY created_at ASC');
        $stmt->execute([$courseId]);
        return $stmt->fetchAll();
    }

    /** Find a quiz by ID. */
    public function findById(int $id): ?array
    {
        $stmt = $this->db->prepare('SELECT * FROM quizzes WHERE id = ? LIMIT 1');
        $stmt->execute([$id]);
        $row = $stmt->fetch();
        return $row ?: null;
    }

    /** Create a quiz. */
    public function create(int $courseId, string $title, string $description, ?int $timeLimit): int
    {
        $stmt = $this->db->prepare(
            'INSERT INTO quizzes (course_id, title, description, time_limit) VALUES (?, ?, ?, ?)'
        );
        $stmt->execute([$courseId, $title, $description, $timeLimit]);
        return (int)$this->db->lastInsertId();
    }

    /** Delete a quiz. */
    public function delete(int $id): bool
    {
        $stmt = $this->db->prepare('DELETE FROM quizzes WHERE id = ?');
        return $stmt->execute([$id]);
    }
}
