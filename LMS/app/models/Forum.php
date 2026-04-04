<?php
/**
 * Forum Model
 */
class Forum extends Model
{
    /** Get forum record by course ID. */
    public function findByCourse(int $courseId): ?array
    {
        $stmt = $this->db->prepare('SELECT * FROM forums WHERE course_id = ? LIMIT 1');
        $stmt->execute([$courseId]);
        $row = $stmt->fetch();
        return $row ?: null;
    }

    /** Get forum by its own ID. */
    public function findById(int $id): ?array
    {
        $stmt = $this->db->prepare('SELECT * FROM forums WHERE id = ? LIMIT 1');
        $stmt->execute([$id]);
        $row = $stmt->fetch();
        return $row ?: null;
    }

    /** Create a forum for a course (called when a course is created). */
    public function create(int $courseId, string $title): int
    {
        $stmt = $this->db->prepare('INSERT INTO forums (course_id, title) VALUES (?, ?)');
        $stmt->execute([$courseId, $title]);
        return (int)$this->db->lastInsertId();
    }
}
