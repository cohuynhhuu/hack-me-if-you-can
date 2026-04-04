<?php
/**
 * Assignment Model
 */
class Assignment extends Model
{
    /** Get all assignments for a course. */
    public function getByCourse(int $courseId): array
    {
        $stmt = $this->db->prepare(
            'SELECT * FROM assignments WHERE course_id = ? ORDER BY due_date ASC'
        );
        $stmt->execute([$courseId]);
        return $stmt->fetchAll();
    }

    /** Find a single assignment by ID. */
    public function findById(int $id): ?array
    {
        $stmt = $this->db->prepare('SELECT * FROM assignments WHERE id = ? LIMIT 1');
        $stmt->execute([$id]);
        $row = $stmt->fetch();
        return $row ?: null;
    }

    /** Create an assignment. */
    public function create(int $courseId, string $title, string $description, ?string $dueDate, int $maxScore): int
    {
        $stmt = $this->db->prepare(
            'INSERT INTO assignments (course_id, title, description, due_date, max_score)
             VALUES (?, ?, ?, ?, ?)'
        );
        $stmt->execute([$courseId, $title, $description, $dueDate, $maxScore]);
        return (int)$this->db->lastInsertId();
    }

    /** Update an assignment. */
    public function update(int $id, string $title, string $description, ?string $dueDate, int $maxScore): bool
    {
        $stmt = $this->db->prepare(
            'UPDATE assignments SET title = ?, description = ?, due_date = ?, max_score = ? WHERE id = ?'
        );
        return $stmt->execute([$title, $description, $dueDate, $maxScore, $id]);
    }

    /** Delete an assignment. */
    public function delete(int $id): bool
    {
        $stmt = $this->db->prepare('DELETE FROM assignments WHERE id = ?');
        return $stmt->execute([$id]);
    }
}
