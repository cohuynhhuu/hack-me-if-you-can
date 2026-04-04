<?php
/**
 * Material Model
 */
class Material extends Model
{
    /** Get all materials for a course. */
    public function getByCourse(int $courseId): array
    {
        $stmt = $this->db->prepare(
            'SELECT * FROM materials WHERE course_id = ? ORDER BY sort_order ASC, created_at ASC'
        );
        $stmt->execute([$courseId]);
        return $stmt->fetchAll();
    }

    /** Find a single material by ID. */
    public function findById(int $id): ?array
    {
        $stmt = $this->db->prepare('SELECT * FROM materials WHERE id = ? LIMIT 1');
        $stmt->execute([$id]);
        $row = $stmt->fetch();
        return $row ?: null;
    }

    /** Add a material to a course. */
    public function create(int $courseId, string $title, string $type, string $content, int $sortOrder = 0): int
    {
        $stmt = $this->db->prepare(
            'INSERT INTO materials (course_id, title, type, content, sort_order) VALUES (?, ?, ?, ?, ?)'
        );
        $stmt->execute([$courseId, $title, $type, $content, $sortOrder]);
        return (int)$this->db->lastInsertId();
    }

    /** Delete a material. */
    public function delete(int $id): bool
    {
        $stmt = $this->db->prepare('DELETE FROM materials WHERE id = ?');
        return $stmt->execute([$id]);
    }
}
