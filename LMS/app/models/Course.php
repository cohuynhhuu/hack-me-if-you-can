<?php
/**
 * Course Model
 */
class Course extends Model
{
    /**
     * Get all active courses for a given language.
     * Admin sees all languages when $lang is null.
     */
    public function getAll(?string $lang = null): array
    {
        if ($lang !== null && in_array($lang, ['en', 'vi'], true)) {
            $stmt = $this->db->prepare(
                'SELECT c.*, u.name AS instructor_name
                 FROM courses c
                 JOIN users u ON u.id = c.instructor_id
                 WHERE c.language = ?
                 ORDER BY c.created_at DESC'
            );
            $stmt->execute([$lang]);
            return $stmt->fetchAll();
        }
        $sql = 'SELECT c.*, u.name AS instructor_name
                FROM courses c
                JOIN users u ON u.id = c.instructor_id
                ORDER BY c.created_at DESC';
        return $this->db->query($sql)->fetchAll();
    }

    /** Get all courses taught by a specific instructor. */
    public function getByInstructor(int $instructorId): array
    {
        $stmt = $this->db->prepare(
            'SELECT c.*, u.name AS instructor_name
             FROM courses c
             JOIN users u ON u.id = c.instructor_id
             WHERE c.instructor_id = ?
             ORDER BY c.created_at DESC'
        );
        $stmt->execute([$instructorId]);
        return $stmt->fetchAll();
    }

    /** Find a single course by ID. */
    public function findById(int $id): ?array
    {
        $stmt = $this->db->prepare(
            'SELECT c.*, u.name AS instructor_name
             FROM courses c
             JOIN users u ON u.id = c.instructor_id
             WHERE c.id = ? LIMIT 1'
        );
        $stmt->execute([$id]);
        $row = $stmt->fetch();
        return $row ?: null;
    }

    /** Create a new course. */
    public function create(int $instructorId, string $title, string $description, string $category, string $language = 'en'): int
    {
        $lang = in_array($language, ['en', 'vi'], true) ? $language : 'en';
        $stmt = $this->db->prepare(
            'INSERT INTO courses (instructor_id, title, description, category, language) VALUES (?, ?, ?, ?, ?)'
        );
        $stmt->execute([$instructorId, $title, $description, $category, $lang]);
        return (int)$this->db->lastInsertId();
    }

    /** Update a course. */
    public function update(int $id, string $title, string $description, string $category, string $status, string $language = 'en'): bool
    {
        $lang = in_array($language, ['en', 'vi'], true) ? $language : 'en';
        $stmt = $this->db->prepare(
            'UPDATE courses SET title = ?, description = ?, category = ?, status = ?, language = ? WHERE id = ?'
        );
        return $stmt->execute([$title, $description, $category, $status, $lang, $id]);
    }

    /** Delete a course. */
    public function delete(int $id): bool
    {
        $stmt = $this->db->prepare('DELETE FROM courses WHERE id = ?');
        return $stmt->execute([$id]);
    }

    /** Count courses (optional language filter). */
    public function countAll(?string $lang = null): int
    {
        if ($lang !== null && in_array($lang, ['en', 'vi'], true)) {
            $stmt = $this->db->prepare('SELECT COUNT(*) FROM courses WHERE language = ?');
            $stmt->execute([$lang]);
            return (int)$stmt->fetchColumn();
        }
        return (int)$this->db->query('SELECT COUNT(*) FROM courses')->fetchColumn();
    }

    /** Get a paginated slice of courses. */
    public function getPaginated(?string $lang, int $offset, int $limit): array
    {
        if ($lang !== null && in_array($lang, ['en', 'vi'], true)) {
            $stmt = $this->db->prepare(
                'SELECT c.*, u.name AS instructor_name
                 FROM courses c
                 JOIN users u ON u.id = c.instructor_id
                 WHERE c.language = ?
                 ORDER BY c.created_at DESC
                 LIMIT ? OFFSET ?'
            );
            $stmt->execute([$lang, $limit, $offset]);
        } else {
            $stmt = $this->db->prepare(
                'SELECT c.*, u.name AS instructor_name
                 FROM courses c
                 JOIN users u ON u.id = c.instructor_id
                 ORDER BY c.created_at DESC
                 LIMIT ? OFFSET ?'
            );
            $stmt->execute([$limit, $offset]);
        }
        return $stmt->fetchAll();
    }

    /** Count total courses. */
    public function count(): int
    {
        return (int)$this->db->query('SELECT COUNT(*) FROM courses')->fetchColumn();
    }

    /** Get courses a student is enrolled in. */
    public function getEnrolledByStudent(int $studentId): array
    {
        $stmt = $this->db->prepare(
            'SELECT c.*, u.name AS instructor_name, e.enrolled_at
             FROM courses c
             JOIN enrollments e ON e.course_id = c.id
             JOIN users u ON u.id = c.instructor_id
             WHERE e.user_id = ?
             ORDER BY e.enrolled_at DESC'
        );
        $stmt->execute([$studentId]);
        return $stmt->fetchAll();
    }
}
