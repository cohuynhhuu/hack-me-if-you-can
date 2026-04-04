<?php
/**
 * Enrollment Model
 */
class Enrollment extends Model
{
    /** Check if a student is already enrolled in a course. */
    public function isEnrolled(int $userId, int $courseId): bool
    {
        $stmt = $this->db->prepare(
            'SELECT COUNT(*) FROM enrollments WHERE user_id = ? AND course_id = ?'
        );
        $stmt->execute([$userId, $courseId]);
        return (int)$stmt->fetchColumn() > 0;
    }

    /** Enroll a student. Returns new enrollment ID. */
    public function enroll(int $userId, int $courseId): int
    {
        $stmt = $this->db->prepare(
            'INSERT INTO enrollments (user_id, course_id) VALUES (?, ?)'
        );
        $stmt->execute([$userId, $courseId]);
        return (int)$this->db->lastInsertId();
    }

    /** Unenroll a student from a course. */
    public function unenroll(int $userId, int $courseId): bool
    {
        $stmt = $this->db->prepare(
            'DELETE FROM enrollments WHERE user_id = ? AND course_id = ?'
        );
        return $stmt->execute([$userId, $courseId]);
    }

    /** Get all students enrolled in a course. */
    public function getStudentsByCourse(int $courseId): array
    {
        $stmt = $this->db->prepare(
            'SELECT u.id, u.name, u.email, e.enrolled_at
             FROM enrollments e
             JOIN users u ON u.id = e.user_id
             WHERE e.course_id = ?
             ORDER BY u.name'
        );
        $stmt->execute([$courseId]);
        return $stmt->fetchAll();
    }

    /** Count students in a course. */
    public function countByCourse(int $courseId): int
    {
        $stmt = $this->db->prepare('SELECT COUNT(*) FROM enrollments WHERE course_id = ?');
        $stmt->execute([$courseId]);
        return (int)$stmt->fetchColumn();
    }

    /** Count total enrollments. */
    public function countTotal(): int
    {
        return (int)$this->db->query('SELECT COUNT(*) FROM enrollments')->fetchColumn();
    }
}
