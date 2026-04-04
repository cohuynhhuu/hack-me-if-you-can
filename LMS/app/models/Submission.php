<?php
/**
 * Submission Model
 */
class Submission extends Model
{
    /** Find a student's submission for an assignment. */
    public function findByStudentAndAssignment(int $studentId, int $assignmentId): ?array
    {
        $stmt = $this->db->prepare(
            'SELECT * FROM submissions WHERE student_id = ? AND assignment_id = ? LIMIT 1'
        );
        $stmt->execute([$studentId, $assignmentId]);
        $row = $stmt->fetch();
        return $row ?: null;
    }

    /** Get all submissions for an assignment (instructor grading view). */
    public function getByAssignment(int $assignmentId): array
    {
        $stmt = $this->db->prepare(
            'SELECT s.*, u.name AS student_name
             FROM submissions s
             JOIN users u ON u.id = s.student_id
             WHERE s.assignment_id = ?
             ORDER BY s.submitted_at DESC'
        );
        $stmt->execute([$assignmentId]);
        return $stmt->fetchAll();
    }

    /** Get all submissions by a student. */
    public function getByStudent(int $studentId): array
    {
        $stmt = $this->db->prepare(
            'SELECT s.*, a.title AS assignment_title, a.max_score, c.title AS course_title
             FROM submissions s
             JOIN assignments a ON a.id = s.assignment_id
             JOIN courses c ON c.id = a.course_id
             WHERE s.student_id = ?
             ORDER BY s.submitted_at DESC'
        );
        $stmt->execute([$studentId]);
        return $stmt->fetchAll();
    }

    /** Find submission by ID. */
    public function findById(int $id): ?array
    {
        $stmt = $this->db->prepare(
            'SELECT s.*, u.name AS student_name, a.title AS assignment_title, a.max_score
             FROM submissions s
             JOIN users u ON u.id = s.student_id
             JOIN assignments a ON a.id = s.assignment_id
             WHERE s.id = ? LIMIT 1'
        );
        $stmt->execute([$id]);
        $row = $stmt->fetch();
        return $row ?: null;
    }

    /** Create a submission. */
    public function create(int $assignmentId, int $studentId, string $filePath): int
    {
        $stmt = $this->db->prepare(
            'INSERT INTO submissions (assignment_id, student_id, file_path) VALUES (?, ?, ?)'
        );
        $stmt->execute([$assignmentId, $studentId, $filePath]);
        return (int)$this->db->lastInsertId();
    }

    /** Grade a submission. */
    public function grade(int $id, float $grade, ?string $feedback): bool
    {
        $stmt = $this->db->prepare(
            'UPDATE submissions SET grade = ?, feedback = ?, graded_at = NOW() WHERE id = ?'
        );
        return $stmt->execute([$grade, $feedback, $id]);
    }

    /** Count graded submissions for a student in a course (for progress). */
    public function countGradedByStudentAndCourse(int $studentId, int $courseId): int
    {
        $stmt = $this->db->prepare(
            'SELECT COUNT(*) FROM submissions s
             JOIN assignments a ON a.id = s.assignment_id
             WHERE s.student_id = ? AND a.course_id = ? AND s.grade IS NOT NULL'
        );
        $stmt->execute([$studentId, $courseId]);
        return (int)$stmt->fetchColumn();
    }
}
