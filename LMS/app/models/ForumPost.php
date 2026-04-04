<?php
/**
 * ForumPost Model
 */
class ForumPost extends Model
{
    /** Get all top-level threads for a forum, newest first. */
    public function getThreads(int $forumId): array
    {
        $stmt = $this->db->prepare(
            'SELECT fp.*, u.name AS author_name
             FROM forum_posts fp
             JOIN users u ON u.id = fp.user_id
             WHERE fp.forum_id = ? AND fp.parent_id IS NULL
             ORDER BY fp.created_at DESC'
        );
        $stmt->execute([$forumId]);
        return $stmt->fetchAll();
    }

    /** Get all direct replies to a post. */
    public function getReplies(int $parentId): array
    {
        $stmt = $this->db->prepare(
            'SELECT fp.*, u.name AS author_name
             FROM forum_posts fp
             JOIN users u ON u.id = fp.user_id
             WHERE fp.parent_id = ?
             ORDER BY fp.created_at ASC'
        );
        $stmt->execute([$parentId]);
        return $stmt->fetchAll();
    }

    /** Find a single post by ID. */
    public function findById(int $id): ?array
    {
        $stmt = $this->db->prepare(
            'SELECT fp.*, u.name AS author_name
             FROM forum_posts fp
             JOIN users u ON u.id = fp.user_id
             WHERE fp.id = ? LIMIT 1'
        );
        $stmt->execute([$id]);
        $row = $stmt->fetch();
        return $row ?: null;
    }

    /** Create a new thread or reply. */
    public function create(int $forumId, int $userId, ?int $parentId, ?string $subject, string $body): int
    {
        $stmt = $this->db->prepare(
            'INSERT INTO forum_posts (forum_id, user_id, parent_id, subject, body) VALUES (?, ?, ?, ?, ?)'
        );
        $stmt->execute([$forumId, $userId, $parentId, $subject, $body]);
        return (int)$this->db->lastInsertId();
    }

    /** Delete a post (cascade removes replies). */
    public function delete(int $id): bool
    {
        $stmt = $this->db->prepare('DELETE FROM forum_posts WHERE id = ?');
        return $stmt->execute([$id]);
    }

    /** Count posts in a forum. */
    public function countByForum(int $forumId): int
    {
        $stmt = $this->db->prepare('SELECT COUNT(*) FROM forum_posts WHERE forum_id = ?');
        $stmt->execute([$forumId]);
        return (int)$stmt->fetchColumn();
    }
}
