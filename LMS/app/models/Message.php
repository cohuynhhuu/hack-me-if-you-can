<?php
/**
 * Message Model
 */
class Message extends Model
{
    /** Get inbox messages for a user (received). */
    public function getInbox(int $userId): array
    {
        $stmt = $this->db->prepare(
            'SELECT m.*, u.name AS sender_name
             FROM messages m
             JOIN users u ON u.id = m.sender_id
             WHERE m.receiver_id = ?
             ORDER BY m.sent_at DESC'
        );
        $stmt->execute([$userId]);
        return $stmt->fetchAll();
    }

    /** Get sent messages for a user. */
    public function getSent(int $userId): array
    {
        $stmt = $this->db->prepare(
            'SELECT m.*, u.name AS receiver_name
             FROM messages m
             JOIN users u ON u.id = m.receiver_id
             WHERE m.sender_id = ?
             ORDER BY m.sent_at DESC'
        );
        $stmt->execute([$userId]);
        return $stmt->fetchAll();
    }

    /** Find a single message by ID. */
    public function findById(int $id): ?array
    {
        $stmt = $this->db->prepare(
            'SELECT m.*, s.name AS sender_name, r.name AS receiver_name
             FROM messages m
             JOIN users s ON s.id = m.sender_id
             JOIN users r ON r.id = m.receiver_id
             WHERE m.id = ? LIMIT 1'
        );
        $stmt->execute([$id]);
        $row = $stmt->fetch();
        return $row ?: null;
    }

    /** Send a message. */
    public function send(int $senderId, int $receiverId, ?string $subject, string $body): int
    {
        $stmt = $this->db->prepare(
            'INSERT INTO messages (sender_id, receiver_id, subject, body) VALUES (?, ?, ?, ?)'
        );
        $stmt->execute([$senderId, $receiverId, $subject, $body]);
        return (int)$this->db->lastInsertId();
    }

    /** Mark a message as read. */
    public function markRead(int $id): bool
    {
        $stmt = $this->db->prepare('UPDATE messages SET is_read = 1 WHERE id = ?');
        return $stmt->execute([$id]);
    }

    /** Count unread messages for a user. */
    public function countUnread(int $userId): int
    {
        $stmt = $this->db->prepare(
            'SELECT COUNT(*) FROM messages WHERE receiver_id = ? AND is_read = 0'
        );
        $stmt->execute([$userId]);
        return (int)$stmt->fetchColumn();
    }
}
