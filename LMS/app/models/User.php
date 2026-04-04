<?php
/**
 * User Model
 */
class User extends Model
{
    /** Find a user by email (for login). */
    public function findByEmail(string $email): ?array
    {
        $stmt = $this->db->prepare('SELECT * FROM users WHERE email = ? LIMIT 1');
        $stmt->execute([$email]);
        $row = $stmt->fetch();
        return $row ?: null;
    }

    /** Find a user by ID. */
    public function findById(int $id): ?array
    {
        $stmt = $this->db->prepare('SELECT id, name, email, role, avatar, created_at FROM users WHERE id = ? LIMIT 1');
        $stmt->execute([$id]);
        $row = $stmt->fetch();
        return $row ?: null;
    }

    /** Get all users, optionally filtered by role. */
    public function getAll(?string $role = null): array
    {
        if ($role) {
            $stmt = $this->db->prepare('SELECT id, name, email, role, created_at FROM users WHERE role = ? ORDER BY name');
            $stmt->execute([$role]);
        } else {
            $stmt = $this->db->query('SELECT id, name, email, role, created_at FROM users ORDER BY name');
        }
        return $stmt->fetchAll();
    }

    /** Create a new user. Returns new user ID. */
    public function create(string $name, string $email, string $password, string $role = 'student'): int
    {
        $hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
        $stmt = $this->db->prepare(
            'INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)'
        );
        $stmt->execute([$name, $email, $hash, $role]);
        return (int)$this->db->lastInsertId();
    }

    /** Update a user's name/email/role. */
    public function update(int $id, string $name, string $email, string $role): bool
    {
        $stmt = $this->db->prepare(
            'UPDATE users SET name = ?, email = ?, role = ? WHERE id = ?'
        );
        return $stmt->execute([$name, $email, $role, $id]);
    }

    /** Change password. */
    public function changePassword(int $id, string $newPassword): bool
    {
        $hash = password_hash($newPassword, PASSWORD_BCRYPT, ['cost' => 12]);
        $stmt = $this->db->prepare('UPDATE users SET password = ? WHERE id = ?');
        return $stmt->execute([$hash, $id]);
    }

    /** Delete a user by ID. */
    public function delete(int $id): bool
    {
        $stmt = $this->db->prepare('DELETE FROM users WHERE id = ?');
        return $stmt->execute([$id]);
    }

    /** Check if an email is already registered. */
    public function emailExists(string $email): bool
    {
        $stmt = $this->db->prepare('SELECT COUNT(*) FROM users WHERE email = ?');
        $stmt->execute([$email]);
        return (int)$stmt->fetchColumn() > 0;
    }

    /** Count all users, optionally by role. */
    public function count(?string $role = null): int
    {
        if ($role) {
            $stmt = $this->db->prepare('SELECT COUNT(*) FROM users WHERE role = ?');
            $stmt->execute([$role]);
        } else {
            $stmt = $this->db->query('SELECT COUNT(*) FROM users');
        }
        return (int)$stmt->fetchColumn();
    }
}
