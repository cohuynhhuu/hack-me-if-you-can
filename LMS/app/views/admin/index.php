<?php
require_once APP_ROOT . '/app/models/Message.php';
$pageTitle = 'Admin Panel';
ob_start();
?>
<div class="page-header">
    <h2>&#9881; Admin Panel</h2>
</div>

<?php /* ── Create User ── */ ?>
<div class="card" style="margin-bottom:1.5rem">
    <div class="card-header"><h3 style="margin:0">Create New User</h3></div>
    <div style="padding:1rem">
        <form action="<?= BASE_URL ?>/admin/createUser" method="POST" class="form-row">
            <div class="form-group" style="flex:2">
                <label>Full Name</label>
                <input type="text" name="name" class="form-control" required placeholder="Jane Doe">
            </div>
            <div class="form-group" style="flex:2">
                <label>Email</label>
                <input type="email" name="email" class="form-control" required placeholder="jane@example.com">
            </div>
            <div class="form-group" style="flex:2">
                <label>Password</label>
                <input type="password" name="password" class="form-control" required placeholder="Min 6 chars" minlength="6">
            </div>
            <div class="form-group" style="flex:1">
                <label>Role</label>
                <select name="role" class="form-control">
                    <option value="student">Student</option>
                    <option value="instructor">Instructor</option>
                    <option value="admin">Admin</option>
                </select>
            </div>
            <div class="form-group" style="flex:0;align-self:flex-end">
                <button type="submit" class="btn btn-primary">Create</button>
            </div>
        </form>
    </div>
</div>

<?php /* ── User Table ── */ ?>
<div class="card" style="margin-bottom:1.5rem">
    <div class="card-header">
        <h3 style="margin:0">All Users (<?= count($users ?? []) ?>)</h3>
    </div>
    <?php if (empty($users)): ?>
    <div style="padding:1rem"><div class="alert alert-info">No users found.</div></div>
    <?php else: ?>
    <table class="table">
        <thead>
            <tr>
                <th>ID</th>
                <th>Name</th>
                <th>Email</th>
                <th>Role</th>
                <th>Joined</th>
                <th>Action</th>
            </tr>
        </thead>
        <tbody>
        <?php foreach ($users as $u): ?>
        <tr>
            <td><?= $u['id'] ?></td>
            <td><?= htmlspecialchars($u['name']) ?></td>
            <td><?= htmlspecialchars($u['email']) ?></td>
            <td>
                <span class="badge badge-<?= $u['role'] === 'admin' ? 'danger' : ($u['role'] === 'instructor' ? 'warning' : 'info') ?>">
                    <?= ucfirst($u['role']) ?>
                </span>
            </td>
            <td><small><?= date('M j, Y', strtotime($u['created_at'])) ?></small></td>
            <td>
                <?php if ($u['id'] != \Auth::id()): ?>
                <form action="<?= BASE_URL ?>/admin/deleteUser/<?= $u['id'] ?>" method="POST" style="display:inline"
                      onsubmit="return confirm('Delete user <?= htmlspecialchars(addslashes($u['name'])) ?>? This cannot be undone.')">
                    <button type="submit" class="btn btn-danger" style="padding:.3rem .65rem;font-size:.8rem">Delete</button>
                </form>
                <?php else: ?>
                <span style="color:#94a3b8;font-size:.8rem">(you)</span>
                <?php endif; ?>
            </td>
        </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
    <?php endif; ?>
</div>

<?php /* ── Course Overview ── */ ?>
<div class="card">
    <div class="card-header">
        <h3 style="margin:0">All Courses (<?= count($courses ?? []) ?>)</h3>
    </div>
    <?php if (empty($courses)): ?>
    <div style="padding:1rem"><div class="alert alert-info">No courses yet.</div></div>
    <?php else: ?>
    <table class="table">
        <thead>
            <tr>
                <th>ID</th>
                <th>Title</th>
                <th>Instructor</th>
                <th>Created</th>
                <th>Action</th>
            </tr>
        </thead>
        <tbody>
        <?php foreach ($courses as $c): ?>
        <tr>
            <td><?= $c['id'] ?></td>
            <td>
                <a href="<?= BASE_URL ?>/course/detail/<?= $c['id'] ?>">
                    <?= htmlspecialchars($c['title']) ?>
                </a>
            </td>
            <td><?= htmlspecialchars($c['instructor_name'] ?? '—') ?></td>
            <td><small><?= date('M j, Y', strtotime($c['created_at'])) ?></small></td>
            <td>
                <a href="<?= BASE_URL ?>/course/detail/<?= $c['id'] ?>" class="btn btn-secondary" style="padding:.3rem .65rem;font-size:.8rem">View</a>
            </td>
        </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
    <?php endif; ?>
</div>
<?php
$content = ob_get_clean();
require_once APP_ROOT . '/app/views/layouts/main.php';
