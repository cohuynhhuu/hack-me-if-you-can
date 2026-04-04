<?php
require_once APP_ROOT . '/app/models/Message.php';
$pageTitle = htmlspecialchars($assignment['title']) . ' — Submissions';
ob_start();
?>
<div class="page-header">
    <div>
        <a href="<?= BASE_URL ?>/course/detail/<?= $course['id'] ?>" style="color:#64748b;font-size:.88rem">
            &#8592; <?= htmlspecialchars($course['title']) ?>
        </a>
        <h2>&#128196; <?= htmlspecialchars($assignment['title']) ?></h2>
        <small>Max Score: <?= $assignment['max_score'] ?> &bull; <?= count($submissions) ?> submission(s)</small>
    </div>
</div>

<div class="card">
    <div class="card-header">Student Submissions</div>
    <div class="card-body" style="padding:0">
        <?php if (empty($submissions)): ?>
        <div class="empty-state">No submissions yet.</div>
        <?php else: ?>
        <table>
            <thead>
                <tr>
                    <th>Student</th>
                    <th>File</th>
                    <th>Submitted</th>
                    <th>Grade</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody>
            <?php foreach ($submissions as $sub): ?>
            <tr>
                <td><?= htmlspecialchars($sub['student_name']) ?></td>
                <td>
                    <a href="<?= BASE_URL ?>/<?= htmlspecialchars($sub['file_path']) ?>" download>
                        <?= htmlspecialchars(basename($sub['file_path'])) ?>
                    </a>
                </td>
                <td style="font-size:.83rem;color:#64748b">
                    <?= htmlspecialchars(date('M j, Y', strtotime($sub['submitted_at']))) ?>
                </td>
                <td>
                    <?php if ($sub['grade'] !== null): ?>
                    <span class="badge badge-active"><?= $sub['grade'] ?>/<?= $assignment['max_score'] ?></span>
                    <?php else: ?>
                    <span class="badge badge-inactive">Pending</span>
                    <?php endif; ?>
                </td>
                <td>
                    <form action="<?= BASE_URL ?>/assignment/grade/<?= $sub['id'] ?>" method="POST"
                          style="display:flex;gap:.4rem;align-items:center">
                        <input type="number" name="grade" class="form-control"
                               style="width:80px;padding:.3rem .5rem"
                               value="<?= $sub['grade'] ?? '' ?>"
                               min="0" max="<?= $assignment['max_score'] ?>" step="0.5" required>
                        <input type="text" name="feedback" class="form-control"
                               style="width:160px;padding:.3rem .5rem"
                               value="<?= htmlspecialchars($sub['feedback'] ?? '') ?>"
                               placeholder="Feedback">
                        <button type="submit" class="btn btn-success btn-sm">Grade</button>
                    </form>
                </td>
            </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
        <?php endif; ?>
    </div>
</div>

<?php
$content = ob_get_clean();
require_once APP_ROOT . '/app/views/layouts/main.php';
