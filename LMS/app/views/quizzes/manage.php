<?php
require_once APP_ROOT . '/app/models/Message.php';
$pageTitle = 'Quiz Attempts — ' . htmlspecialchars($quiz['title']);
ob_start();
?>
<div class="page-header">
    <div>
        <a href="<?= BASE_URL ?>/course/detail/<?= $course['id'] ?>" style="color:#64748b;font-size:.88rem">
            &#8592; <?= htmlspecialchars($course['title']) ?>
        </a>
        <h2>&#128203; Student Attempts — <?= htmlspecialchars($quiz['title']) ?></h2>
    </div>
</div>

<?php if (empty($attempts)): ?>
<div class="alert alert-info">No students have taken this quiz yet.</div>
<?php else: ?>
<div class="card">
    <div class="card-header">
        <h3 style="margin:0">Results (<?= count($attempts) ?> attempt<?= count($attempts) != 1 ? 's' : '' ?>)</h3>
    </div>
    <table class="table">
        <thead>
            <tr>
                <th>#</th>
                <th>Student</th>
                <th>Score</th>
                <th>Max</th>
                <th>Percentage</th>
                <th>Status</th>
                <th>Date Taken</th>
            </tr>
        </thead>
        <tbody>
        <?php foreach ($attempts as $idx => $a): ?>
        <?php
            $pct  = $a['max_score'] > 0 ? round($a['score'] / $a['max_score'] * 100) : 0;
            $pass = $pct >= ($quiz['pass_score'] ?? 50);
        ?>
        <tr>
            <td><?= $idx + 1 ?></td>
            <td><?= htmlspecialchars($a['student_name']) ?></td>
            <td><?= $a['score'] ?></td>
            <td><?= $a['max_score'] ?></td>
            <td>
                <div class="progress-bar-container" style="width:120px">
                    <div class="progress-bar" style="width:<?= $pct ?>%;background:<?= $pass ? '#22c55e' : '#ef4444' ?>"></div>
                </div>
                <small><?= $pct ?>%</small>
            </td>
            <td>
                <span class="badge badge-<?= $pass ? 'success' : 'danger' ?>">
                    <?= $pass ? 'Pass' : 'Fail' ?>
                </span>
            </td>
            <td><small><?= date('M j, Y H:i', strtotime($a['taken_at'])) ?></small></td>
        </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
    <?php
    $avg = count($attempts) ? round(array_sum(array_map(fn($a) => $a['max_score'] > 0 ? $a['score'] / $a['max_score'] * 100 : 0, $attempts)) / count($attempts)) : 0;
    ?>
    <div style="padding:.75rem 1rem;background:#f8fafc;border-top:1px solid var(--border);color:#64748b;font-size:.88rem">
        Average Score: <strong><?= $avg ?>%</strong>
    </div>
</div>
<?php endif; ?>

<div style="margin-top:1rem">
    <a href="<?= BASE_URL ?>/course/detail/<?= $course['id'] ?>" class="btn btn-secondary">Back to Course</a>
</div>
<?php
$content = ob_get_clean();
require_once APP_ROOT . '/app/views/layouts/main.php';
