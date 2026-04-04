<?php
require_once APP_ROOT . '/app/models/Message.php';
$pageTitle = htmlspecialchars($assignment['title']);
ob_start();
?>
<div class="page-header">
    <div>
        <a href="<?= BASE_URL ?>/course/detail/<?= $course['id'] ?>" style="color:#64748b;font-size:.88rem">
            &#8592; <?= htmlspecialchars($course['title']) ?>
        </a>
        <h2>&#128196; <?= htmlspecialchars($assignment['title']) ?></h2>
        <small>
            Due: <?= $assignment['due_date'] ? date('M j, Y g:i A', strtotime($assignment['due_date'])) : 'No deadline' ?>
            &bull; Max Score: <?= $assignment['max_score'] ?>
        </small>
    </div>
</div>

<?php if (!empty($assignment['description'])): ?>
<div class="card mb-2">
    <div class="card-header">Instructions</div>
    <div class="card-body"><?= nl2br(htmlspecialchars($assignment['description'])) ?></div>
</div>
<?php endif; ?>

<?php if ($submission): ?>
<!-- Already submitted -->
<div class="card mb-2">
    <div class="card-header" style="background:#f0fdf4">
        &#10003; Submission Received
    </div>
    <div class="card-body">
        <p><strong>File:</strong>
            <a href="<?= BASE_URL ?>/<?= htmlspecialchars($submission['file_path']) ?>" download>
                <?= htmlspecialchars(basename($submission['file_path'])) ?>
            </a>
        </p>
        <p><strong>Submitted:</strong> <?= htmlspecialchars(date('M j, Y g:i A', strtotime($submission['submitted_at']))) ?></p>
        <?php if ($submission['grade'] !== null): ?>
        <div class="alert alert-success">
            <strong>Grade: <?= $submission['grade'] ?> / <?= $assignment['max_score'] ?></strong>
            (<?= round($submission['grade'] / $assignment['max_score'] * 100) ?>%)
            <?php if ($submission['feedback']): ?>
            <br><strong>Feedback:</strong> <?= nl2br(htmlspecialchars($submission['feedback'])) ?>
            <?php endif; ?>
        </div>
        <?php else: ?>
        <div class="alert alert-info">Awaiting grading.</div>
        <?php endif; ?>
    </div>
</div>
<?php else: ?>
<!-- Submission form -->
<div class="card" style="max-width:600px">
    <div class="card-header">Submit Your Work</div>
    <div class="card-body">
        <form action="<?= BASE_URL ?>/assignment/submit/<?= $assignment['id'] ?>" method="POST" enctype="multipart/form-data">
            <div class="form-group">
                <label for="submission_file">Upload File <span style="color:red">*</span></label>
                <input type="file" id="submission_file" name="submission_file" class="form-control" required>
                <div class="form-text">Allowed types: pdf, doc, docx, zip, py, txt — Max 10 MB</div>
            </div>
            <button type="submit" class="btn btn-primary">Submit Assignment</button>
        </form>
    </div>
</div>
<?php endif; ?>

<?php
$content = ob_get_clean();
require_once APP_ROOT . '/app/views/layouts/main.php';
