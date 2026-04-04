<?php
require_once APP_ROOT . '/app/models/Message.php';
$pageTitle = htmlspecialchars($quiz['title']);
$timeLimit = $quiz['time_limit'] ?? null;
ob_start();
?>
<div class="page-header">
    <div>
        <a href="<?= BASE_URL ?>/course/detail/<?= $course['id'] ?>" style="color:#64748b;font-size:.88rem">
            &#8592; <?= htmlspecialchars($course['title']) ?>
        </a>
        <h2>&#9998; <?= htmlspecialchars($quiz['title']) ?></h2>
        <small>
            <?= count($questions) ?> question(s)
            <?php if ($timeLimit): ?>
            &bull; <span id="timer-display" style="font-weight:600;color:#dc2626">Time: <?= $timeLimit ?>:00</span>
            <?php endif; ?>
        </small>
    </div>
</div>

<?php if (!empty($quiz['description'])): ?>
<div class="alert alert-info mb-2"><?= htmlspecialchars($quiz['description']) ?></div>
<?php endif; ?>

<form action="<?= BASE_URL ?>/quiz/submitQuiz/<?= $quiz['id'] ?>" method="POST" id="quiz-form">
    <?php foreach ($questions as $i => $q): ?>
    <div class="quiz-question">
        <h4><?= ($i + 1) ?>. <?= htmlspecialchars($q['question_text']) ?></h4>
        <?php foreach ($q['options'] as $idx => $opt): ?>
        <label class="quiz-option">
            <input type="radio" name="q_<?= $q['id'] ?>" value="<?= $idx ?>" required>
            <?= htmlspecialchars($opt) ?>
        </label>
        <?php endforeach; ?>
    </div>
    <?php endforeach; ?>

    <?php if (empty($questions)): ?>
    <div class="alert alert-warning">No questions have been added to this quiz yet.</div>
    <?php else: ?>
    <div class="card-body" style="background:#fff;padding:1rem;border:1px solid var(--border);border-radius:8px">
        <button type="submit" class="btn btn-primary" onclick="return confirm('Submit your answers? You cannot retake this quiz.')">
            Submit Quiz
        </button>
        <a href="<?= BASE_URL ?>/course/detail/<?= $course['id'] ?>" class="btn btn-secondary">Cancel</a>
    </div>
    <?php endif; ?>
</form>

<?php if ($timeLimit): ?>
<script>
(function() {
    var total = <?= (int)$timeLimit * 60 ?>;
    var display = document.getElementById('timer-display');
    var form = document.getElementById('quiz-form');
    var interval = setInterval(function() {
        total--;
        if (total <= 0) {
            clearInterval(interval);
            display.textContent = 'Time up!';
            form.submit();
            return;
        }
        var m = Math.floor(total / 60);
        var s = total % 60;
        display.textContent = 'Time: ' + m + ':' + (s < 10 ? '0' : '') + s;
        if (total <= 60) display.style.color = '#dc2626';
    }, 1000);
})();
</script>
<?php endif; ?>

<?php
$content = ob_get_clean();
require_once APP_ROOT . '/app/views/layouts/main.php';
