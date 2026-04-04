<?php
require_once APP_ROOT . '/app/models/Message.php';
$pageTitle = 'Quiz Result — ' . htmlspecialchars($quiz['title']);
$score    = $result['score'] ?? 0;
$maxScore = $result['max_score'] ?? 0;
$pct      = $maxScore > 0 ? round($score / $maxScore * 100) : 0;
$pass     = $pct >= ($quiz['pass_score'] ?? 50);
ob_start();
?>
<div class="page-header">
    <div>
        <a href="<?= BASE_URL ?>/course/detail/<?= $course['id'] ?>" style="color:#64748b;font-size:.88rem">
            &#8592; <?= htmlspecialchars($course['title']) ?>
        </a>
        <h2>&#128203; Quiz Result — <?= htmlspecialchars($quiz['title']) ?></h2>
    </div>
</div>

<div class="stats-cards" style="margin-bottom:1.5rem">
    <div class="stat-card <?= $pass ? '' : 'stat-card-danger' ?>">
        <div class="stat-number"><?= $pct ?>%</div>
        <div class="stat-label">Your Score</div>
    </div>
    <div class="stat-card">
        <div class="stat-number"><?= $score ?> / <?= $maxScore ?></div>
        <div class="stat-label">Points</div>
    </div>
    <div class="stat-card <?= $pass ? 'stat-card-success' : 'stat-card-danger' ?>">
        <div class="stat-number"><?= $pass ? '&#10003; Pass' : '&#10007; Fail' ?></div>
        <div class="stat-label">Passing Score: <?= $quiz['pass_score'] ?? 50 ?>%</div>
    </div>
</div>

<h3 style="margin-bottom:1rem">Review</h3>
<?php
$studentAnswers = isset($result['answers']) ? (is_array($result['answers']) ? $result['answers'] : json_decode($result['answers'], true)) : [];
?>
<?php foreach ($questions as $i => $q): ?>
<?php
    $qid      = (string)$q['id'];
    $correct  = (int)$q['correct_option'];
    $selected = isset($studentAnswers[$qid]) ? (int)$studentAnswers[$qid] : -1;
    $isRight  = $selected === $correct;
?>
<div class="quiz-question" style="border-left:4px solid <?= $isRight ? '#22c55e' : '#ef4444' ?>">
    <h4><?= ($i + 1) ?>. <?= htmlspecialchars($q['question_text']) ?>
        <span style="font-size:.8rem;font-weight:400;color:<?= $isRight ? '#22c55e' : '#ef4444' ?>">
            (<?= $q['points'] ?? 1 ?> pt<?= ($q['points'] ?? 1) != 1 ? 's' : '' ?> — <?= $isRight ? 'Correct' : 'Incorrect' ?>)
        </span>
    </h4>
    <?php foreach ($q['options'] as $idx => $opt): ?>
    <?php
        $classes = 'quiz-option';
        if ($idx === $correct) $classes .= ' correct';
        if ($idx === $selected && !$isRight) $classes .= ' incorrect';
    ?>
    <label class="<?= $classes ?>">
        <?php if ($idx === $selected): ?>&#9654; <?php endif; ?>
        <?= htmlspecialchars($opt) ?>
        <?php if ($idx === $correct): ?> <strong>(correct)</strong><?php endif; ?>
    </label>
    <?php endforeach; ?>
</div>
<?php endforeach; ?>

<div style="margin-top:1.5rem">
    <a href="<?= BASE_URL ?>/course/detail/<?= $course['id'] ?>" class="btn btn-primary">Back to Course</a>
    <a href="<?= BASE_URL ?>/dashboard/index" class="btn btn-secondary">Dashboard</a>
</div>
<?php
$content = ob_get_clean();
require_once APP_ROOT . '/app/views/layouts/main.php';
