<?php
require_once APP_ROOT . '/app/models/Message.php';
$pageTitle = htmlspecialchars($forum['title']);
ob_start();
?>
<div class="page-header">
    <div>
        <a href="<?= BASE_URL ?>/course/detail/<?= $course['id'] ?>" style="color:#64748b;font-size:.88rem">
            &#8592; <?= htmlspecialchars($course['title']) ?>
        </a>
        <h2>&#128172; <?= htmlspecialchars($forum['title']) ?></h2>
    </div>
    <button class="btn btn-primary" onclick="document.getElementById('new-thread-form').style.display='block'">
        &#43; New Thread
    </button>
</div>

<!-- New thread form -->
<div id="new-thread-form" style="display:none" class="card mb-2">
    <div class="card-header">Start a New Thread</div>
    <div class="card-body">
        <form action="<?= BASE_URL ?>/forum/postThread" method="POST">
            <input type="hidden" name="forum_id" value="<?= $forum['id'] ?>">
            <div class="form-group">
                <label>Subject <span style="color:red">*</span></label>
                <input type="text" name="subject" class="form-control" required autofocus>
            </div>
            <div class="form-group">
                <label>Message <span style="color:red">*</span></label>
                <textarea name="body" class="form-control" rows="4" required></textarea>
            </div>
            <div class="d-flex gap-1">
                <button type="submit" class="btn btn-primary">Post Thread</button>
                <button type="button" class="btn btn-secondary"
                        onclick="document.getElementById('new-thread-form').style.display='none'">Cancel</button>
            </div>
        </form>
    </div>
</div>

<!-- Thread list -->
<div class="card">
    <div class="card-header">Threads (<?= count($threads) ?>)</div>
    <?php if (empty($threads)): ?>
    <div class="empty-state">No threads yet. Be the first to start a discussion!</div>
    <?php else: ?>
    <?php foreach ($threads as $thread): ?>
    <div class="thread-item">
        <div class="thread-avatar"><?= strtoupper(substr($thread['author_name'], 0, 1)) ?></div>
        <div class="thread-content">
            <div class="thread-subject">
                <a href="<?= BASE_URL ?>/forum/thread/<?= $thread['id'] ?>">
                    <?= htmlspecialchars($thread['subject']) ?>
                </a>
            </div>
            <div class="thread-meta">
                <?= htmlspecialchars($thread['author_name']) ?> &bull;
                <?= htmlspecialchars(date('M j, Y g:i A', strtotime($thread['created_at']))) ?>
            </div>
            <p style="font-size:.88rem;color:#64748b;margin-top:.25rem">
                <?= htmlspecialchars(substr($thread['body'], 0, 120)) ?>...
            </p>
        </div>
        <?php if (Auth::hasRole('instructor', 'admin')): ?>
        <form action="<?= BASE_URL ?>/forum/delete/<?= $thread['id'] ?>" method="POST"
              onsubmit="return confirm('Delete this thread and all replies?')">
            <button class="btn btn-danger btn-sm">&#10005;</button>
        </form>
        <?php endif; ?>
    </div>
    <?php endforeach; ?>
    <?php endif; ?>
</div>

<?php
$content = ob_get_clean();
require_once APP_ROOT . '/app/views/layouts/main.php';
