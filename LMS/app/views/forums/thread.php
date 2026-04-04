<?php
require_once APP_ROOT . '/app/models/Message.php';
$pageTitle = htmlspecialchars($post['subject'] ?? 'Thread');
ob_start();
?>
<div class="page-header">
    <div>
        <a href="<?= BASE_URL ?>/forum/view/<?= $forum['id'] ?>" style="color:#64748b;font-size:.88rem">
            &#8592; <?= htmlspecialchars($forum['title']) ?>
        </a>
        <h2><?= htmlspecialchars($post['subject']) ?></h2>
    </div>
</div>

<!-- Original post -->
<div class="card mb-2">
    <div class="card-header" style="background:#eff6ff">
        <div class="d-flex align-center gap-1">
            <div class="thread-avatar" style="width:32px;height:32px;font-size:.85rem">
                <?= strtoupper(substr($post['author_name'], 0, 1)) ?>
            </div>
            <div>
                <strong><?= htmlspecialchars($post['author_name']) ?></strong>
                <small style="margin-left:.5rem"><?= htmlspecialchars(date('M j, Y g:i A', strtotime($post['created_at']))) ?></small>
            </div>
        </div>
    </div>
    <div class="card-body">
        <?= nl2br(htmlspecialchars($post['body'])) ?>
    </div>
</div>

<!-- Replies -->
<?php if (!empty($replies)): ?>
<div class="section-title">Replies (<?= count($replies) ?>)</div>
<?php foreach ($replies as $reply): ?>
<div class="card mb-1" style="margin-left:2rem">
    <div class="card-header" style="background:#f8fafc">
        <div class="d-flex align-center gap-1">
            <div class="thread-avatar" style="width:28px;height:28px;font-size:.78rem;background:#64748b">
                <?= strtoupper(substr($reply['author_name'], 0, 1)) ?>
            </div>
            <div>
                <strong><?= htmlspecialchars($reply['author_name']) ?></strong>
                <small style="margin-left:.5rem"><?= htmlspecialchars(date('M j, Y g:i A', strtotime($reply['created_at']))) ?></small>
            </div>
        </div>
    </div>
    <div class="card-body">
        <?= nl2br(htmlspecialchars($reply['body'])) ?>
    </div>
</div>
<?php endforeach; ?>
<?php endif; ?>

<!-- Reply form -->
<div class="card mt-2">
    <div class="card-header">Post a Reply</div>
    <div class="card-body">
        <form action="<?= BASE_URL ?>/forum/postReply" method="POST">
            <input type="hidden" name="forum_id" value="<?= $forum['id'] ?>">
            <input type="hidden" name="parent_id" value="<?= $post['id'] ?>">
            <div class="form-group">
                <textarea name="body" class="form-control" rows="4" placeholder="Write your reply..." required></textarea>
            </div>
            <button type="submit" class="btn btn-primary">Post Reply</button>
        </form>
    </div>
</div>

<?php
$content = ob_get_clean();
require_once APP_ROOT . '/app/views/layouts/main.php';
