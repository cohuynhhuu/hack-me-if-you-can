<?php
require_once APP_ROOT . '/app/models/Message.php';
$pageTitle = htmlspecialchars($message['subject'] ?? 'Message');
ob_start();
?>
<div class="page-header">
    <div>
        <a href="<?= BASE_URL ?>/message/inbox" style="color:#64748b;font-size:.88rem">&#8592; Inbox</a>
        <h2><?= htmlspecialchars($message['subject'] ?? '(no subject)') ?></h2>
    </div>
    <a href="<?= BASE_URL ?>/message/compose?to=<?= $message['sender_id'] ?>" class="btn btn-primary">Reply</a>
</div>

<div class="card" style="max-width:700px">
    <div class="card-header">
        <div>
            <strong>From:</strong> <?= htmlspecialchars($message['sender_name']) ?> &nbsp;
            <strong>To:</strong> <?= htmlspecialchars($message['receiver_name']) ?>
        </div>
        <small><?= htmlspecialchars(date('M j, Y g:i A', strtotime($message['sent_at']))) ?></small>
    </div>
    <div class="card-body" style="white-space:pre-wrap;font-size:.95rem;line-height:1.7">
        <?= nl2br(htmlspecialchars($message['body'])) ?>
    </div>
</div>

<?php
$content = ob_get_clean();
require_once APP_ROOT . '/app/views/layouts/main.php';
