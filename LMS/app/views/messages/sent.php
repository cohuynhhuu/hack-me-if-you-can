<?php
require_once APP_ROOT . '/app/models/Message.php';
$pageTitle = 'Sent Messages';
ob_start();
?>
<div class="page-header">
    <h2>&#9993; Sent Messages</h2>
    <a href="<?= BASE_URL ?>/message/compose" class="btn btn-primary">&#43; Compose</a>
</div>

<div class="tabs">
    <a class="tab-link" href="<?= BASE_URL ?>/message/inbox">Inbox</a>
    <a class="tab-link active" data-tab="tab-sent">Sent (<?= count($messages) ?>)</a>
</div>

<div class="card">
    <div class="card-body" style="padding:0">
        <?php if (empty($messages)): ?>
        <div class="empty-state">No sent messages.</div>
        <?php else: ?>
        <table>
            <thead><tr><th>To</th><th>Subject</th><th>Date</th><th></th></tr></thead>
            <tbody>
            <?php foreach ($messages as $msg): ?>
            <tr>
                <td><?= htmlspecialchars($msg['receiver_name']) ?></td>
                <td><?= htmlspecialchars($msg['subject'] ?? '(no subject)') ?></td>
                <td style="font-size:.83rem;color:#64748b"><?= htmlspecialchars(date('M j, Y', strtotime($msg['sent_at']))) ?></td>
                <td><a href="<?= BASE_URL ?>/message/read/<?= $msg['id'] ?>" class="btn btn-secondary btn-sm">View</a></td>
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
