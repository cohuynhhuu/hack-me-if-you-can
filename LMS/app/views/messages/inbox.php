<?php
require_once APP_ROOT . '/app/models/Message.php';
$pageTitle = 'Inbox';
ob_start();
?>
<div class="page-header">
    <h2>&#9993; Messages</h2>
    <a href="<?= BASE_URL ?>/message/compose" class="btn btn-primary">&#43; Compose</a>
</div>

<div class="tabs">
    <a class="tab-link active" data-tab="tab-inbox">Inbox (<?= count($messages) ?>)</a>
    <a class="tab-link" href="<?= BASE_URL ?>/message/sent">Sent</a>
</div>

<div id="tab-inbox" class="tab-pane active">
    <div class="card">
        <div class="card-body" style="padding:0">
            <?php if (empty($messages)): ?>
            <div class="empty-state">Your inbox is empty.</div>
            <?php else: ?>
            <table>
                <thead><tr><th>From</th><th>Subject</th><th>Date</th><th>Status</th><th></th></tr></thead>
                <tbody>
                <?php foreach ($messages as $msg): ?>
                <tr style="<?= !$msg['is_read'] ? 'font-weight:600' : '' ?>">
                    <td><?= htmlspecialchars($msg['sender_name']) ?></td>
                    <td><?= htmlspecialchars($msg['subject'] ?? '(no subject)') ?></td>
                    <td style="font-size:.83rem;color:#64748b"><?= htmlspecialchars(date('M j, Y', strtotime($msg['sent_at']))) ?></td>
                    <td><?= $msg['is_read'] ? '<span class="badge badge-inactive">Read</span>' : '<span class="badge badge-active">New</span>' ?></td>
                    <td><a href="<?= BASE_URL ?>/message/read/<?= $msg['id'] ?>" class="btn btn-secondary btn-sm">View</a></td>
                </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
            <?php endif; ?>
        </div>
    </div>
</div>

<?php
$content = ob_get_clean();
require_once APP_ROOT . '/app/views/layouts/main.php';
