<?php
require_once APP_ROOT . '/app/models/Message.php';
$pageTitle = 'Compose Message';
ob_start();
?>
<div class="page-header">
    <div>
        <a href="<?= BASE_URL ?>/message/inbox" style="color:#64748b;font-size:.88rem">&#8592; Inbox</a>
        <h2>&#9993; Compose Message</h2>
    </div>
</div>

<div class="card" style="max-width:640px">
    <div class="card-body">
        <form action="<?= BASE_URL ?>/message/send" method="POST">
            <div class="form-group">
                <label for="receiver_id">To <span style="color:red">*</span></label>
                <select id="receiver_id" name="receiver_id" class="form-control" required>
                    <option value="">-- Select recipient --</option>
                    <?php foreach ($users as $u): ?>
                    <?php if ($u['id'] == Auth::id()) continue; ?>
                    <option value="<?= $u['id'] ?>"
                        <?= ($toUser && (int)$toUser['id'] === (int)$u['id']) ? 'selected' : '' ?>>
                        <?= htmlspecialchars($u['name']) ?> (<?= htmlspecialchars($u['email']) ?>) — <?= htmlspecialchars(ucfirst($u['role'])) ?>
                    </option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div class="form-group">
                <label for="subject">Subject</label>
                <input type="text" id="subject" name="subject" class="form-control"
                       placeholder="Optional subject line">
            </div>
            <div class="form-group">
                <label for="body">Message <span style="color:red">*</span></label>
                <textarea id="body" name="body" class="form-control" rows="6"
                          placeholder="Write your message here..." required></textarea>
            </div>
            <div class="d-flex gap-1">
                <button type="submit" class="btn btn-primary">Send Message</button>
                <a href="<?= BASE_URL ?>/message/inbox" class="btn btn-secondary">Cancel</a>
            </div>
        </form>
    </div>
</div>

<?php
$content = ob_get_clean();
require_once APP_ROOT . '/app/views/layouts/main.php';
