<?php
require_once APP_ROOT . '/app/models/Message.php';
$pageTitle = 'Edit Course';
ob_start();
?>
<div class="page-header">
    <div>
        <a href="<?= BASE_URL ?>/course/detail/<?= $course['id'] ?>" style="color:#64748b;font-size:.88rem">&#8592; Back to Course</a>
        <h2>Edit Course</h2>
    </div>
</div>

<div class="card" style="max-width:680px">
    <div class="card-header">Edit Course Details</div>
    <div class="card-body">
        <form action="<?= BASE_URL ?>/course/update/<?= $course['id'] ?>" method="POST">
            <div class="form-group">
                <label for="title">Course Title <span style="color:red">*</span></label>
                <input type="text" id="title" name="title" class="form-control"
                       value="<?= htmlspecialchars($course['title']) ?>" required>
            </div>
            <div class="form-group">
                <label for="category">Category</label>
                <input type="text" id="category" name="category" class="form-control"
                       value="<?= htmlspecialchars($course['category'] ?? '') ?>">
            </div>
            <div class="form-group">
                <label for="language">Language</label>
                <select id="language" name="language" class="form-control">
                    <option value="en" <?= ($course['language'] ?? 'en') === 'en' ? 'selected' : '' ?>>English</option>
                    <option value="vi" <?= ($course['language'] ?? 'en') === 'vi' ? 'selected' : '' ?>>Tiếng Việt</option>
                </select>
            </div>
            <div class="form-group">
                <label for="description">Description</label>
                <textarea id="description" name="description" class="form-control" rows="5"><?= htmlspecialchars($course['description'] ?? '') ?></textarea>
            </div>
            <div class="form-group">
                <label for="status">Status</label>
                <select id="status" name="status" class="form-control">
                    <?php foreach (['active','inactive','archived'] as $s): ?>
                    <option value="<?= $s ?>" <?= $course['status'] === $s ? 'selected' : '' ?>><?= ucfirst($s) ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div class="d-flex gap-1">
                <button type="submit" class="btn btn-primary">Save Changes</button>
                <a href="<?= BASE_URL ?>/course/detail/<?= $course['id'] ?>" class="btn btn-secondary">Cancel</a>
            </div>
        </form>
    </div>
</div>

<?php
$content = ob_get_clean();
require_once APP_ROOT . '/app/views/layouts/main.php';
