<?php
require_once APP_ROOT . '/app/models/Message.php';
$pageTitle = 'Create Course';
ob_start();
?>
<div class="page-header">
    <div>
        <a href="<?= BASE_URL ?>/course/index" style="color:#64748b;font-size:.88rem">&#8592; Back to Courses</a>
        <h2>Create New Course</h2>
    </div>
</div>

<div class="card" style="max-width:680px">
    <div class="card-header">Course Details</div>
    <div class="card-body">
        <form action="<?= BASE_URL ?>/course/store" method="POST">
            <div class="form-group">
                <label for="title">Course Title <span style="color:red">*</span></label>
                <input type="text" id="title" name="title" class="form-control"
                       placeholder="e.g., Introduction to Programming" required autofocus>
            </div>
            <div class="form-group">
                <label for="category">Category</label>
                <input type="text" id="category" name="category" class="form-control"
                       placeholder="e.g., Computer Science, Mathematics">
            </div>
            <div class="form-group">
                <label for="language">Language</label>
                <select id="language" name="language" class="form-control">
                    <option value="en" <?= Lang::locale() === 'en' ? 'selected' : '' ?>>English</option>
                    <option value="vi" <?= Lang::locale() === 'vi' ? 'selected' : '' ?>>Tiếng Việt</option>
                </select>
            </div>
            <div class="form-group">
                <label for="description">Description</label>
                <textarea id="description" name="description" class="form-control" rows="5"
                          placeholder="Describe what students will learn in this course..."></textarea>
            </div>
            <div class="d-flex gap-1">
                <button type="submit" class="btn btn-primary">Create Course</button>
                <a href="<?= BASE_URL ?>/course/index" class="btn btn-secondary">Cancel</a>
            </div>
        </form>
    </div>
</div>

<?php
$content = ob_get_clean();
require_once APP_ROOT . '/app/views/layouts/main.php';
