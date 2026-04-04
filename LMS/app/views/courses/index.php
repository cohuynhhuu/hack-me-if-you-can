<?php
require_once APP_ROOT . '/app/models/Message.php';
$pageTitle = 'Courses';
ob_start();
?>
<div class="page-header">
    <div>
        <h2>&#128218; <?= Auth::hasRole('admin') ? 'All Courses' : (Lang::locale() === 'vi' ? 'Tất cả khóa học' : 'All Courses') ?></h2>
        <?php if (!Auth::hasRole('admin')): ?>
        <p style="margin:.2rem 0 0;font-size:.85rem;color:var(--text-sub)">
            <?= Lang::locale() === 'vi' ? '&#127760; Hiển thị khóa học Tiếng Việt' : '&#127760; Showing English courses' ?>
            &mdash; <a href="<?= BASE_URL ?>/lang/set/<?= Lang::locale() === 'vi' ? 'en' : 'vi' ?>">
                <?= Lang::locale() === 'vi' ? 'Switch to English' : 'Chuyển sang Tiếng Việt' ?>
            </a>
        </p>
        <?php endif; ?>
    </div>
    <?php if (Auth::hasRole('instructor', 'admin')): ?>
    <a href="<?= BASE_URL ?>/course/create" class="btn btn-primary">&#43; New Course</a>
    <?php endif; ?>
</div>

<?php if (empty($courses)): ?>
<div class="empty-state">
    <div style="font-size:3rem">&#128218;</div>
    <p>No courses available yet.</p>
    <?php if (Auth::hasRole('instructor', 'admin')): ?>
    <a href="<?= BASE_URL ?>/course/create" class="btn btn-primary">Create First Course</a>
    <?php endif; ?>
</div>
<?php else: ?>
<div class="course-grid">
    <?php foreach ($courses as $course): ?>
    <div class="course-card">
        <div class="course-card-banner"></div>
        <div class="course-card-body">
            <div class="d-flex justify-between align-center mb-1">
                <span class="badge badge-<?= $course['status'] ?>"><?= htmlspecialchars(ucfirst($course['status'])) ?></span>
                <div style="display:flex;gap:.4rem;align-items:center">
                    <?php if (!empty($course['language'])): ?>
                    <span style="font-size:.72rem;background:<?= $course['language']==='vi'?'#dbeafe':'#dcfce7' ?>;color:<?= $course['language']==='vi'?'#1e40af':'#166534' ?>;padding:.1rem .45rem;border-radius:20px;font-weight:600">
                        <?= $course['language'] === 'vi' ? '&#127973; VI' : '&#127468;&#127463; EN' ?>
                    </span>
                    <?php endif; ?>
                    <?php if (!empty($course['category'])): ?>
                    <span style="font-size:.78rem;color:var(--text-sub)"><?= htmlspecialchars($course['category']) ?></span>
                    <?php endif; ?>
                </div>
            </div>
            <div class="course-card-title">
                <a href="<?= BASE_URL ?>/course/detail/<?= $course['id'] ?>">
                    <?= htmlspecialchars($course['title']) ?>
                </a>
            </div>
            <div class="course-card-meta">
                By <?= htmlspecialchars($course['instructor_name']) ?>
            </div>
            <?php if (!empty($course['description'])): ?>
            <p style="font-size:.85rem;color:#64748b;margin-bottom:.5rem">
                <?= htmlspecialchars(substr($course['description'], 0, 100)) ?>...
            </p>
            <?php endif; ?>
        </div>
        <div class="course-card-footer">
            <span>&#128101; <?= $course['student_count'] ?> students</span>
            <?php if (Auth::hasRole('student')): ?>
                <?php if ($course['is_enrolled']): ?>
                <a href="<?= BASE_URL ?>/course/detail/<?= $course['id'] ?>" class="btn btn-success btn-sm">
                    &#10003; Enrolled
                </a>
                <?php else: ?>
                <form action="<?= BASE_URL ?>/course/enroll/<?= $course['id'] ?>" method="POST" style="display:inline">
                    <button type="submit" class="btn btn-primary btn-sm">Enroll</button>
                </form>
                <?php endif; ?>
            <?php else: ?>
            <a href="<?= BASE_URL ?>/course/detail/<?= $course['id'] ?>" class="btn btn-secondary btn-sm">View</a>
            <?php endif; ?>
        </div>
    </div>
    <?php endforeach; ?>
</div>
<?php endif; ?>

<?php if ($totalPages > 1):
    $offset = ($page - 1) * $perPage;
    $from   = $offset + 1;
    $to     = min($offset + $perPage, $total);
?>
<p class="pagination-info">Showing <?= $from ?>–<?= $to ?> of <?= $total ?> courses</p>
<nav class="pagination" aria-label="Course pages">

    <?php if ($page > 1): ?>
        <a href="<?= BASE_URL ?>/course/index?page=<?= $page - 1 ?>">&lsaquo;&nbsp;Prev</a>
    <?php else: ?>
        <span class="disabled">&lsaquo;&nbsp;Prev</span>
    <?php endif; ?>

    <?php
    $pStart = max(2, $page - 2);
    $pEnd   = min($totalPages - 1, $page + 2);
    ?>

    <a href="<?= BASE_URL ?>/course/index?page=1" class="<?= $page === 1 ? 'active' : '' ?>">1</a>

    <?php if ($pStart > 2): ?><span class="ellipsis">&hellip;</span><?php endif; ?>

    <?php for ($i = $pStart; $i <= $pEnd; $i++): ?>
        <a href="<?= BASE_URL ?>/course/index?page=<?= $i ?>" class="<?= $i === $page ? 'active' : '' ?>"><?= $i ?></a>
    <?php endfor; ?>

    <?php if ($pEnd < $totalPages - 1): ?><span class="ellipsis">&hellip;</span><?php endif; ?>

    <?php if ($totalPages > 1): ?>
        <a href="<?= BASE_URL ?>/course/index?page=<?= $totalPages ?>" class="<?= $page === $totalPages ? 'active' : '' ?>"><?= $totalPages ?></a>
    <?php endif; ?>

    <?php if ($page < $totalPages): ?>
        <a href="<?= BASE_URL ?>/course/index?page=<?= $page + 1 ?>">Next&nbsp;&rsaquo;</a>
    <?php else: ?>
        <span class="disabled">Next&nbsp;&rsaquo;</span>
    <?php endif; ?>

</nav>
<?php endif; ?>

<?php
$content = ob_get_clean();
require_once APP_ROOT . '/app/views/layouts/main.php';
