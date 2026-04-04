<?php
require_once APP_ROOT . '/app/models/Message.php';
$pageTitle = 'Dashboard';
$role = \Auth::role();
ob_start();
?>

<div class="page-header" style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:.5rem">
    <div>
        <h2 style="margin:0">
            <?php if ($role === 'admin'): ?>&#9881;
            <?php elseif ($role === 'instructor'): ?>&#128196;
            <?php else: ?>&#127891;
            <?php endif; ?>
            <?= t('dashboard') ?>
        </h2>
        <p style="margin:.25rem 0 0;color:var(--text-sub)"><?= t('welcome_back') ?>, <strong><?= htmlspecialchars(\Auth::name()) ?></strong>
            &nbsp;<span class="badge badge-<?= $role === 'admin' ? 'danger' : ($role === 'instructor' ? 'warning' : 'info') ?>">
                <?= ucfirst($role) ?>
            </span>
        </p>
    </div>
    <?php if ($role === 'student'): ?>
    <a href="<?= BASE_URL ?>/course/index" class="btn btn-primary"><?= t('browse_courses') ?></a>
    <?php elseif ($role === 'instructor'): ?>
    <a href="<?= BASE_URL ?>/course/create" class="btn btn-primary"><?= t('new_course_btn') ?></a>
    <?php else: ?>
    <a href="<?= BASE_URL ?>/admin/index" class="btn btn-primary"><?= t('admin_panel_btn') ?></a>
    <?php endif; ?>
</div>

<?php /* ─────────────────── STUDENT ─────────────────── */ ?>
<?php if ($role === 'student'): ?>
<div class="stats-cards">
    <div class="flip-card">
        <div class="flip-inner">
            <div class="flip-front" style="background:linear-gradient(135deg,#6366f1,#4f46e5)">
                <div class="flip-icon">&#127891;</div>
                <div class="flip-label"><?= t('enrolled_courses') ?></div>
            </div>
            <div class="flip-back">
                <div class="flip-number" style="color:#6366f1"><?= count($courses ?? []) ?></div>
                <div class="flip-desc"><?= t('enrolled_courses') ?></div>
            </div>
        </div>
    </div>
    <div class="flip-card">
        <div class="flip-inner">
            <div class="flip-front" style="background:linear-gradient(135deg,#10b981,#059669)">
                <div class="flip-icon">&#128200;</div>
                <div class="flip-label"><?= t('quizzes_taken') ?></div>
            </div>
            <div class="flip-back">
                <div class="flip-number" style="color:#10b981"><?= $completedQuizzes ?? 0 ?></div>
                <div class="flip-desc"><?= t('quizzes_taken') ?></div>
            </div>
        </div>
    </div>
    <div class="flip-card">
        <div class="flip-inner">
            <div class="flip-front" style="background:linear-gradient(135deg,#f59e0b,#d97706)">
                <div class="flip-icon">&#128203;</div>
                <div class="flip-label"><?= t('assignments_submitted') ?></div>
            </div>
            <div class="flip-back">
                <div class="flip-number" style="color:#f59e0b"><?= $submittedAssignments ?? 0 ?></div>
                <div class="flip-desc"><?= t('assignments_submitted') ?></div>
            </div>
        </div>
    </div>
    <div class="flip-card">
        <div class="flip-inner">
            <div class="flip-front" style="background:linear-gradient(135deg,#3b82f6,#2563eb)">
                <div class="flip-icon">&#11088;</div>
                <div class="flip-label"><?= t('avg_quiz_score') ?></div>
            </div>
            <div class="flip-back">
                <div class="flip-number" style="color:#3b82f6"><?= isset($avgScore) ? $avgScore . '%' : '&mdash;' ?></div>
                <div class="flip-desc"><?= t('avg_quiz_score') ?></div>
            </div>
        </div>
    </div>
</div>

<?php if (!empty($courses)): ?>
<div class="card" style="margin-bottom:1.5rem">
    <div class="card-header"><h3 style="margin:0"><?= t('my_courses') ?></h3></div>
    <div style="padding:1rem">
    <?php foreach ($courses as $c): ?>
    <?php $prog = $progress[$c['id']] ?? ['done' => 0, 'total' => 0, 'percent' => 0]; ?>
    <div style="margin-bottom:1.25rem">
        <div style="display:flex;justify-content:space-between;margin-bottom:.25rem">
            <a href="<?= BASE_URL ?>/course/detail/<?= $c['id'] ?>" style="font-weight:500">
                <?= htmlspecialchars($c['title']) ?>
            </a>
            <small style="color:#64748b"><?= $prog['done'] ?>/<?= $prog['total'] ?> assignments graded</small>
        </div>
        <div class="progress-bar-container">
            <div class="progress-bar" style="width:<?= $prog['percent'] ?>%"></div>
        </div>
        <small style="color:#64748b"><?= $prog['percent'] ?>% complete</small>
    </div>
    <?php endforeach; ?>
    </div>
</div>
<?php endif; ?>

<?php if (!empty($quizChartLabels)): ?>
<div class="card" style="margin-bottom:1.5rem">
    <div class="card-header"><h3 style="margin:0"><?= t('quiz_scores') ?></h3></div>
    <div style="padding:1rem">
        <canvas id="quizChart" height="100"></canvas>
    </div>
</div>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script>
new Chart(document.getElementById('quizChart'), {
    type: 'bar',
    data: {
        labels: <?= json_encode($quizChartLabels ?? []) ?>,
        datasets: [{
            label: 'Score (%)',
            data: <?= json_encode($quizChartData ?? []) ?>,
            backgroundColor: 'rgba(99,102,241,0.7)',
            borderRadius: 4
        }]
    },
    options: {
        scales: { y: { beginAtZero:true, max:100 } },
        plugins: { legend: { display: false } }
    }
});
</script>
<?php endif; ?>

<?php if (!empty($recentSubmissions)): ?>
<div class="card">
    <div class="card-header"><h3 style="margin:0"><?= t('recent_submissions') ?></h3></div>
    <table class="table">
        <thead><tr><th><?= t('col_assignment') ?></th><th><?= t('col_course') ?></th><th><?= t('col_grade') ?></th><th><?= t('col_submitted') ?></th></tr></thead>
        <tbody>
        <?php foreach ($recentSubmissions as $s): ?>
        <tr>
            <td><?= htmlspecialchars($s['assignment_title'] ?? 'Assignment') ?></td>
            <td><?= htmlspecialchars($s['course_title'] ?? '') ?></td>
            <td>
                <?php if ($s['grade'] !== null): ?>
                    <span class="badge badge-success"><?= $s['grade'] ?>/100</span>
                <?php else: ?>
                    <span class="badge badge-warning"><?= t('pending') ?></span>
                <?php endif; ?>
            </td>
            <td><small><?= date('M j, Y', strtotime($s['submitted_at'])) ?></small></td>
        </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
</div>
<?php endif; ?>
<?php endif; /* end student */ ?>

<?php /* ─────────────────── INSTRUCTOR ─────────────────── */ ?>
<?php if ($role === 'instructor'): ?>
<div class="stats-cards">
    <div class="flip-card">
        <div class="flip-inner">
            <div class="flip-front" style="background:linear-gradient(135deg,#6366f1,#4f46e5)">
                <div class="flip-icon">&#128196;</div>
                <div class="flip-label"><?= t('my_courses_stat') ?></div>
            </div>
            <div class="flip-back">
                <div class="flip-number" style="color:#6366f1"><?= count($courseStats ?? []) ?></div>
                <div class="flip-desc"><?= t('my_courses_stat') ?></div>
            </div>
        </div>
    </div>
    <div class="flip-card">
        <div class="flip-inner">
            <div class="flip-front" style="background:linear-gradient(135deg,#10b981,#059669)">
                <div class="flip-icon">&#128101;</div>
                <div class="flip-label"><?= t('total_students') ?></div>
            </div>
            <div class="flip-back">
                <div class="flip-number" style="color:#10b981"><?= array_sum(array_column($courseStats ?? [], 'enrollment_count')) ?></div>
                <div class="flip-desc"><?= t('total_students') ?></div>
            </div>
        </div>
    </div>
    <div class="flip-card">
        <div class="flip-inner">
            <div class="flip-front" style="background:linear-gradient(135deg,<?= ($pendingGrading ?? 0) > 0 ? '#f59e0b,#d97706' : '#10b981,#059669' ?>)">
                <div class="flip-icon">&#9998;</div>
                <div class="flip-label"><?= t('pending_gradings') ?></div>
            </div>
            <div class="flip-back">
                <div class="flip-number" style="color:<?= ($pendingGrading ?? 0) > 0 ? '#f59e0b' : '#10b981' ?>"><?= $pendingGrading ?? 0 ?></div>
                <div class="flip-desc"><?= t('pending_gradings') ?></div>
            </div>
        </div>
    </div>
    <div class="flip-card">
        <div class="flip-inner">
            <div class="flip-front" style="background:linear-gradient(135deg,#3b82f6,#2563eb)">
                <div class="flip-icon">&#10067;</div>
                <div class="flip-label"><?= t('quizzes_created') ?></div>
            </div>
            <div class="flip-back">
                <div class="flip-number" style="color:#3b82f6"><?= $totalQuizzes ?? 0 ?></div>
                <div class="flip-desc"><?= t('quizzes_created') ?></div>
            </div>
        </div>
    </div>
</div>

<?php if (!empty($courseStats)): ?>
<div class="card" style="margin-bottom:1.5rem">
    <div class="card-header"><h3 style="margin:0"><?= t('course_overview') ?></h3></div>
    <table class="table">
        <thead><tr><th><?= t('col_course') ?></th><th><?= t('col_students') ?></th><th><?= t('col_avg_score') ?></th><th><?= t('col_status') ?></th><th></th></tr></thead>
        <tbody>
        <?php foreach ($courseStats as $cs): ?>
        <tr>
            <td><a href="<?= BASE_URL ?>/course/detail/<?= $cs['id'] ?>"><?= htmlspecialchars($cs['title']) ?></a></td>
            <td><?= $cs['enrollment_count'] ?></td>
            <td><?= $cs['avg_quiz_score'] !== null ? round($cs['avg_quiz_score']) . '%' : '—' ?></td>
            <td>
                <?php if (($cs['pending_submissions'] ?? 0) > 0): ?>
                <span class="badge badge-warning"><?= $cs['pending_submissions'] ?> <?= t('ungraded') ?></span>
                <?php else: ?>
                <span class="badge badge-success"><?= t('all_graded') ?></span>
                <?php endif; ?>
            </td>
            <td><a href="<?= BASE_URL ?>/course/detail/<?= $cs['id'] ?>" class="btn btn-secondary" style="padding:.3rem .75rem;font-size:.8rem">Manage</a></td>
        </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
</div>
<?php endif; ?>

<?php if (!empty($enrollChartLabels)): ?>
<div class="card">
    <div class="card-header"><h3 style="margin:0"><?= t('enrollment_chart') ?></h3></div>
    <div style="padding:1rem">
        <canvas id="enrollChart" height="100"></canvas>
    </div>
</div>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script>
new Chart(document.getElementById('enrollChart'), {
    type: 'bar',
    data: {
        labels: <?= json_encode($enrollChartLabels ?? []) ?>,
        datasets: [{
            label: 'Students',
            data: <?= json_encode($enrollChartData ?? []) ?>,
            backgroundColor: 'rgba(16,185,129,0.7)',
            borderRadius: 4
        }]
    },
    options: {
        scales: { y: { beginAtZero:true, ticks:{ stepSize:1 } } },
        plugins: { legend: { display: false } }
    }
});
</script>
<?php endif; ?>
<?php endif; /* end instructor */ ?>

<?php /* ─────────────────── ADMIN ─────────────────── */ ?>
<?php if ($role === 'admin'): ?>
<div class="stats-cards">
    <div class="flip-card">
        <div class="flip-inner">
            <div class="flip-front" style="background:linear-gradient(135deg,#6366f1,#4f46e5)">
                <div class="flip-icon">&#128100;</div>
                <div class="flip-label"><?= t('total_users') ?></div>
            </div>
            <div class="flip-back">
                <div class="flip-number" style="color:#6366f1"><?= $totalUsers ?? 0 ?></div>
                <div class="flip-desc"><?= t('total_users') ?></div>
            </div>
        </div>
    </div>
    <div class="flip-card">
        <div class="flip-inner">
            <div class="flip-front" style="background:linear-gradient(135deg,#3b82f6,#2563eb)">
                <div class="flip-icon">&#127891;</div>
                <div class="flip-label"><?= t('students') ?></div>
            </div>
            <div class="flip-back">
                <div class="flip-number" style="color:#3b82f6"><?= $totalStudents ?? 0 ?></div>
                <div class="flip-desc"><?= t('students') ?></div>
            </div>
        </div>
    </div>
    <div class="flip-card">
        <div class="flip-inner">
            <div class="flip-front" style="background:linear-gradient(135deg,#f59e0b,#d97706)">
                <div class="flip-icon">&#128104;&#8205;&#127979;</div>
                <div class="flip-label"><?= t('instructors') ?></div>
            </div>
            <div class="flip-back">
                <div class="flip-number" style="color:#f59e0b"><?= $totalInstructors ?? 0 ?></div>
                <div class="flip-desc"><?= t('instructors') ?></div>
            </div>
        </div>
    </div>
    <div class="flip-card">
        <div class="flip-inner">
            <div class="flip-front" style="background:linear-gradient(135deg,#10b981,#059669)">
                <div class="flip-icon">&#128218;</div>
                <div class="flip-label"><?= t('courses') ?></div>
            </div>
            <div class="flip-back">
                <div class="flip-number" style="color:#10b981"><?= $totalCourses ?? 0 ?></div>
                <div class="flip-desc"><?= t('courses') ?></div>
            </div>
        </div>
    </div>
    <div class="flip-card">
        <div class="flip-inner">
            <div class="flip-front" style="background:linear-gradient(135deg,#ef4444,#dc2626)">
                <div class="flip-icon">&#128279;</div>
                <div class="flip-label"><?= t('enrollments') ?></div>
            </div>
            <div class="flip-back">
                <div class="flip-number" style="color:#ef4444"><?= $totalEnrollments ?? 0 ?></div>
                <div class="flip-desc"><?= t('enrollments') ?></div>
            </div>
        </div>
    </div>
</div>

<?php if (!empty($topCourses)): ?>
<div class="card" style="margin-bottom:1.5rem">
    <div class="card-header"><h3 style="margin:0"><?= t('top_courses') ?></h3></div>
    <table class="table">
        <thead><tr><th>#</th><th><?= t('col_course') ?></th><th><?= t('col_instructor') ?></th><th><?= t('col_students') ?></th></tr></thead>
        <tbody>
        <?php foreach ($topCourses as $i => $tc): ?>
        <tr>
            <td><?= $i + 1 ?></td>
            <td><a href="<?= BASE_URL ?>/course/detail/<?= $tc['id'] ?>"><?= htmlspecialchars($tc['title']) ?></a></td>
            <td><?= htmlspecialchars($tc['instructor_name']) ?></td>
            <td><strong><?= $tc['student_count'] ?></strong></td>
        </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
</div>
<?php endif; ?>

<?php if (!empty($enrollChartLabels)): ?>
<?php $chartCount = count($enrollChartLabels); ?>
<div class="card">
    <div class="card-header" style="display:flex;align-items:center;justify-content:space-between">
        <h3 style="margin:0">&#128200; <?= t('enrollment_overview') ?></h3>
        <small style="color:#64748b"><?= $chartCount ?> course<?= $chartCount != 1 ? 's' : '' ?></small>
    </div>
    <div style="padding:1.25rem 1rem">
        <canvas id="adminChart"></canvas>
    </div>
</div>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script>
(function () {
    var labels = <?= json_encode($enrollChartLabels) ?>;
    var data   = <?= json_encode($enrollChartData) ?>;
    var palette = [
        ['#6366f1','#818cf8'], ['#3b82f6','#60a5fa'], ['#10b981','#34d399'],
        ['#f59e0b','#fbbf24'], ['#ef4444','#f87171'], ['#8b5cf6','#a78bfa'],
        ['#ec4899','#f472b6'], ['#06b6d4','#22d3ee'], ['#84cc16','#a3e635'],
        ['#f97316','#fb923c']
    ];
    var bgColors     = data.map(function(_, i) { return palette[i % palette.length][0]; });
    var hoverColors  = data.map(function(_, i) { return palette[i % palette.length][1]; });
    var borderColors = bgColors;

    new Chart(document.getElementById('adminChart'), {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Students Enrolled',
                data: data,
                backgroundColor: bgColors,
                hoverBackgroundColor: hoverColors,
                borderColor: borderColors,
                borderWidth: 0,
                borderRadius: 10,
                borderSkipped: false,
            }]
        },
        options: {
            responsive: true,
            animation: { duration: 800, easing: 'easeOutQuart' },
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: '#1e293b',
                    titleColor: '#f1f5f9',
                    bodyColor: '#94a3b8',
                    padding: 10,
                    cornerRadius: 8,
                    callbacks: {
                        label: function(ctx) {
                            return '  ' + ctx.parsed.y + ' student' + (ctx.parsed.y !== 1 ? 's' : '');
                        }
                    }
                }
            },
            scales: {
                x: {
                    grid: { display: false },
                    ticks: { color: '#64748b', font: { size: 12, weight: '500' } }
                },
                y: {
                    beginAtZero: true,
                    ticks: { stepSize: 1, color: '#94a3b8', font: { size: 11 } },
                    grid: { color: '#f1f5f9', drawBorder: false }
                }
            }
        }
    });
})();
</script>
<?php endif; ?>

<div style="margin-top:1.5rem">
    <a href="<?= BASE_URL ?>/admin/index" class="btn btn-primary">&#9881; Admin Panel</a>
</div>
<?php endif; /* end admin */ ?>

<?php
$content = ob_get_clean();
require_once APP_ROOT . '/app/views/layouts/main.php';
