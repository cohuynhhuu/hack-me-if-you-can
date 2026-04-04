<?php
require_once APP_ROOT . '/app/models/Message.php';
$pageTitle = htmlspecialchars($course['title']);
ob_start();
?>
<div class="page-header">
    <div>
        <a href="<?= BASE_URL ?>/course/index" style="color:#64748b;font-size:.88rem">&#8592; All Courses</a>
        <h2><?= htmlspecialchars($course['title']) ?></h2>
        <small>Instructor: <?= htmlspecialchars($course['instructor_name']) ?>
            | Category: <?= htmlspecialchars($course['category'] ?? 'General') ?>
            | <span class="badge badge-<?= $course['status'] ?>"><?= ucfirst($course['status']) ?></span>
        </small>
    </div>
    <div class="d-flex gap-1" style="flex-wrap:wrap">
        <?php if (Auth::hasRole('student') && !$isEnrolled): ?>
        <form action="<?= BASE_URL ?>/course/enroll/<?= $course['id'] ?>" method="POST">
            <button class="btn btn-primary">Enroll in Course</button>
        </form>
        <?php elseif (Auth::hasRole('student') && $isEnrolled): ?>
        <form action="<?= BASE_URL ?>/course/unenroll/<?= $course['id'] ?>" method="POST"
              onsubmit="return confirm('Unenroll from this course?')">
            <button class="btn btn-secondary">Unenroll</button>
        </form>
        <?php endif; ?>
        <?php if (Auth::hasRole('instructor', 'admin')): ?>
        <a href="<?= BASE_URL ?>/course/edit/<?= $course['id'] ?>" class="btn btn-warning">Edit</a>
        <form action="<?= BASE_URL ?>/course/delete/<?= $course['id'] ?>" method="POST"
              onsubmit="return confirm('Delete this course and all its data?')">
            <button class="btn btn-danger">Delete</button>
        </form>
        <?php endif; ?>
    </div>
</div>

<?php if (!empty($course['description'])): ?>
<div class="card mb-2"><div class="card-body"><?= nl2br(htmlspecialchars($course['description'])) ?></div></div>
<?php endif; ?>

<!-- Tabs -->
<div class="tabs">
    <a class="tab-link active" data-tab="tab-materials">Materials
        <span class="badge badge-student"><?= count($materials) ?></span>
    </a>
    <a class="tab-link" data-tab="tab-assignments">Assignments
        <span class="badge badge-student"><?= count($assignments) ?></span>
    </a>
    <a class="tab-link" data-tab="tab-quizzes">Quizzes
        <span class="badge badge-student"><?= count($quizzes) ?></span>
    </a>
    <a class="tab-link" data-tab="tab-students">Students
        <span class="badge badge-student"><?= count($students) ?></span>
    </a>
    <?php if ($forum): ?>
    <a class="tab-link" href="<?= BASE_URL ?>/forum/view/<?= $forum['id'] ?>">Forum &#8599;</a>
    <?php endif; ?>
</div>

<!-- Materials Tab -->
<div id="tab-materials" class="tab-pane active">
    <div class="card">
        <div class="card-header">
            Course Materials
            <?php if (Auth::hasRole('instructor', 'admin')): ?>
            <button class="btn btn-primary btn-sm" onclick="document.getElementById('add-material-form').style.display='block'">
                &#43; Add Material
            </button>
            <?php endif; ?>
        </div>
        <?php if (Auth::hasRole('instructor', 'admin')): ?>
        <div id="add-material-form" style="display:none;padding:1rem;border-bottom:1px solid var(--border);background:#f8fafc">
            <form action="<?= BASE_URL ?>/material/store" method="POST" enctype="multipart/form-data">
                <input type="hidden" name="course_id" value="<?= $course['id'] ?>">
                <div class="form-row">
                    <div class="form-group">
                        <label>Title</label>
                        <input type="text" name="title" class="form-control" required>
                    </div>
                    <div class="form-group">
                        <label>Type</label>
                        <select name="type" class="form-control" id="mat-type" onchange="toggleMaterialInput()">
                            <option value="file">File Upload</option>
                            <option value="link">External Link</option>
                        </select>
                    </div>
                </div>
                <div id="input-file" class="form-group">
                    <label>Upload File</label>
                    <input type="file" name="material_file" class="form-control">
                </div>
                <div id="input-link" class="form-group" style="display:none">
                    <label>URL</label>
                    <input type="url" name="link_url" class="form-control" placeholder="https://...">
                </div>
                <div class="d-flex gap-1">
                    <button type="submit" class="btn btn-success btn-sm">Save</button>
                    <button type="button" class="btn btn-secondary btn-sm"
                            onclick="document.getElementById('add-material-form').style.display='none'">Cancel</button>
                </div>
            </form>
        </div>
        <?php endif; ?>
        <div class="card-body" style="padding:0">
            <?php if (empty($materials)): ?>
            <div class="empty-state">No materials uploaded yet.</div>
            <?php else: ?>
            <table>
                <thead><tr><th>Title</th><th>Type</th><th>Action</th></tr></thead>
                <tbody>
                <?php foreach ($materials as $mat): ?>
                <tr>
                    <td><?= htmlspecialchars($mat['title']) ?></td>
                    <td><span class="badge badge-<?= $mat['type'] === 'link' ? 'instructor' : 'student' ?>"><?= htmlspecialchars($mat['type']) ?></span></td>
                    <td>
                        <?php if ($mat['type'] === 'link'): ?>
                        <a href="<?= htmlspecialchars($mat['content']) ?>" target="_blank" rel="noopener noreferrer" class="btn btn-info btn-sm">Open Link</a>
                        <?php else: ?>
                        <a href="<?= BASE_URL ?>/<?= htmlspecialchars($mat['content']) ?>" class="btn btn-secondary btn-sm" download>Download</a>
                        <?php endif; ?>
                        <?php if (Auth::hasRole('instructor', 'admin')): ?>
                        <form action="<?= BASE_URL ?>/material/delete/<?= $mat['id'] ?>" method="POST" style="display:inline"
                              onsubmit="return confirm('Delete this material?')">
                            <button class="btn btn-danger btn-sm">&#10005;</button>
                        </form>
                        <?php endif; ?>
                    </td>
                </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
            <?php endif; ?>
        </div>
    </div>
</div>

<!-- Assignments Tab -->
<div id="tab-assignments" class="tab-pane">
    <div class="card">
        <div class="card-header">
            Assignments
            <?php if (Auth::hasRole('instructor', 'admin')): ?>
            <button class="btn btn-primary btn-sm" onclick="document.getElementById('add-assign-form').style.display='block'">
                &#43; Add Assignment
            </button>
            <?php endif; ?>
        </div>
        <?php if (Auth::hasRole('instructor', 'admin')): ?>
        <div id="add-assign-form" style="display:none;padding:1rem;border-bottom:1px solid var(--border);background:#f8fafc">
            <form action="<?= BASE_URL ?>/assignment/create" method="POST">
                <input type="hidden" name="course_id" value="<?= $course['id'] ?>">
                <div class="form-row">
                    <div class="form-group">
                        <label>Title</label>
                        <input type="text" name="title" class="form-control" required>
                    </div>
                    <div class="form-group">
                        <label>Due Date</label>
                        <input type="datetime-local" name="due_date" class="form-control">
                    </div>
                </div>
                <div class="form-group">
                    <label>Description</label>
                    <textarea name="description" class="form-control"></textarea>
                </div>
                <div class="form-group" style="max-width:180px">
                    <label>Max Score</label>
                    <input type="number" name="max_score" class="form-control" value="100" min="1">
                </div>
                <div class="d-flex gap-1">
                    <button type="submit" class="btn btn-success btn-sm">Save</button>
                    <button type="button" class="btn btn-secondary btn-sm"
                            onclick="document.getElementById('add-assign-form').style.display='none'">Cancel</button>
                </div>
            </form>
        </div>
        <?php endif; ?>
        <div class="card-body" style="padding:0">
            <?php if (empty($assignments)): ?>
            <div class="empty-state">No assignments yet.</div>
            <?php else: ?>
            <table>
                <thead><tr><th>Title</th><th>Due Date</th><th>Max Score</th><th>Action</th></tr></thead>
                <tbody>
                <?php foreach ($assignments as $a): ?>
                <tr>
                    <td><?= htmlspecialchars($a['title']) ?></td>
                    <td><?= $a['due_date'] ? htmlspecialchars(date('M j, Y', strtotime($a['due_date']))) : 'N/A' ?></td>
                    <td><?= $a['max_score'] ?></td>
                    <td>
                        <a href="<?= BASE_URL ?>/assignment/view/<?= $a['id'] ?>" class="btn btn-primary btn-sm">
                            <?= Auth::hasRole('student') ? 'Submit' : 'View Submissions' ?>
                        </a>
                        <?php if (Auth::hasRole('instructor', 'admin')): ?>
                        <form action="<?= BASE_URL ?>/assignment/delete/<?= $a['id'] ?>" method="POST" style="display:inline"
                              onsubmit="return confirm('Delete this assignment?')">
                            <button class="btn btn-danger btn-sm">&#10005;</button>
                        </form>
                        <?php endif; ?>
                    </td>
                </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
            <?php endif; ?>
        </div>
    </div>
</div>

<!-- Quizzes Tab -->
<div id="tab-quizzes" class="tab-pane">
    <div class="card">
        <div class="card-header">
            Quizzes
            <?php if (Auth::hasRole('instructor', 'admin')): ?>
            <a href="#create-quiz" class="btn btn-primary btn-sm"
               onclick="document.getElementById('create-quiz-modal').style.display='block';return false">
                &#43; Create Quiz
            </a>
            <?php endif; ?>
        </div>
        <div class="card-body" style="padding:0">
            <?php if (empty($quizzes)): ?>
            <div class="empty-state">No quizzes available.</div>
            <?php else: ?>
            <table>
                <thead><tr><th>Title</th><th>Time Limit</th><th>Action</th></tr></thead>
                <tbody>
                <?php foreach ($quizzes as $q): ?>
                <tr>
                    <td><?= htmlspecialchars($q['title']) ?></td>
                    <td><?= $q['time_limit'] ? $q['time_limit'] . ' min' : 'No limit' ?></td>
                    <td>
                        <?php if (Auth::hasRole('student')): ?>
                        <a href="<?= BASE_URL ?>/quiz/take/<?= $q['id'] ?>" class="btn btn-primary btn-sm">Take Quiz</a>
                        <?php else: ?>
                        <a href="<?= BASE_URL ?>/quiz/manage/<?= $q['id'] ?>" class="btn btn-info btn-sm">Results</a>
                        <form action="<?= BASE_URL ?>/quiz/delete/<?= $q['id'] ?>" method="POST" style="display:inline"
                              onsubmit="return confirm('Delete this quiz?')">
                            <button class="btn btn-danger btn-sm">&#10005;</button>
                        </form>
                        <?php endif; ?>
                    </td>
                </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
            <?php endif; ?>
        </div>
    </div>

    <!-- Quick quiz create form -->
    <?php if (Auth::hasRole('instructor', 'admin')): ?>
    <div id="create-quiz-modal" style="display:none" class="card mt-2">
        <div class="card-header">Create Quiz</div>
        <div class="card-body">
            <form action="<?= BASE_URL ?>/quiz/create" method="POST" id="quiz-form">
                <input type="hidden" name="course_id" value="<?= $course['id'] ?>">
                <div class="form-row">
                    <div class="form-group">
                        <label>Quiz Title</label>
                        <input type="text" name="title" class="form-control" required>
                    </div>
                    <div class="form-group">
                        <label>Time Limit (minutes, optional)</label>
                        <input type="number" name="time_limit" class="form-control" placeholder="Leave empty for no limit">
                    </div>
                </div>
                <div class="form-group">
                    <label>Description</label>
                    <textarea name="description" class="form-control"></textarea>
                </div>

                <div class="section-title">Questions</div>
                <div id="questions-container"></div>
                <button type="button" class="btn btn-secondary btn-sm mb-2" onclick="addQuestion()">&#43; Add Question</button>

                <div class="d-flex gap-1">
                    <button type="submit" class="btn btn-success">Save Quiz</button>
                    <button type="button" class="btn btn-secondary"
                            onclick="document.getElementById('create-quiz-modal').style.display='none'">Cancel</button>
                </div>
            </form>
        </div>
    </div>
    <?php endif; ?>
</div>

<!-- Students Tab -->
<div id="tab-students" class="tab-pane">
    <div class="card">
        <div class="card-header">Enrolled Students</div>
        <div class="card-body" style="padding:0">
            <?php if (empty($students)): ?>
            <div class="empty-state">No students enrolled yet.</div>
            <?php else: ?>
            <table>
                <thead><tr><th>Name</th><th>Email</th><th>Enrolled</th></tr></thead>
                <tbody>
                <?php foreach ($students as $s): ?>
                <tr>
                    <td><?= htmlspecialchars($s['name']) ?></td>
                    <td><?= htmlspecialchars($s['email']) ?></td>
                    <td><?= htmlspecialchars(date('M j, Y', strtotime($s['enrolled_at']))) ?></td>
                </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
            <?php endif; ?>
        </div>
    </div>
</div>

<script>
function toggleMaterialInput() {
    var type = document.getElementById('mat-type').value;
    document.getElementById('input-file').style.display = type === 'file' ? 'block' : 'none';
    document.getElementById('input-link').style.display = type === 'link' ? 'block' : 'none';
}

var qIndex = 0;
function addQuestion() {
    var i = qIndex++;
    var html = '<div class="quiz-question" id="q-'+i+'">' +
        '<div class="d-flex justify-between mb-1"><strong>Question '+(i+1)+'</strong>' +
        '<button type="button" onclick="document.getElementById(\'q-'+i+'\').remove()" class="btn btn-danger btn-sm">&#10005;</button></div>' +
        '<div class="form-group"><label>Question Text</label>' +
        '<input type="text" name="question_text['+i+']" class="form-control" required></div>' +
        '<div id="opts-'+i+'"></div>' +
        '<button type="button" onclick="addOption('+i+')" class="btn btn-secondary btn-sm">&#43; Add Option</button>' +
        '<div class="form-group mt-1"><label>Correct Answer (0-based index)</label>' +
        '<input type="number" name="correct_answer['+i+']" class="form-control" value="0" min="0"></div>' +
        '</div>';
    document.getElementById('questions-container').insertAdjacentHTML('beforeend', html);
    addOption(i); addOption(i); addOption(i); addOption(i); // default 4 options
}

var optCounts = {};
function addOption(qi) {
    if (!optCounts[qi]) optCounts[qi] = 0;
    var oi = optCounts[qi]++;
    var html = '<div class="form-group"><label>Option '+(oi+1)+'</label>' +
        '<input type="text" name="options['+qi+']['+oi+']" class="form-control" placeholder="Option text" required></div>';
    document.getElementById('opts-'+qi).insertAdjacentHTML('beforeend', html);
}
</script>

<?php
$content = ob_get_clean();
require_once APP_ROOT . '/app/views/layouts/main.php';
