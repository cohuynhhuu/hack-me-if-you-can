<?php
// Flash message helper
$flash = $_SESSION['flash'] ?? null;
unset($_SESSION['flash']);
?>
<!DOCTYPE html>
<html lang="<?= Lang::locale() ?>" data-theme="light">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= htmlspecialchars($pageTitle ?? 'LMS') ?> | LMS</title>
    <link rel="stylesheet" href="<?= BASE_URL ?>/css/style.css">
    <script>(function(){var t=localStorage.getItem('lms-theme');if(t)document.documentElement.setAttribute('data-theme',t);})();</script>
</head>
<body>
<div class="wrapper">
    <!-- Sidebar -->
    <aside class="sidebar">
        <div class="sidebar-brand">LMS <span>&#8226;</span> University</div>
        <nav class="sidebar-nav">
            <div class="nav-section"><?= t('nav_main') ?></div>
            <a href="<?= BASE_URL ?>/dashboard/index"
               class="<?= strpos($_SERVER['REQUEST_URI'], '/dashboard') !== false ? 'active' : '' ?>">
                &#9641; <?= t('nav_dashboard') ?>
            </a>
            <a href="<?= BASE_URL ?>/course/index"
               class="<?= strpos($_SERVER['REQUEST_URI'], '/course') !== false ? 'active' : '' ?>">
                &#128218; <?= t('nav_courses') ?>
            </a>

            <?php if (Auth::hasRole('instructor', 'admin')): ?>
            <div class="nav-section"><?= t('nav_teaching') ?></div>
            <a href="<?= BASE_URL ?>/course/create">&#43; <?= t('nav_new_course') ?></a>
            <?php endif; ?>

            <?php if (Auth::hasRole('admin')): ?>
            <div class="nav-section"><?= t('nav_admin_section') ?></div>
            <a href="<?= BASE_URL ?>/admin/index"
               class="<?= strpos($_SERVER['REQUEST_URI'], '/admin') !== false ? 'active' : '' ?>">
                &#9881; <?= t('nav_admin_panel') ?>
            </a>
            <?php endif; ?>

            <div class="nav-section"><?= t('nav_communication') ?></div>
            <a href="<?= BASE_URL ?>/message/inbox"
               class="<?= strpos($_SERVER['REQUEST_URI'], '/message') !== false ? 'active' : '' ?>">
                &#9993; <?= t('nav_messages') ?>
                <?php
                $unread = (new Message())->countUnread(Auth::id());
                if ($unread > 0): ?>
                    <span class="badge badge-admin" style="margin-left:auto"><?= $unread ?></span>
                <?php endif; ?>
            </a>
        </nav>
        <div class="sidebar-footer">
            <div style="font-weight:600;color:#cbd5e1"><?= htmlspecialchars(Auth::name()) ?></div>
            <div style="font-size:.78rem;margin-top:.2rem;">
                <span class="badge badge-<?= Auth::role() ?>"><?= Auth::role() ?></span>
            </div>
            <a href="<?= BASE_URL ?>/auth/logout" class="btn btn-secondary btn-sm" style="margin-top:.75rem;width:100%;justify-content:center;">
                <?= t('logout') ?>
            </a>
        </div>
    </aside>

    <!-- Main -->
    <div class="main-content">
        <header class="topbar">
            <div style="display:flex;align-items:center;gap:.5rem">
                <button class="sidebar-toggle" id="sidebar-toggle" aria-label="Toggle navigation">&#9776;</button>
                <span class="topbar-title"><?= htmlspecialchars($pageTitle ?? 'Dashboard') ?></span>
            </div>
            <div class="topbar-user">
                <!-- Language switcher -->
                <div class="lang-switcher">
                    <a href="<?= BASE_URL ?>/lang/set/en" class="<?= Lang::locale() === 'en' ? 'active' : '' ?>">EN</a>
                    <a href="<?= BASE_URL ?>/lang/set/vi" class="<?= Lang::locale() === 'vi' ? 'active' : '' ?>">VI</a>
                </div>
                <!-- Theme toggle -->
                <button class="btn-icon" id="theme-toggle" type="button" title="Toggle theme">&#127769;</button>
                <!-- Messages -->
                <a href="<?= BASE_URL ?>/message/inbox" style="position:relative;font-size:1.1rem">&#9993;
                    <?php if (($unread ?? 0) > 0): ?>
                        <span class="badge badge-admin" style="position:absolute;top:-4px;right:-8px;font-size:.62rem;padding:.1rem .3rem;line-height:1"><?= $unread ?></span>
                    <?php endif; ?>
                </a>
                <span class="user-name" style="font-weight:500"><?= htmlspecialchars(Auth::name()) ?></span>
                <span class="badge-role"><?= ucfirst(Auth::role()) ?></span>
            </div>
        </header>

        <main class="page-content">
            <?php if ($flash): ?>
            <div class="alert alert-<?= htmlspecialchars($flash['type']) ?>">
                <?= htmlspecialchars($flash['message']) ?>
            </div>
            <?php endif; ?>

            <?= $content ?? '' ?>
        </main>
    </div>
    <div class="sidebar-overlay" id="sidebar-overlay"></div>
</div>
<script>
// Simple tab switching
document.querySelectorAll('.tab-link').forEach(function(link) {
    link.addEventListener('click', function(e) {
        e.preventDefault();
        var target = this.dataset.tab;
        document.querySelectorAll('.tab-link').forEach(l => l.classList.remove('active'));
        document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
        this.classList.add('active');
        var pane = document.getElementById(target);
        if (pane) pane.classList.add('active');
    });
});

// Theme toggle
(function () {
    var btn = document.getElementById('theme-toggle');
    function applyTheme(theme) {
        document.documentElement.setAttribute('data-theme', theme);
        localStorage.setItem('lms-theme', theme);
        if (btn) btn.textContent = theme === 'dark' ? '\u2600\ufe0f' : '\ud83c\udf19';
    }
    applyTheme(localStorage.getItem('lms-theme') || 'light');
    if (btn) btn.addEventListener('click', function () {
        var current = document.documentElement.getAttribute('data-theme');
        applyTheme(current === 'dark' ? 'light' : 'dark');
    });
})();

// Sidebar mobile toggle
(function () {
    var toggle  = document.getElementById('sidebar-toggle');
    var sidebar = document.querySelector('.sidebar');
    var overlay = document.getElementById('sidebar-overlay');
    function openSidebar() {
        sidebar.classList.add('sidebar-open');
        overlay.classList.add('active');
        document.body.style.overflow = 'hidden';
    }
    function closeSidebar() {
        sidebar.classList.remove('sidebar-open');
        overlay.classList.remove('active');
        document.body.style.overflow = '';
    }
    if (toggle) toggle.addEventListener('click', function () {
        sidebar.classList.contains('sidebar-open') ? closeSidebar() : openSidebar();
    });
    if (overlay) overlay.addEventListener('click', closeSidebar);
    // Auto-close when a nav link is tapped on mobile
    sidebar.querySelectorAll('a').forEach(function (a) {
        a.addEventListener('click', function () {
            if (window.innerWidth <= 992) closeSidebar();
        });
    });
})();
</script>
</body>
</html>
