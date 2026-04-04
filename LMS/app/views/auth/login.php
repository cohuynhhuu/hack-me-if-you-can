<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login | LMS</title>
    <link rel="stylesheet" href="<?= BASE_URL ?>/css/style.css">
</head>
<body>
<div class="auth-page">
    <div class="auth-card">
        <div class="auth-logo">&#127979;</div>
        <h1>Welcome Back</h1>
        <p class="auth-subtitle">Sign in to your LMS account</p>

        <?php $flash = $_SESSION['flash'] ?? null; unset($_SESSION['flash']); ?>
        <?php if ($flash): ?>
        <div class="alert alert-<?= htmlspecialchars($flash['type']) ?>">
            <?= htmlspecialchars($flash['message']) ?>
        </div>
        <?php endif; ?>

        <form action="<?= BASE_URL ?>/auth/doLogin" method="POST">
            <div class="form-group">
                <label for="email">Email Address</label>
                <input type="email" id="email" name="email" class="form-control"
                       placeholder="you@university.edu" required autofocus>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" class="form-control"
                       placeholder="••••••••" required>
            </div>
            <button type="submit" class="btn btn-primary w-100" style="justify-content:center;padding:.7rem;">
                Sign In
            </button>
        </form>

        <p style="text-align:center;margin-top:1.25rem;font-size:.9rem;color:#64748b;">
            Don't have an account?
            <a href="<?= BASE_URL ?>/auth/register">Create one</a>
        </p>

        <div style="margin-top:1.5rem;padding:1rem;background:#f8fafc;border-radius:8px;font-size:.82rem;color:#64748b;">
            <strong>Demo credentials:</strong><br>
            Admin: admin@lms.edu<br>
            Instructor: john.smith@lms.edu<br>
            Student: alice@student.edu<br>
            Password: <code>password123</code>
        </div>
    </div>
</div>
</body>
</html>
