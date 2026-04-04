<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register | LMS</title>
    <link rel="stylesheet" href="<?= BASE_URL ?>/css/style.css">
</head>
<body>
<div class="auth-page">
    <div class="auth-card">
        <div class="auth-logo">&#127979;</div>
        <h1>Create Account</h1>
        <p class="auth-subtitle">Join the Learning Management System</p>

        <?php $flash = $_SESSION['flash'] ?? null; unset($_SESSION['flash']); ?>
        <?php if ($flash): ?>
        <div class="alert alert-<?= htmlspecialchars($flash['type']) ?>">
            <?= htmlspecialchars($flash['message']) ?>
        </div>
        <?php endif; ?>

        <form action="<?= BASE_URL ?>/auth/doRegister" method="POST">
            <div class="form-group">
                <label for="name">Full Name</label>
                <input type="text" id="name" name="name" class="form-control"
                       placeholder="John Doe" required autofocus>
            </div>
            <div class="form-group">
                <label for="email">Email Address</label>
                <input type="email" id="email" name="email" class="form-control"
                       placeholder="you@university.edu" required>
            </div>
            <div class="form-row">
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" id="password" name="password" class="form-control"
                           placeholder="Min 6 characters" required>
                </div>
                <div class="form-group">
                    <label for="password_confirm">Confirm Password</label>
                    <input type="password" id="password_confirm" name="password_confirm"
                           class="form-control" placeholder="••••••••" required>
                </div>
            </div>
            <div class="form-group">
                <label for="role">Register As</label>
                <select id="role" name="role" class="form-control">
                    <option value="student">Student</option>
                    <option value="instructor">Instructor</option>
                </select>
            </div>
            <button type="submit" class="btn btn-primary w-100" style="justify-content:center;padding:.7rem;">
                Create Account
            </button>
        </form>

        <p style="text-align:center;margin-top:1.25rem;font-size:.9rem;color:#64748b;">
            Already have an account? <a href="<?= BASE_URL ?>/auth/login">Sign in</a>
        </p>
    </div>
</div>
</body>
</html>
