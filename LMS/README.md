# LMS — Learning Management System

A full-featured Learning Management System prototype built with plain PHP (custom MVC), MySQL, and vanilla HTML/CSS/JS. Designed for university demonstration purposes.

---

## Features

| Module | Roles |
|---|---|
| User authentication (register / login / logout) | All |
| Course catalog with enrollment | Student, Instructor, Admin |
| Course materials (file upload + links) | Instructor (manage), Student (view) |
| Discussion forum per course | All enrolled |
| Private messaging | All |
| Assignments (create, submit, grade) | Instructor (manage), Student (submit) |
| Auto-graded quizzes (timed, multiple-choice) | Instructor (manage), Student (take) |
| Role-aware analytics dashboard with Chart.js | All |
| Admin panel: user & course management | Admin |

---

## Tech Stack

- **Backend**: PHP 8.x (custom MVC, no framework)
- **Database**: MySQL 8.0+
- **ORM**: PDO with prepared statements
- **Frontend**: Vanilla HTML5 / CSS3 / JavaScript, Chart.js (CDN)
- **Auth**: Session-based with bcrypt passwords
- **URL routing**: Apache `.htaccess` rewrite → `public/index.php`

---

## Project Structure

```
LMS/
├── app/
│   ├── controllers/          # 9 controllers
│   ├── core/                 # MVC kernel (App, Router, Controller, Model, Database, Auth)
│   ├── models/               # 12 models
│   └── views/
│       ├── admin/
│       ├── assignments/
│       ├── auth/
│       ├── courses/
│       ├── dashboard/
│       ├── errors/
│       ├── forums/
│       ├── layouts/
│       ├── messages/
│       └── quizzes/
├── config/
│   └── config.php            # DB credentials, BASE_URL, constants
├── database/
│   ├── schema.sql            # Table definitions
│   └── seed.sql              # Sample data
├── docs/
│   └── diagrams.md           # ERD, Use Case, DFD (Mermaid)
├── public/
│   ├── css/style.css
│   ├── uploads/
│   │   ├── materials/
│   │   └── submissions/
│   ├── .htaccess
│   └── index.php             # Front controller
└── .htaccess                 # Root protection
```

---

## Setup

### Requirements

- PHP 8.0+, Apache (with `mod_rewrite`), MySQL 8.0+
- XAMPP / Laragon / WAMP or any LAMP/WAMP stack works fine

### Steps

1. **Clone / copy** this project to your web server root, e.g. `C:\xampp\htdocs\LMS`

2. **Create the database**:
   ```sql
   CREATE DATABASE lms CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
   ```

3. **Import schema then seed data**:
   ```bash
   mysql -u root -p lms < database/schema.sql
   mysql -u root -p lms < database/seed.sql
   ```

4. **Configure** `config/config.php`:
   ```php
   define('DB_HOST', 'localhost');
   define('DB_NAME', 'lms');
   define('DB_USER', 'root');
   define('DB_PASS', '');          // your MySQL password
   define('BASE_URL', 'http://localhost/LMS/public');
   ```

5. **Create upload directories** (if not present):
   ```
   public/uploads/materials/
   public/uploads/submissions/
   ```
   Ensure the web server has write permission on these folders.

6. **Enable mod_rewrite** (Apache). In `httpd.conf`, ensure:
   ```
   AllowOverride All
   ```

7. **Open** `http://localhost/LMS/public` in your browser.

---

## Demo Accounts

| Role | Email | Password |
|---|---|---|
| Admin | admin@lms.local | password123 |
| Instructor | instructor1@lms.local | password123 |
| Instructor | instructor2@lms.local | password123 |
| Student | student1@lms.local | password123 |
| Student | student2@lms.local | password123 |
| Student | student3@lms.local | password123 |
| Student | student4@lms.local | password123 |
| Student | student5@lms.local | password123 |

---

## URL Structure

```
/                        → Dashboard
/auth/login              → Login
/auth/register           → Register
/course/index            → Course catalog
/course/detail/{id}      → Course detail (materials, assignments, quizzes, students tabs)
/course/create           → Create course (instructor)
/forum/view/{forumId}    → Forum threads
/message/inbox           → Message inbox
/assignment/view/{id}    → Assignment (grading or submission)
/quiz/take/{id}          → Take quiz (student)
/quiz/result/{id}        → Quiz result
/quiz/manage/{id}        → Quiz attempts (instructor)
/admin/index             → Admin panel
/dashboard/index         → Dashboard
```

---

## Diagrams

See [`docs/diagrams.md`](docs/diagrams.md) for:
- **ERD** — Entity-Relationship Diagram (all 12 tables)
- **Use Case Diagram** — Student / Instructor / Admin actors
- **DFD Level 1** — Data Flow Diagram

Render with any Mermaid-compatible viewer (e.g., [mermaid.live](https://mermaid.live), VS Code Mermaid extension, GitHub markdown).

---

## Security Notes

- Passwords hashed with `bcrypt` (`password_hash` / `password_verify`)
- All user output escaped with `htmlspecialchars`
- Database queries use PDO prepared statements (no SQL injection)
- File uploads whitelist-validated by MIME type and extension
- Sessions regenerated on login (`session_regenerate_id(true)`)
- `.htaccess` denies direct access to `app/` and `config/`
