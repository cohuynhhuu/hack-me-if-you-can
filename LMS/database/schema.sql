-- ============================================================
-- LMS Database Schema
-- Compatible: MySQL 8.0+
-- ============================================================

CREATE DATABASE IF NOT EXISTS lms_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE lms_db;

-- ============================================================
-- Table: users
-- Stores all system users (students, instructors, admins)
-- ============================================================
CREATE TABLE users (
    id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    name        VARCHAR(100)  NOT NULL,
    email       VARCHAR(150)  NOT NULL UNIQUE,
    password    VARCHAR(255)  NOT NULL,
    role        ENUM('student','instructor','admin') NOT NULL DEFAULT 'student',
    avatar      VARCHAR(255)  DEFAULT NULL,
    created_at  DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================
-- Table: courses
-- ============================================================
CREATE TABLE courses (
    id             INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    instructor_id  INT UNSIGNED NOT NULL,
    title          VARCHAR(200)  NOT NULL,
    description    TEXT          DEFAULT NULL,
    category       VARCHAR(100)  DEFAULT NULL,
    status         ENUM('active','inactive','archived') NOT NULL DEFAULT 'active',
    created_at     DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at     DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_courses_instructor FOREIGN KEY (instructor_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================
-- Table: enrollments
-- ============================================================
CREATE TABLE enrollments (
    id           INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id      INT UNSIGNED NOT NULL,
    course_id    INT UNSIGNED NOT NULL,
    enrolled_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_enrollment (user_id, course_id),
    CONSTRAINT fk_enrollments_user   FOREIGN KEY (user_id)   REFERENCES users(id)   ON DELETE CASCADE,
    CONSTRAINT fk_enrollments_course FOREIGN KEY (course_id) REFERENCES courses(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================
-- Table: materials
-- Course resources (uploaded files or external links)
-- ============================================================
CREATE TABLE materials (
    id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    course_id   INT UNSIGNED   NOT NULL,
    title       VARCHAR(200)   NOT NULL,
    type        ENUM('file','link') NOT NULL DEFAULT 'file',
    content     VARCHAR(500)   NOT NULL,   -- file path or URL
    sort_order  SMALLINT       NOT NULL DEFAULT 0,
    created_at  DATETIME       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_materials_course FOREIGN KEY (course_id) REFERENCES courses(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================
-- Table: forums
-- One forum per course
-- ============================================================
CREATE TABLE forums (
    id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    course_id   INT UNSIGNED   NOT NULL UNIQUE,
    title       VARCHAR(200)   NOT NULL,
    created_at  DATETIME       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_forums_course FOREIGN KEY (course_id) REFERENCES courses(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================
-- Table: forum_posts
-- Threads and replies (parent_id NULL = top-level post)
-- ============================================================
CREATE TABLE forum_posts (
    id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    forum_id    INT UNSIGNED   NOT NULL,
    user_id     INT UNSIGNED   NOT NULL,
    parent_id   INT UNSIGNED   DEFAULT NULL,  -- NULL = thread, non-NULL = reply
    subject     VARCHAR(200)   DEFAULT NULL,
    body        TEXT           NOT NULL,
    created_at  DATETIME       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_forumposts_forum  FOREIGN KEY (forum_id)  REFERENCES forums(id)      ON DELETE CASCADE,
    CONSTRAINT fk_forumposts_user   FOREIGN KEY (user_id)   REFERENCES users(id)       ON DELETE CASCADE,
    CONSTRAINT fk_forumposts_parent FOREIGN KEY (parent_id) REFERENCES forum_posts(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================
-- Table: messages
-- Direct messages between users
-- ============================================================
CREATE TABLE messages (
    id           INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    sender_id    INT UNSIGNED   NOT NULL,
    receiver_id  INT UNSIGNED   NOT NULL,
    subject      VARCHAR(200)   DEFAULT NULL,
    body         TEXT           NOT NULL,
    is_read      TINYINT(1)     NOT NULL DEFAULT 0,
    sent_at      DATETIME       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_messages_sender   FOREIGN KEY (sender_id)   REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_messages_receiver FOREIGN KEY (receiver_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================
-- Table: assignments
-- ============================================================
CREATE TABLE assignments (
    id           INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    course_id    INT UNSIGNED   NOT NULL,
    title        VARCHAR(200)   NOT NULL,
    description  TEXT           DEFAULT NULL,
    due_date     DATETIME       DEFAULT NULL,
    max_score    SMALLINT       NOT NULL DEFAULT 100,
    created_at   DATETIME       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_assignments_course FOREIGN KEY (course_id) REFERENCES courses(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================
-- Table: submissions
-- Student file submissions for assignments
-- ============================================================
CREATE TABLE submissions (
    id             INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    assignment_id  INT UNSIGNED   NOT NULL,
    student_id     INT UNSIGNED   NOT NULL,
    file_path      VARCHAR(500)   NOT NULL,
    grade          DECIMAL(5,2)   DEFAULT NULL,
    feedback       TEXT           DEFAULT NULL,
    submitted_at   DATETIME       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    graded_at      DATETIME       DEFAULT NULL,
    UNIQUE KEY uq_submission (assignment_id, student_id),
    CONSTRAINT fk_submissions_assignment FOREIGN KEY (assignment_id) REFERENCES assignments(id) ON DELETE CASCADE,
    CONSTRAINT fk_submissions_student    FOREIGN KEY (student_id)    REFERENCES users(id)        ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================
-- Table: quizzes
-- ============================================================
CREATE TABLE quizzes (
    id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    course_id   INT UNSIGNED   NOT NULL,
    title       VARCHAR(200)   NOT NULL,
    description TEXT           DEFAULT NULL,
    time_limit  SMALLINT       DEFAULT NULL,  -- minutes, NULL = no limit
    created_at  DATETIME       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_quizzes_course FOREIGN KEY (course_id) REFERENCES courses(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================
-- Table: quiz_questions
-- Multiple-choice questions; options stored as JSON array
-- ============================================================
CREATE TABLE quiz_questions (
    id              INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    quiz_id         INT UNSIGNED   NOT NULL,
    question_text   TEXT           NOT NULL,
    options         JSON           NOT NULL,  -- e.g. ["A) ...", "B) ...", "C) ...", "D) ..."]
    correct_answer  TINYINT        NOT NULL,  -- 0-based index into options array
    points          TINYINT        NOT NULL DEFAULT 1,
    sort_order      SMALLINT       NOT NULL DEFAULT 0,
    CONSTRAINT fk_questions_quiz FOREIGN KEY (quiz_id) REFERENCES quizzes(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================
-- Table: quiz_results
-- Stores each student's attempt score
-- ============================================================
CREATE TABLE quiz_results (
    id           INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    quiz_id      INT UNSIGNED   NOT NULL,
    student_id   INT UNSIGNED   NOT NULL,
    score        DECIMAL(5,2)   NOT NULL DEFAULT 0,
    max_score    DECIMAL(5,2)   NOT NULL DEFAULT 0,
    answers      JSON           DEFAULT NULL,  -- {"question_id": chosen_index, ...}
    taken_at     DATETIME       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_results_quiz    FOREIGN KEY (quiz_id)    REFERENCES quizzes(id) ON DELETE CASCADE,
    CONSTRAINT fk_results_student FOREIGN KEY (student_id) REFERENCES users(id)   ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
