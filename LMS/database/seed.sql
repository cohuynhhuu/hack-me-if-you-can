-- ============================================================
-- LMS Seed Data
-- Run AFTER schema.sql
-- ============================================================
USE lms_db;

-- ============================================================
-- Users (password = "password123" hashed with bcrypt)
-- ============================================================
-- password = "password123" — hash: $2y$10$yW5muCLdNRoUlVybh0pMb.F2fKxIiIyP9GpyHYachH3Y1WpOc86My
INSERT INTO users (id, name, email, password, role) VALUES
(1,  'Admin System',   'admin@lms.local',       '$2y$10$yW5muCLdNRoUlVybh0pMb.F2fKxIiIyP9GpyHYachH3Y1WpOc86My', 'admin'),
(2,  'Dr. John Smith', 'instructor1@lms.local', '$2y$10$yW5muCLdNRoUlVybh0pMb.F2fKxIiIyP9GpyHYachH3Y1WpOc86My', 'instructor'),
(3,  'Dr. Sarah Lee',  'instructor2@lms.local', '$2y$10$yW5muCLdNRoUlVybh0pMb.F2fKxIiIyP9GpyHYachH3Y1WpOc86My', 'instructor'),
(4,  'Alice Johnson',  'student1@lms.local',    '$2y$10$yW5muCLdNRoUlVybh0pMb.F2fKxIiIyP9GpyHYachH3Y1WpOc86My', 'student'),
(5,  'Bob Williams',   'student2@lms.local',    '$2y$10$yW5muCLdNRoUlVybh0pMb.F2fKxIiIyP9GpyHYachH3Y1WpOc86My', 'student'),
(6,  'Carol Martinez', 'student3@lms.local',    '$2y$10$yW5muCLdNRoUlVybh0pMb.F2fKxIiIyP9GpyHYachH3Y1WpOc86My', 'student'),
(7,  'David Chen',     'student4@lms.local',    '$2y$10$yW5muCLdNRoUlVybh0pMb.F2fKxIiIyP9GpyHYachH3Y1WpOc86My', 'student'),
(8,  'Eva Brown',      'student5@lms.local',    '$2y$10$yW5muCLdNRoUlVybh0pMb.F2fKxIiIyP9GpyHYachH3Y1WpOc86My', 'student');

-- ============================================================
-- Courses
-- ============================================================
INSERT INTO courses (id, instructor_id, title, description, category, status) VALUES
(1, 2, 'Introduction to Programming', 'Learn the fundamentals of programming using Python. Covers variables, loops, functions and OOP.', 'Computer Science', 'active'),
(2, 2, 'Data Structures & Algorithms', 'Deep dive into arrays, linked lists, trees, graphs and sorting algorithms.', 'Computer Science', 'active'),
(3, 3, 'Calculus I',                   'Limits, derivatives, integrals and their applications.', 'Mathematics', 'active'),
(4, 3, 'Linear Algebra',               'Vectors, matrices, linear transformations and eigenvalues.', 'Mathematics', 'active');

-- ============================================================
-- Enrollments
-- ============================================================
INSERT INTO enrollments (user_id, course_id) VALUES
(4, 1), (4, 2), (4, 3),
(5, 1), (5, 3), (5, 4),
(6, 1), (6, 2),
(7, 2), (7, 3),
(8, 1), (8, 4);

-- ============================================================
-- Materials
-- ============================================================
INSERT INTO materials (course_id, title, type, content, sort_order) VALUES
(1, 'Week 1: Introduction to Python',    'link', 'https://docs.python.org/3/tutorial/index.html', 1),
(1, 'Week 2: Control Flow',              'file', 'uploads/materials/control_flow.pdf',            2),
(1, 'Week 3: Functions',                 'file', 'uploads/materials/functions.pdf',               3),
(2, 'Lecture Notes: Arrays',             'file', 'uploads/materials/arrays.pdf',                  1),
(2, 'Big-O Cheat Sheet',                 'link', 'https://www.bigocheatsheet.com/',               2),
(3, 'Calculus Textbook Chapter 1',       'file', 'uploads/materials/calc_ch1.pdf',               1),
(3, 'Khan Academy - Limits',             'link', 'https://www.khanacademy.org/math/calculus-1',  2),
(4, 'Linear Algebra Notes',              'file', 'uploads/materials/linalg_notes.pdf',           1);

-- ============================================================
-- Forums (one per course)
-- ============================================================
INSERT INTO forums (id, course_id, title) VALUES
(1, 1, 'Intro to Programming - Discussion'),
(2, 2, 'Data Structures - Discussion'),
(3, 3, 'Calculus I - Discussion'),
(4, 4, 'Linear Algebra - Discussion');

-- ============================================================
-- Forum Posts (threads and replies)
-- ============================================================
INSERT INTO forum_posts (id, forum_id, user_id, parent_id, subject, body) VALUES
(1,  1, 4,    NULL, 'Question about Week 2',       'I am confused about how while loops terminate. Can someone explain?'),
(2,  1, 2,    1,    NULL,                           'Great question Alice! A while loop terminates when its condition evaluates to False. Make sure your loop variable is updated inside the loop body.'),
(3,  1, 5,    1,    NULL,                           'I had the same confusion. The key is to always have a "stopping condition" in your loop.'),
(4,  1, 6,    NULL, 'Study Group?',                 'Anyone interested in forming a study group for the midterm?'),
(5,  1, 8,    4,    NULL,                           'I am in! Let us meet at the library on Saturday.'),
(6,  2, 7,    NULL, 'Linked Lists vs Arrays',       'When should we prefer a linked list over an array?'),
(7,  2, 2,    6,    NULL,                           'Use linked lists when you need frequent insertions/deletions. Use arrays for random access by index.'),
(8,  3, 4,    NULL, 'Limit definition help',        'Can someone explain the epsilon-delta definition of a limit in simple terms?'),
(9,  3, 3,    8,    NULL,                           'Think of it this way: for any small error margin (epsilon) you choose, there is a neighborhood (delta) around the point where the function stays within that error margin.');

-- ============================================================
-- Messages
-- ============================================================
INSERT INTO messages (sender_id, receiver_id, subject, body, is_read) VALUES
(4, 2, 'Question about assignment',  'Hi Dr. Smith, I have a question about Assignment 1. When you say "demonstrate recursion", do you want us to show multiple examples?', 0),
(2, 4, 'RE: Question about assignment', 'Hi Alice, yes please show at least two different examples of recursion such as factorial and fibonacci.', 1),
(5, 3, 'Calculus help needed',       'Dr. Lee, I am struggling with the chain rule. Could we schedule office hours?', 0),
(7, 2, 'DSA question',               'Dr. Smith, is the time complexity of QuickSort always O(n log n)?', 0);

-- ============================================================
-- Assignments
-- ============================================================
INSERT INTO assignments (id, course_id, title, description, due_date, max_score) VALUES
(1, 1, 'Assignment 1: Basic Python',      'Write a Python script that demonstrates variables, conditionals, and loops. Include comments.', '2026-04-20 23:59:00', 100),
(2, 1, 'Assignment 2: Functions & OOP',   'Implement a class hierarchy for a simple bank account system using OOP principles.',            '2026-05-05 23:59:00', 100),
(3, 2, 'Assignment 1: Linked List',       'Implement a singly linked list from scratch in Python with insert, delete, and search methods.', '2026-04-25 23:59:00', 100),
(4, 3, 'Problem Set 1: Limits',           'Solve the 10 limit problems from Chapter 2 of the textbook. Show all work.',                    '2026-04-18 23:59:00', 50),
(5, 4, 'Assignment 1: Matrix Operations', 'Implement matrix addition, multiplication and transpose in Python without using NumPy.',         '2026-04-28 23:59:00', 100);

-- ============================================================
-- Submissions
-- ============================================================
INSERT INTO submissions (assignment_id, student_id, file_path, grade, feedback, graded_at) VALUES
(1, 4, 'uploads/submissions/alice_assign1.py',   92.00, 'Excellent work! Clean code and good use of comments.',   '2026-04-22 10:00:00'),
(1, 5, 'uploads/submissions/bob_assign1.py',     78.00, 'Good effort. The loop logic has a small off-by-one error.', '2026-04-22 10:30:00'),
(1, 6, 'uploads/submissions/carol_assign1.py',   85.00, 'Well structured. Consider adding more descriptive variable names.', '2026-04-22 11:00:00'),
(1, 8, 'uploads/submissions/eva_assign1.py',     88.00, 'Good. The conditional logic is correct.',                '2026-04-23 09:00:00'),
(3, 4, 'uploads/submissions/alice_ll.py',        95.00, 'Outstanding implementation with edge case handling.',    '2026-04-27 14:00:00'),
(3, 7, 'uploads/submissions/david_ll.py',        71.00, 'Basic implementation works but missing delete method.',  '2026-04-27 15:00:00'),
(4, 4, 'uploads/submissions/alice_limits.pdf',   46.00, 'Very good. Minor arithmetic error on problem 8.',        '2026-04-20 09:00:00'),
(4, 5, 'uploads/submissions/bob_limits.pdf',     38.00, 'Needs improvement on epsilon-delta problems.',           '2026-04-20 09:30:00');

-- ============================================================
-- Quizzes
-- ============================================================
INSERT INTO quizzes (id, course_id, title, description, time_limit) VALUES
(1, 1, 'Python Basics Quiz',       'Test your knowledge of Python fundamentals.',      20),
(2, 2, 'DSA Fundamentals Quiz',    'Multiple choice quiz on basic data structures.',   15),
(3, 3, 'Calculus Concepts Quiz',   'Quiz on limits and derivatives.',                  25);

-- ============================================================
-- Quiz Questions
-- ============================================================
INSERT INTO quiz_questions (id, quiz_id, question_text, options, correct_answer, points, sort_order) VALUES
-- Quiz 1: Python Basics
(1,  1, 'What is the output of: print(type(3.14))?',
    '["<class \'int\'>", "<class \'float\'>", "<class \'str\'>", "<class \'double\'>"]', 1, 1, 1),
(2,  1, 'Which keyword is used to define a function in Python?',
    '["func", "def", "function", "define"]', 1, 1, 2),
(3,  1, 'What does the "len()" function return?',
    '["The last element", "The first element", "The number of items", "The sum of items"]', 2, 1, 3),
(4,  1, 'Which of the following is a mutable data type in Python?',
    '["tuple", "string", "list", "int"]', 2, 1, 4),
(5,  1, 'What is the correct syntax for a Python for-loop over a list?',
    '["for i in list:", "for (i=0;i<n;i++):", "foreach i in list:", "loop i in list:"]', 0, 1, 5),
-- Quiz 2: DSA
(6,  2, 'What is the time complexity of accessing an element in an array by index?',
    '["O(n)", "O(log n)", "O(1)", "O(n^2)"]', 2, 1, 1),
(7,  2, 'Which data structure follows LIFO order?',
    '["Queue", "Stack", "Linked List", "Tree"]', 1, 1, 2),
(8,  2, 'What is the worst-case time complexity of QuickSort?',
    '["O(n log n)", "O(n)", "O(n^2)", "O(log n)"]', 2, 1, 3),
(9,  2, 'In a binary search tree, where is the smallest value located?',
    '["Root", "Rightmost node", "Leftmost node", "Any leaf node"]', 2, 1, 4),
-- Quiz 3: Calculus
(10, 3, 'What is the limit of sin(x)/x as x approaches 0?',
    '["0", "Undefined", "infinity", "1"]', 3, 1, 1),
(11, 3, 'What is the derivative of x^3?',
    '["x^2", "2x^2", "3x^2", "3x^3"]', 2, 1, 2),
(12, 3, 'Which rule is used to differentiate a product of two functions?',
    '["Chain Rule", "Product Rule", "Quotient Rule", "Power Rule"]', 1, 1, 3);

-- ============================================================
-- Quiz Results
-- ============================================================
INSERT INTO quiz_results (quiz_id, student_id, score, max_score, answers) VALUES
(1, 4, 5.00, 5.00, '{"1":1,"2":1,"3":2,"4":2,"5":0}'),
(1, 5, 3.00, 5.00, '{"1":0,"2":1,"3":2,"4":1,"5":0}'),
(1, 6, 4.00, 5.00, '{"1":1,"2":1,"3":2,"4":0,"5":0}'),
(1, 8, 4.00, 5.00, '{"1":1,"2":1,"3":1,"4":2,"5":0}'),
(2, 4, 4.00, 4.00, '{"6":2,"7":1,"8":2,"9":2}'),
(2, 7, 3.00, 4.00, '{"6":2,"7":0,"8":2,"9":2}'),
(3, 4, 3.00, 3.00, '{"10":3,"11":2,"12":1}'),
(3, 5, 2.00, 3.00, '{"10":0,"11":2,"12":1}');
