-- ============================================================
--  Migration: add `language` column + reseed courses
--  Run via: cmd /c "mysql --default-character-set=utf8mb4 -u root lms_db < file.sql"
-- ============================================================
SET NAMES utf8mb4;
SET CHARACTER SET utf8mb4;

-- 1. Add language column (safe to re-run with IF NOT EXISTS workaround)
ALTER TABLE courses
  ADD COLUMN IF NOT EXISTS `language` ENUM('en','vi') NOT NULL DEFAULT 'en'
  AFTER `category`;

-- 2. Mark original 4 courses as English
UPDATE courses SET `language` = 'en' WHERE id <= 4;

-- 3. Remove all the garbled seeded courses
DELETE FROM courses WHERE id > 4;

-- 4. Reset AUTO_INCREMENT so ids start cleanly from 5
ALTER TABLE courses AUTO_INCREMENT = 5;

-- ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
--  ENGLISH COURSES  (46 new + 4 existing = 50 total)
-- ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
INSERT INTO courses (instructor_id, title, description, category, language, status, created_at) VALUES

-- Computer Science
(2, 'Object-Oriented Programming',            'Classes, inheritance, polymorphism, encapsulation and design patterns in Java.', 'Computer Science', 'en', 'active', '2025-01-05 08:00:00'),
(3, 'Operating Systems',                       'Process management, memory management, file systems, scheduling and concurrency.', 'Computer Science', 'en', 'active', '2025-01-06 08:00:00'),
(2, 'Computer Networks',                       'OSI model, TCP/IP, routing, switching, DNS, HTTP/HTTPS and network security.', 'Computer Science', 'en', 'active', '2025-01-07 08:00:00'),
(3, 'Compiler Design',                         'Lexical analysis, parsing, semantic analysis, code generation and optimization.', 'Computer Science', 'en', 'active', '2025-01-08 08:00:00'),
(2, 'Discrete Mathematics',                    'Logic, sets, relations, graph theory, combinatorics and proof techniques.', 'Computer Science', 'en', 'active', '2025-01-09 08:00:00'),
(3, 'Theory of Computation',                   'Automata, regular languages, context-free grammars, Turing machines and complexity.', 'Computer Science', 'en', 'active', '2025-01-10 08:00:00'),
(2, 'Artificial Intelligence Fundamentals',    'Search algorithms, constraint satisfaction, knowledge representation and planning.', 'Computer Science', 'en', 'active', '2025-01-11 08:00:00'),
(3, 'Distributed Systems',                     'CAP theorem, consensus protocols, replication, distributed transactions and fault tolerance.', 'Computer Science', 'en', 'active', '2025-01-12 08:00:00'),

-- Web Development
(2, 'HTML & CSS Fundamentals',                 'HTML5 semantics, CSS3, Flexbox, Grid, responsive design and accessibility.', 'Web Development', 'en', 'active', '2025-01-13 08:00:00'),
(3, 'JavaScript — Modern ES2024',              'Arrow functions, promises, async/await, modules, destructuring and the latest ECMAScript features.', 'Web Development', 'en', 'active', '2025-01-14 08:00:00'),
(2, 'React.js Advanced',                       'Hooks, context API, Redux Toolkit, React Query, performance optimization and testing.', 'Web Development', 'en', 'active', '2025-01-15 08:00:00'),
(3, 'Node.js & Express API Development',       'REST APIs, middleware, JWT authentication, rate limiting and deployment.', 'Web Development', 'en', 'active', '2025-01-16 08:00:00'),
(2, 'TypeScript In Depth',                     'Advanced types, generics, decorators, declaration files and integration with React/Node.', 'Web Development', 'en', 'active', '2025-01-17 08:00:00'),
(3, 'Next.js Full-Stack Development',          'SSR, SSG, ISR, API routes, authentication and deployment on Vercel.', 'Web Development', 'en', 'active', '2025-01-18 08:00:00'),
(2, 'GraphQL API Design',                      'Schema definition, resolvers, mutations, subscriptions, Apollo Client and DataLoader.', 'Web Development', 'en', 'active', '2025-01-19 08:00:00'),

-- Data Science & AI
(3, 'Machine Learning Fundamentals',           'Supervised and unsupervised learning, scikit-learn, cross-validation and model evaluation.', 'Data Science', 'en', 'active', '2025-01-20 08:00:00'),
(2, 'Deep Learning with PyTorch',              'Neural networks, CNN, RNN, LSTM, Transformers and practical model training.', 'Data Science', 'en', 'active', '2025-01-21 08:00:00'),
(3, 'Data Analysis with Python',               'Pandas, NumPy, data cleaning, transformation, aggregation and export pipelines.', 'Data Science', 'en', 'active', '2025-01-22 08:00:00'),
(2, 'Data Visualisation',                      'Matplotlib, Seaborn, Plotly and building interactive dashboards with Dash.', 'Data Science', 'en', 'active', '2025-01-23 08:00:00'),
(3, 'Natural Language Processing',             'Text preprocessing, word embeddings, BERT fine-tuning and sequence-to-sequence models.', 'Data Science', 'en', 'active', '2025-01-24 08:00:00'),

-- Databases
(2, 'SQL — From Basics to Advanced',           'SELECT, JOIN, subqueries, window functions, indexing and query optimisation.', 'Databases', 'en', 'active', '2025-01-25 08:00:00'),
(3, 'PostgreSQL Deep Dive',                    'JSONB, full-text search, partitioning, vacuuming, pg_stat and replication.', 'Databases', 'en', 'active', '2025-01-26 08:00:00'),
(2, 'MongoDB & NoSQL Design',                  'Document modelling, aggregation pipeline, indexing strategy, sharding and Atlas.', 'Databases', 'en', 'active', '2025-01-27 08:00:00'),
(3, 'Database Design & Normalisation',         'Entity-relationship model, normal forms, indexing strategies and schema design patterns.', 'Databases', 'en', 'active', '2025-01-28 08:00:00'),

-- DevOps & Cloud
(2, 'Docker & Containerisation',               'Images, containers, Docker Compose, volumes, networking and security best practices.', 'DevOps', 'en', 'active', '2025-01-29 08:00:00'),
(3, 'Kubernetes in Practice',                  'Pods, deployments, services, ingress, ConfigMaps, secrets and Helm charts.', 'DevOps', 'en', 'active', '2025-01-30 08:00:00'),
(2, 'CI/CD with GitHub Actions',               'Workflows, matrix builds, artifact caching, environment secrets and blue-green deployment.', 'DevOps', 'en', 'active', '2025-01-31 08:00:00'),
(3, 'AWS Cloud Practitioner to Solutions Architect', 'EC2, S3, RDS, Lambda, IAM, VPC, CloudFormation and cost optimisation on AWS.', 'DevOps', 'en', 'active', '2025-02-01 08:00:00'),
(2, 'Terraform Infrastructure as Code',        'HCL syntax, providers, modules, remote state, workspaces and multi-cloud deployment.', 'DevOps', 'en', 'active', '2025-02-02 08:00:00'),

-- Cybersecurity
(3, 'Introduction to Cybersecurity',           'CIA triad, threat modelling, common attack vectors and security frameworks.', 'Cybersecurity', 'en', 'active', '2025-02-03 08:00:00'),
(2, 'Ethical Hacking & Penetration Testing',   'Reconnaissance, scanning, exploitation, post-exploitation and professional reporting.', 'Cybersecurity', 'en', 'active', '2025-02-04 08:00:00'),
(3, 'Web Application Security (OWASP Top 10)', 'SQL injection, XSS, CSRF, SSRF, broken auth and mitigation techniques.', 'Cybersecurity', 'en', 'active', '2025-02-05 08:00:00'),
(2, 'Applied Cryptography',                    'Symmetric/asymmetric encryption, hashing, PKI, TLS 1.3 and real-world applications.', 'Cybersecurity', 'en', 'active', '2025-02-06 08:00:00'),

-- Mobile Development
(3, 'React Native Cross-Platform Apps',        'Navigation, state management, native APIs, animations and publishing to app stores.', 'Mobile Development', 'en', 'active', '2025-02-07 08:00:00'),
(2, 'Flutter & Dart',                          'Widgets, layouts, riverpod state management, Firebase integration and platform channels.', 'Mobile Development', 'en', 'active', '2025-02-08 08:00:00'),
(3, 'Android Development with Kotlin',         'Jetpack Compose, ViewModel, Room, coroutines, WorkManager and Google Play deployment.', 'Mobile Development', 'en', 'active', '2025-02-09 08:00:00'),
(2, 'iOS Development with Swift',              'SwiftUI, UIKit, Core Data, Combine, async/await and App Store Connect.', 'Mobile Development', 'en', 'active', '2025-02-10 08:00:00'),

-- Software Engineering
(3, 'Software Design Patterns',                'Creational, structural and behavioural patterns with real-world implementation examples.', 'Software Engineering', 'en', 'active', '2025-02-11 08:00:00'),
(2, 'Clean Code & Refactoring',                'Naming, functions, comments, SOLID principles, code smells and refactoring techniques.', 'Software Engineering', 'en', 'active', '2025-02-12 08:00:00'),
(3, 'System Design Interview Prep',            'Scalability, load balancing, caching, databases, microservices and case studies for interviews.', 'Software Engineering', 'en', 'active', '2025-02-13 08:00:00'),
(2, 'Agile, Scrum & Project Management',       'Scrum ceremonies, sprint planning, backlog grooming, velocity tracking and Jira workflows.', 'Software Engineering', 'en', 'active', '2025-02-14 08:00:00'),

-- Mathematics
(3, 'Calculus II',                             'Multivariable calculus, double and triple integrals, vector calculus and series.', 'Mathematics', 'en', 'active', '2025-02-15 08:00:00'),
(2, 'Probability & Statistics',                'Random variables, distributions, hypothesis testing, regression and Bayesian statistics.', 'Mathematics', 'en', 'active', '2025-02-16 08:00:00'),

-- Game Development
(3, 'Unity 3D Game Development',               'GameObjects, physics, C# scripting, UI systems, animations and build for PC/mobile.', 'Game Development', 'en', 'active', '2025-02-17 08:00:00'),
(2, 'Godot Engine 4',                          '2D and 3D game development, GDScript, tilemaps, shaders and publishing games.', 'Game Development', 'en', 'active', '2025-02-18 08:00:00'),
(3, 'Game Design Fundamentals',                'Core loop design, level design, game balancing, monetisation and playtesting.', 'Game Development', 'en', 'active', '2025-02-19 08:00:00');

-- ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
--  VIETNAMESE COURSES  (50 courses)
-- ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
INSERT INTO courses (instructor_id, title, description, category, language, status, created_at) VALUES

-- Lập trình
(2, 'Lập trình Python cơ bản',              'Học Python từ đầu: cú pháp, vòng lặp, hàm, module và lập trình hướng đối tượng.', 'Lập trình', 'vi', 'active', '2025-02-20 08:00:00'),
(3, 'Lập trình Python nâng cao',            'Decorator, generator, async/await, packaging, unit testing và metaprogramming.', 'Lập trình', 'vi', 'active', '2025-02-21 08:00:00'),
(2, 'Lập trình C++ từ cơ bản đến nâng cao', 'Con trỏ, quản lý bộ nhớ, STL, templates và lập trình hướng đối tượng trong C++.', 'Lập trình', 'vi', 'active', '2025-02-22 08:00:00'),
(3, 'Lập trình Java Spring Boot',           'Xây dựng REST API với Spring Boot, JPA/Hibernate, Spring Security và Docker.', 'Lập trình', 'vi', 'active', '2025-02-23 08:00:00'),
(2, 'Lập trình C# và .NET',                 'Cú pháp C#, LINQ, delegates, events, async/await và xây dựng ứng dụng .NET.', 'Lập trình', 'vi', 'active', '2025-02-24 08:00:00'),
(3, 'Lập trình Rust cho người mới',         'Ownership, borrowing, lifetimes, traits, error handling và systems programming.', 'Lập trình', 'vi', 'active', '2025-02-25 08:00:00'),
(2, 'Cấu trúc dữ liệu và Giải thuật',       'Mảng, danh sách liên kết, ngăn xếp, hàng đợi, cây, đồ thị và độ phức tạp thuật toán.', 'Lập trình', 'vi', 'active', '2025-02-26 08:00:00'),
(3, 'Lập trình hàm (Functional Programming)', 'Pure functions, immutability, higher-order functions, functor, monad với Haskell và Elixir.', 'Lập trình', 'vi', 'active', '2025-02-27 08:00:00'),

-- Web Development (tiếng Việt)
(2, 'HTML & CSS cho người mới bắt đầu',     'Xây dựng trang web tĩnh với HTML5 và CSS3, Flexbox, Grid và Responsive Design.', 'Web Development', 'vi', 'active', '2025-02-28 08:00:00'),
(3, 'JavaScript hiện đại (ES6+)',           'Arrow functions, Promises, async/await, modules, destructuring và các tính năng ES2024.', 'Web Development', 'vi', 'active', '2025-03-01 08:00:00'),
(2, 'ReactJS từ cơ bản đến nâng cao',       'Components, hooks, context API, Redux Toolkit, React Router và tối ưu hiệu suất.', 'Web Development', 'vi', 'active', '2025-03-02 08:00:00'),
(3, 'Vue.js 3 thực chiến',                  'Composition API, Vuex/Pinia, Vue Router, testing và xây dựng SPA hoàn chỉnh.', 'Web Development', 'vi', 'active', '2025-03-03 08:00:00'),
(2, 'Laravel PHP Framework',                'Eloquent ORM, Blade, authentication, queues, events và triển khai Laravel.', 'Web Development', 'vi', 'active', '2025-03-04 08:00:00'),
(3, 'Node.js và Express REST API',          'Server-side JavaScript, middleware, JWT authentication, rate limiting và deploy.', 'Web Development', 'vi', 'active', '2025-03-05 08:00:00'),
(2, 'Tailwind CSS thực chiến',              'Utility-first CSS, responsive design, dark mode, custom components và Tailwind plugins.', 'Web Development', 'vi', 'active', '2025-03-06 08:00:00'),

-- Khoa học dữ liệu & AI
(3, 'Nhập môn Khoa học Dữ liệu',            'Data science workflow, Pandas, NumPy, Matplotlib và làm sạch dữ liệu thực tế.', 'Khoa học Dữ liệu', 'vi', 'active', '2025-03-07 08:00:00'),
(2, 'Machine Learning cơ bản',              'Supervised learning, unsupervised learning, scikit-learn và đánh giá mô hình.', 'Khoa học Dữ liệu', 'vi', 'active', '2025-03-08 08:00:00'),
(3, 'Deep Learning với TensorFlow',         'Mạng nơ-ron, CNN, RNN, LSTM và xây dựng mô hình deep learning thực tế.', 'Khoa học Dữ liệu', 'vi', 'active', '2025-03-09 08:00:00'),
(2, 'Xử lý ngôn ngữ tự nhiên (NLP)',        'Text preprocessing, word embeddings, Transformers và fine-tuning BERT tiếng Việt.', 'Khoa học Dữ liệu', 'vi', 'active', '2025-03-10 08:00:00'),
(3, 'Phân tích và trực quan hóa dữ liệu',   'Pandas, Seaborn, Plotly và xây dựng dashboard tương tác với Dash.', 'Khoa học Dữ liệu', 'vi', 'active', '2025-03-11 08:00:00'),

-- Cơ sở dữ liệu
(2, 'SQL từ cơ bản đến nâng cao',           'SELECT, JOIN, subquery, window functions, indexing và tối ưu câu truy vấn.', 'Cơ sở Dữ liệu', 'vi', 'active', '2025-03-12 08:00:00'),
(3, 'MySQL thực chiến',                     'Thiết kế CSDL, stored procedures, triggers, transactions và replication.', 'Cơ sở Dữ liệu', 'vi', 'active', '2025-03-13 08:00:00'),
(2, 'MongoDB và thiết kế NoSQL',            'Document model, aggregation pipeline, indexing, sharding và MongoDB Atlas.', 'Cơ sở Dữ liệu', 'vi', 'active', '2025-03-14 08:00:00'),
(3, 'Thiết kế và chuẩn hóa cơ sở dữ liệu', 'ERD, các dạng chuẩn hóa, chiến lược đánh index và các mẫu thiết kế schema.', 'Cơ sở Dữ liệu', 'vi', 'active', '2025-03-15 08:00:00'),
(2, 'Redis và chiến lược caching',          'Cấu trúc dữ liệu Redis, caching patterns, pub/sub, Lua scripting và Redis Cluster.', 'Cơ sở Dữ liệu', 'vi', 'active', '2025-03-16 08:00:00'),

-- DevOps
(3, 'Docker từ cơ bản đến nâng cao',        'Container, images, Docker Compose, volumes, networking và bảo mật container.', 'DevOps', 'vi', 'active', '2025-03-17 08:00:00'),
(2, 'Kubernetes thực chiến',                'Pods, deployments, services, ingress, ConfigMap, Secrets và Helm charts.', 'DevOps', 'vi', 'active', '2025-03-18 08:00:00'),
(3, 'CI/CD với GitHub Actions',             'Workflows, jobs, artifact caching, environment secrets và automated deployment.', 'DevOps', 'vi', 'active', '2025-03-19 08:00:00'),
(2, 'Hạ tầng AWS trên đám mây',             'EC2, S3, RDS, Lambda, IAM, VPC, CloudFormation và tối ưu chi phí AWS.', 'DevOps', 'vi', 'active', '2025-03-20 08:00:00'),
(3, 'Linux Administration cơ bản',          'Hệ thống file, quyền truy cập, bash scripting, quản lý tiến trình và mạng.', 'DevOps', 'vi', 'active', '2025-03-21 08:00:00'),

-- An ninh mạng
(2, 'Nhập môn An ninh mạng',                'CIA triad, threat modelling, cryptography cơ bản và nền tảng bảo mật mạng.', 'An ninh Mạng', 'vi', 'active', '2025-03-22 08:00:00'),
(3, 'Ethical Hacking và Penetration Testing', 'Reconnaissance, scanning, khai thác lỗ hổng, post-exploitation và báo cáo.', 'An ninh Mạng', 'vi', 'active', '2025-03-23 08:00:00'),
(2, 'Bảo mật ứng dụng Web (OWASP)',         'SQL injection, XSS, CSRF, SSRF, broken authentication và kỹ thuật phòng ngừa.', 'An ninh Mạng', 'vi', 'active', '2025-03-24 08:00:00'),
(3, 'Mật mã học ứng dụng',                  'Mã hóa đối xứng/bất đối xứng, hashing, PKI, TLS 1.3 và ứng dụng thực tế.', 'An ninh Mạng', 'vi', 'active', '2025-03-25 08:00:00'),

-- Lập trình di động
(2, 'React Native thực chiến',              'Navigation, state management với Zustand, native APIs, animations và publish app.', 'Lập trình Di động', 'vi', 'active', '2025-03-26 08:00:00'),
(3, 'Flutter và Dart từ đầu',               'Widgets, layouts, Riverpod, tích hợp Firebase và xây dựng app thực tế.', 'Lập trình Di động', 'vi', 'active', '2025-03-27 08:00:00'),
(2, 'Lập trình Android với Kotlin',         'Jetpack Compose, ViewModel, Room, coroutines và xuất bản lên Google Play.', 'Lập trình Di động', 'vi', 'active', '2025-03-28 08:00:00'),
(3, 'Lập trình iOS với Swift',              'SwiftUI, UIKit, Core Data, Combine, async/await và xuất bản App Store.', 'Lập trình Di động', 'vi', 'active', '2025-03-29 08:00:00'),

-- Toán học
(2, 'Giải tích 1',                          'Giới hạn, đạo hàm, tích phân bất định và tích phân xác định với ứng dụng.', 'Toán học', 'vi', 'active', '2025-03-30 08:00:00'),
(3, 'Giải tích 2',                          'Tích phân bội, chuỗi số, phương trình vi phân và biến đổi Laplace.', 'Toán học', 'vi', 'active', '2025-03-31 08:00:00'),
(2, 'Đại số tuyến tính',                    'Ma trận, định thức, không gian vector, eigenvalues, eigenvectors và ứng dụng trong ML.', 'Toán học', 'vi', 'active', '2025-04-01 08:00:00'),
(3, 'Xác suất và Thống kê',                 'Biến ngẫu nhiên, phân phối, ước lượng, kiểm định giả thuyết và hồi quy tuyến tính.', 'Toán học', 'vi', 'active', '2025-04-02 08:00:00'),
(2, 'Toán rời rạc',                         'Logic mệnh đề, tập hợp, hàm, quan hệ, lý thuyết đồ thị và tổ hợp.', 'Toán học', 'vi', 'active', '2025-04-03 08:00:00'),

-- Kỹ năng mềm & Nghề nghiệp
(3, 'Kỹ năng thuyết trình chuyên nghiệp',   'Cấu trúc bài thuyết trình, storytelling, xử lý câu hỏi và sử dụng PowerPoint/Slides.', 'Kỹ năng Mềm', 'vi', 'active', '2025-04-04 08:00:00'),
(2, 'Quản lý thời gian và Năng suất',       'GTD, Pomodoro, time blocking, priority matrix và các công cụ Notion/Obsidian.', 'Kỹ năng Mềm', 'vi', 'active', '2025-04-05 08:00:00'),
(3, 'Tiếng Anh Kỹ thuật cho IT',            'Technical vocabulary, documentation writing, code comments và giao tiếp với team quốc tế.', 'Kỹ năng Mềm', 'vi', 'active', '2025-04-06 08:00:00'),
(2, 'Kỹ năng phỏng vấn IT',                 'Giải leetcode, system design, behavioral questions và cách chuẩn bị hồ sơ xin việc.', 'Kỹ năng Mềm', 'vi', 'active', '2025-04-07 08:00:00'),

-- Thiết kế
(3, 'Figma — Thiết kế UI/UX',               'Components, auto layout, prototyping, design systems và handoff cho lập trình viên.', 'Thiết kế', 'vi', 'active', '2025-04-08 08:00:00'),
(2, 'UI/UX Design cơ bản',                  'Design thinking, user research, wireframing, prototyping và usability testing.', 'Thiết kế', 'vi', 'active', '2025-04-09 08:00:00');
