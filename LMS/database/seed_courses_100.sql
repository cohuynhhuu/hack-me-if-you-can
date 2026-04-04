-- ============================================================
--  100 additional courses for LMS demo
--  Instructors: id=2, id=3
-- ============================================================
INSERT INTO courses (instructor_id, title, description, category, status, created_at) VALUES

-- ── Lập trình & Khoa học máy tính ──────────────────────────
(2, 'Lập trình Python cơ bản', 'Học Python từ đầu: cú pháp, vòng lặp, hàm, OOP và các thư viện phổ biến.', 'Lập trình', 'active', '2025-01-05 08:00:00'),
(3, 'Lập trình Python nâng cao', 'Decorator, generator, context manager, async/await, packaging và testing trong Python.', 'Lập trình', 'active', '2025-01-06 08:00:00'),
(2, 'Nhập môn C++', 'Con trỏ, quản lý bộ nhớ, STL, lập trình hướng đối tượng với C++.', 'Lập trình', 'active', '2025-01-07 08:00:00'),
(3, 'Cấu trúc dữ liệu & Giải thuật', 'Array, linked list, stack, queue, tree, graph, sorting, searching và Big-O notation.', 'Khoa học máy tính', 'active', '2025-01-08 08:00:00'),
(2, 'Lập trình Java cơ bản', 'OOP với Java, collections framework, exception handling, I/O streams.', 'Lập trình', 'active', '2025-01-09 08:00:00'),
(3, 'Lập trình Java Spring Boot', 'Xây dựng REST API với Spring Boot, JPA, Spring Security và deployment.', 'Lập trình', 'active', '2025-01-10 08:00:00'),
(2, 'Lập trình C# cơ bản', 'Cú pháp C#, LINQ, delegates, events và .NET ecosystem.', 'Lập trình', 'active', '2025-01-11 08:00:00'),
(3, 'Kiến trúc hệ thống phần mềm', 'Microservices, monolith, event-driven architecture, domain-driven design.', 'Khoa học máy tính', 'active', '2025-01-12 08:00:00'),
(2, 'Lập trình Rust từ đầu', 'Ownership, borrowing, lifetimes, concurrency và systems programming với Rust.', 'Lập trình', 'active', '2025-01-13 08:00:00'),
(3, 'Giới thiệu về Thuật toán', 'Phân tích thuật toán, đệ quy, dynamic programming, greedy algorithms.', 'Khoa học máy tính', 'active', '2025-01-14 08:00:00'),

-- ── Web Development ─────────────────────────────────────────
(2, 'HTML & CSS cho người mới bắt đầu', 'Xây dựng trang web tĩnh với HTML5 và CSS3, Flexbox, Grid và Responsive Design.', 'Web Development', 'active', '2025-01-15 08:00:00'),
(3, 'JavaScript hiện đại (ES6+)', 'Arrow functions, promises, async/await, modules, destructuring và các tính năng mới nhất.', 'Web Development', 'active', '2025-01-16 08:00:00'),
(2, 'ReactJS cơ bản đến nâng cao', 'Components, hooks, context API, Redux, React Router và tối ưu hiệu suất.', 'Web Development', 'active', '2025-01-17 08:00:00'),
(3, 'Vue.js 3 thực chiến', 'Composition API, Vuex/Pinia, Vue Router và xây dựng SPA hoàn chỉnh.', 'Web Development', 'active', '2025-01-18 08:00:00'),
(2, 'Node.js & Express.js', 'Server-side JavaScript, RESTful API, middleware, authentication và PostgreSQL.', 'Web Development', 'active', '2025-01-19 08:00:00'),
(3, 'Laravel PHP Framework', 'Eloquent ORM, Blade templating, authentication, queues và real-time với Laravel.', 'Web Development', 'active', '2025-01-20 08:00:00'),
(2, 'TypeScript từ cơ bản đến nâng cao', 'Type system, interfaces, generics, decorators và best practices trong dự án lớn.', 'Web Development', 'active', '2025-01-21 08:00:00'),
(3, 'Next.js & SSR/SSG', 'Server-side rendering, static generation, API routes và deployment trên Vercel.', 'Web Development', 'active', '2025-01-22 08:00:00'),
(2, 'GraphQL API Design', 'Schema definition, resolvers, mutations, subscriptions và Apollo Client.', 'Web Development', 'active', '2025-01-23 08:00:00'),
(3, 'Tailwind CSS thực chiến', 'Utility-first CSS, responsive design, dark mode, component creation với Tailwind.', 'Web Development', 'active', '2025-01-24 08:00:00'),

-- ── Data Science & AI/ML ────────────────────────────────────
(2, 'Nhập môn Khoa học Dữ liệu', 'Giới thiệu data science workflow, Pandas, NumPy và visualisation với Matplotlib.', 'Data Science', 'active', '2025-01-25 08:00:00'),
(3, 'Machine Learning cơ bản', 'Supervised learning, unsupervised learning, scikit-learn và model evaluation.', 'AI & Machine Learning', 'active', '2025-01-26 08:00:00'),
(2, 'Deep Learning với TensorFlow', 'Neural networks, CNN, RNN, LSTM và xây dựng mô hình deep learning thực tế.', 'AI & Machine Learning', 'active', '2025-01-27 08:00:00'),
(3, 'Natural Language Processing', 'Text preprocessing, word embeddings, transformers và mô hình ngôn ngữ với BERT.', 'AI & Machine Learning', 'active', '2025-01-28 08:00:00'),
(2, 'Computer Vision với OpenCV', 'Image processing, feature detection, object detection và segmentation.', 'AI & Machine Learning', 'active', '2025-01-29 08:00:00'),
(3, 'Phân tích dữ liệu với Pandas', 'Data cleaning, transformation, pivot tables, merging và advanced analytics.', 'Data Science', 'active', '2025-01-30 08:00:00'),
(2, 'Data Visualisation với Python', 'Matplotlib, Seaborn, Plotly và Dash để tạo dashboard tương tác.', 'Data Science', 'active', '2025-01-31 08:00:00'),
(3, 'Reinforcement Learning', 'Q-learning, policy gradients, OpenAI Gym và ứng dụng game AI.', 'AI & Machine Learning', 'active', '2025-02-01 08:00:00'),
(2, 'MLOps & Deployment mô hình AI', 'MLflow, DVC, Docker, CI/CD cho mô hình AI và model monitoring.', 'AI & Machine Learning', 'active', '2025-02-02 08:00:00'),
(3, 'Thống kê cho Data Science', 'Xác suất, phân phối, kiểm định giả thuyết, hồi quy và Bayesian statistics.', 'Data Science', 'active', '2025-02-03 08:00:00'),

-- ── Cơ sở dữ liệu ───────────────────────────────────────────
(2, 'SQL cơ bản đến nâng cao', 'SELECT, JOIN, subquery, window functions, indexing và query optimization.', 'Cơ sở dữ liệu', 'active', '2025-02-04 08:00:00'),
(3, 'MySQL thực chiến', 'Database design, stored procedures, triggers, transactions và replication.', 'Cơ sở dữ liệu', 'active', '2025-02-05 08:00:00'),
(2, 'PostgreSQL nâng cao', 'JSONB, full-text search, partitioning, pg_stat và performance tuning.', 'Cơ sở dữ liệu', 'active', '2025-02-06 08:00:00'),
(3, 'MongoDB & NoSQL', 'Document model, aggregation pipeline, indexing, sharding và replica sets.', 'Cơ sở dữ liệu', 'active', '2025-02-07 08:00:00'),
(2, 'Redis & Caching Strategies', 'Data structures, caching patterns, pub/sub, Lua scripting và Redis Cluster.', 'Cơ sở dữ liệu', 'active', '2025-02-08 08:00:00'),
(3, 'Database Design & Normalization', 'ERD, normalization forms, indexing strategies và schema design patterns.', 'Cơ sở dữ liệu', 'active', '2025-02-09 08:00:00'),

-- ── DevOps & Cloud ───────────────────────────────────────────
(2, 'Docker từ cơ bản đến nâng cao', 'Containers, images, Docker Compose, volumes, networking và best practices.', 'DevOps', 'active', '2025-02-10 08:00:00'),
(3, 'Kubernetes thực chiến', 'Pods, deployments, services, ingress, ConfigMap, Secrets và Helm charts.', 'DevOps', 'active', '2025-02-11 08:00:00'),
(2, 'CI/CD với GitHub Actions', 'Workflows, jobs, steps, artifacts, environment secrets và deployment automation.', 'DevOps', 'active', '2025-02-12 08:00:00'),
(3, 'AWS Cloud Fundamentals', 'EC2, S3, RDS, Lambda, IAM, VPC và kiến trúc serverless trên AWS.', 'Cloud', 'active', '2025-02-13 08:00:00'),
(2, 'Terraform Infrastructure as Code', 'HCL, providers, modules, state management và multi-cloud deployment.', 'DevOps', 'active', '2025-02-14 08:00:00'),
(3, 'Linux Administration cơ bản', 'File system, permissions, bash scripting, process management và networking.', 'DevOps', 'active', '2025-02-15 08:00:00'),
(2, 'Nginx & Load Balancing', 'Reverse proxy, load balancing, SSL/TLS termination và caching với Nginx.', 'DevOps', 'active', '2025-02-16 08:00:00'),
(3, 'Monitoring với Prometheus & Grafana', 'Metrics collection, alerting, dashboard creation và observability best practices.', 'DevOps', 'active', '2025-02-17 08:00:00'),

-- ── An ninh mạng ─────────────────────────────────────────────
(2, 'Nhập môn An ninh mạng', 'CIA triad, threat models, cryptography basics, network security fundamentals.', 'An ninh mạng', 'active', '2025-02-18 08:00:00'),
(3, 'Ethical Hacking & Penetration Testing', 'Reconnaissance, scanning, exploitation, post-exploitation và báo cáo.', 'An ninh mạng', 'active', '2025-02-19 08:00:00'),
(2, 'Web Application Security (OWASP)', 'SQL injection, XSS, CSRF, broken auth, SSRF và các kỹ thuật phòng ngừa.', 'An ninh mạng', 'active', '2025-02-20 08:00:00'),
(3, 'Mật mã học ứng dụng', 'Symmetric/asymmetric encryption, hashing, PKI, TLS và ứng dụng thực tế.', 'An ninh mạng', 'active', '2025-02-21 08:00:00'),
(2, 'Digital Forensics cơ bản', 'Thu thập bằng chứng số, phân tích file system, memory forensics và log analysis.', 'An ninh mạng', 'active', '2025-02-22 08:00:00'),

-- ── Phát triển di động ───────────────────────────────────────
(3, 'React Native từ đầu', 'Cross-platform mobile development, navigation, state management và native APIs.', 'Mobile Development', 'active', '2025-02-23 08:00:00'),
(2, 'Flutter & Dart cơ bản', 'Widgets, layouts, state management với Provider/Riverpod và pub.dev packages.', 'Mobile Development', 'active', '2025-02-24 08:00:00'),
(3, 'Android Development với Kotlin', 'Activities, fragments, Jetpack Compose, Room, ViewModel và coroutines.', 'Mobile Development', 'active', '2025-02-25 08:00:00'),
(2, 'iOS Development với Swift', 'SwiftUI, UIKit, Core Data, networking và App Store deployment.', 'Mobile Development', 'active', '2025-02-26 08:00:00'),

-- ── Thiết kế & UX ────────────────────────────────────────────
(3, 'UI/UX Design cơ bản', 'Design thinking, user research, wireframing, prototyping và usability testing.', 'Thiết kế', 'active', '2025-02-27 08:00:00'),
(2, 'Figma thực chiến', 'Components, auto layout, prototyping, design systems và handoff cho developer.', 'Thiết kế', 'active', '2025-02-28 08:00:00'),
(3, 'Adobe Photoshop cho Web Designer', 'Layer masking, smart objects, exportation và web graphic design workflows.', 'Thiết kế', 'active', '2025-03-01 08:00:00'),
(2, 'Motion Design với After Effects', 'Keyframing, expressions, particle systems và animation cho UI/UX.', 'Thiết kế', 'active', '2025-03-02 08:00:00'),
(3, 'Thiết kế logo & Brand Identity', 'Typography, color theory, logo design principles và brand style guide.', 'Thiết kế', 'active', '2025-03-03 08:00:00'),

-- ── Toán học & Vật lý ───────────────────────────────────────
(2, 'Giải tích 1', 'Giới hạn, đạo hàm, tích phân và ứng dụng trong kỹ thuật và khoa học.', 'Toán học', 'active', '2025-03-04 08:00:00'),
(3, 'Giải tích 2', 'Tích phân bội, chuỗi số, phương trình vi phân và biến đổi Laplace.', 'Toán học', 'active', '2025-03-05 08:00:00'),
(2, 'Đại số tuyến tính', 'Ma trận, định thức, không gian vector, eigenvalues và ứng dụng trong ML.', 'Toán học', 'active', '2025-03-06 08:00:00'),
(3, 'Xác suất & Thống kê', 'Biến ngẫu nhiên, phân phối, ước lượng, kiểm định và hồi quy tuyến tính.', 'Toán học', 'active', '2025-03-07 08:00:00'),
(2, 'Toán rời rạc', 'Logic, tập hợp, đồ thị, tổ hợp và ứng dụng trong thuật toán.', 'Toán học', 'active', '2025-03-08 08:00:00'),
(3, 'Vật lý đại cương 1', 'Cơ học, nhiệt học, sóng và các bài tập ứng dụng thực tế.', 'Vật lý', 'active', '2025-03-09 08:00:00'),
(2, 'Vật lý đại cương 2', 'Điện từ học, quang học, thuyết tương đối và vật lý lượng tử cơ bản.', 'Vật lý', 'active', '2025-03-10 08:00:00'),

-- ── Quản trị & Kinh doanh ────────────────────────────────────
(3, 'Quản lý dự án Agile & Scrum', 'Scrum framework, sprint planning, retrospectives, Kanban và công cụ Jira.', 'Quản lý', 'active', '2025-03-11 08:00:00'),
(2, 'Quản trị kinh doanh cơ bản', 'Chiến lược kinh doanh, marketing, tài chính cơ bản và vận hành doanh nghiệp.', 'Kinh doanh', 'active', '2025-03-12 08:00:00'),
(3, 'Digital Marketing toàn diện', 'SEO, SEM, social media marketing, email marketing và analytics.', 'Kinh doanh', 'active', '2025-03-13 08:00:00'),
(2, 'Kế toán tài chính cơ bản', 'Bảng cân đối kế toán, báo cáo kết quả kinh doanh, dòng tiền và phân tích tài chính.', 'Tài chính', 'active', '2025-03-14 08:00:00'),
(3, 'Khởi nghiệp & Lean Startup', 'Business model canvas, MVP, customer development và tăng trưởng startup.', 'Kinh doanh', 'active', '2025-03-15 08:00:00'),
(2, 'Leadership & Kỹ năng lãnh đạo', 'Phong cách lãnh đạo, xây dựng đội nhóm, giải quyết xung đột và communication.', 'Quản lý', 'active', '2025-03-16 08:00:00'),

-- ── Ngoại ngữ ────────────────────────────────────────────────
(3, 'Tiếng Anh giao tiếp cơ bản', 'Phát âm, ngữ pháp căn bản, hội thoại hàng ngày và kỹ năng nghe nói.', 'Ngoại ngữ', 'active', '2025-03-17 08:00:00'),
(2, 'Tiếng Anh học thuật (IELTS Prep)', 'Reading, writing, listening, speaking và chiến lược thi IELTS đạt 7.0+.', 'Ngoại ngữ', 'active', '2025-03-18 08:00:00'),
(3, 'Business English', 'Email, presentation, negotiation, report writing và giao tiếp chuyên nghiệp.', 'Ngoại ngữ', 'active', '2025-03-19 08:00:00'),
(2, 'Tiếng Nhật cho người mới bắt đầu', 'Hiragana, Katakana, ngữ pháp cơ bản N5-N4 và giao tiếp căn bản.', 'Ngoại ngữ', 'active', '2025-03-20 08:00:00'),
(3, 'Tiếng Hàn cơ bản (TOPIK I)', 'Hangul, từ vựng, ngữ pháp cơ bản và luyện thi TOPIK cấp độ 1-2.', 'Ngoại ngữ', 'active', '2025-03-21 08:00:00'),

-- ── Kỹ năng mềm & Phát triển bản thân ───────────────────────
(2, 'Kỹ năng thuyết trình hiệu quả', 'Cấu trúc bài thuyết trình, kỹ thuật storytelling, xử lý câu hỏi và ngôn ngữ cơ thể.', 'Kỹ năng mềm', 'active', '2025-03-22 08:00:00'),
(3, 'Quản lý thời gian & Năng suất', 'GTD, Pomodoro, time blocking, priority matrix và tools như Notion, Obsidian.', 'Kỹ năng mềm', 'active', '2025-03-23 08:00:00'),
(2, 'Tư duy phản biện & Giải quyết vấn đề', 'Logic thinking, bias nhận thức, root cause analysis và design thinking.', 'Kỹ năng mềm', 'active', '2025-03-24 08:00:00'),
(3, 'Viết sáng tạo & Kỹ năng viết', 'Storytelling, copywriting, technical writing và blogging chuyên nghiệp.', 'Kỹ năng mềm', 'active', '2025-03-25 08:00:00'),

-- ── Kỹ thuật & Khoa học ─────────────────────────────────────
(2, 'Điện tử cơ bản', 'Linh kiện điện tử, mạch điện, Arduino và lập trình vi điều khiển.', 'Kỹ thuật', 'active', '2025-03-26 08:00:00'),
(3, 'IoT & Embedded Systems', 'Raspberry Pi, sensor integration, MQTT, LoRa và smart home applications.', 'Kỹ thuật', 'active', '2025-03-27 08:00:00'),
(2, 'Robotics cơ bản', 'Kinematics, ROS, sensors, actuators và lập trình robot tự hành.', 'Kỹ thuật', 'active', '2025-03-28 08:00:00'),
(3, 'Trí tuệ nhân tạo ứng dụng trong Y tế', 'Medical imaging AI, clinical NLP, predictive health models và đạo đức AI.', 'AI & Machine Learning', 'active', '2025-03-29 08:00:00'),

-- ── Game Development ─────────────────────────────────────────
(2, 'Unity 3D cho người mới bắt đầu', 'Game objects, physics, scripting với C#, UI và build game cho PC/mobile.', 'Game Development', 'active', '2025-03-30 08:00:00'),
(3, 'Godot Engine thực chiến', '2D/3D game development, GDScript, scenes, tilemaps và shipping game.', 'Game Development', 'active', '2025-03-31 08:00:00'),
(2, 'Game Design & Mechanics', 'Core loop, balancing, level design, monetization và game testing.', 'Game Development', 'active', '2025-04-01 08:00:00'),

-- ── Đặc biệt / Hỗn hợp ──────────────────────────────────────
(3, 'Blockchain & Web3 cơ bản', 'Distributed ledger, consensus mechanisms, smart contracts với Solidity và Ethereum.', 'Blockchain', 'active', '2025-04-02 08:00:00'),
(2, 'Lập trình hàm (Functional Programming)', 'Pure functions, immutability, higher-order functions với Haskell/Scala/Elixir.', 'Lập trình', 'active', '2025-04-03 08:00:00'),
(3, 'Open Source Contribution Guide', 'Git workflow, code review, pull requests, community norms và tìm dự án OSS.', 'Lập trình', 'active', '2025-04-04 08:00:00'),
(2, 'Clean Code & Refactoring', 'SOLID principles, design patterns, code smells và kỹ thuật refactoring hiệu quả.', 'Lập trình', 'active', '2025-04-05 08:00:00'),
(3, 'System Design Interview Preparation', 'Scalability, load balancing, caching, databases, microservices và case studies.', 'Khoa học máy tính', 'active', '2025-04-06 08:00:00'),
(2, 'Competitive Programming', 'Giải thuật nâng cao, DP, graphs, number theory và luyện tập Codeforces/LeetCode.', 'Khoa học máy tính', 'active', '2025-04-07 08:00:00'),
(3, 'Phát triển ứng dụng Desktop với Electron', 'Cross-platform desktop apps, IPC, native APIs, auto-update và packaging.', 'Web Development', 'active', '2025-04-08 08:00:00'),
(2, 'API Design Best Practices', 'RESTful conventions, versioning, auth, rate limiting, OpenAPI spec và testing.', 'Web Development', 'active', '2025-04-09 08:00:00'),
(3, 'Nhập môn Quantum Computing', 'Qubit, gates, circuits, Grover, Shor algorithms và Qiskit framework.', 'Khoa học máy tính', 'inactive', '2025-04-10 08:00:00'),
(2, 'AR/VR Development với Unity', 'XR Interaction Toolkit, hand tracking, spatial UI và deployment cho Meta Quest.', 'Game Development', 'inactive', '2025-04-11 08:00:00');
