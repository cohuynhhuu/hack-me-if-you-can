<?php
require_once APP_ROOT . '/app/core/Controller.php';
require_once APP_ROOT . '/app/models/Forum.php';
require_once APP_ROOT . '/app/models/ForumPost.php';
require_once APP_ROOT . '/app/models/Course.php';

/**
 * ForumController — View forum, create threads, reply
 */
class ForumController extends Controller
{
    private Forum $forumModel;
    private ForumPost $postModel;
    private Course $courseModel;

    public function __construct()
    {
        Auth::requireLogin();
        $this->forumModel  = new Forum();
        $this->postModel   = new ForumPost();
        $this->courseModel = new Course();
    }

    /** GET /forum/view/{forumId} — Forum landing with thread list */
    public function view(int $forumId): void
    {
        $forum = $this->forumModel->findById($forumId);
        if (!$forum) {
            $this->flash('danger', 'Forum not found.');
            $this->redirect('course/index');
        }

        $course  = $this->courseModel->findById($forum['course_id']);
        $threads = $this->postModel->getThreads($forumId);

        $this->view('forums/index', compact('forum', 'course', 'threads'));
    }

    /** GET /forum/thread/{postId} — View single thread with replies */
    public function thread(int $postId): void
    {
        $post = $this->postModel->findById($postId);
        if (!$post || $post['parent_id'] !== null) {
            $this->flash('danger', 'Thread not found.');
            $this->redirect('course/index');
        }

        $forum   = $this->forumModel->findById($post['forum_id']);
        $course  = $this->courseModel->findById($forum['course_id']);
        $replies = $this->postModel->getReplies($postId);

        $this->view('forums/thread', compact('post', 'forum', 'course', 'replies'));
    }

    /** POST /forum/postThread — Create a new top-level thread */
    public function postThread(): void
    {
        $forumId = (int)($_POST['forum_id'] ?? 0);
        $subject = trim($_POST['subject'] ?? '');
        $body    = trim($_POST['body'] ?? '');

        if (!$forumId || empty($subject) || empty($body)) {
            $this->flash('danger', 'Subject and message are required.');
            $this->redirect('forum/view/' . $forumId);
        }

        // XSS prevention — strip tags from body, keep basic formatting
        $body = htmlspecialchars($body, ENT_QUOTES, 'UTF-8');

        $this->postModel->create($forumId, Auth::id(), null, $subject, $body);
        $this->flash('success', 'Thread posted.');
        $this->redirect('forum/view/' . $forumId);
    }

    /** POST /forum/postReply — Reply to an existing thread */
    public function postReply(): void
    {
        $parentId = (int)($_POST['parent_id'] ?? 0);
        $forumId  = (int)($_POST['forum_id'] ?? 0);
        $body     = trim($_POST['body'] ?? '');

        if (!$parentId || !$forumId || empty($body)) {
            $this->flash('danger', 'Reply body is required.');
            $this->redirect('forum/thread/' . $parentId);
        }

        $body = htmlspecialchars($body, ENT_QUOTES, 'UTF-8');

        $this->postModel->create($forumId, Auth::id(), $parentId, null, $body);
        $this->flash('success', 'Reply posted.');
        $this->redirect('forum/thread/' . $parentId);
    }

    /** POST /forum/delete/{postId} */
    public function delete(int $postId): void
    {
        Auth::requireRole('instructor', 'admin');
        $post = $this->postModel->findById($postId);
        if ($post) {
            $forumId = $post['forum_id'];
            $this->postModel->delete($postId);
            $this->flash('success', 'Post deleted.');
            $this->redirect('forum/view/' . $forumId);
        }
        $this->redirect('course/index');
    }
}
