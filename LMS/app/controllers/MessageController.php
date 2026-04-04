<?php
require_once APP_ROOT . '/app/core/Controller.php';
require_once APP_ROOT . '/app/models/Message.php';
require_once APP_ROOT . '/app/models/User.php';

/**
 * MessageController — Inbox, compose, read
 */
class MessageController extends Controller
{
    private Message $messageModel;
    private User $userModel;

    public function __construct()
    {
        Auth::requireLogin();
        $this->messageModel = new Message();
        $this->userModel    = new User();
    }

    /** GET /message/inbox */
    public function inbox(): void
    {
        $messages = $this->messageModel->getInbox(Auth::id());
        $this->view('messages/inbox', ['messages' => $messages]);
    }

    /** GET /message/sent */
    public function sent(): void
    {
        $messages = $this->messageModel->getSent(Auth::id());
        $this->view('messages/sent', ['messages' => $messages]);
    }

    /** GET /message/read/{id} */
    public function read(int $id): void
    {
        $message = $this->messageModel->findById($id);

        if (!$message || ((int)$message['receiver_id'] !== Auth::id() && (int)$message['sender_id'] !== Auth::id())) {
            $this->flash('danger', 'Message not found.');
            $this->redirect('message/inbox');
        }

        // Mark as read if recipient
        if ((int)$message['receiver_id'] === Auth::id() && !$message['is_read']) {
            $this->messageModel->markRead($id);
        }

        $this->view('messages/read', ['message' => $message]);
    }

    /** GET /message/compose[?to={userId}] */
    public function compose(): void
    {
        $toUserId = isset($_GET['to']) ? (int)$_GET['to'] : null;
        $toUser   = $toUserId ? $this->userModel->findById($toUserId) : null;
        $users    = $this->userModel->getAll(); // all users for dropdown

        $this->view('messages/compose', compact('toUser', 'users'));
    }

    /** POST /message/send */
    public function send(): void
    {
        $receiverId = (int)($_POST['receiver_id'] ?? 0);
        $subject    = trim($_POST['subject'] ?? '');
        $body       = trim($_POST['body'] ?? '');

        if (!$receiverId || empty($body)) {
            $this->flash('danger', 'Recipient and message body are required.');
            $this->redirect('message/compose');
        }

        // Prevent sending to self
        if ($receiverId === Auth::id()) {
            $this->flash('danger', 'You cannot send a message to yourself.');
            $this->redirect('message/compose');
        }

        $subject = $subject ? htmlspecialchars($subject, ENT_QUOTES, 'UTF-8') : null;
        $body    = htmlspecialchars($body, ENT_QUOTES, 'UTF-8');

        $this->messageModel->send(Auth::id(), $receiverId, $subject, $body);
        $this->flash('success', 'Message sent.');
        $this->redirect('message/sent');
    }
}
