<?php
require_once APP_ROOT . '/app/core/Controller.php';
require_once APP_ROOT . '/app/models/Material.php';
require_once APP_ROOT . '/app/models/Course.php';

/**
 * MaterialController — Upload and delete course materials
 */
class MaterialController extends Controller
{
    private Material $materialModel;
    private Course $courseModel;

    public function __construct()
    {
        Auth::requireLogin();
        $this->materialModel = new Material();
        $this->courseModel   = new Course();
    }

    /** POST /material/store — Add material to a course */
    public function store(): void
    {
        Auth::requireRole('instructor', 'admin');

        $courseId  = (int)($_POST['course_id'] ?? 0);
        $title     = trim($_POST['title'] ?? '');
        $type      = $_POST['type'] ?? 'file';
        $linkUrl   = trim($_POST['link_url'] ?? '');

        if (!$courseId || empty($title)) {
            $this->flash('danger', 'Invalid input.');
            $this->redirect('course/detail/' . $courseId);
        }

        if (!in_array($type, ['file', 'link'], true)) {
            $type = 'file';
        }

        $content = '';

        if ($type === 'link') {
            // Validate URL
            if (!filter_var($linkUrl, FILTER_VALIDATE_URL)) {
                $this->flash('danger', 'Invalid URL.');
                $this->redirect('course/detail/' . $courseId);
            }
            $content = htmlspecialchars($linkUrl, ENT_QUOTES, 'UTF-8');
        } else {
            // File upload
            if (!isset($_FILES['material_file']) || $_FILES['material_file']['error'] !== UPLOAD_ERR_OK) {
                $this->flash('danger', 'File upload failed.');
                $this->redirect('course/detail/' . $courseId);
            }

            $file     = $_FILES['material_file'];
            $origName = basename($file['name']);
            $ext      = strtolower(pathinfo($origName, PATHINFO_EXTENSION));
            $allowed  = ['pdf', 'doc', 'docx', 'ppt', 'pptx', 'txt', 'zip', 'png', 'jpg'];

            if (!in_array($ext, $allowed, true)) {
                $this->flash('danger', 'File type not allowed.');
                $this->redirect('course/detail/' . $courseId);
            }

            if ($file['size'] > MAX_UPLOAD_SIZE) {
                $this->flash('danger', 'File exceeds 10 MB limit.');
                $this->redirect('course/detail/' . $courseId);
            }

            $dir = UPLOAD_DIR . 'materials/';
            if (!is_dir($dir)) {
                mkdir($dir, 0755, true);
            }

            $newName = 'mat_' . uniqid() . '.' . $ext;
            $dest    = $dir . $newName;

            if (!move_uploaded_file($file['tmp_name'], $dest)) {
                $this->flash('danger', 'Could not save file.');
                $this->redirect('course/detail/' . $courseId);
            }

            $content = 'uploads/materials/' . $newName;
        }

        $this->materialModel->create($courseId, $title, $type, $content);
        $this->flash('success', 'Material added.');
        $this->redirect('course/detail/' . $courseId);
    }

    /** POST /material/delete/{id} */
    public function delete(int $id): void
    {
        Auth::requireRole('instructor', 'admin');

        $material = $this->materialModel->findById($id);
        if (!$material) {
            $this->flash('danger', 'Material not found.');
            $this->redirect('course/index');
        }

        // Remove file from disk if applicable
        if ($material['type'] === 'file') {
            $filePath = APP_ROOT . '/public/' . $material['content'];
            if (file_exists($filePath)) {
                unlink($filePath);
            }
        }

        $this->materialModel->delete($id);
        $this->flash('success', 'Material removed.');
        $this->redirect('course/detail/' . $material['course_id']);
    }
}
