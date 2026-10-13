<?php
// IAM-Local — API REST : GET /api/roles.php
require_once __DIR__ . '/../includes/functions.php';

$user = api_require_auth();
$db = db();
iam_ensure_roles_application_column($db);

$appId = isset($_GET['app_id']) ? (int) $_GET['app_id'] : null;

if ($appId !== null && $appId > 0) {
    // Rôles propres à l'application + rôles globaux (attribuables sur cette app)
    $stmt = $db->prepare('SELECT id, name, code, description, is_system, application_id FROM roles
        WHERE application_id = ? OR application_id IS NULL
        ORDER BY application_id IS NULL DESC, name');
    $stmt->execute([$appId]);
} else {
    $stmt = $db->query('SELECT id, name, code, description, is_system, application_id FROM roles ORDER BY application_id IS NULL DESC, name');
}
$roles = $stmt->fetchAll();
api_json_response(['roles' => $roles]);
