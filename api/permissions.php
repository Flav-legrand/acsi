<?php
// IAM-Local — API REST : GET /api/permissions.php
require_once __DIR__ . '/../includes/functions.php';

$user = api_require_auth();
$appId = input('app_id') ? (int) input('app_id') : null;

// Si admin global, retourner toutes les permissions
if (iam_user_is_admin($user['id'])) {
    $db = db();
    if ($appId) {
        $stmt = $db->prepare('SELECT * FROM permissions WHERE application_id = ?');
        $stmt->execute([$appId]);
    } else {
        $stmt = $db->query('SELECT * FROM permissions');
    }
    api_json_response(['permissions' => $stmt->fetchAll(), 'is_global_admin' => true]);
}

$perms = iam_user_permissions($user['id'], $appId);
api_json_response(['permissions' => $perms, 'is_global_admin' => false]);
