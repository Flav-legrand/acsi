<?php
// IAM-Local — API REST : PUT|DELETE /api/user_edit.php?id=
require_once __DIR__ . '/../includes/functions.php';

$user = api_require_auth();

if (!iam_user_is_admin((int) $user['id']) && !iam_user_has_permission((int) $user['id'], 'users.manage')) {
    api_json_response(['error' => 'Permission insuffisante.'], 403);
}

$db   = db();
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$targetId = (int) input('id', 0);

if ($targetId <= 0) api_json_response(['error' => 'ID utilisateur requis.'], 422);

$target = iam_find_user_by_id($targetId);
if (!$target) api_json_response(['error' => 'Utilisateur introuvable.'], 404);

// DELETE
if ($method === 'DELETE') {
    if ((int) $target['id'] === 1) api_json_response(['error' => 'Impossible de supprimer l\'administrateur principal.'], 403);
    $db->prepare('DELETE FROM users WHERE id = ?')->execute([$targetId]);
    iam_audit('user_deleted', "Utilisateur supprimé: {$target['email']}", (int) $user['id'], $user['email'], $_SERVER['REMOTE_ADDR'] ?? '', $_SERVER['HTTP_USER_AGENT'] ?? '');
    api_json_response(['success' => true, 'message' => 'Utilisateur supprimé.']);
}

// PUT
if ($method === 'PUT') {
    $body = api_request_body();
    $fields = [];
    $params = [];

    foreach (['email', 'username', 'phone', 'first_name', 'last_name', 'matricule'] as $f) {
        if (isset($body[$f])) {
            $fields[] = "$f = ?";
            $params[] = trim($body[$f]);
        }
    }
    if (isset($body['organization_id'])) {
        $fields[] = 'organization_id = ?';
        $params[] = $body['organization_id'] ? (int) $body['organization_id'] : null;
    }
    if (isset($body['status']) && in_array($body['status'], ['active','inactive','locked'])) {
        $fields[] = 'status = ?';
        $params[] = $body['status'];
        if ($body['status'] === 'active') {
            $fields[] = 'locked_until = NULL';
            $fields[] = 'failed_attempts = 0';
        }
    }

    if (!empty($fields)) {
        $fields[] = 'updated_at = NOW()';
        $sql = 'UPDATE users SET ' . implode(', ', $fields) . ' WHERE id = ?';
        $params[] = $targetId;
        $db->prepare($sql)->execute($params);
    }

    // Rôles
    if (isset($body['roles']) && is_array($body['roles'])) {
        $db->prepare('DELETE FROM user_roles WHERE user_id = ?')->execute([$targetId]);
        $insertRole = $db->prepare('INSERT IGNORE INTO user_roles (user_id, role_id, application_id) VALUES (?, ?, ?)');
        foreach ($body['roles'] as $ra) {
            $rid = (int) $ra['role_id'];
            $aid = (int) $ra['app_id'];
            if ($rid > 0 && $aid > 0 && iam_role_allowed_for_app($rid, $aid)) $insertRole->execute([$targetId, $rid, $aid]);
        }
    }

    iam_audit('user_updated', "Utilisateur modifié: {$target['email']}", (int) $user['id'], $user['email'], $_SERVER['REMOTE_ADDR'] ?? '', $_SERVER['HTTP_USER_AGENT'] ?? '');
    api_json_response(['success' => true, 'message' => 'Utilisateur mis à jour.']);
}

api_json_response(['error' => 'Méthode non supportée.'], 405);
