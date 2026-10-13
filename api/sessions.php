<?php
// IAM-Local — API REST : GET /api/sessions.php
require_once __DIR__ . '/../includes/functions.php';

$user = api_require_auth();
if (!iam_user_is_admin((int) $user['id']) && !iam_user_has_permission((int) $user['id'], 'audit.view')) {
    api_json_response(['error' => 'Permission insuffisante.'], 403);
}

$db = db();
$targetUserId = input('user_id') ? (int) input('user_id') : null;
$page    = max(1, (int) input('page', 1));
$perPage = min(100, max(1, (int) input('per_page', 20)));
$offset  = ($page - 1) * $perPage;

if ($targetUserId) {
    $countStmt = $db->prepare('SELECT COUNT(*) FROM sessions WHERE user_id = ?');
    $countStmt->execute([$targetUserId]);
    $total = (int) $countStmt->fetchColumn();
    $stmt = $db->prepare('SELECT s.*, u.email, u.first_name, u.last_name
                          FROM sessions s INNER JOIN users u ON u.id = s.user_id
                          WHERE s.user_id = ? ORDER BY s.created_at DESC LIMIT ? OFFSET ?');
    $params = [$targetUserId, $perPage, $offset];
} else {
    $total = (int) $db->query('SELECT COUNT(*) FROM sessions')->fetchColumn();
    $stmt = $db->prepare('SELECT s.*, u.email, u.first_name, u.last_name
                          FROM sessions s INNER JOIN users u ON u.id = s.user_id
                          ORDER BY s.created_at DESC LIMIT ? OFFSET ?');
    $params = [$perPage, $offset];
}
$stmt->execute($params);

api_json_response([
    'sessions'  => $stmt->fetchAll(),
    'total'     => $total,
    'page'      => $page,
    'per_page'  => $perPage,
    'last_page' => ceil($total / $perPage),
]);
