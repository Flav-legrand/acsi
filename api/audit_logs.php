<?php
// IAM-Local — API REST : GET /api/audit-logs.php
require_once __DIR__ . '/../includes/functions.php';

$user = api_require_auth();
if (!iam_user_is_admin((int) $user['id']) && !iam_user_has_permission((int) $user['id'], 'audit.view')) {
    api_json_response(['error' => 'Permission insuffisante.'], 403);
}

$db = db();
$page    = max(1, (int) input('page', 1));
$perPage = min(100, max(1, (int) input('per_page', 50)));
$search  = input('search', '');
$action  = input('action', '');
$offset  = ($page - 1) * $perPage;

$where  = '';
$params = [];
$conditions = [];

if ($search !== '') {
    $conditions[] = '(al.email LIKE ? OR al.action LIKE ? OR al.details LIKE ?)';
    $s = "%$search%";
    $params = array_merge($params, [$s, $s, $s]);
}
if ($action !== '') {
    $conditions[] = 'al.action = ?';
    $params[] = $action;
}

if (!empty($conditions)) $where = 'WHERE ' . implode(' AND ', $conditions);

$stmtCount = $db->prepare("SELECT COUNT(*) FROM audit_logs al $where");
$stmtCount->execute($params);
$total = (int) $stmtCount->fetchColumn();

$sql = "SELECT al.*, u.username
        FROM audit_logs al
        LEFT JOIN users u ON u.id = al.user_id
        $where
        ORDER BY al.created_at DESC
        LIMIT ? OFFSET ?";
$params[] = $perPage;
$params[] = $offset;
$stmt = $db->prepare($sql);
$stmt->execute($params);

api_json_response([
    'logs'      => $stmt->fetchAll(),
    'total'     => $total,
    'page'      => $page,
    'per_page'  => $perPage,
    'last_page' => ceil($total / $perPage),
]);
