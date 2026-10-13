<?php
// IAM-Local — API REST : GET /api/userinfo.php
require_once __DIR__ . '/../includes/functions.php';

$user = api_require_auth();
$appId = input('app_id') ? (int) input('app_id') : null;

$roles    = iam_user_roles($user['id'], $appId);
$perms    = iam_user_permissions($user['id'], $appId);
$apps     = iam_user_apps($user['id']);
$isAdmin  = iam_user_is_admin($user['id']);
$isAppAdmin = $appId !== null && in_array('admin', array_column($roles, 'code'), true);
if ($isAdmin || $isAppAdmin) {
    $perms[] = ['id' => null, 'code' => '*', 'name' => 'Accès complet'];
}
$org      = null;
if ($user['organization_id']) {
    $db = db();
    $stmt = $db->prepare('SELECT * FROM organizations WHERE id = ?');
    $stmt->execute([$user['organization_id']]);
    $org = $stmt->fetch();
}

api_json_response([
    'id'         => (int) $user['id'],
    'username'   => $user['username'],
    'email'      => $user['email'],
    'phone'      => $user['phone'],
    'first_name' => $user['first_name'],
    'last_name'  => $user['last_name'],
    'full_name'  => trim($user['first_name'] . ' ' . $user['last_name']),
    'photo'      => $user['photo'],
    'matricule'  => $user['matricule'],
    'status'     => $user['status'],
    'mfa_enabled'=> (bool) $user['mfa_enabled'],
    'organization' => $org,
    'is_admin'   => $isAdmin,
    'is_app_admin' => $isAppAdmin,
    'roles'      => $roles,
    'permissions'=> $perms,
    'apps'       => $apps,
    'last_login' => $user['last_login_at'],
]);
