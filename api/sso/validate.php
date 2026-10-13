<?php
// IAM-Local — API REST : POST /api/sso/validate.php
// Appelée par les apps clientes pour valider un jeton SSO
// Corps JSON: { token, app_code }
require_once __DIR__ . '/../../includes/functions.php';

$body = api_request_body();
$token   = $body['token'] ?? input('token');
$appCode = $body['app_code'] ?? input('app_code');
$ip      = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
$ua      = $_SERVER['HTTP_USER_AGENT'] ?? '';

if (empty($token)) api_json_response(['error' => 'Token requis.'], 422);
if (empty($appCode)) api_json_response(['error' => 'app_code requis.'], 422);

// Valider le jeton SSO (usage unique)
$row = iam_consume_sso_token($token, $ip, $ua);
if (!$row) api_json_response(['error' => 'Jeton SSO invalide, expiré ou déjà utilisé.'], 401);

// Vérifier l'application
$db = db();
$stmt = $db->prepare('SELECT * FROM applications WHERE code = ? AND active = 1 LIMIT 1');
$stmt->execute([$appCode]);
$app = $stmt->fetch();
if (!$app) api_json_response(['error' => 'Application inconnue ou désactivée.'], 401);

// Vérifier que l'application concerne bien le token
if ((int) $row['application_id'] !== (int) $app['id']) {
    api_json_response(['error' => 'Le jeton ne correspond pas à cette application.'], 403);
}

// Récupérer l'utilisateur
$user = iam_find_user_by_id((int) $row['user_id']);
if (!$user || $user['status'] !== 'active') {
    api_json_response(['error' => 'Utilisateur inactif ou introuvable.'], 401);
}

// Créer une session locale pour l'application
$sessionToken = iam_create_session((int) $user['id'], $ip, $ua);
$accessToken = iam_sign_token([
    'sub' => $user['id'],
    'uid' => (int) $user['id'],
    'email' => $user['email'],
    'app' => $appCode,
    'iat' => time(),
    'exp' => time() + 3600,
]);

iam_audit('sso_login', "SSO vers application: $appCode", (int) $user['id'], $user['email'], $ip, $ua, $app['name']);

$roles    = iam_user_roles($user['id'], (int) $app['id']);
$perms    = iam_user_permissions($user['id'], (int) $app['id']);
$allPerms = array_column($perms, 'code');
$isAdmin  = iam_user_is_admin($user['id']);
$isAppAdmin = in_array('admin', array_column($roles, 'code'), true);
if ($isAdmin || $isAppAdmin) {
    $allPerms[] = '*';
}

api_json_response([
    'success'       => true,
    'access_token'  => $accessToken,
    'session_token' => $sessionToken,
    'token_type'    => 'Bearer',
    'user' => [
        'id'         => (int) $user['id'],
        'username'   => $user['username'],
        'email'      => $user['email'],
        'first_name' => $user['first_name'],
        'last_name'  => $user['last_name'],
        'full_name'  => trim($user['first_name'] . ' ' . $user['last_name']),
        'photo'      => $user['photo'],
        'matricule'  => $user['matricule'],
        'organization_id' => $user['organization_id'],
    ],
    'roles'         => $roles,
    'permissions'   => $allPerms,
    'is_global_admin' => $isAdmin,
    'is_app_admin'  => $isAppAdmin,
    'app' => [
        'id'   => (int) $app['id'],
        'code' => $app['code'],
        'name' => $app['name'],
    ],
]);
