<?php
// IAM-Local — Endpoint OIDC /userinfo (Bearer access token RS256)
require_once __DIR__ . '/../../includes/functions.php';
require_once __DIR__ . '/../../includes/oauth.php';

header('Content-Type: application/json; charset=utf-8');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(204); exit; }

$auth = preg_match('/Bearer\s+(\S+)/i', $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '', $m) ? $m[1] : '';
if ($auth === '') {
    iam_oauth_error(401, 'invalid_token', 'Jeton manquant.');
}
$payload = iam_oauth_jwt_decode($auth);
if (!$payload) {
    iam_oauth_error(401, 'invalid_token', 'Jeton invalide ou expiré.');
}
$user = iam_find_user_by_id((int) ($payload['sub'] ?? 0));
if (!$user || $user['status'] !== 'active') {
    iam_oauth_error(401, 'invalid_token', 'Utilisateur indisponible.');
}
$claims = [
    'sub' => (string) $user['id'],
    'preferred_username' => $user['username'],
    'name' => trim(($user['first_name'] ?? '') . ' ' . ($user['last_name'] ?? '')),
    'given_name' => $user['first_name'] ?? '',
    'family_name' => $user['last_name'] ?? '',
    'email' => $user['email'] ?? '',
    'email_verified' => true,
];
$scope = explode(' ', (string) ($payload['scope'] ?? 'profile'));
if (in_array('profile', $scope, true)) {
    $claims['updated_at'] = strtotime((string) ($user['updated_at'] ?? 'now'));
}
if (in_array('profile', $scope, true)) {
    foreach (['matricule' => 'employee_number', 'department' => 'department', 'service' => 'organization_unit', 'fonction' => 'title', 'phone' => 'phone_number'] as $col => $claim) {
        $claims[$claim] = $user[$col] ?? null;
    }
}
iam_audit('oauth_userinfo', 'Lecture des claims OIDC', (int) $user['id'], $user['email'] ?? '', $_SERVER['REMOTE_ADDR'] ?? '', $_SERVER['HTTP_USER_AGENT'] ?? '');
echo json_encode($claims);