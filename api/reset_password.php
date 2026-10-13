<?php
// IAM-Local — API REST : POST /api/reset_password.php
// Corps: { user_id?, new_password, current_password? }  — admin reset (pas besoin de current)
require_once __DIR__ . '/../includes/functions.php';

$user = api_require_auth();
$body = api_request_body();

$ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
if (!iam_rate_limit_ip($ip, IP_RATE_MAX_ATTEMPTS, IP_RATE_WINDOW_MINUTES)) {
    api_json_response(['error' => 'Trop de tentatives depuis cette adresse IP. Réessayez plus tard.'], 429);
}

$targetId    = !empty($body['user_id']) ? (int) $body['user_id'] : (int) $user['id'];
$newPassword = $body['new_password'] ?? '';
$currentPass = $body['current_password'] ?? '';

if (empty($newPassword)) api_json_response(['error' => 'new_password requis.'], 422);

$target = iam_find_user_by_id($targetId);
if (!$target) api_json_response(['error' => 'Utilisateur introuvable.'], 404);

$isSelf = ((int) $target['id'] === (int) $user['id']);
$isAdmin = iam_user_is_admin((int) $user['id']);

if ($isSelf) {
    if (!iam_rate_limit((int) $user['id'], MAX_LOGIN_ATTEMPTS, LOCKOUT_MINUTES)) {
        api_json_response(['error' => 'Trop de tentatives. Réessayez plus tard.'], 429);
    }
    if (!$currentPass) api_json_response(['error' => 'current_password requis pour changer votre propre mot de passe.'], 422);
    if (!iam_verify_password($currentPass, $target['password_hash'])) {
        api_json_response(['error' => 'Mot de passe actuel incorrect.'], 401);
    }
} elseif (!$isAdmin) {
    api_json_response(['error' => 'Permission insuffisante.'], 403);
}

$policy = iam_get_password_policy();
$errors = iam_validate_password($newPassword, $policy);
if (!empty($errors)) api_json_response(['error' => 'Mot de passe invalide.', 'details' => $errors], 422);

iam_update_password((int) $target['id'], $newPassword);
iam_audit('password_changed', $isSelf ? 'Changement de mot de passe auto' : "Mot de passe réinitialisé par admin", (int) $user['id'], $user['email'], $_SERVER['REMOTE_ADDR'] ?? '', $_SERVER['HTTP_USER_AGENT'] ?? '');

api_json_response(['success' => true, 'message' => 'Mot de passe mis à jour.']);
