<?php
// IAM-Local — API REST : POST /api/mfa/verify.php
// Corps: { code }
// Deux cas :
//  - MFA "en attente" (login API avec mfa_required) : finalise la connexion
//    et délivre access_token + refresh_token.
//  - Session navigateur : marque simplement la MFA comme vérifiée.
require_once __DIR__ . '/../../includes/functions.php';

iam_session_start();

$body  = api_request_body();
$code  = trim($body['code'] ?? '');
$ip    = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
$ua    = $_SERVER['HTTP_USER_AGENT'] ?? '';

$userId  = $_SESSION['iam_mfa_user_id'] ?? 0;
$pending = true;
if ($userId <= 0 && !empty($_SESSION['iam_user']['id'])) {
    $userId  = (int) $_SESSION['iam_user']['id'];
    $pending = false;
}

if (empty($code)) api_json_response(['error' => 'Code OTP requis.'], 422);
if ($userId <= 0) api_json_response(['error' => 'Session MFA invalide.'], 401);
if (!iam_rate_limit_ip($ip, IP_RATE_MAX_ATTEMPTS, IP_RATE_WINDOW_MINUTES)) {
    api_json_response(['error' => 'Trop de tentatives depuis cette adresse IP.'], 429);
}

$valid = iam_verify_otp($userId, $code);
if (!$valid) {
    api_json_response(['error' => 'Code OTP invalide ou expiré.'], 401);
}

unset($_SESSION['iam_mfa_user_id']);
$_SESSION['iam_mfa_verified'] = true;

$user = iam_find_user_by_id($userId);
if (!$user) api_json_response(['error' => 'Utilisateur introuvable.'], 500);

iam_audit('mfa_verified', 'MFA vérifié', $userId, $user['email'] ?? '', $ip, $ua);

if ($pending) {
    // Connexion API en cours : délivrer les jetons maintenant.
    iam_audit('login_success', 'Connexion API complétée (MFA)', $userId, $user['email'], $ip, $ua);
    api_json_response(iam_build_login_response($user, $ip, $ua));
}

api_json_response(['success' => true, 'message' => 'MFA vérifié avec succès.']);