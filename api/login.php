<?php
// IAM-Local — API REST : POST /api/login.php
// Corps JSON: { identifier, password, app_code?, remember_me? }
require_once __DIR__ . '/../includes/functions.php';
require_once __DIR__ . '/../includes/mailer.php';

iam_session_start();

$body = api_request_body();
$identifier = trim($body['identifier'] ?? '');
$password   = $body['password'] ?? '';
$appCode    = trim($body['app_code'] ?? '');
$ip         = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
$ua         = $_SERVER['HTTP_USER_AGENT'] ?? '';

if (empty($identifier) || empty($password)) {
    api_json_response(['error' => 'Identifiant et mot de passe requis.'], 422);
}

// Rate limiting par adresse IP
if (!iam_rate_limit_ip($ip, IP_RATE_MAX_ATTEMPTS, IP_RATE_WINDOW_MINUTES)) {
    iam_audit('ip_rate_limited', 'Limite rate-limit IP atteinte', null, $identifier, $ip, $ua);
    api_json_response(['error' => 'Trop de tentatives depuis cette adresse IP. Réessayez plus tard.'], 429);
}

// Trouver l'utilisateur
$user = iam_find_user($identifier);
if (!$user) {
    iam_record_login_attempt($identifier, $ip, $ua, false);
    api_json_response(['error' => 'Identifiants incorrects.'], 401);
}

// Statut / verrouillage
if ($user['status'] === 'inactive' || $user['status'] === 'pending') {
    api_json_response(['error' => 'Compte désactivé ou en attente de validation.'], 403);
}
if (iam_is_locked($user)) {
    iam_record_login_attempt($identifier, $ip, $ua, false);
    api_json_response(['error' => 'Compte verrouillé temporairement. Réessayez plus tard.'], 423);
}
if (!iam_rate_limit((int) $user['id'], MAX_LOGIN_ATTEMPTS, LOCKOUT_MINUTES)) {
    api_json_response(['error' => 'Trop de tentatives. Réessayez plus tard.'], 429);
}

// Vérification mot de passe
if (!iam_verify_password($password, $user['password_hash'])) {
    iam_record_login_attempt($identifier, $ip, $ua, false);
    iam_increment_failed_attempts((int) $user['id']);
    $policy = iam_get_password_policy();
    $failed = iam_get_failed_attempts($user['email']);
    if ($failed >= $policy['lockout_threshold']) {
        iam_lock_user((int) $user['id'], $policy['lockout_minutes']);
        iam_audit('account_locked', "Verrouillage après $failed tentatives", (int) $user['id'], $user['email'], $ip, $ua);
        api_json_response(['error' => 'Trop de tentatives. Compte verrouillé.'], 423);
    }
    api_json_response(['error' => 'Identifiants incorrects.', 'attempts_remaining' => $policy['lockout_threshold'] - $failed], 401);
}

// Connexion réussie (credentiels valides)
iam_reset_failed_attempts((int) $user['id']);
iam_record_login_attempt($identifier, $ip, $ua, true);

// Mettre à jour dernière connexion
$db = db();
$stmt = $db->prepare('UPDATE users SET last_login_at = NOW(), last_login_ip = ? WHERE id = ?');
$stmt->execute([$ip, $user['id']]);

iam_audit('login_success', "Connexion via l'API", (int) $user['id'], $user['email'], $ip, $ua);

// La MFA est exigée si : politique globale MFA_FORCE_ALL (sauf admin) ou OTP activé sur le compte.
$mfaRequired = (MFA_FORCE_ALL && !iam_user_is_admin((int) $user['id'])) || (bool) $user['mfa_enabled'];

if ($mfaRequired) {
    // Pas de jetons tant que le code n'est pas vérifié via /api/mfa/verify.php
    unset($_SESSION['iam_user'], $_SESSION['iam_session_token'], $_SESSION['iam_mfa_verified']);
    $_SESSION['iam_mfa_user_id'] = (int) $user['id'];

    $otp = iam_generate_otp((int) $user['id'], 'email');
    $subject = IAM_NAME . ' — Code de vérification';
    $html = "<h3>Code de vérification</h3><p>Votre code OTP est : <strong>$otp</strong></p><p>Ce code expire dans " . OTP_LIFETIME . " secondes.</p><p>Si vous n'avez pas demandé cette vérification, ignorez cet e-mail.</p>";
    iam_send_email($user['email'], $subject, $html);

    iam_audit('mfa_send', 'Envoi MFA (API): email', (int) $user['id'], $user['email'], $ip, $ua);

    api_json_response([
        'success'      => true,
        'mfa_required' => true,
        'message'      => 'Code de vérification envoyé par e-mail.',
        'expires_in'   => OTP_LIFETIME,
        'user' => [
            'id'       => (int) $user['id'],
            'username' => $user['username'],
            'email'    => $user['email'],
        ],
        'must_change_password' => (bool) $user['must_change_password'],
    ]);
}

// Pas de MFA exigée : on délivre directement les jetons.
api_json_response(iam_build_login_response($user, $ip, $ua));
