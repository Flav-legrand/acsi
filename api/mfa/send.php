<?php
// IAM-Local — API REST : POST /api/mfa/send.php
// Corps: { user_id?, method: 'email'|'totp' }
require_once __DIR__ . '/../../includes/functions.php';
require_once __DIR__ . '/../../includes/mailer.php';

iam_session_start();

$body = api_request_body();
$method = $body['method'] ?? 'email';
$userId = !empty($body['user_id']) ? (int) $body['user_id'] : ($_SESSION['iam_user']['id'] ?? 0);

if ($userId <= 0) api_json_response(['error' => 'Utilisateur non identifié.'], 401);
if (!in_array($method, ['email', 'sms', 'totp'])) api_json_response(['error' => 'Méthode invalide.'], 422);

$user = iam_find_user_by_id($userId);
if (!$user) api_json_response(['error' => 'Utilisateur introuvable.'], 404);

if ($method === 'email') {
    $otp = iam_generate_otp($userId, 'email');
    $subject = IAM_NAME . ' — Code de vérification';
    $html = "<h3>Code de vérification</h3><p>Votre code OTP est : <strong>$otp</strong></p><p>Ce code expire dans " . OTP_LIFETIME . " secondes.</p><p>Si vous n'avez pas demandé cette vérification, ignorez cet e-mail.</p>";
    iam_send_email($user['email'], $subject, $html);
}

iam_audit('mfa_send', "Envoi MFA: $method", $userId, $user['email'], $_SERVER['REMOTE_ADDR'] ?? '', $_SERVER['HTTP_USER_AGENT'] ?? '');

api_json_response(['success' => true, 'message' => 'Code de vérification envoyé.', 'expires_in' => OTP_LIFETIME]);
