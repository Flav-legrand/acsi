<?php
// IAM-Local — Callback OAuth (retour après autorisation du fournisseur mail)
require_once __DIR__ . '/../includes/functions.php';
require_once __DIR__ . '/../includes/mailer.php';

iam_session_start();

$provider = $_SESSION['iam_oauth_provider'] ?? ($_GET['state'] ?? '');

if (isset($_GET['error'])) {
    header('Location: ' . IAM_BASE_URL . '/admin/email.php?msg=oauth_error&detail=' . urlencode(substr((string) $_GET['error'], 0, 80)));
    exit;
}

$code  = $_GET['code'] ?? '';
$state = $_GET['state'] ?? '';
$provider = $_SESSION['iam_oauth_provider'] ?? '';

if ($code === '' || $state === '' || $provider === '' || !hash_equals($_SESSION['iam_oauth_state'] ?? '', $state)) {
    header('Location: ' . IAM_BASE_URL . '/admin/email.php?msg=oauth_invalid');
    exit;
}
unset($_SESSION['iam_oauth_state'], $_SESSION['iam_oauth_provider']);

if (!array_key_exists($provider, iam_oauth_providers())) {
    header('Location: ' . IAM_BASE_URL . '/admin/email.php?msg=oauth_invalid');
    exit;
}

[$ok, $refreshOrErr, $email] = iam_oauth_exchange_code($provider, $code);
if (!$ok) {
    header('Location: ' . IAM_BASE_URL . '/admin/email.php?msg=oauth_token&detail=' . urlencode(substr($refreshOrErr, 0, 120)));
    exit;
}

iam_oauth_save_token($provider, $refreshOrErr, $email);
iam_audit('oauth_connected', 'Compte ' . $provider . ' connecté pour l\'envoi MFA : ' . $email, $_SESSION['iam_user']['id'] ?? null, $_SESSION['iam_user']['email'] ?? '', $_SERVER['REMOTE_ADDR'] ?? '', $_SERVER['HTTP_USER_AGENT'] ?? '');

header('Location: ' . IAM_BASE_URL . '/admin/email.php?msg=oauth_ok&provider=' . urlencode($provider) . '&email=' . urlencode($email));
exit;