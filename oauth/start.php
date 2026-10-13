<?php
// IAM-Local — Démarrage du flux OAuth (connexion d'un compte mail pour l'envoi MFA)
require_once __DIR__ . '/../includes/functions.php';
require_once __DIR__ . '/../includes/mailer.php';

iam_session_start();

// Seul un administrateur connecté peut démarrer le flux
if (empty($_SESSION['iam_user']['id']) || !iam_user_is_admin((int) $_SESSION['iam_user']['id'])) {
    header('Location: ' . IAM_BASE_URL . '/login.php');
    exit;
}

$provider = $_GET['provider'] ?? '';
$providers = iam_oauth_providers();
if (!isset($providers[$provider])) {
    header('Location: ' . IAM_BASE_URL . '/admin/email.php?msg=oauth_invalid');
    exit;
}

$c = iam_oauth_config($provider);
if (empty($c['client_id']) || empty($c['client_secret'])) {
    header('Location: ' . IAM_BASE_URL . '/admin/email.php?msg=config_missing&provider=' . urlencode($provider));
    exit;
}

try {
    $state = bin2hex(random_bytes(16));
    $_SESSION['iam_oauth_state'] = $state;
    $_SESSION['iam_oauth_provider'] = $provider;
    $url = iam_oauth_auth_url($provider, $state);
    header('Location: ' . $url);
    exit;
} catch (\Throwable $e) {
    error_log('[IAM-Local] OAuth start : ' . $e->getMessage());
    header('Location: ' . IAM_BASE_URL . '/admin/email.php?msg=oauth_error&detail=' . urlencode(substr($e->getMessage(), 0, 80)));
    exit;
}