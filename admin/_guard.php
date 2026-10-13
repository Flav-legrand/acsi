<?php
// Guard d'administration : authentification + rôle admin
require_once __DIR__ . '/../includes/functions.php';

iam_session_start();

if (!iam_is_logged_in()) {
    $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $currentUrl = $scheme . '://' . ($_SERVER['HTTP_HOST'] ?? 'localhost') . ($_SERVER['REQUEST_URI'] ?? '/');
    header('Location: ' . IAM_BASE_URL . '/login.php?return=' . urlencode($currentUrl));
    exit;
}
if (!empty($_SESSION['iam_mfa_required']) && empty($_SESSION['iam_mfa_verified'])) {
    header('Location: ' . IAM_BASE_URL . '/mfa.php');
    exit;
}

$GLOBALS['iam_admin'] = iam_find_user_by_id((int) $_SESSION['iam_user']['id']);
if (!$GLOBALS['iam_admin'] || $GLOBALS['iam_admin']['status'] !== 'active') {
    iam_session_destroy();
    header('Location: ' . IAM_BASE_URL . '/login.php');
    exit;
}
if (!iam_user_is_admin((int) $GLOBALS['iam_admin']['id'])) {
    http_response_code(403);
    die('Accès refusé : réservé aux administrateurs de l\'IAM.');
}

$iam_admin_user = $GLOBALS['iam_admin'];
$iamAdmin = $GLOBALS['iam_admin'] ?? [];