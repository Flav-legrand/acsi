<?php
// IAM-Local — Déconnexion
require_once __DIR__ . '/includes/functions.php';
require_once __DIR__ . '/includes/oauth.php';

iam_session_start();

$redirect = IAM_BASE_URL . '/login.php?msg=logout';

// Logout OIDC : seuls les URI explicitement associés au client sont acceptés.
$logoutClientId = trim((string) ($_GET['client_id'] ?? ''));
$logoutUri = (string) ($_GET['post_logout_redirect_uri'] ?? '');
$logoutState = (string) ($_GET['state'] ?? '');
if ($logoutClientId !== '' && $logoutUri !== '') {
    $client = iam_oauth_client($logoutClientId);
    $allowedLogoutUris = json_decode((string) ($client['post_logout_uris'] ?? '[]'), true);
    if ($client && (int) $client['is_active'] === 1 && is_array($allowedLogoutUris) && in_array($logoutUri, $allowedLogoutUris, true)) {
        $redirect = $logoutUri;
        if ($logoutState !== '') {
            $redirect .= (strpos($redirect, '?') === false ? '?' : '&') . 'state=' . rawurlencode($logoutState);
        }
    }
}

// Open redirect : le paramètre « redirect » n'est honoré que s'il
// pointe vers l'hôte qui sert le portail. Sans cette vérification,
// n'importe qui pouvait forger
//   /logout.php?redirect=https://attaquant.example/iam-login
// et faire atterrir la victime, après sa déconnexion, sur une copie
// pirate de la page de connexion IAM.
if ($logoutClientId === '' && isset($_GET['redirect'])) {
    $candidate = rawurldecode($_GET['redirect']);
    $host = parse_url($candidate, PHP_URL_HOST);
    $currentHost = $_SERVER['HTTP_HOST'] ?? '';
    $allowed = ['localhost', '127.0.0.1', '::1', '[::1]'];
    if ($host !== null && $host !== ''
        && (in_array(strtolower($host), $allowed, true)
            || strtolower($host) === strtolower(preg_replace('/:\d+$/', '', $currentHost)))) {
        $redirect = $candidate;
    }
}

$ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
$ua = $_SERVER['HTTP_USER_AGENT'] ?? '';

if (!empty($_SESSION['iam_user'])) {
    iam_audit('logout', 'Déconnexion du portail IAM', (int) $_SESSION['iam_user']['id'], $_SESSION['iam_user']['email'] ?? '', $ip, $ua);
}

iam_session_destroy();
header('Location: ' . $redirect);
exit;