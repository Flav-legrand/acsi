<?php
// IAM-Local — SSO : point d'entrée pour les applications
// URL : /IAM-Local/sso/authorize.php?app=gestion-presence&return=http://localhost/app/dashboard.php
require_once __DIR__ . '/../includes/functions.php';

iam_session_start();

$appCode = trim($_GET['app'] ?? '');
$return  = $_GET['return'] ?? '';
// Accès direct : prompt=login force la ressaisie des identifiants IAM
$prompt  = ($_GET['prompt'] ?? '') === 'login';
$ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
$ua = $_SERVER['HTTP_USER_AGENT'] ?? '';

if ($appCode === '') {
    header('Location: ' . IAM_BASE_URL . '/portal.php');
    exit;
}

// 1. Vérifier que l'application existe et est active
$db = db();
$stmt = $db->prepare('SELECT * FROM applications WHERE code = ? AND active = 1 LIMIT 1');
$stmt->execute([$appCode]);
$app = $stmt->fetch();
if (!$app) {
    http_response_code(404);
    die('Application inconnue ou désactivée.');
}

// 2. Pas connecté ou accès direct forcé ? -> login puis retour ici
if (!iam_is_logged_in() || $prompt) {
    // L'URL de retour ne contient PAS prompt pour éviter une boucle de connexion
    $returnUri = rawurlencode(IAM_BASE_URL . '/sso/authorize.php?app=' . rawurlencode($appCode) . '&return=' . rawurlencode($return));
    header('Location: ' . IAM_BASE_URL . '/login.php?return=' . $returnUri . ($prompt ? '&prompt=1' : ''));
    exit;
}

// 3. MFA requis
if (!empty($_SESSION['iam_mfa_required']) && empty($_SESSION['iam_mfa_verified'])) {
    header('Location: ' . IAM_BASE_URL . '/mfa.php');
    exit;
}

$userId = (int) $_SESSION['iam_user']['id'];

// 4. Vérifier que l'utilisateur a accès à l'application
$accessStmt = $db->prepare('SELECT COUNT(*) FROM user_roles WHERE user_id = ? AND application_id = ?');
$accessStmt->execute([$userId, (int) $app['id']]);
$hasAccess = $accessStmt->fetchColumn() > 0;

if (!$hasAccess && !iam_user_is_admin($userId)) {
    http_response_code(403);
    die('Vous n\'avez pas accès à cette application. Contactez l\'administrateur IAM.');
}

// 5. Créer un jeton SSO à usage unique
//    Validation de l'URL de retour : elle doit appartenir à l'application
//    (même hôte, port ignoré) ou être vide (=> URL par défaut de l'app).
$returnUrl = $return !== '' ? $return : $app['url'];
$appHost   = strtolower(trim(parse_url($app['url'], PHP_URL_HOST) ?? '', '[]'));
$retHost   = strtolower(trim(parse_url($returnUrl, PHP_URL_HOST) ?? '', '[]'));
$appHost   = preg_replace('/:\d+$/', '', $appHost) ?: $appHost;
$retHost   = preg_replace('/:\d+$/', '', $retHost) ?: $retHost;
if ($return !== '' && $retHost !== '' && $retHost !== $appHost) {
    http_response_code(403);
    die('URL de retour invalide.');
}
$token = iam_create_sso_token($userId, (int) $app['id'], $returnUrl, $ip, $ua);

iam_audit('sso_issue', "Jeton SSO émis pour l'application: $appCode", $userId, $_SESSION['iam_user']['email'] ?? '', $ip, $ua);

// 6. Rediriger vers l'application avec le jeton
$redirect = $returnUrl
          . (strpos($returnUrl, '?') !== false ? '&' : '?')
          . 'sso_token=' . $token;

header('Location: ' . $redirect);
exit;