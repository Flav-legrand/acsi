<?php
// IAM-Local — Point d'autorisation OAuth 2.0 / OIDC (Authorization Code + PKCE)
require_once __DIR__ . '/includes/functions.php';
require_once __DIR__ . '/includes/oauth.php';

iam_session_start();
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$ALLOWED_SCOPES = ['openid', 'profile', 'email', 'roles', 'offline_access'];

// ── Paramètres de la requête d'autorisation ──
// En POST (soumission du consentement), les paramètres sont repris des
// champs cachés du formulaire afin de rester validés par le même chemin.
$isPostReq     = $_SERVER['REQUEST_METHOD'] === 'POST';
$prm           = $isPostReq ? $_POST : $_GET;
$responseType  = trim($prm['response_type'] ?? 'code');
$clientId      = trim($prm['client_id'] ?? '');
$redirectUri   = $prm['redirect_uri'] ?? '';
$scope         = trim($prm['scope'] ?? 'openid profile email');
$state         = $prm['state'] ?? '';
$codeChallenge       = $prm['code_challenge'] ?? '';
$codeChallengeMethod = $prm['code_challenge_method'] ?? 'plain';
$nonce         = $prm['nonce'] ?? '';

function oauth_redirect_error(string $redirectUri, string $error, string $desc, string $state): void
{
    $sep = (strpos($redirectUri, '?') === false) ? '?' : '&';
    header('Location: ' . $redirectUri . $sep . 'error=' . urlencode($error) . '&error_description=' . urlencode($desc) . '&state=' . urlencode($state));
    exit;
}

$client = iam_oauth_client($clientId);
if (!$client || (int) $client['is_active'] !== 1) {
    http_response_code(400);
    exit('Client OAuth inconnu ou inactif.');
}
if (!iam_oauth_client_allows_grant($client, 'authorization_code')) {
    http_response_code(400);
    exit('Le flux Authorization Code n’est pas autorisé pour ce client.');
}
if ($responseType !== 'code' && $responseType !== 'id_token code') {
    if (iam_oauth_redirect_ok($client, $redirectUri)) oauth_redirect_error($redirectUri, 'unsupported_response_type', 'Seul response_type=code est supporté.', $state);
    http_response_code(400);
    exit('response_type non supporté.');
}
if (!$redirectUri || !iam_oauth_redirect_ok($client, $redirectUri)) {
    http_response_code(400);
    exit('redirect_uri invalide pour ce client.');
}
if (!iam_oauth_pkce_request_allowed($client, $codeChallenge, $codeChallengeMethod)) {
    oauth_redirect_error($redirectUri, 'invalid_request', 'Un code_challenge PKCE S256 valide est obligatoire pour ce client.', $state);
}
if ($codeChallenge !== '') {
    $codeChallengeMethod = strtoupper($codeChallengeMethod) === 'S256' ? 'S256' : 'plain';
}
if (!iam_oauth_client_allows_scopes($client, $scope, $ALLOWED_SCOPES)) {
    oauth_redirect_error($redirectUri, 'invalid_scope', 'Un ou plusieurs scopes ne sont pas autorisés pour ce client.', $state);
}
if (in_array('offline_access', explode(' ', $scope), true) && (int) ($client['refresh_enabled'] ?? 1) !== 1) {
    oauth_redirect_error($redirectUri, 'invalid_scope', 'Le renouvellement de jeton n’est pas activé pour ce client.', $state);
}

// ── Authentification requise ──
$returnNow = IAM_BASE_URL . '/oauth.php?' . http_build_query(array_merge($_GET, ['auth' => '1']));
if (!iam_is_logged_in()) {
    header('Location: ' . IAM_BASE_URL . '/login.php?return=' . urlencode($returnNow));
    exit;
}
$uid = (int) $_SESSION['iam_user']['id'];
if (!empty($_SESSION['iam_mfa_required']) && empty($_SESSION['iam_mfa_verified']) && !iam_user_is_admin($uid)) {
    header('Location: ' . IAM_BASE_URL . '/mfa.php?return=' . urlencode($returnNow));
    exit;
}

// ── Consentement (POST) ──
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf'] ?? '')) {
        exit('Session expirée. Retournez au portail et réessayez.');
    }
    if (($_POST['approve'] ?? '') !== '1') {
        oauth_redirect_error($redirectUri, 'access_denied', 'L’utilisateur a refusé le consentement.', $state);
    }
    $code = bin2hex(random_bytes(32));
    $stmt = db()->prepare('INSERT INTO oauth_codes (code, client_id, user_id, redirect_uri, scope, code_challenge, code_challenge_method, nonce, expires_at)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, UTC_TIMESTAMP() + INTERVAL 5 MINUTE)');
    $stmt->execute([$code, $clientId, $uid, $redirectUri, $scope, $codeChallenge !== '' ? $codeChallenge : null, $codeChallenge !== '' ? $codeChallengeMethod : null, $nonce !== '' ? $nonce : null]);
    iam_oauth_log_event($clientId, $uid, 'authorization_granted');
    iam_audit('oauth_consent', "Code d'autorisation octroyé au client: {$client['name']}", $uid, $_SESSION['iam_user']['email'] ?? '', $_SERVER['REMOTE_ADDR'] ?? '', $_SERVER['HTTP_USER_AGENT'] ?? '', $client['name']);
    $sep = (strpos($redirectUri, '?') === false) ? '?' : '&';
    header('Location: ' . $redirectUri . $sep . 'code=' . urlencode($code) . ($state !== '' ? '&state=' . urlencode($state) : ''));
    exit;
}

// ── Affichage du consentement ──
$user = iam_find_user_by_id($uid);
$scopes = array_values(array_filter(explode(' ', $scope)));
$scopeLabels = [
    'openid'  => 'Ouvrir une session OpenID Connect (identité : sub)',
    'profile' => 'Votre profil : nom, prénom, matricule, direction, service, fonction',
    'email'   => 'Votre adresse e-mail',
    'roles'   => 'Vos rôles autorisés pour cette application',
    'offline_access' => 'Renouveler la session sans nouvelle connexion',
];
?>
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Consentement — <?php echo htmlspecialchars(IAM_NAME); ?></title>
<link rel="stylesheet" href="<?php echo htmlspecialchars(IAM_BASE_URL); ?>/assets/css/iam.css">
</head>
<body class="auth-body">
<div class="auth-card">
    <div class="auth-logo">
        <div class="logo-badge"><img src="<?php echo htmlspecialchars(IAM_BASE_URL); ?>/images/acsi.jpg" alt="ACSI"></div>
        <h1>Autoriser l'application</h1>
        <p><strong><?php echo htmlspecialchars($client['name']); ?></strong> demande l'accès à vos informations.</p>
    </div>

    <div class="consent-box">
        <p style="margin-top:0;"><strong>Connecté en tant que :</strong><br>
        <?php echo htmlspecialchars(trim(($user['first_name'] ?? '') . ' ' . ($user['last_name'] ?? ''))); ?> — <?php echo htmlspecialchars($user['email'] ?? ''); ?></p>
        <p style="margin-bottom:6px;"><strong>Permissions demandées :</strong></p>
        <ul style="margin-top:0; padding-left:20px; line-height:1.8;">
            <?php foreach ($scopes as $s): ?>
                <li><?php echo htmlspecialchars($scopeLabels[$s] ?? $s); ?></li>
            <?php endforeach; ?>
        </ul>
        <p class="text-muted" style="font-size:12px; margin-bottom:0;">
            Cette application pourra échanger un code contre des jetons. Vous pourrez révoquer l'accès à tout moment depuis votre profil.
            <?php if ($codeChallenge !== ''): ?>Le flux est sécurisé par PKCE.<?php endif; ?>
        </p>
    </div>

    <div style="display:flex; gap:12px; margin-top:20px;">
        <form method="POST" style="flex:1;">
            <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
            <input type="hidden" name="approve" value="1">
            <input type="hidden" name="response_type" value="<?php echo htmlspecialchars($responseType); ?>">
            <input type="hidden" name="client_id" value="<?php echo htmlspecialchars($clientId); ?>">
            <input type="hidden" name="redirect_uri" value="<?php echo htmlspecialchars($redirectUri); ?>">
            <input type="hidden" name="scope" value="<?php echo htmlspecialchars($scope); ?>">
            <input type="hidden" name="state" value="<?php echo htmlspecialchars($state); ?>">
            <input type="hidden" name="code_challenge" value="<?php echo htmlspecialchars($codeChallenge); ?>">
            <input type="hidden" name="code_challenge_method" value="<?php echo htmlspecialchars($codeChallengeMethod); ?>">
            <input type="hidden" name="nonce" value="<?php echo htmlspecialchars($nonce); ?>">
            <button type="submit" class="btn btn-primary btn-block"><i class="fas fa-check"></i> Autoriser</button>
        </form>
        <form method="POST" style="flex:1;">
            <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
            <input type="hidden" name="approve" value="0">
            <input type="hidden" name="response_type" value="<?php echo htmlspecialchars($responseType); ?>">
            <input type="hidden" name="client_id" value="<?php echo htmlspecialchars($clientId); ?>">
            <input type="hidden" name="redirect_uri" value="<?php echo htmlspecialchars($redirectUri); ?>">
            <input type="hidden" name="scope" value="<?php echo htmlspecialchars($scope); ?>">
            <input type="hidden" name="state" value="<?php echo htmlspecialchars($state); ?>">
            <input type="hidden" name="code_challenge" value="<?php echo htmlspecialchars($codeChallenge); ?>">
            <input type="hidden" name="code_challenge_method" value="<?php echo htmlspecialchars($codeChallengeMethod); ?>">
            <input type="hidden" name="nonce" value="<?php echo htmlspecialchars($nonce); ?>">
            <button type="submit" class="btn btn-outline btn-block">Refuser</button>
        </form>
    </div>

    <div class="auth-footer">
        <?php echo htmlspecialchars(IAM_NAME); ?> — Serveur d'autorisation OAuth 2.0 / OIDC
    </div>
</div>
</body>
</html>