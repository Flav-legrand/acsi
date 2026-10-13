<?php
// IAM-Local — Endpoint OAuth 2.0 /token
require_once __DIR__ . '/../../includes/functions.php';
require_once __DIR__ . '/../../includes/oauth.php';

header('Content-Type: application/json; charset=utf-8');

$grant = $_POST['grant_type'] ?? $_GET['grant_type'] ?? '';

switch ($grant) {
    /* ------------------- authorization_code + PKCE ------------------- */
    case 'authorization_code':
        $code = trim($_POST['code'] ?? '');
        $redirectUri = $_POST['redirect_uri'] ?? '';
        $verifier = $_POST['code_verifier'] ?? '';
        $clientAuth = iam_oauth_client_auth();
        $clientId = $clientAuth[0] ?? '';

        if ($code === '' || $clientId === '') {
            iam_oauth_error(400, 'invalid_request', 'code et client_id sont requis.');
        }
        $client = iam_oauth_client($clientId);
        if (!$client || (int) $client['is_active'] !== 1) {
            iam_oauth_error(401, 'invalid_client', 'Client inconnu ou inactif.');
        }
        if (!iam_oauth_client_allows_grant($client, 'authorization_code')) {
            iam_oauth_error(400, 'unauthorized_client', 'Authorization Code non autorisé pour ce client.');
        }
        // Client confidentiel : le secret doit correspondre
        if ($client['client_type'] === 'confidential') {
            if (!$clientAuth || !password_verify($clientAuth[1] ?? '', $client['client_secret'] ?? '')) {
                iam_oauth_error(401, 'invalid_client', 'Authentification du client échouée.');
            }
        }
        $db = db();
        $stmt = $db->prepare('SELECT * FROM oauth_codes WHERE code = ? LIMIT 1');
        $stmt->execute([$code]);
        $row = $stmt->fetch();
        if (!$row) iam_oauth_error(400, 'invalid_grant', 'Code inconnu.');
        if ((int) $row['used'] === 1) iam_oauth_error(400, 'invalid_grant', 'Code déjà consommé.');
        if ($row['client_id'] !== $clientId) iam_oauth_error(400, 'invalid_grant', 'Le code n’appartient pas à ce client.');
        if (strtotime((string) $row['expires_at']) < time()) iam_oauth_error(400, 'invalid_grant', 'Code expiré.');
        if ($redirectUri === '' || $redirectUri !== $row['redirect_uri']) iam_oauth_error(400, 'invalid_grant', 'redirect_uri manquant ou incohérent.');
        // PKCE
        if (iam_oauth_client_is_public($client)
            && (empty($row['code_challenge']) || ($row['code_challenge_method'] ?? '') !== 'S256')) {
            iam_oauth_error(400, 'invalid_grant', 'Le code public ne possède pas de challenge PKCE S256 valide.');
        }
        if (!empty($row['code_challenge'])) {
            if ($verifier === '') iam_oauth_error(400, 'invalid_grant', 'code_verifier manquant (PKCE).');
            if (preg_match('/^[A-Za-z0-9._~-]{43,128}$/', $verifier) !== 1) {
                iam_oauth_error(400, 'invalid_grant', 'code_verifier invalide.');
            }
            $calc = $row['code_challenge_method'] === 'S256'
                ? base64_url_encode(hash('sha256', $verifier, true))
                : $verifier;
            if (!hash_equals($row['code_challenge'], $calc)) iam_oauth_error(400, 'invalid_grant', 'code_verifier invalide.');
        }
        // Consommation du code
        $db->prepare('UPDATE oauth_codes SET used = 1 WHERE id = ?')->execute([(int) $row['id']]);
        $tokens = iam_oauth_issue_tokens($client, (int) $row['user_id'], $row['scope'] ?: 'profile', $row['nonce'] ?: null);
        iam_audit('oauth_token', "Code échangé contre des jetons: {$client['name']}", (int) $row['user_id'], '', $_SERVER['REMOTE_ADDR'] ?? '', $_SERVER['HTTP_USER_AGENT'] ?? '', $client['name']);
        echo json_encode($tokens);
        break;

    /* ----------------------- client_credentials ----------------------- */
    case 'client_credentials':
        $clientAuth = iam_oauth_client_auth();
        $clientId = $clientAuth[0] ?? '';
        $client = iam_oauth_client($clientId);
        if (!$client || (int) $client['is_active'] !== 1 || $client['client_type'] !== 'confidential' || empty($client['client_secret'])) {
            iam_oauth_error(401, 'invalid_client', 'Client inconnu, inactif ou public.');
        }
        if (!$clientAuth || !password_verify($clientAuth[1] ?? '', $client['client_secret'])) {
            iam_oauth_error(401, 'invalid_client', 'Authentification du client échouée.');
        }
        if (!iam_oauth_client_allows_grant($client, 'client_credentials')) {
            iam_oauth_error(400, 'unauthorized_client', 'client_credentials non autorisé pour ce client.');
        }
        $scope = trim($_POST['scope'] ?? 'profile') ?: 'profile';
        if (!iam_oauth_client_allows_scopes($client, $scope, ['profile', 'email', 'roles'])) {
            iam_oauth_error(400, 'invalid_scope', 'Un ou plusieurs scopes ne sont pas autorisés pour ce client.');
        }
        $key = iam_oauth_current_key();
        $accessTtl = max(60, min(86400, (int) ($client['token_lifetime'] ?? 3600)));
        $access = iam_oauth_jwt_rs256([
            'iss' => IAM_BASE_URL,
            'sub' => $client['client_id'],
            'aud' => $client['client_id'],
            'scope' => $scope,
        ], $key, $accessTtl);
        iam_oauth_log_event((string) $client['client_id'], null, 'client_credentials');
        iam_audit('oauth_client_credentials', "Jeton machine: {$client['name']}", null, '', $_SERVER['REMOTE_ADDR'] ?? '', $_SERVER['HTTP_USER_AGENT'] ?? '', $client['name']);
        echo json_encode(['access_token' => $access, 'token_type' => 'Bearer', 'expires_in' => $accessTtl, 'scope' => $scope]);
        break;

    /* ------------------------ refresh_token ------------------------ */
    case 'refresh_token':
        $rt = trim($_POST['refresh_token'] ?? '');
        if ($rt === '') iam_oauth_error(400, 'invalid_request', 'refresh_token requis.');
        $db = db();
        $stmt = $db->prepare("SELECT rt.*, u.status AS ustatus, u.email AS uemail FROM refresh_tokens rt
                              INNER JOIN users u ON u.id = rt.user_id
                              WHERE rt.token = ? AND rt.revoked = 0 LIMIT 1");
        $stmt->execute([$rt]);
        $row = $stmt->fetch();
        if (!$row) iam_oauth_error(400, 'invalid_grant', 'refresh_token invalide ou révoqué.');
        if (strtotime((string) $row['expires_at']) < time()) iam_oauth_error(400, 'invalid_grant', 'refresh_token expiré.');
        $clientAuth = iam_oauth_client_auth();
        $clientId = $clientAuth[0] ?? '';
        if (!empty($row['client_id']) && $row['client_id'] !== $clientId) iam_oauth_error(400, 'invalid_grant', 'Client incohérent.');
        $client = iam_oauth_client((string) ($row['client_id'] ?: $clientId));
        if (!$client || (int) $client['is_active'] !== 1) iam_oauth_error(401, 'invalid_client', 'Client introuvable ou inactif.');
        if ($row['ustatus'] !== 'active') iam_oauth_error(400, 'invalid_grant', 'Compte utilisateur indisponible.');
        // Rotation du refresh token
        $db->prepare('UPDATE refresh_tokens SET revoked = 1 WHERE id = ?')->execute([(int) $row['id']]);
        $tokens = iam_oauth_issue_tokens($client, (int) $row['user_id'], $row['scope'] ?: 'profile');
        echo json_encode($tokens);
        break;

    default:
        iam_oauth_error(400, 'unsupported_grant_type', 'grant_type inconnu.');
}