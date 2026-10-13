<?php
/**
 * IAM-Local — Client SSO (bibliothèque autonome)
 *
 * À inclure dans les applications externes (Gestion des Présences, Gestion des
 * Salaires, ou toute autre application à connecter au portail IAM).
 * NE DÉPEND PAS des includes/functions.php d'IAM-Local.
 * Utilise cURL pour communiquer avec l'API IAM.
 *
 * Usage :
 *   define('IAM_APP_CODE', '<code de l'app enregistrée dans l'\''IAM>');
 *   if (!defined('IAM_BASE_URL')) define('IAM_BASE_URL', '<URL du portail IAM>');
 *   require_once '/chemin/vers/iam_client.php';
 *   iam_client_config();
 *   iam_client_require_login();
 *
 * IAM_APP_CODE et IAM_BASE_URL doivent être définis par l'application hôte
 * AVANT l'inclusion pour adapter le client à l'environnement courant.
 * IAM_APP_SESSION_TTL (optionnel) : durée de vie de la session locale
 * en secondes avant d'exiger une nouvelle connexion (défaut 28800 = 8 h).
 */

/* ================================================================
   CONSTANTES
   ================================================================ */
if (!defined('IAM_BASE_URL')) {
    define('IAM_BASE_URL', 'http://localhost/IAM-Local');
}
// IAM_APP_CODE DOIT être défini par l'application avant inclusion

/* ================================================================
   CONFIGURATION
   ================================================================ */

/**
 * Configure le client SSO. Doit être appelé une fois après l'inclusion.
 * Démarre aussi la session PHP.
 *
 * @return array Configuration active
 */
function iam_client_config(): array
{
    iam_client_session_start();

    return [
        'base_url' => IAM_BASE_URL,
        'app_code' => IAM_APP_CODE,
    ];
}

/* ================================================================
   SESSION
   ================================================================ */

/**
 * Démarre la session PHP de l'application hôte (pas celle d'IAM-Local).
 */
function iam_client_session_start(): void
{
    if (session_status() === PHP_SESSION_NONE) {
        if (defined('IAM_APP_SESSION_NAME')) {
            session_name(IAM_APP_SESSION_NAME);
        }
        ini_set('session.cookie_httponly', 1);
        ini_set('session.use_strict_mode', 1);
        session_start();
    }
}

/* ================================================================
   AUTHENTIFICATION
   ================================================================ */

/**
 * Vérifie si l'utilisateur est authentifié dans l'application hôte.
 * Redirige vers l'IAM si non authentifié.
 *
 * @return void
 */
function iam_client_require_login(): void
{
    // Vérifier d'abord si un token SSO est présent dans l'URL
    $ssoToken = $_GET['sso_token'] ?? '';
    if ($ssoToken !== '') {
        if (iam_client_login_with_sso_token($ssoToken)) {
            // Atterrir sur la page courante sans le jeton (usage unique)
            // et sans dépendre de iam_return_url (défini uniquement sur lien direct)
            unset($_SESSION['iam_return_url']);
            $query = trim(preg_replace('/sso_token=[^&]*&?/', '', $_SERVER['QUERY_STRING'] ?? ''), '&?');
            header('Location: ' . $_SERVER['PHP_SELF'] . ($query !== '' ? '?' . $query : ''));
            exit;
        }
    }

    if (iam_client_is_authenticated()) {
        return;
    }

    // Sauvegarder l'URL demandée pour retour après SSO
    iam_client_session_start();
    $currentUrl = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http')
                . '://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
    $_SESSION['iam_return_url'] = $currentUrl;

    // Rediriger vers l'IAM (prompt=login = toujours ressaisir les identifiants IAM)
    $appCode   = defined('IAM_APP_CODE') ? IAM_APP_CODE : '';
    $returnUri = rawurlencode($currentUrl);
    header('Location: ' . IAM_BASE_URL . '/sso/authorize.php?app=' . rawurlencode($appCode) . '&return=' . $returnUri . '&prompt=login');
    exit;
}

/**
 * Indique si l'utilisateur est authentifié.
 * La session locale expire automatiquement après IAM_APP_SESSION_TTL
 * secondes (défaut : 8 h) — au-delà, l'accès par lien direct
 * déclenche à nouveau la ressaisie des identifiants IAM.
 *
 * @return bool
 */
function iam_client_is_authenticated(): bool
{
    iam_client_session_start();
    if (empty($_SESSION['iam_authenticated']) || empty($_SESSION['iam_user'])) {
        return false;
    }
    $lifetime = defined('IAM_APP_SESSION_TTL') ? (int) IAM_APP_SESSION_TTL : 28800;
    if (time() - (int) ($_SESSION['iam_login_time'] ?? 0) > $lifetime) {
        unset($_SESSION['iam_authenticated'], $_SESSION['iam_user']);
        unset($_SESSION['iam_roles'], $_SESSION['iam_permissions']);
        return false;
    }
    return true;
}

/**
 * Retourne les données utilisateur courantes depuis la session.
 *
 * @return array|null Tableau user ou null
 */
function iam_client_user(): ?array
{
    iam_client_session_start();
    return $_SESSION['iam_user'] ?? null;
}

/**
 * Vérifie si l'utilisateur possède une permission donnée.
 *
 * @param string $code Code de la permission (ex: 'presence.view')
 * @return bool
 */
function iam_client_has_permission(string $code): bool
{
    iam_client_session_start();
    $perms = $_SESSION['iam_permissions'] ?? [];
    return in_array($code, $perms, true);
}

/**
 * Déconnecte l'utilisateur de l'application hôte et redirige vers la déconnexion IAM.
 *
 * @return void
 */
function iam_client_logout(): void
{
    iam_client_session_start();

    // Sauvegarder l'URL de retour (page de login de l'app)
    $appLoginUrl = IAM_BASE_URL . '/login.php';

    // Supprimer les données IAM de la session
    unset($_SESSION['iam_user']);
    unset($_SESSION['iam_roles']);
    unset($_SESSION['iam_permissions']);
    unset($_SESSION['iam_authenticated']);
    unset($_SESSION['iam_return_url']);

    // Détruire la session
    session_destroy();

    // Rediriger vers la déconnexion IAM
    header('Location: ' . IAM_BASE_URL . '/logout.php?redirect=' . rawurlencode($appLoginUrl));
    exit;
}

/* ================================================================
   SSO TOKEN VALIDATION
   ================================================================ */

/**
 * Appelle l'API IAM pour valider un jeton SSO.
 *
 * @param string $token Le jeton SSO
 * @return array|null Données utilisateur ou null si invalide
 */
function iam_client_validate_token(string $token): ?array
{
    $apiUrl = IAM_BASE_URL . '/api/sso/validate.php';

    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL            => $apiUrl,
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => json_encode([
            'token'    => $token,
            'app_code' => defined('IAM_APP_CODE') ? IAM_APP_CODE : '',
        ]),
        CURLOPT_HTTPHEADER     => [
            'Content-Type: application/json',
            'Accept: application/json',
        ],
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 10,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
    ]);

    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error    = curl_error($ch);
    curl_close($ch);

    if ($response === false || $httpCode === 0) {
        error_log('IAM Client: Erreur cURL — ' . $error);
        return null;
    }

    $data = json_decode($response, true);
    if (!is_array($data)) {
        return null;
    }

    if ($httpCode === 200 && empty($data['error'])) {
        return $data;
    }

    return null;
}

/**
 * Indique si l'accès direct au lien de l'application doit exiger la
 * ressaisie des identifiants IAM, selon le paramètre graphique sso_prompt
 * défini par l'administrateur (Administration > Applications).
 *
 * Valeur par défaut (endpoint injoignable) : true (comportement sécurisé).
 * Résultat mis en cache pour la durée de la requête.
 *
 * @param string $appCode Code de l'application dans l'IAM
 * @return bool true => rediriger vers authorize.php?prompt=login
 */
function iam_client_requires_prompt(string $appCode): bool
{
    static $cache = [];

    if (isset($cache[$appCode])) {
        return $cache[$appCode];
    }

    $cfgUrl = rtrim(IAM_BASE_URL, '/') . '/api/sso/app_config.php?code=' . rawurlencode($appCode);
    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL            => $cfgUrl,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 5,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
    ]);
    $body = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    $prompt = true;
    if ($httpCode === 200 && $body !== false) {
        $data = json_decode((string) $body, true);
        if (is_array($data) && isset($data['sso_prompt'])) {
            $prompt = (bool) $data['sso_prompt'];
        }
    }

    $cache[$appCode] = $prompt;
    return $prompt;
}

/**
 * Valide un jeton SSO et crée la session locale.
 *
 * @param string $token Le jeton SSO reçu via URL
 * @return bool true si la connexion a réussi
 */
function iam_client_login_with_sso_token(string $token): bool
{
    $userData = iam_client_validate_token($token);
    if ($userData === null) {
        return false;
    }

    iam_client_session_start();

    // Stocker les données utilisateur
    $user = $userData['user'] ?? $userData;
    $_SESSION['iam_user'] = [
        'id'         => (int) ($user['id'] ?? 0),
        'username'   => $user['username'] ?? '',
        'email'      => $user['email'] ?? '',
        'first_name' => $user['first_name'] ?? '',
        'last_name'  => $user['last_name'] ?? '',
        'photo'      => $user['photo'] ?? null,
        'matricule'  => $user['matricule'] ?? null,
    ];

    // Stocker les rôles
    $roles = $userData['roles'] ?? [];
    $_SESSION['iam_roles'] = array_map(function ($r) {
        return [
            'id'   => (int) ($r['id'] ?? 0),
            'name' => $r['name'] ?? '',
            'code' => $r['code'] ?? '',
        ];
    }, $roles);

    // Stocker les permissions (tableau de codes)
    $permissions = $userData['permissions'] ?? [];
    $_SESSION['iam_permissions'] = array_map(function ($p) {
        if (is_string($p)) return $p;
        return $p['code'] ?? '';
    }, $permissions);

    $_SESSION['iam_authenticated'] = true;
    $_SESSION['iam_login_time']    = time();

    return true;
}
