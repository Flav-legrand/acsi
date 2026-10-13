<?php
require_once __DIR__ . '/_guard.php';
require_once __DIR__ . '/../includes/oauth.php';
require_once __DIR__ . '/../includes/OAuthClient.php';
require_once __DIR__ . '/../includes/OAuthClientService.php';
require_once __DIR__ . '/../includes/platforms/IamServiceProvider.php';

iam_oauth_ensure_client_schema();
$db = db();
$clientService = new OAuthClientService($db);
$message = '';
$error = '';
$platformRegistry = IamLocal\Platforms\IamServiceProvider::platforms();
$platforms = $platformRegistry->all();
$platformLabels = array_map(static fn($adapter) => $adapter->getLabel(), $platforms);
$availableScopes = ['openid', 'profile', 'email', 'roles', 'offline_access'];

function oidc_admin_slug(string $value): string
{
    $slug = strtolower(trim((string) preg_replace('/[^a-zA-Z0-9]+/', '-', $value), '-'));
    return substr($slug !== '' ? $slug : 'application-oauth', 0, 42);
}

function oidc_admin_uris($values): array
{
    if (!is_array($values)) $values = preg_split('/\r\n|\r|\n/', (string) $values);
    return array_values(array_unique(array_filter(array_map('trim', $values), static fn($uri) => $uri !== '')));
}

function oidc_admin_uri_valid(string $uri, string $clientType): bool
{
    return (new OAuthClientService())->validateRedirectUri($uri, $clientType);
}

function oidc_admin_parse_form(array $platforms, array $availableScopes): array
{
    $platform = (string) ($_POST['platform'] ?? 'laravel');
    $clientType = (string) ($_POST['client_type'] ?? 'confidential');
    $name = trim((string) ($_POST['name'] ?? ''));
    $baseUrl = rtrim(trim((string) ($_POST['base_url'] ?? '')), '/');
    $baseParts = parse_url($baseUrl);
    $baseValid = $baseParts && in_array(strtolower((string) ($baseParts['scheme'] ?? '')), ['https', 'http'], true)
        && !empty($baseParts['host']) && !isset($baseParts['user']) && !isset($baseParts['pass']);
    $baseHost = strtolower((string) ($baseParts['host'] ?? ''));
    $baseIsLocal = in_array($baseHost, ['localhost', '127.0.0.1', '::1'], true);
    $isProduction = strtolower((string) (getenv('APP_ENV') ?: getenv('IAM_ENVIRONMENT') ?: 'production')) === 'production';
    $baseValid = $baseValid && (strtolower((string) ($baseParts['scheme'] ?? '')) === 'https' || $baseIsLocal || !$isProduction);
    $redirects = oidc_admin_uris($_POST['redirect_uris'] ?? []);
    $logoutUris = oidc_admin_uris($_POST['post_logout_redirect_uris'] ?? []);
    $scopes = array_values(array_unique(array_intersect($availableScopes, (array) ($_POST['scopes'] ?? []))));
    $isPublic = $clientType === 'public';
    $allowedGrants = ['authorization_code', 'refresh_token', 'client_credentials'];
    $grants = array_values(array_unique(array_intersect($allowedGrants, (array) ($_POST['grant_types'] ?? []))));
    $mapping = [];
    $iamRoles = (array) ($_POST['iam_role'] ?? []);
    $appRoles = (array) ($_POST['app_role'] ?? []);
    foreach ($iamRoles as $index => $role) {
        $role = trim((string) $role);
        $mapped = trim((string) ($appRoles[$index] ?? ''));
        if ($role !== '' && $mapped !== '') $mapping[$role] = $mapped;
    }

    $errors = [];
    if (!isset($platforms[$platform])) $errors[] = 'Choisissez une plateforme enregistrée.';
    if (!in_array($clientType, ['confidential', 'public'], true)) $errors[] = 'Choisissez un type de client valide.';
    if ($name === '' || strlen($name) > 120) $errors[] = 'Le nom est obligatoire et limité à 120 caractères.';
    if (!$baseValid) $errors[] = 'Saisissez une URL de base complète en HTTP ou HTTPS.';
    if (in_array('authorization_code', $grants, true) && !$redirects) $errors[] = 'Ajoutez au moins une URI de redirection pour Authorization Code.';
    foreach (array_merge($redirects, $logoutUris) as $uri) {
        if (!oidc_admin_uri_valid($uri, $clientType)) {
            $errors[] = 'Une URI de redirection ou de logout n’est pas valide pour ce type d’application.';
            break;
        }
    }
    if (!$grants) $errors[] = 'Sélectionnez au moins un grant OAuth.';
    if ($isPublic && in_array('client_credentials', $grants, true)) $errors[] = 'Un client public ne peut pas utiliser client_credentials.';
    if (!$scopes) $errors[] = 'Sélectionnez au moins un scope autorisé.';
    if (in_array('authorization_code', $grants, true) && !in_array('openid', $scopes, true)) $errors[] = 'Le scope openid est requis pour un client utilisateur.';
    if (in_array('offline_access', $scopes, true) && empty($_POST['refresh_enabled'])) $errors[] = 'Le scope offline_access exige l’activation des refresh tokens.';
    if (in_array('offline_access', $scopes, true) && !in_array('refresh_token', $grants, true)) $errors[] = 'Le scope offline_access exige le grant refresh_token.';
    foreach (['access_token_minutes' => [1, 1440], 'refresh_token_days' => [1, 365]] as $key => [$min, $max]) {
        $value = filter_var($_POST[$key] ?? null, FILTER_VALIDATE_INT);
        if ($value === false || $value < $min || $value > $max) $errors[] = "La valeur $key doit être comprise entre $min et $max.";
    }

    return [
        'errors' => array_values(array_unique($errors)),
        'platform' => $platform,
        'name' => $name,
        'description' => trim((string) ($_POST['description'] ?? '')),
        'base_url' => $baseUrl,
        'redirects' => $redirects,
        'logout_uris' => $logoutUris,
        'scopes' => $scopes,
        'is_public' => $isPublic,
        'client_type' => $clientType,
        'grant_types' => $grants,
        'is_active' => isset($_POST['is_active']) ? 1 : 0,
        'token_lifetime' => max(60, min(86400, (int) ($_POST['access_token_minutes'] ?? 60) * 60)),
        'refresh_lifetime' => max(60, min(31536000, (int) ($_POST['refresh_token_days'] ?? 30) * 86400)),
        'refresh_enabled' => isset($_POST['refresh_enabled']) ? 1 : 0,
        'pkce_required' => ($isPublic || isset($_POST['pkce_required'])) ? 1 : 0,
        'mappings' => $mapping,
        'jit' => isset($_POST['jit_provisioning']) ? 1 : 0,
    ];
}

function oidc_admin_env(array $setup): string
{
    $platforms = IamLocal\Platforms\IamServiceProvider::platforms();
    $platform = $platforms->get((string) $setup['platform']);
    $client = $setup;
    $client['client_secret'] = (string) ($setup['secret'] ?? '');
    $client['redirect_uris'] = $setup['redirect_uris'] ?? [$setup['redirect_uri'] ?? ''];
    $client['post_logout_uris'] = $setup['post_logout_uris'] ?? [$setup['logout_uri'] ?? ''];
    return $platform->getEnvTemplate($client);
}

if (!empty($_SESSION['iam_oidc_setup_once']) || !empty($_SESSION['iam_oidc_env_once'])) {
    header('Cache-Control: no-store, private');
}
if (isset($_GET['download_env'])) {
    $setup = $_SESSION['iam_oidc_env_once'] ?? null;
    unset($_SESSION['iam_oidc_env_once']);
    if (!is_array($setup)) {
        http_response_code(410);
        exit('Le fichier .env n’est disponible qu’une seule fois après la création ou la rotation du secret.');
    }
    header('Content-Type: text/plain; charset=utf-8');
    header('Content-Disposition: attachment; filename="iam-oidc.env"');
    header('Cache-Control: no-store, private');
    echo oidc_admin_env($setup);
    exit;
}

if (empty($_SESSION['csrf_token'])) $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf'] ?? '')) {
        $error = 'Session expirée. Réessayez.';
    } else {
        $action = (string) ($_POST['action'] ?? '');
        if ($action === 'rotate_signing_key') {
            iam_oauth_rotate_key();
            iam_audit('oauth_key_rotated', 'Rotation de la clé de signature OIDC', (int) $iam_admin_user['id'], $iam_admin_user['email'], $_SERVER['REMOTE_ADDR'] ?? '', $_SERVER['HTTP_USER_AGENT'] ?? '');
            $message = 'Clé de signature OIDC remplacée.';
        } elseif ($action === 'create_client' || $action === 'update_client') {
            $data = oidc_admin_parse_form($platforms, $availableScopes);
            if ($data['errors']) {
                $error = implode(' ', $data['errors']);
            } elseif ($action === 'create_client') {
                $adapter = $platformRegistry->get($data['platform']);
                $clientSlug = oidc_admin_slug($data['name']);
                $appCode = substr($clientSlug, 0, 44);
                $checkCode = $db->prepare('SELECT COUNT(*) FROM applications WHERE code = ?');
                $checkCode->execute([$appCode]);
                if ((int) $checkCode->fetchColumn()) $appCode = substr($appCode, 0, 38) . '-' . bin2hex(random_bytes(3));
                try {
                    $db->beginTransaction();
                    $oauthClient = $clientService->createClient([
                        'name' => $data['name'],
                        'slug' => $clientSlug,
                        'description' => $data['description'],
                        'platform' => $data['platform'],
                        'platform_version' => trim((string) ($_POST['platform_version'] ?? '')) ?: null,
                        'client_type' => $data['client_type'],
                        'redirect_uris' => $data['redirects'],
                        'post_logout_uris' => $data['logout_uris'],
                        'scopes' => $data['scopes'],
                        'grant_types' => $data['grant_types'],
                        'token_lifetime' => $data['token_lifetime'],
                        'refresh_lifetime' => $data['refresh_lifetime'],
                        'base_url' => $data['base_url'],
                        'is_active' => $data['is_active'],
                        'refresh_enabled' => $data['refresh_enabled'],
                        'pkce_required' => $data['pkce_required'],
                        'role_mappings' => $data['mappings'],
                        'jit_provisioning' => $data['jit'],
                    ]);
                    $secret = $clientService->takePlainSecretOnce();
                    $clientId = (string) $oauthClient->get('client_id');
                    $db->prepare('INSERT INTO applications (code, name, description, url, color, icon, client_id, redirect_uri, scopes, active, is_system, sso_prompt) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0)')
                       ->execute([$appCode, $data['name'], $data['description'], $data['base_url'], '#176b87', 'fa-cube', $clientId, $data['redirects'][0] ?? '', implode(' ', $data['scopes']), $data['is_active']]);
                    $applicationId = (int) $db->lastInsertId();
                    $db->prepare('UPDATE oauth_clients SET application_id=? WHERE id=?')->execute([$applicationId, (int) $oauthClient->get('id')]);
                    $db->commit();
                    $setup = ['name' => $data['name'], 'platform' => $data['platform'], 'client_id' => $clientId, 'secret' => $secret ?? '', 'issuer' => IAM_BASE_URL, 'redirect_uris' => $data['redirects'], 'post_logout_uris' => $data['logout_uris'], 'redirect_uri' => $data['redirects'][0] ?? '', 'logout_uri' => $data['logout_uris'][0] ?? '', 'scopes' => $data['scopes'], 'token_lifetime' => $data['token_lifetime'], 'refresh_lifetime' => $data['refresh_lifetime'], 'refresh_enabled' => $data['refresh_enabled'], 'pkce_required' => $data['pkce_required'], 'jit' => $data['jit'], 'mappings' => $data['mappings']];
                    $_SESSION['iam_oidc_setup_once'] = $setup;
                    $_SESSION['iam_oidc_env_once'] = $setup;
                    iam_audit('oauth_client_created', 'Client OAuth créé: ' . $data['name'], (int) $iam_admin_user['id'], $iam_admin_user['email'], $_SERVER['REMOTE_ADDR'] ?? '', $_SERVER['HTTP_USER_AGENT'] ?? '');
                    header('Location: ' . IAM_BASE_URL . '/admin/oidc_apps.php?created=1');
                    exit;
                } catch (Throwable $e) {
                    if ($db->inTransaction()) $db->rollBack();
                    $error = 'Création impossible : ' . $e->getMessage();
                }
            } else {
                $clientRowId = (int) ($_POST['id'] ?? 0);
                $find = $db->prepare('SELECT c.*, a.id AS linked_app_id FROM oauth_clients c LEFT JOIN applications a ON a.id = c.application_id WHERE c.id = ?');
                $find->execute([$clientRowId]);
                $current = $find->fetch();
                if (!$current) {
                    $error = 'Client OIDC introuvable.';
                } elseif ($data['platform'] !== $current['platform'] || $data['client_type'] !== $current['client_type']) {
                    $error = 'La plateforme et le type de client ne peuvent pas être modifiés après création.';
                } else {
                    try {
                        $db->beginTransaction();
                        $db->prepare('UPDATE oauth_clients SET name=?, description=?, base_url=?, redirect_uris=?, post_logout_uris=?, grant_types=?, scopes=?, token_lifetime=?, refresh_lifetime=?, refresh_enabled=?, pkce_required=?, role_mappings=?, jit_provisioning=?, is_active=?, updated_at=UTC_TIMESTAMP() WHERE id=?')
                           ->execute([$data['name'], $data['description'], $data['base_url'], json_encode($data['redirects']), json_encode($data['logout_uris']), json_encode($data['grant_types']), json_encode($data['scopes']), $data['token_lifetime'], $data['refresh_lifetime'], $data['refresh_enabled'], $data['pkce_required'], json_encode($data['mappings'], JSON_UNESCAPED_UNICODE), $data['jit'], $data['is_active'], $clientRowId]);
                        if ($current['linked_app_id']) {
                            $db->prepare('UPDATE applications SET name=?, description=?, url=?, redirect_uri=?, scopes=?, active=? WHERE id=?')->execute([$data['name'], $data['description'], $data['base_url'], $data['redirects'][0] ?? '', implode(' ', $data['scopes']), $data['is_active'], $current['linked_app_id']]);
                        }
                        if (!$data['refresh_enabled'] || !$data['is_active']) $db->prepare('UPDATE refresh_tokens SET revoked=1 WHERE client_id=? AND revoked=0')->execute([$current['client_id']]);
                        $db->commit();
                        $message = 'Configuration mise à jour.';
                    } catch (Throwable $e) {
                        if ($db->inTransaction()) $db->rollBack();
                        $error = 'Mise à jour impossible : ' . $e->getMessage();
                    }
                }
            }
        } elseif ($action === 'toggle_client' || $action === 'delete_client' || $action === 'rotate_secret') {
            $id = (int) ($_POST['id'] ?? 0);
            $stmt = $db->prepare('SELECT c.*, a.id AS linked_app_id FROM oauth_clients c LEFT JOIN applications a ON a.id=c.application_id WHERE c.id=?');
            $stmt->execute([$id]);
            $client = $stmt->fetch();
            if (!$client) {
                $error = 'Client OAuth introuvable.';
            } elseif ($action === 'toggle_client') {
                $active = (int) $client['is_active'] === 1 ? 0 : 1;
                $db->prepare('UPDATE oauth_clients SET is_active=?, updated_at=UTC_TIMESTAMP() WHERE id=?')->execute([$active, $id]);
                if ($client['linked_app_id']) $db->prepare('UPDATE applications SET active=? WHERE id=?')->execute([$active, $client['linked_app_id']]);
                if (!$active) $db->prepare('UPDATE refresh_tokens SET revoked=1 WHERE client_id=? AND revoked=0')->execute([$client['client_id']]);
                $message = $active ? 'Client activé.' : 'Client désactivé et refresh tokens révoqués.';
            } elseif ($action === 'rotate_secret') {
                if ($client['client_type'] !== 'confidential') {
                    $error = 'Les clients publics n’ont pas de secret à régénérer.';
                } else {
                    $secret = $clientService->regenerateSecret(new OAuthClient($client));
                    $setup = ['name' => $client['name'], 'platform' => $client['platform'], 'client_id' => $client['client_id'], 'secret' => $secret, 'issuer' => IAM_BASE_URL, 'redirect_uris' => json_decode($client['redirect_uris'], true) ?: [], 'post_logout_uris' => json_decode($client['post_logout_uris'] ?? '[]', true) ?: [], 'scopes' => json_decode($client['scopes'], true) ?: [], 'token_lifetime' => (int) $client['token_lifetime'], 'refresh_lifetime' => (int) $client['refresh_lifetime'], 'refresh_enabled' => (int) $client['refresh_enabled'], 'pkce_required' => (int) $client['pkce_required'], 'jit' => (int) $client['jit_provisioning'], 'mappings' => json_decode($client['role_mappings'] ?? '{}', true) ?: []];
                    $_SESSION['iam_oidc_setup_once'] = $setup;
                    $_SESSION['iam_oidc_env_once'] = $setup;
                    iam_oauth_log_event((string) $client['client_id'], (int) $iam_admin_user['id'], 'secret_rotated');
                    header('Location: ' . IAM_BASE_URL . '/admin/oidc_apps.php?rotated=1');
                    exit;
                }
            } else {
                $db->beginTransaction();
                $db->prepare('UPDATE refresh_tokens SET revoked=1 WHERE client_id=? AND revoked=0')->execute([$client['client_id']]);
                $db->prepare('DELETE FROM oauth_clients WHERE id=?')->execute([$id]);
                if ($client['linked_app_id']) $db->prepare('DELETE FROM applications WHERE id=?')->execute([$client['linked_app_id']]);
                $db->commit();
                $message = 'Client et fiche application supprimés.';
            }
        }
    }
}

$freshSetup = $_SESSION['iam_oidc_setup_once'] ?? null;
unset($_SESSION['iam_oidc_setup_once']);
$testResults = null;
if (isset($_GET['test'])) {
    $probe = static function (string $path): int {
        $url = rtrim(IAM_BASE_URL, '/') . $path;
        $context = stream_context_create(['http' => ['timeout' => 4, 'ignore_errors' => true, 'follow_location' => 0]]);
        @file_get_contents($url, false, $context);
        $statusLine = $http_response_header[0] ?? '';
        return preg_match('/\s(\d{3})\s/', $statusLine, $match) ? (int) $match[1] : 0;
    };
    $metadataStatus = $probe('/.well-known/openid-configuration.php');
    $authStatus = $probe('/oauth.php');
    $tokenStatus = $probe('/api/oauth/token.php');
    $userinfoStatus = $probe('/api/oauth/userinfo.php');
    $jwksStatus = $probe('/api/oauth/jwks.php');
    $testResults = [
        'Découverte OIDC (HTTP ' . $metadataStatus . ')' => $metadataStatus === 200,
        'Autorisation (HTTP ' . $authStatus . ')' => $authStatus === 400,
        'Échange de jetons (HTTP ' . $tokenStatus . ')' => $tokenStatus === 400,
        'UserInfo (HTTP ' . $userinfoStatus . ')' => $userinfoStatus === 401,
        'JWKS (HTTP ' . $jwksStatus . ')' => $jwksStatus === 200,
    ];
}

$detailId = (int) ($_GET['view'] ?? 0);
$detail = null;
if ($detailId) {
    $stmt = $db->prepare('SELECT c.*, a.code AS app_code, a.description AS app_description, a.url AS app_url FROM oauth_clients c LEFT JOIN applications a ON a.id=c.application_id WHERE c.id=?');
    $stmt->execute([$detailId]);
    $detail = $stmt->fetch() ?: null;
}

$search = trim((string) ($_GET['q'] ?? ''));
$filterStatus = (string) ($_GET['status'] ?? '');
$filterType = (string) ($_GET['type'] ?? '');
$page = max(1, (int) ($_GET['page'] ?? 1));
$pageSize = 10;
$where = [];
$params = [];
if ($search !== '') { $where[] = '(c.name LIKE ? OR c.client_id LIKE ?)'; $params[] = '%' . $search . '%'; $params[] = '%' . $search . '%'; }
if (in_array($filterStatus, ['active', 'inactive'], true)) { $where[] = 'c.is_active = ?'; $params[] = $filterStatus === 'active' ? 1 : 0; }
if (isset($platforms[$filterType])) { $where[] = 'c.platform = ?'; $params[] = $filterType; }
$whereSql = $where ? ' WHERE ' . implode(' AND ', $where) : '';
$count = $db->prepare('SELECT COUNT(*) FROM oauth_clients c' . $whereSql);
$count->execute($params);
$total = (int) $count->fetchColumn();
$pages = max(1, (int) ceil($total / $pageSize));
$page = min($page, $pages);
$list = $db->prepare('SELECT c.* FROM oauth_clients c' . $whereSql . ' ORDER BY c.created_at DESC LIMIT ' . $pageSize . ' OFFSET ' . (($page - 1) * $pageSize));
$list->execute($params);
$clients = $list->fetchAll();
$history = [];
if ($detail) {
    $historyStmt = $db->prepare('SELECT * FROM oauth_client_events WHERE client_id=? ORDER BY created_at DESC LIMIT 20');
    $historyStmt->execute([$detail['client_id']]);
    $history = $historyStmt->fetchAll();
}
$signingKeys = $db->query('SELECT kid, alg, active, created_at FROM oauth_keys ORDER BY id DESC')->fetchAll(PDO::FETCH_ASSOC);

$pageTitle = 'Applications OAuth / OIDC';
$active = 'oauth';
include __DIR__ . '/_header.php';
?>
<?php if ($error): ?><div class="alert alert-danger"><?php echo htmlspecialchars($error); ?></div><?php endif; ?>
<?php if ($message): ?><div class="alert alert-success"><?php echo htmlspecialchars($message); ?></div><?php endif; ?>
<?php if ($freshSetup): ?>
    <?php $freshAdapter = $platformRegistry->get((string) $freshSetup['platform']); ?>
    <section class="oidc-secret-notice" aria-labelledby="oidc-secret-heading">
        <div><strong id="oidc-secret-heading"><?php echo !empty($freshSetup['secret']) ? 'Secret généré, affiché une seule fois' : 'Client public créé'; ?></strong>
            <?php if (!empty($freshSetup['secret'])): ?><p>Copiez le secret maintenant. Il ne sera plus affiché après cette page.</p><?php endif; ?></div>
        <label>Client ID <span class="oidc-copy-row"><code id="freshClientId"><?php echo htmlspecialchars($freshSetup['client_id']); ?></code><button type="button" class="btn btn-outline btn-sm" data-copy="freshClientId">Copier</button></span></label>
        <?php if (!empty($freshSetup['secret'])): ?><label>Client Secret <span class="oidc-copy-row"><code id="freshClientSecret"><?php echo htmlspecialchars($freshSetup['secret']); ?></code><button type="button" class="btn btn-outline btn-sm" data-copy="freshClientSecret">Copier le secret</button></span></label><?php endif; ?>
        <a class="btn btn-primary btn-sm" href="?download_env=1"><i class="fas fa-download"></i> Télécharger le .env</a>
        <details><summary>Configuration <?php echo htmlspecialchars($freshAdapter->getLabel()); ?></summary>
            <pre><code><?php echo htmlspecialchars($freshAdapter->getConfigTemplate($freshSetup)); ?></code></pre>
            <?php if ($freshAdapter->getInstallCommand()): ?><p>Installation : <code><?php echo htmlspecialchars($freshAdapter->getInstallCommand()); ?></code></p><?php endif; ?>
            <?php if ($freshAdapter->getDocsUrl()): ?><p>Documentation : <a href="<?php echo htmlspecialchars($freshAdapter->getDocsUrl()); ?>" target="_blank" rel="noopener">Consulter la documentation</a></p><?php endif; ?>
        </details>
    </section>
<?php endif; ?>

<?php if ($testResults !== null): ?>
    <div class="alert alert-info"><strong>Test des endpoints IAM</strong><ul><?php foreach ($testResults as $label => $ok): ?><li><?php echo $ok ? 'OK' : 'Échec'; ?> · <?php echo htmlspecialchars($label); ?></li><?php endforeach; ?></ul></div>
<?php endif; ?>

<?php if ($detail): ?>
    <?php $redirectList = json_decode($detail['redirect_uris'] ?? '[]', true) ?: []; $logoutList = json_decode($detail['post_logout_uris'] ?? '[]', true) ?: []; $roleMap = json_decode($detail['role_mappings'] ?? '{}', true) ?: []; $detailScopes = json_decode($detail['scopes'] ?? '[]', true) ?: []; $detailGrants = json_decode($detail['grant_types'] ?? '[]', true) ?: []; $detailAdapter = $platformRegistry->get((string) $detail['platform']); ?>
    <div class="d-flex justify-between align-center mb-3"><div><a href="<?php echo IAM_BASE_URL; ?>/admin/oidc_apps.php">← Toutes les applications</a><h2 style="margin:8px 0 0;"><?php echo htmlspecialchars($detail['name']); ?></h2></div><span class="badge <?php echo (int) $detail['is_active'] ? 'badge-success' : 'badge-muted'; ?>"><?php echo (int) $detail['is_active'] ? 'Actif' : 'Inactif'; ?></span></div>
    <div class="cards-grid">
        <section class="card"><div class="card-body"><h3>Configuration OIDC</h3><dl class="oidc-details">
            <dt>Plateforme</dt><dd><?php echo htmlspecialchars($detailAdapter->getLabel()); ?></dd>
            <dt>Type client</dt><dd><?php echo htmlspecialchars($detail['client_type']); ?></dd>
            <dt>Client ID</dt><dd><code><?php echo htmlspecialchars($detail['client_id']); ?></code></dd>
            <dt>Slug</dt><dd><?php echo htmlspecialchars($detail['slug']); ?></dd>
            <dt>Base URL</dt><dd><?php echo htmlspecialchars($detail['base_url'] ?? ''); ?></dd>
            <dt>Redirect URIs</dt><dd><?php echo nl2br(htmlspecialchars(implode("\n", $redirectList))); ?></dd>
            <dt>Post-logout URIs</dt><dd><?php echo nl2br(htmlspecialchars(implode("\n", $logoutList))); ?></dd>
            <dt>Scopes</dt><dd><?php echo htmlspecialchars(implode(' ', $detailScopes)); ?></dd>
            <dt>Grants</dt><dd><?php echo htmlspecialchars(implode(', ', $detailGrants)); ?></dd>
            <dt>Access token</dt><dd><?php echo (int) $detail['token_lifetime']; ?> secondes</dd>
            <dt>Refresh token</dt><dd><?php echo (int) $detail['refresh_enabled'] ? (int) $detail['refresh_lifetime'] . ' secondes' : 'Désactivé'; ?></dd>
            <dt>PKCE</dt><dd><?php echo ((int) $detail['pkce_required'] || $detail['client_type'] === 'public') ? 'Obligatoire' : 'Optionnel'; ?></dd>
            <dt>Mapping des rôles</dt><dd><?php echo $roleMap ? htmlspecialchars(json_encode($roleMap, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT)) : 'Aucun'; ?></dd>
            <dt>JIT</dt><dd><?php echo (int) $detail['jit_provisioning'] ? 'Activé (le client crée le compte local)' : 'Désactivé'; ?></dd>
            <dt>Dernière utilisation</dt><dd><?php echo htmlspecialchars($detail['last_used_at'] ?? 'Jamais'); ?></dd>
        </dl><div class="d-flex gap-2 flex-wrap mt-3"><a class="btn btn-outline btn-sm" href="?view=<?php echo (int) $detail['id']; ?>&amp;test=1"><i class="fas fa-stethoscope"></i> Tester les endpoints</a><form method="POST"><input type="hidden" name="csrf" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>"><input type="hidden" name="action" value="rotate_secret"><input type="hidden" name="id" value="<?php echo (int) $detail['id']; ?>"><button class="btn btn-outline btn-sm" onclick="return confirm('Révoquer les refresh tokens et remplacer le secret ?');"><i class="fas fa-rotate"></i> Régénérer le secret</button></form></div></div></section>
        <section class="card"><div class="card-body"><h3>Modifier la configuration</h3><form method="POST" id="oidcEditForm"><input type="hidden" name="csrf" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>"><input type="hidden" name="action" value="update_client"><input type="hidden" name="id" value="<?php echo (int) $detail['id']; ?>">
            <input type="hidden" name="platform" value="<?php echo htmlspecialchars($detail['platform']); ?>"><input type="hidden" name="client_type" value="<?php echo htmlspecialchars($detail['client_type']); ?>">
            <div class="form-group"><label>Nom</label><input class="form-control" name="name" required value="<?php echo htmlspecialchars($detail['name']); ?>"></div>
            <div class="form-group"><label>Description</label><textarea class="form-control" name="description"><?php echo htmlspecialchars($detail['app_description'] ?? ''); ?></textarea></div>
            <div class="form-group"><label>URL de base</label><input class="form-control" name="base_url" type="url" required value="<?php echo htmlspecialchars($detail['base_url'] ?? ''); ?>"></div>
            <div class="form-group"><label>Redirect URIs, une par ligne</label><textarea class="form-control" name="redirect_uris" rows="3"><?php echo htmlspecialchars(implode("\n", $redirectList)); ?></textarea></div>
            <div class="form-group"><label>Post-logout redirect URIs</label><textarea class="form-control" name="post_logout_redirect_uris" rows="2"><?php echo htmlspecialchars(implode("\n", $logoutList)); ?></textarea></div>
            <fieldset class="form-group"><legend>Scopes</legend><?php foreach ($availableScopes as $scope): ?><label class="oidc-check"><input type="checkbox" name="scopes[]" value="<?php echo $scope; ?>" <?php echo in_array($scope, $detailScopes, true) ? 'checked' : ''; ?>> <?php echo $scope; ?></label><?php endforeach; ?></fieldset>
            <fieldset class="form-group"><legend>Grant types</legend><?php foreach (['authorization_code', 'refresh_token', 'client_credentials'] as $grantType): ?><label class="oidc-check"><input type="checkbox" name="grant_types[]" value="<?php echo $grantType; ?>" <?php echo in_array($grantType, $detailGrants, true) ? 'checked' : ''; ?>> <?php echo $grantType; ?></label><?php endforeach; ?></fieldset>
            <div class="form-row"><div class="form-group"><label>Access token (minutes)</label><input class="form-control" type="number" min="1" max="1440" name="access_token_minutes" value="<?php echo max(1, (int) $detail['token_lifetime'] / 60); ?>"></div><div class="form-group"><label>Refresh token (jours)</label><input class="form-control" type="number" min="1" max="365" name="refresh_token_days" value="<?php echo max(1, (int) ceil($detail['refresh_lifetime'] / 86400)); ?>"></div></div>
            <label class="oidc-check"><input type="checkbox" name="refresh_enabled" <?php echo (int) $detail['refresh_enabled'] ? 'checked' : ''; ?>> Activer les refresh tokens</label><label class="oidc-check"><input type="checkbox" name="pkce_required" <?php echo (int) $detail['pkce_required'] ? 'checked' : ''; ?>> Exiger PKCE S256</label><label class="oidc-check"><input type="checkbox" name="jit_provisioning" <?php echo (int) $detail['jit_provisioning'] ? 'checked' : ''; ?>> Demander le JIT au client</label><label class="oidc-check"><input type="checkbox" name="is_active" <?php echo (int) $detail['is_active'] ? 'checked' : ''; ?>> Client actif</label>
            <h4>Mapping des rôles IAM vers l’application</h4><div id="roleMapRows"><?php foreach ($roleMap as $iamRole => $appRole): ?><div class="oidc-map-row"><input class="form-control" name="iam_role[]" value="<?php echo htmlspecialchars((string) $iamRole); ?>" placeholder="Rôle IAM"><span>→</span><input class="form-control" name="app_role[]" value="<?php echo htmlspecialchars((string) $appRole); ?>" placeholder="Rôle application"><button type="button" class="btn btn-outline btn-sm" data-remove-row title="Supprimer">×</button></div><?php endforeach; ?></div><button type="button" class="btn btn-outline btn-sm" data-add-role>+ Ajouter un mapping</button><div class="mt-3"><button class="btn btn-primary">Enregistrer les modifications</button></div>
        </form></div></section>
        <section class="card" style="grid-column:1/-1"><div class="card-body"><h3>Historique des connexions</h3><div class="table-wrap"><table class="table"><thead><tr><th>Date</th><th>Événement</th><th>Utilisateur</th><th>IP</th><th>User-Agent</th></tr></thead><tbody><?php if (!$history): ?><tr><td colspan="5">Aucun événement enregistré.</td></tr><?php else: foreach ($history as $event): ?><tr><td><?php echo htmlspecialchars($event['created_at']); ?></td><td><?php echo htmlspecialchars($event['event']); ?></td><td><?php echo htmlspecialchars((string) ($event['user_id'] ?? '')); ?></td><td><?php echo htmlspecialchars((string) ($event['ip_address'] ?? '')); ?></td><td><?php echo htmlspecialchars((string) ($event['user_agent'] ?? '')); ?></td></tr><?php endforeach; endif; ?></tbody></table></div></div></section>
    </div>
<?php else: ?>
        <div class="d-flex justify-between align-center mb-3"><div><h2 style="margin:0;">Applications OAuth / OIDC</h2><p class="text-muted">Clients OAuth/OIDC multi-plateformes.</p></div><div class="d-flex gap-2"><form method="POST" onsubmit="return confirm('Remplacer la clé de signature JWKS ?');"><input type="hidden" name="csrf" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>"><input type="hidden" name="action" value="rotate_signing_key"><button class="btn btn-outline"><i class="fas fa-key"></i> Rotation JWKS</button></form><button class="btn btn-primary" type="button" data-open-wizard><i class="fas fa-plus"></i> Nouvelle application</button></div></div>
        <form method="GET" class="oidc-filters"><input class="form-control" type="search" name="q" value="<?php echo htmlspecialchars($search); ?>" placeholder="Rechercher par nom ou Client ID"><select class="form-control" name="type"><option value="">Toutes les plateformes</option><?php foreach ($platforms as $value => $adapter): ?><option value="<?php echo htmlspecialchars($value); ?>" <?php echo $filterType === $value ? 'selected' : ''; ?>><?php echo htmlspecialchars($adapter->getLabel()); ?></option><?php endforeach; ?></select><select class="form-control" name="status"><option value="">Tous les statuts</option><option value="active" <?php echo $filterStatus === 'active' ? 'selected' : ''; ?>>Actifs</option><option value="inactive" <?php echo $filterStatus === 'inactive' ? 'selected' : ''; ?>>Inactifs</option></select><select class="form-control" name="client_type"><option value="">Tous les types client</option><option value="confidential">Confidentiel</option><option value="public">Public</option></select><button class="btn btn-outline">Filtrer</button></form>
    <div class="card"><div class="table-wrap"><table class="table"><thead><tr><th>Application</th><th>Type</th><th>Client ID</th><th>Statut</th><th>Création</th><th>Dernière utilisation</th><th>Actions</th></tr></thead><tbody>
        <?php if (!$clients): ?><tr><td colspan="7" class="text-center text-muted">Aucune application OAuth. Créez-en une pour commencer.</td></tr><?php else: foreach ($clients as $client): $adapter = $platformRegistry->get((string) $client['platform']); ?><tr><td><strong><?php echo htmlspecialchars($client['name']); ?></strong><br><small><?php echo htmlspecialchars($client['base_url'] ?? ''); ?></small></td><td><span class="badge"><?php echo htmlspecialchars($adapter->getLabel()); ?></span></td><td><span class="oidc-copy-row"><code><?php echo htmlspecialchars($client['client_id']); ?></code><button type="button" class="btn btn-outline btn-sm" data-copy-value="<?php echo htmlspecialchars($client['client_id']); ?>" title="Copier le Client ID"><i class="fas fa-copy"></i></button></span><br><small><?php echo htmlspecialchars($client['client_type']); ?></small></td><td><span class="badge <?php echo (int) $client['is_active'] ? 'badge-success' : 'badge-muted'; ?>"><?php echo (int) $client['is_active'] ? 'Actif' : 'Inactif'; ?></span></td><td><?php echo htmlspecialchars($client['created_at']); ?></td><td><?php echo htmlspecialchars($client['last_used_at'] ?? 'Jamais'); ?></td><td><div class="oidc-actions"><a class="btn btn-outline btn-sm" href="?view=<?php echo (int) $client['id']; ?>">Voir / Modifier</a><?php if ($client['client_type'] === 'confidential'): ?><form method="POST"><input type="hidden" name="csrf" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>"><input type="hidden" name="action" value="rotate_secret"><input type="hidden" name="id" value="<?php echo (int) $client['id']; ?>"><button class="btn btn-outline btn-sm" title="Régénérer le secret" onclick="return confirm('Remplacer le secret et révoquer les refresh tokens ?');"><i class="fas fa-rotate"></i></button></form><?php endif; ?><form method="POST"><input type="hidden" name="csrf" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>"><input type="hidden" name="action" value="toggle_client"><input type="hidden" name="id" value="<?php echo (int) $client['id']; ?>"><button class="btn btn-outline btn-sm"><?php echo (int) $client['is_active'] ? 'Désactiver' : 'Activer'; ?></button></form><form method="POST" onsubmit="return confirm('Supprimer ce client et sa fiche application ? Les rôles associés seront également supprimés.');"><input type="hidden" name="csrf" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>"><input type="hidden" name="action" value="delete_client"><input type="hidden" name="id" value="<?php echo (int) $client['id']; ?>"><button class="btn btn-danger btn-sm" title="Supprimer"><i class="fas fa-trash"></i></button></form></div></td></tr><?php endforeach; endif; ?>
    </tbody></table></div></div>
    <?php if ($pages > 1): ?><nav class="oidc-pagination" aria-label="Pagination"><?php for ($i = 1; $i <= $pages; $i++): ?><a class="btn btn-sm <?php echo $i === $page ? 'btn-primary' : 'btn-outline'; ?>" href="?<?php echo htmlspecialchars(http_build_query(array_merge($_GET, ['page' => $i]))); ?>"><?php echo $i; ?></a><?php endfor; ?></nav><?php endif; ?>

    <div id="oidcWizard" class="oidc-modal" hidden><div class="oidc-modal-panel"><div class="d-flex justify-between align-center"><h2>Nouvelle application OAuth/OIDC</h2><button type="button" class="btn btn-outline" data-close-wizard aria-label="Fermer">×</button></div><div class="oidc-steps"><span aria-current="step">1 · Application</span><span>2 · OAuth/OIDC</span><span>3 · Rôles</span></div>
        <form method="POST" id="oidcCreateForm"><input type="hidden" name="csrf" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>"><input type="hidden" name="action" value="create_client"><div class="oidc-step" data-step="0"><h3>Informations générales</h3><div class="form-group"><label>Nom de l’application *</label><input class="form-control" name="name" required maxlength="120" placeholder="Gestion des Salaires"></div><div class="form-group"><label>Description</label><textarea class="form-control" name="description" rows="2"></textarea></div><div class="form-group"><label>Type d’application *</label><select class="form-control" name="platform" id="oidcPlatform"><?php foreach ($platforms as $value => $adapter): ?><option value="<?php echo htmlspecialchars($value); ?>"><?php echo htmlspecialchars($adapter->getLabel()); ?></option><?php endforeach; ?></select></div><div class="form-group"><label>URL de base *</label><input class="form-control" type="url" name="base_url" id="oidcBaseUrl" required placeholder="https://gestion-salaires.example.com"></div><label class="oidc-check"><input type="checkbox" name="is_active" checked> Activer l’application à la création</label><div class="oidc-wizard-actions"><span></span><button type="button" class="btn btn-primary" data-next>Continuer</button></div></div>
        <div class="oidc-step" data-step="1" hidden><h3>OAuth / OIDC</h3><div class="form-group"><label>Redirect URIs, une par ligne *</label><div id="redirectRows"><div class="oidc-uri-row"><input class="form-control" name="redirect_uris[]" required placeholder="https://example.com/auth/iam/callback"><button type="button" class="btn btn-outline btn-sm" data-remove-row title="Supprimer">×</button></div><div class="oidc-uri-row"><input class="form-control" name="redirect_uris[]" placeholder="https://example.com/auth/iam/callback/"><button type="button" class="btn btn-outline btn-sm" data-remove-row title="Supprimer">×</button></div></div><button type="button" class="btn btn-outline btn-sm" data-add-uri="redirectRows">+ Ajouter une URI</button><small class="text-muted">Les deux variantes sans et avec barre finale sont préremplies à partir de l’URL de base.</small></div><div class="form-group"><label>Post-logout redirect URIs</label><div id="logoutRows"><div class="oidc-uri-row"><input class="form-control" name="post_logout_redirect_uris[]" placeholder="https://example.com/"><button type="button" class="btn btn-outline btn-sm" data-remove-row title="Supprimer">×</button></div></div><button type="button" class="btn btn-outline btn-sm" data-add-uri="logoutRows">+ Ajouter une URI</button></div><fieldset class="form-group"><legend>Scopes autorisés</legend><?php foreach ($availableScopes as $scope): ?><label class="oidc-check"><input type="checkbox" name="scopes[]" value="<?php echo $scope; ?>" <?php echo in_array($scope, ['openid', 'profile', 'email'], true) ? 'checked' : ''; ?>> <?php echo $scope; ?></label><?php endforeach; ?></fieldset><div class="form-row"><div class="form-group"><label>Access token (minutes)</label><input class="form-control" type="number" min="1" max="1440" name="access_token_minutes" value="60" required></div><div class="form-group"><label>Refresh token (jours)</label><input class="form-control" type="number" min="1" max="365" name="refresh_token_days" value="30" required></div></div><label class="oidc-check"><input type="checkbox" name="refresh_enabled" checked> Activer les refresh tokens</label><small class="text-muted">Le client doit aussi demander le scope offline_access pour recevoir un refresh token.</small><label class="oidc-check" id="pkceOption"><input type="checkbox" name="pkce_required"> Exiger PKCE S256 (recommandé)</label><div class="oidc-wizard-actions"><button type="button" class="btn btn-outline" data-back>Retour</button><button type="button" class="btn btn-primary" data-next>Continuer</button></div></div>
        <div class="oidc-step" data-step="2" hidden><h3>Mapping des rôles (facultatif)</h3><p class="text-muted">Les codes de rôles IAM seront traduits dans les claims OIDC lorsque le scope <code>roles</code> est demandé.</p><div id="roleMapCreateRows"></div><button type="button" class="btn btn-outline btn-sm" data-add-role>+ Ajouter un mapping</button><label class="oidc-check"><input type="checkbox" name="jit_provisioning"> Demander la création de l’utilisateur local au premier login (JIT côté application)</label><div class="oidc-wizard-actions"><button type="button" class="btn btn-outline" data-back>Retour</button><button type="submit" class="btn btn-success"><i class="fas fa-plus"></i> Créer le client</button></div></div></form>
    </div></div>
<?php endif; ?>

<style>
.oidc-filters{display:grid;grid-template-columns:minmax(220px,1fr) minmax(170px,240px) minmax(130px,170px) auto;gap:8px;margin:14px 0}.oidc-actions,.oidc-copy-row{display:flex;align-items:center;gap:6px;flex-wrap:wrap}.oidc-actions form{display:inline-flex}.oidc-pagination{display:flex;gap:6px;justify-content:flex-end;margin-top:14px}.oidc-secret-notice{display:grid;gap:12px;margin-bottom:18px;padding:18px;border:1px solid #e6a6a6;border-left:5px solid #c93636;background:#fff8f7}.oidc-secret-notice>div p{margin:4px 0;color:#8b2b2b}.oidc-secret-notice label{display:grid;gap:5px}.oidc-secret-notice code{overflow-wrap:anywhere}.oidc-details{display:grid;grid-template-columns:minmax(150px,220px) minmax(0,1fr);gap:9px 14px}.oidc-details dt{color:#64748b}.oidc-details dd{margin:0;overflow-wrap:anywhere}.oidc-check{display:flex;gap:8px;align-items:center;margin:8px 0}.oidc-map-row,.oidc-uri-row{display:grid;grid-template-columns:minmax(0,1fr) auto minmax(0,1fr) auto;gap:8px;align-items:center;margin:7px 0}.oidc-uri-row{grid-template-columns:minmax(0,1fr) auto}.oidc-modal{position:fixed;inset:0;z-index:1100;display:grid;place-items:center;padding:16px;background:rgba(12,24,32,.6)}.oidc-modal[hidden]{display:none}.oidc-modal-panel{width:min(100%,780px);max-height:min(92vh,900px);overflow:auto;background:#fff;padding:clamp(16px,3vw,28px);border-radius:6px}.oidc-modal-panel h2{margin:0}.oidc-steps{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px;margin:18px 0}.oidc-steps span{padding:9px;border-bottom:2px solid #d8e0e4;color:#62727a;font-size:13px}.oidc-steps span[aria-current=step]{border-color:#087e8b;color:#12333d;font-weight:700}.oidc-step[hidden]{display:none}.oidc-step h3{margin:0 0 16px}.oidc-wizard-actions{display:flex;justify-content:space-between;gap:10px;margin-top:20px}.oidc-secret-notice pre{white-space:pre-wrap;overflow-wrap:anywhere}.oidc-secret-notice details{margin-top:8px}@media(max-width:760px){.oidc-filters{grid-template-columns:1fr 1fr}.oidc-filters input{grid-column:1/-1}.oidc-details{grid-template-columns:1fr;gap:3px}.oidc-details dd{margin-bottom:8px}.oidc-map-row{grid-template-columns:minmax(0,1fr) auto}.oidc-map-row span{display:none}.oidc-map-row input:last-of-type{grid-column:1}.oidc-actions{min-width:180px}.table-wrap{overflow-x:auto}}@media(max-width:480px){.oidc-filters{grid-template-columns:1fr}.oidc-filters input{grid-column:auto}.oidc-modal{padding:6px}.oidc-modal-panel{max-height:98vh}.oidc-steps span{font-size:11px;text-align:center}}
</style>
<script>
(() => {
    const wizard = document.getElementById('oidcWizard');
    const open = document.querySelector('[data-open-wizard]');
    if (!wizard || !open) return;
    const steps = [...wizard.querySelectorAll('.oidc-step')];
    const indicators = [...wizard.querySelectorAll('.oidc-steps span')];
    let current = 0;
    function showStep(index) {
        current = Math.max(0, Math.min(steps.length - 1, index));
        steps.forEach((step, i) => step.hidden = i !== current);
        indicators.forEach((item, i) => i === current ? item.setAttribute('aria-current', 'step') : item.removeAttribute('aria-current'));
    }
    open.addEventListener('click', () => { window.location.href = 'oidc_wizard.php'; });
    wizard.querySelectorAll('[data-close-wizard]').forEach(button => button.addEventListener('click', () => wizard.hidden = true));
    wizard.querySelectorAll('[data-next]').forEach(button => button.addEventListener('click', () => {
        const required = [...steps[current].querySelectorAll('input[required]')];
        const invalid = required.find(input => !input.checkValidity());
        if (invalid) { invalid.reportValidity(); return; }
        showStep(current + 1);
    }));
    wizard.querySelectorAll('[data-back]').forEach(button => button.addEventListener('click', () => showStep(current - 1)));
    wizard.querySelectorAll('[data-add-uri]').forEach(button => button.addEventListener('click', () => {
        const target = document.getElementById(button.dataset.addUri);
        const row = document.createElement('div'); row.className = 'oidc-uri-row';
        const input = document.createElement('input'); input.className = 'form-control'; input.name = button.dataset.addUri === 'redirectRows' ? 'redirect_uris[]' : 'post_logout_redirect_uris[]'; input.placeholder = 'https://example.com/callback'; input.required = button.dataset.addUri === 'redirectRows';
        const remove = document.createElement('button'); remove.type = 'button'; remove.className = 'btn btn-outline btn-sm'; remove.textContent = '×'; remove.title = 'Supprimer'; remove.dataset.removeRow = '';
        row.append(input, remove); target.append(row); input.focus();
    }));
    document.addEventListener('click', event => {
        const remove = event.target.closest('[data-remove-row]');
        if (remove) remove.closest('.oidc-uri-row,.oidc-map-row')?.remove();
        const addRole = event.target.closest('[data-add-role]');
        if (addRole) {
            const target = addRole.closest('.oidc-step')?.querySelector('#roleMapCreateRows') || document.getElementById('roleMapRows');
            if (!target) return;
            const row = document.createElement('div'); row.className = 'oidc-map-row';
            const left = document.createElement('input'); left.className = 'form-control'; left.name = 'iam_role[]'; left.placeholder = 'Rôle IAM';
            const arrow = document.createElement('span'); arrow.textContent = '→';
            const right = document.createElement('input'); right.className = 'form-control'; right.name = 'app_role[]'; right.placeholder = 'Rôle Laravel';
            const remove = document.createElement('button'); remove.type = 'button'; remove.className = 'btn btn-outline btn-sm'; remove.textContent = '×'; remove.title = 'Supprimer'; remove.dataset.removeRow = '';
            row.append(left, arrow, right, remove); target.append(row); left.focus();
        }
    });
    document.getElementById('oidcPlatform').addEventListener('change', event => {
        const publicClient = ['spa', 'mobile'].includes(event.target.value);
        const service = event.target.value === 'api';
        const pkce = document.querySelector('#pkceOption input');
        pkce.checked = publicClient;
        pkce.disabled = publicClient;
        const redirectInput = document.querySelector('#redirectRows input');
        redirectInput.required = !service;
        document.getElementById('redirectRows').closest('.form-group').hidden = service;
        document.getElementById('logoutRows').closest('.form-group').hidden = service;
    });
    document.getElementById('oidcBaseUrl').addEventListener('change', event => {
        const base = event.target.value.replace(/\/$/, '');
        const platform = document.getElementById('oidcPlatform').value;
        if (platform === 'mobile' || platform === 'api') return;
        const rows = [...document.querySelectorAll('#redirectRows input')];
        if (rows[0] && !rows[0].value) rows[0].value = base + '/auth/iam/callback';
        if (rows[1] && !rows[1].value) rows[1].value = base + '/auth/iam/callback/';
        const logout = document.querySelector('#logoutRows input');
        if (logout && !logout.value) logout.value = base + '/';
    });
    document.getElementById('oidcCreateForm').addEventListener('submit', event => {
        if (!steps.every(step => !step.querySelector('input[required]:invalid'))) return;
        const base = document.getElementById('oidcBaseUrl').value.replace(/\/$/, '');
        const callbacks = [...document.querySelectorAll('#redirectRows input')];
        if (document.getElementById('oidcPlatform').value !== 'api') {
            if (callbacks[0] && !callbacks[0].value) callbacks[0].value = base + '/auth/iam/callback';
            if (callbacks[1] && !callbacks[1].value) callbacks[1].value = base + '/auth/iam/callback/';
            const logout = document.querySelector('#logoutRows input');
            if (logout && !logout.value) logout.value = base + '/';
        }
    });
})();
document.addEventListener('click', async event => {
    const button = event.target.closest('[data-copy],[data-copy-value]');
    if (!button) return;
    const value = button.dataset.copyValue || document.getElementById(button.dataset.copy)?.textContent || '';
    try { await navigator.clipboard.writeText(value); button.title = 'Copié'; } catch { button.title = 'Copie indisponible'; }
});
</script>
<?php include __DIR__ . '/_footer.php'; ?>