<?php
require_once __DIR__ . '/_guard.php';
require_once __DIR__ . '/../includes/oauth.php';

header('Location: ' . IAM_BASE_URL . '/admin/oidc_apps.php');
exit;

$db  = db();
$msg = '';
$type = 'success';
$err = '';

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf'] ?? '')) {
        $err = 'Session expirée. Réessayez.';
    } else {
        $action = $_POST['action'] ?? '';
        switch ($action) {
            case 'create_client':
                $name  = trim($_POST['name'] ?? '');
                $uris  = array_values(array_filter(array_map('trim', preg_split('/\r\n|\r|\n/', $_POST['redirect_uris'] ?? '')), fn($u) => $u !== ''));
                $platform = in_array($_POST['platform'] ?? '', ['django', 'flutter', 'service'], true) ? $_POST['platform'] : 'django';
                $isPublic = $platform === 'flutter';
                $grants = $platform === 'service' ? 'client_credentials' : 'authorization_code';
                $scope = trim($_POST['scope'] ?? ($platform === 'service' ? 'profile' : 'openid profile email'));
                $allowedScopes = ['openid', 'profile', 'email'];
                $scopes = array_values(array_unique(array_filter(explode(' ', $scope))));
                $scopeValid = $scopes !== [] && !array_diff($scopes, $allowedScopes)
                    && ($platform === 'service' || in_array('openid', $scopes, true));
                $redirectsValid = $platform === 'service';
                if ($platform !== 'service' && $uris) {
                    $redirectsValid = true;
                    foreach ($uris as $uri) {
                        $parts = parse_url($uri);
                        $scheme = strtolower((string) ($parts['scheme'] ?? ''));
                        $host = strtolower((string) ($parts['host'] ?? ''));
                        $localHttp = $scheme === 'http' && in_array($host, ['localhost', '127.0.0.1', '::1'], true);
                        $validWebUri = in_array($scheme, ['http', 'https'], true) && $host !== ''
                            && ($scheme === 'https' || $localHttp);
                        $validMobileUri = preg_match('/^[a-z][a-z0-9+.-]*$/', $scheme) === 1
                            && !in_array($scheme, ['http', 'https', 'javascript', 'data'], true)
                            && $host !== '';
                        if (!$parts || isset($parts['user']) || isset($parts['pass']) || isset($parts['fragment'])
                            || ($isPublic ? !$validMobileUri : !$validWebUri)) {
                            $redirectsValid = false;
                            break;
                        }
                    }
                }
                if ($name === '' || !$redirectsValid) {
                    $err = $platform === 'service'
                        ? 'Saisissez un nom de client valide.'
                        : ($isPublic
                            ? 'Saisissez une URI mobile valide, par exemple gestionpartenaires://callback.'
                            : 'Saisissez au moins une URI HTTPS valide (HTTP est accepté uniquement sur localhost).');
                } elseif (!$scopeValid) {
                    $err = 'Scopes non valides. Utilisez openid, profile et/ou email; openid est requis pour une application utilisateur.';
                } else {
                    $clientId = 'iam.' . bin2hex(random_bytes(8));
                    $secret = $isPublic ? null : bin2hex(random_bytes(32));
                    $db->prepare('INSERT INTO oauth_clients (client_id, client_secret_hash, name, redirect_uris, grant_types, scope, active) VALUES (?, ?, ?, ?, ?, ?, 1)')
                       ->execute([$clientId, $secret !== null ? password_hash($secret, PASSWORD_BCRYPT) : null, $name, json_encode($uris, JSON_UNESCAPED_UNICODE), $grants, implode(' ', $scopes)]);
                    $_SESSION['iam_oauth_setup_once'] = [
                        'name' => $name,
                        'platform' => $platform,
                        'client_id' => $clientId,
                        'secret' => $secret,
                        'redirect_uris' => $uris,
                        'scope' => implode(' ', $scopes),
                    ];
                    iam_audit('oauth_client_created', "Client OAuth créé ($platform): $name", $iamAdmin['id'], $iamAdmin['email'], $_SERVER['REMOTE_ADDR'] ?? '', $_SERVER['HTTP_USER_AGENT'] ?? '');
                    $msg = $isPublic
                        ? "Client Flutter public créé : $clientId. Aucun secret n'est émis; PKCE S256 est obligatoire."
                        : ($platform === 'service' ? "Client service créé : $clientId." : "Client Django créé : $clientId. Copiez le secret affiché ci-dessous maintenant.");
                }
                break;

            case 'toggle_client':
                $db->prepare('UPDATE oauth_clients SET active = IF(active=1,0,1) WHERE id = ?')->execute([(int) ($_POST['id'] ?? 0)]);
                $msg = 'Client mis à jour.';
                break;

            case 'delete_client':
                $db->prepare('DELETE FROM oauth_clients WHERE id = ?')->execute([(int) ($_POST['id'] ?? 0)]);
                $msg = 'Client supprimé.';
                break;

            case 'rotate_key':
                iam_oauth_rotate_key();
                iam_audit('oauth_key_rotated', 'Rotation de la clé de signature OIDC', $iamAdmin['id'], $iamAdmin['email'], $_SERVER['REMOTE_ADDR'] ?? '', $_SERVER['HTTP_USER_AGENT'] ?? '');
                $msg = 'Clé de signature OIDC remplacée (les anciens jetons restent valides jusqu’à expiration).';
                break;
        }
    }
}

$clients = $db->query('SELECT * FROM oauth_clients ORDER BY name')->fetchAll();
$keys = $db->query('SELECT kid, alg, active, created_at FROM oauth_keys ORDER BY id DESC')->fetchAll();
if (!empty($_SESSION['iam_oauth_setup_once'])) {
    header('Cache-Control: no-store, private');
}

$pageTitle = 'OAuth 2.0 / OIDC';
$active = 'oauth';
include __DIR__ . '/_header.php';
?>
<?php if ($err): ?><div class="alert alert-danger"><?php echo htmlspecialchars($err); ?></div><?php endif; ?>
<?php if ($msg): ?><div class="alert alert-success"><?php echo htmlspecialchars($msg); ?></div><?php endif; ?>

<?php
$freshSetup = $_SESSION['iam_oauth_setup_once'] ?? null;
unset($_SESSION['iam_oauth_setup_once']);
if (is_array($freshSetup) && !empty($freshSetup['client_id'])):
    $platformLabel = ['django' => 'Django / serveur web', 'flutter' => 'Flutter mobile', 'service' => 'Service API'][ $freshSetup['platform'] ] ?? 'OIDC';
?>
    <div class="card" style="border-left:4px solid var(--primary);">
        <div class="card-body">
            <div class="card-title">Configuration prête — <?php echo htmlspecialchars($freshSetup['name']); ?></div>
            <p class="text-muted">Renseignez ces paramètres dans le connecteur OIDC de votre application.</p>
            <dl style="display:grid; grid-template-columns:minmax(130px, 190px) minmax(0, 1fr); gap:8px 16px; margin:0;">
                <dt>Plateforme</dt><dd style="margin:0;"><?php echo htmlspecialchars($platformLabel); ?></dd>
                <dt>Issuer</dt><dd class="mono" style="margin:0; overflow-wrap:anywhere;"><?php echo htmlspecialchars(IAM_BASE_URL); ?></dd>
                <dt>Découverte OIDC</dt><dd class="mono" style="margin:0; overflow-wrap:anywhere;"><?php echo htmlspecialchars(IAM_BASE_URL); ?>/.well-known/openid-configuration.php</dd>
                <dt>Client ID</dt><dd class="mono" style="margin:0; overflow-wrap:anywhere;"><?php echo htmlspecialchars($freshSetup['client_id']); ?></dd>
                <?php if (!empty($freshSetup['secret'])): ?>
                    <dt>Client secret</dt><dd class="mono" style="margin:0; overflow-wrap:anywhere;"><strong><?php echo htmlspecialchars($freshSetup['secret']); ?></strong><br><small>Affiché une seule fois. Stockez-le dans la configuration serveur, jamais dans le navigateur.</small></dd>
                <?php else: ?>
                    <dt>Client secret</dt><dd style="margin:0;">Aucun (client public)</dd>
                <?php endif; ?>
                <dt>URI de redirection</dt><dd class="mono" style="margin:0; overflow-wrap:anywhere;"><?php echo htmlspecialchars(implode(', ', $freshSetup['redirect_uris'])); ?></dd>
                <dt>Scopes</dt><dd class="mono" style="margin:0;"><?php echo htmlspecialchars($freshSetup['scope']); ?></dd>
                <?php if ($freshSetup['platform'] === 'flutter'): ?>
                    <dt>Sécurité mobile</dt><dd style="margin:0;">PKCE S256 obligatoire; aucun secret à intégrer à l’application.</dd>
                <?php endif; ?>
            </dl>
        </div>
    </div>
<?php endif; ?>

<div class="card">
    <div class="card-body">
        <div class="d-flex justify-between align-center mb-3">
            <div class="card-title">Clients OAuth (« applications tierces »)</div>
            <button class="btn btn-primary" onclick="document.getElementById('clientModal').style.display='block'"><i class="fas fa-plus"></i> Nouveau client</button>
        </div>
        <div class="table-wrap">
            <table class="table">
                <tr><th>Nom</th><th>Type</th><th>client_id</th><th>URI de redirection</th><th>Flux</th><th>Statut</th><th>Actions</th></tr>
                <?php if (empty($clients)): ?>
                    <tr><td colspan="7" class="text-center text-muted">Aucun client OAuth. Créez-en un pour configurer la connexion OIDC d’une application.</td></tr>
                <?php else: foreach ($clients as $c): ?>
                    <tr>
                        <td><strong><?php echo htmlspecialchars($c['name']); ?></strong></td>
                        <td><span class="badge badge-<?php echo empty($c['client_secret_hash']) ? 'warning' : 'info'; ?>"><?php echo empty($c['client_secret_hash']) ? 'Public · PKCE' : 'Serveur · secret'; ?></span></td>
                        <td><code><?php echo htmlspecialchars($c['client_id']); ?></code></td>
                        <td style="max-width:320px;"><?php echo nl2br(htmlspecialchars(implode("\n", json_decode($c['redirect_uris'] ?? '[]', true) ?: []))); ?></td>
                        <td><small><?php echo htmlspecialchars($c['grant_types']); ?></small></td>
                        <td><span class="badge badge-<?php echo (int) $c['active'] === 1 ? 'success' : 'muted'; ?>"><?php echo (int) $c['active'] === 1 ? 'actif' : 'inactif'; ?></span></td>
                        <td>
                            <form method="POST" style="display:inline;">
                                <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                                <input type="hidden" name="action" value="toggle_client">
                                <input type="hidden" name="id" value="<?php echo (int) $c['id']; ?>">
                                <button class="btn btn-outline btn-sm"><?php echo (int) $c['active'] === 1 ? '<i class="fas fa-pause"></i> Désactiver' : '<i class="fas fa-play"></i> Activer'; ?></button>
                            </form>
                            <form method="POST" style="display:inline;" onsubmit="return confirm('Supprimer ce client OAuth ?');">
                                <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                                <input type="hidden" name="action" value="delete_client">
                                <input type="hidden" name="id" value="<?php echo (int) $c['id']; ?>">
                                <button class="btn btn-danger btn-sm"><i class="fas fa-trash"></i> Supprimer</button>
                            </form>
                        </td>
                    </tr>
                <?php endforeach; endif; ?>
            </table>
        </div>
    </div>
</div>

<div class="card mt-3">
    <div class="card-body">
        <div class="d-flex justify-between align-center">
            <div class="card-title">Clés de signature OIDC (JWKS)</div>
            <form method="POST" onsubmit="return confirm('Remplacer la clé de signature ? Les anciens jetons restent validables jusqu’à expiration.');">
                <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                <input type="hidden" name="action" value="rotate_key">
                <button class="btn btn-outline btn-sm"><i class="fas fa-rotate"></i> Rotation de clé</button>
            </form>
        </div>
        <table class="table mt-2">
            <tr><th>kid</th><th>Algorithme</th><th>Statut</th><th>Créée le</th></tr>
            <?php foreach ($keys as $k): ?>
                <tr>
                    <td><code><?php echo htmlspecialchars($k['kid']); ?></code></td>
                    <td><?php echo htmlspecialchars($k['alg']); ?></td>
                    <td><span class="badge badge-<?php echo (int) $k['active'] === 1 ? 'success' : 'muted'; ?>"><?php echo (int) $k['active'] === 1 ? 'active (signature)' : 'ancienne (validation)'; ?></span></td>
                    <td><?php echo htmlspecialchars($k['created_at']); ?></td>
                </tr>
            <?php endforeach; ?>
        </table>
        <p class="text-muted" style="margin-bottom:0;">Découverte OIDC : <code><?php echo htmlspecialchars(IAM_BASE_URL); ?>/.well-known/openid-configuration.php</code> — Les applications Flutter utilisent un client public sans secret; les applications serveur gardent leur secret uniquement côté serveur.</p>
    </div>
</div>

<div id="clientModal" style="display:none; position:fixed; inset:0; background:rgba(15,23,42,.55); z-index:1000;" onclick="if(event.target===this)this.style.display='none';">
    <div style="width:min(100% - 24px, 620px); max-height:calc(100vh - 32px); overflow:auto; margin:16px auto; background:#fff; border-radius:10px; padding:clamp(16px, 4vw, 26px);">
        <h3 style="margin-top:0;">Configurer une application</h3>
        <form method="POST">
            <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
            <input type="hidden" name="action" value="create_client">
            <div class="form-group">
                <label for="oauthPlatform">Plateforme</label>
                <select id="oauthPlatform" name="platform" class="form-control">
                    <option value="django" selected>Django ou autre serveur web</option>
                    <option value="flutter">Flutter mobile</option>
                    <option value="service">Service API sans utilisateur</option>
                </select>
                <small id="oauthPlatformHelp" class="text-muted">Client confidentiel : le secret reste sur le serveur Django. Flux Authorization Code + PKCE.</small>
            </div>
            <div class="form-group"><label for="oauthClientName">Nom de l’application *</label><input id="oauthClientName" type="text" name="name" class="form-control" required placeholder="ex. Gestion Partenaires"></div>
            <div class="form-group" id="oauthRedirectGroup">
                <label for="oauthRedirectUris">URI de redirection (une par ligne) *</label>
                <textarea id="oauthRedirectUris" name="redirect_uris" class="form-control" rows="2" required placeholder="http://localhost:8000/oidc/callback/">http://localhost:8000/oidc/callback/</textarea>
                <small id="oauthRedirectHelp" class="text-muted">Elle doit correspondre exactement à la route callback configurée dans l’application. HTTP est accepté uniquement sur localhost.</small>
            </div>
            <div class="form-group">
                <label for="oauthScopes">Scopes</label>
                <input id="oauthScopes" type="text" name="scope" class="form-control" value="openid profile email">
                <small class="text-muted">Les scopes déterminent les informations de profil autorisées.</small>
            </div>
            <div id="oauthSecurityNote" class="alert alert-info" style="margin-top:12px;">
                Le secret serveur sera affiché une seule fois après la création.
            </div>
            <div class="d-flex gap-2" style="flex-wrap:wrap;">
                <button type="submit" class="btn btn-primary"><i class="fas fa-wand-magic-sparkles"></i> Créer la configuration</button>
                <button type="button" class="btn btn-outline" onclick="document.getElementById('clientModal').style.display='none';">Annuler</button>
            </div>
        </form>
    </div>
</div>
<script>
(() => {
    const platform = document.getElementById('oauthPlatform');
    const redirectGroup = document.getElementById('oauthRedirectGroup');
    const redirectUris = document.getElementById('oauthRedirectUris');
    const redirectHelp = document.getElementById('oauthRedirectHelp');
    const scopes = document.getElementById('oauthScopes');
    const help = document.getElementById('oauthPlatformHelp');
    const securityNote = document.getElementById('oauthSecurityNote');
    let redirectEdited = false;
    redirectUris.addEventListener('input', () => { redirectEdited = true; });

    function updatePlatform() {
        if (platform.value === 'flutter') {
            help.textContent = 'Client public : aucun secret n’est créé. L’échange du code exige PKCE S256.';
            redirectUris.placeholder = 'gestionpartenaires://callback';
            redirectHelp.textContent = 'Utilisez le schéma déclaré dans l’application Flutter et le même callback dans son plugin OIDC.';
            securityNote.textContent = 'Aucun secret ne sera généré ni intégré à l’application mobile.';
            scopes.value = 'openid profile email';
            redirectGroup.hidden = false;
            redirectUris.required = true;
            if (!redirectEdited) redirectUris.value = 'gestionpartenaires://callback';
        } else if (platform.value === 'service') {
            help.textContent = 'Client confidentiel pour un service serveur-à-serveur; aucune connexion utilisateur ni callback.';
            redirectGroup.hidden = true;
            redirectUris.required = false;
            redirectUris.value = '';
            securityNote.textContent = 'Le secret serveur sera affiché une seule fois. Ne le placez jamais dans un client navigateur.';
            scopes.value = 'profile';
        } else {
            help.textContent = 'Client confidentiel : le secret reste sur le serveur Django. Flux Authorization Code + PKCE.';
            redirectUris.placeholder = 'http://localhost:8000/oidc/callback/';
            redirectHelp.textContent = 'Elle doit correspondre exactement à la route callback configurée dans l’application. HTTP est accepté uniquement sur localhost.';
            securityNote.textContent = 'Le secret serveur sera affiché une seule fois après la création.';
            redirectGroup.hidden = false;
            redirectUris.required = true;
            if (!redirectEdited || redirectUris.value === 'gestionpartenaires://callback') {
                redirectUris.value = 'http://localhost:8000/oidc/callback/';
                redirectEdited = false;
            }
            scopes.value = 'openid profile email';
        }
    }

    platform.addEventListener('change', updatePlatform);
    updatePlatform();
})();
</script>
<?php include __DIR__ . '/_footer.php'; ?>