<?php
require_once __DIR__ . '/_guard.php';
require_once __DIR__ . '/_sso_generator.php';

$db  = db();
iam_ensure_app_bridge_column($db);
iam_ensure_roles_application_column($db);

function iam_bridge_config_from_post(): array
{
    $map = [];
    $matchIam = $_POST['bridge_match_iam'] ?? 'username';
    foreach (preg_split('/\r\n|\r|\n/', (string) ($_POST['bridge_role_map'] ?? '')) as $line) {
        $line = trim($line);
        if ($line === '' || strpos($line, '=') === false) continue;
        [$k, $v] = explode('=', $line, 2);
        $map[trim($k)] = trim($v);
    }
    return [
        'enabled'      => isset($_POST['bridge_enabled']),
        'db_host'      => trim($_POST['bridge_db_host'] ?? 'localhost'),
        'db_port'      => trim($_POST['bridge_db_port'] ?? '3306'),
        'db_name'      => trim($_POST['bridge_db_name'] ?? ''),
        'db_user'      => trim($_POST['bridge_db_user'] ?? 'root'),
        'db_pass'      => (string) ($_POST['bridge_db_pass'] ?? ''),
        'table'        => trim($_POST['bridge_table'] ?? ''),
        'match_iam'    => in_array($matchIam, ['username', 'email', 'matricule'], true) ? $matchIam : 'username',
        'match_local'  => trim($_POST['bridge_match_local'] ?? ''),
        'key_id'       => trim($_POST['bridge_key_id'] ?? 'id'),
        'key_login'    => trim($_POST['bridge_key_login'] ?? ''),
        'key_nom'      => trim($_POST['bridge_key_nom'] ?? ''),
        'key_role'     => trim($_POST['bridge_key_role'] ?? ''),
        'role_source'  => ($_POST['bridge_role_source'] ?? 'local') === 'map' ? 'map' : 'local',
        'role_default' => trim($_POST['bridge_role_default'] ?? ''),
        'role_map'     => $map,
        'auto_create'  => isset($_POST['bridge_auto_create']),
        'create_role'  => trim($_POST['bridge_create_role'] ?? ''),
        'create_status'=> trim($_POST['bridge_create_status'] ?? ''),
        'create_pwd_col'   => trim($_POST['bridge_create_pwd_col'] ?? ''),
        'create_status_col'=> trim($_POST['bridge_create_status_col'] ?? ''),
    ];
}

/**
 * Retire l'intégration SSO déployée dans le dossier local de l'application
 * (fichier garde + ligne auto_prepend_file du .htaccess).
 * Retourne true si un dossier local a été traité.
 */
function iam_remove_sso_files(array $app): bool
{
    $code = iam_app_code_slug($app['code'] ?? 'app');
    $localPath = iam_local_path_from_url((string) ($app['url'] ?? ''), (string) ($_SERVER['DOCUMENT_ROOT'] ?? ''));
    if ($localPath === null || !is_dir($localPath)) {
        return false;
    }
    @unlink($localPath . '/iam-sso-' . $code . '.php');

    $htPath = $localPath . '/.htaccess';
    if (is_file($htPath)) {
        $ht = (string) @file_get_contents($htPath);
        $ht = preg_replace(
            '#<IfModule\s+[^>]+>\s*php_value auto_prepend_file "[^"]*iam-sso-' . preg_quote($code, '#') . '\.php"\s*</IfModule>\s*#i',
            '',
            $ht
        );
        $ht = preg_replace('/^#.*IAM-Local.*\R?/mi', '', (string) $ht);
        $ht = preg_replace('/^#\s*Ne pas supprimer.*\R?/mi', '', (string) $ht);
        $ht = trim((string) $ht);
        if ($ht === '') {
            @unlink($htPath);
        } else {
            @file_put_contents($htPath, $ht . "\n");
        }
    }
    return true;
}

$msg = '';
$err = '';
$type = 'success';
$deployResult = null;
$iamAdmin = $GLOBALS['iam_admin'] ?? [];
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf'] ?? '')) {
        $err = 'Session expirée.';
    } else {
        $action = $_POST['action'] ?? '';
        switch ($action) {
            case 'create':
                $code = iam_app_code_slug((string) ($_POST['code'] ?? ''));
                $name = trim($_POST['name'] ?? '');
                $url  = trim($_POST['url'] ?? '');
                $preflight = iam_app_preflight($db, $code, $name, $url);
                if (!$preflight['ready']) {
                    foreach ($preflight['checks'] as $check) {
                        if ($check['status'] === 'error') {
                            $err = $check['detail'];
                            break;
                        }
                    }
                    break;
                }
                $redirectUri = '';
                $clientSecret = bin2hex(random_bytes(16));
                $bridge = iam_bridge_config_from_post();
                if ($bridge['enabled'] && ($bridge['db_name'] === '' || $bridge['table'] === '' || $bridge['match_local'] === '')) {
                    $err = 'Pont de session locale : base, table et colonne de correspondance obligatoires.';
                    break;
                }
                $bridgeJson = $bridge['enabled'] ? json_encode($bridge, JSON_UNESCAPED_UNICODE) : null;
                $stmt = $db->prepare('INSERT INTO applications (code, name, description, url, color, icon, active, sso_prompt, redirect_uri, client_id, client_secret, bridge_config) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)');
                $stmt->execute([
                    $code, $name, trim($_POST['description'] ?? ''), $url,
                    trim($_POST['color'] ?? '#4361ee'),
                    trim($_POST['icon'] ?? 'fa-cube'),
                    isset($_POST['active']) ? 1 : 0,
                    isset($_POST['sso_prompt']) ? 1 : 0,
                    $redirectUri,
                    'iam-native-' . $code,
                    $clientSecret,
                    $bridgeJson,
                ]);
                $appId = (int) $db->lastInsertId();
                iam_audit('app_created', "Application créée: $name", $iamAdmin['id'], $iamAdmin['email'], $_SERVER['REMOTE_ADDR'] ?? '', $_SERVER['HTTP_USER_AGENT'] ?? '');

                // Déploiement automatique de l'intégration SSO (accès via lien direct)
                $appsList = $db->query('SELECT * FROM applications WHERE id = ' . $appId)->fetch();
                if ($appsList && !empty($appsList['url'])) {
                    $deployResult = iam_deploy_sso($appsList);
                    $msg = 'Application créée. ' . ($deployResult['message'] ?? '');
                    if ($deployResult['status'] !== 'deployed' && $deployResult['status'] !== 'not_local') {
                        $type = 'warning';
                    }
                } else {
                    $msg = 'Application créée.';
                }
                break;

            case 'update':
                $id = (int) ($_POST['id'] ?? 0);
                $bridge = iam_bridge_config_from_post();
                if ($bridge['enabled'] && ($bridge['db_name'] === '' || $bridge['table'] === '' || $bridge['match_local'] === '')) {
                    $err = 'Pont de session locale : base, table et colonne de correspondance obligatoires.';
                    break;
                }
                $bridgeJson = $bridge['enabled'] ? json_encode($bridge, JSON_UNESCAPED_UNICODE) : null;
                $db->prepare('UPDATE applications SET name=?, description=?, url=?, color=?, icon=?, active=?, sso_prompt=?, bridge_config=? WHERE id=?')
                   ->execute([
                       trim($_POST['name'] ?? ''), trim($_POST['description'] ?? ''), trim($_POST['url'] ?? ''),
                       trim($_POST['color'] ?? '#4361ee'), trim($_POST['icon'] ?? 'fa-cube'),
                       isset($_POST['active']) ? 1 : 0,
                       isset($_POST['sso_prompt']) ? 1 : 0,
                       $bridgeJson, $id,
                   ]);
                iam_audit('app_updated', "Application modifiée", $iamAdmin['id'], $iamAdmin['email'], $_SERVER['REMOTE_ADDR'] ?? '', $_SERVER['HTTP_USER_AGENT'] ?? '');
                $msg = 'Application mise à jour.';

                // Redéployer l'intégration SSO si l'URL a changé
                $stmt = $db->prepare('SELECT * FROM applications WHERE id = ?');
                $stmt->execute([$id]);
                $appsList = $stmt->fetch();
                if ($appsList && !empty($appsList['url'])) {
                    $deployResult = iam_deploy_sso($appsList);
                    if (($deployResult['status'] ?? '') !== 'deployed') {
                        $msg .= ' ' . ($deployResult['message'] ?? '');
                    }
                }
                break;

            case 'deploy_sso':
                $id = (int) ($_POST['id'] ?? 0);
                $stmt = $db->prepare('SELECT * FROM applications WHERE id = ?');
                $stmt->execute([$id]);
                $appsList = $stmt->fetch();
                if (!$appsList) { $err = 'Application introuvable.'; break; }
                $deployResult = iam_deploy_sso($appsList);
                $msg = $deployResult['message'] ?? '';
                if ($deployResult['status'] !== 'deployed') { $type = 'warning'; }
                iam_audit('sso_deploy', "Intégration SSO régénérée pour: {$appsList['code']}", $iamAdmin['id'], $iamAdmin['email'], $_SERVER['REMOTE_ADDR'] ?? '', $_SERVER['HTTP_USER_AGENT'] ?? '');
                break;

            case 'remove_sso':
                $id = (int) ($_POST['id'] ?? 0);
                $stmt = $db->prepare('SELECT * FROM applications WHERE id = ?');
                $stmt->execute([$id]);
                $appsList = $stmt->fetch();
                if ($appsList) {
                    if (iam_remove_sso_files($appsList)) {
                        $msg = 'Intégration SSO retirée du dossier de l\'application.';
                        iam_audit('sso_removed', "Intégration SSO retirée pour: {$appsList['code']}", $iamAdmin['id'], $iamAdmin['email'], $_SERVER['REMOTE_ADDR'] ?? '', $_SERVER['HTTP_USER_AGENT'] ?? '');
                    } else {
                        $err = 'Application non locale : rien à retirer ici.';
                    }
                } else {
                    $err = 'Application introuvable.';
                }
                break;

            case 'delete':
                $id = (int) ($_POST['id'] ?? 0);
                $stmt = $db->prepare('SELECT * FROM applications WHERE id = ?');
                $stmt->execute([$id]);
                $delApp = $stmt->fetch();
                if (!$delApp) {
                    $err = 'Application introuvable.';
                } elseif ((int) $delApp['is_system'] > 0) {
                    // Ne pas supprimer les applications système (is_system = 1)
                    $err = 'Cette application système ne peut pas être supprimée.';
                } else {
                    // Retirer l'intégration SSO déployée dans le dossier local
                    iam_remove_sso_files($delApp);
                    $db->prepare('DELETE FROM applications WHERE id = ?')->execute([$id]);
                    iam_audit('app_deleted', "Application supprimée: {$delApp['code']}", $iamAdmin['id'], $iamAdmin['email'], $_SERVER['REMOTE_ADDR'] ?? '', $_SERVER['HTTP_USER_AGENT'] ?? '');
                    $msg = 'Application supprimée (intégration SSO retirée).';
                }
                break;

            case 'add_permission':
                $appId  = (int) ($_POST['application_id'] ?? 0);
                $name   = trim($_POST['name'] ?? '');
                $code   = strtolower(trim(preg_replace('/[^a-zA-Z0-9_]+/', '.', $_POST['code'] ?? '')));
                $desc   = trim($_POST['description'] ?? '');
                if ($appId <= 0 || $name === '' || $code === '') { $err = 'Application, nom et code obligatoires.'; break; }
                $dup = $db->prepare('SELECT COUNT(*) FROM permissions WHERE code = ?');
                $dup->execute([$code]);
                if ((int) $dup->fetchColumn() > 0) {
                    $err = 'Ce code de permission existe déjà. Les codes sont uniques dans toute la plateforme.';
                } else {
                    $db->prepare('INSERT INTO permissions (application_id, name, code, description) VALUES (?, ?, ?, ?)')->execute([$appId, $name, $code, $desc]);
                    iam_audit('permission_created', "Permission créée: $code", $iamAdmin['id'], $iamAdmin['email'], $_SERVER['REMOTE_ADDR'] ?? '', $_SERVER['HTTP_USER_AGENT'] ?? '');
                    $msg = 'Permission créée.';
                }
                break;

            case 'update_permission':
                $pid  = (int) ($_POST['id'] ?? 0);
                $name = trim($_POST['name'] ?? '');
                $code = strtolower(trim(preg_replace('/[^a-zA-Z0-9_]+/', '.', $_POST['code'] ?? '')));
                $desc = trim($_POST['description'] ?? '');
                if ($pid <= 0 || $name === '' || $code === '') { $err = 'Nom et code de permission obligatoires.'; break; }
                $dup = $db->prepare('SELECT COUNT(*) FROM permissions WHERE code = ? AND id <> ?');
                $dup->execute([$code, $pid]);
                if ((int) $dup->fetchColumn() > 0) {
                    $err = 'Ce code de permission existe déjà. Les codes sont uniques dans toute la plateforme.';
                    break;
                }
                $db->prepare('UPDATE permissions SET name = ?, code = ?, description = ? WHERE id = ?')->execute([$name, $code, $desc, $pid]);
                iam_audit('permission_updated', "Permission modifiée: $code", $iamAdmin['id'], $iamAdmin['email'], $_SERVER['REMOTE_ADDR'] ?? '', $_SERVER['HTTP_USER_AGENT'] ?? '');
                $msg = 'Permission mise à jour. Pensez à répercuter tout changement de code dans l’application concernée.';
                break;

            case 'update_permission':
                $pid  = (int) ($_POST['id'] ?? 0);
                $name = trim($_POST['name'] ?? '');
                $code = strtolower(trim(preg_replace('/[^a-zA-Z0-9_]+/', '.', $_POST['code'] ?? '')));
                $desc = trim($_POST['description'] ?? '');
                if ($pid <= 0 || $name === '' || $code === '') { $err = 'Nom et code de permission obligatoires.'; break; }
                $owner = $db->prepare('SELECT application_id FROM permissions WHERE id = ?');
                $owner->execute([$pid]);
                if ($owner->fetchColumn() === false) { $err = 'Permission introuvable.'; break; }
                $dup = $db->prepare('SELECT COUNT(*) FROM permissions WHERE code = ? AND id <> ?');
                $dup->execute([$code, $pid]);
                if ((int) $dup->fetchColumn() > 0) {
                    $err = 'Ce code de permission existe déjà. Les codes sont uniques dans toute la plateforme.';
                    break;
                }
                $db->prepare('UPDATE permissions SET name = ?, code = ?, description = ? WHERE id = ?')
                   ->execute([$name, $code, $desc, $pid]);
                iam_audit('permission_updated', "Permission modifiée: $code", $iamAdmin['id'], $iamAdmin['email'], $_SERVER['REMOTE_ADDR'] ?? '', $_SERVER['HTTP_USER_AGENT'] ?? '');
                $msg = 'Permission mise à jour. Si le code a changé, répercutez-le dans le code de l’application.';
                break;

            case 'add_access':
                $appId  = (int) ($_POST['application_id'] ?? 0);
                $userId = (int) ($_POST['user_id'] ?? 0);
                $roleId = (int) ($_POST['role_id'] ?? 0);
                if ($appId <= 0 || $userId <= 0 || $roleId <= 0) { $err = 'Application, utilisateur et rôle obligatoires.'; break; }
                if (!iam_role_allowed_for_app($roleId, $appId)) { $err = 'Ce rôle n\'appartient pas à cette application.'; break; }
                $db->prepare('DELETE FROM user_roles WHERE user_id = ? AND application_id = ?')->execute([$userId, $appId]);
                $db->prepare('INSERT INTO user_roles (user_id, role_id, application_id) VALUES (?, ?, ?)')->execute([$userId, $roleId, $appId]);
                iam_audit('app_access_granted', "Accès accordé à l'utilisateur #$userId (app #$appId, rôle #$roleId)", $iamAdmin['id'], $iamAdmin['email'], $_SERVER['REMOTE_ADDR'] ?? '', $_SERVER['HTTP_USER_AGENT'] ?? '');
                $msg = 'Accès ajouté / mis à jour.';
                break;

            case 'remove_access':
                $appId  = (int) ($_POST['application_id'] ?? 0);
                $userId = (int) ($_POST['user_id'] ?? 0);
                if ($appId <= 0 || $userId <= 0) { $err = 'Application et utilisateur obligatoires.'; break; }
                $db->prepare('DELETE FROM user_roles WHERE user_id = ? AND application_id = ?')->execute([$userId, $appId]);
                iam_audit('app_access_removed', "Accès retiré à l'utilisateur #$userId (app #$appId)", $iamAdmin['id'], $iamAdmin['email'], $_SERVER['REMOTE_ADDR'] ?? '', $_SERVER['HTTP_USER_AGENT'] ?? '');
                $msg = 'Accès retiré.';
                break;

            case 'delete_permission':
                $pid = (int) ($_POST['id'] ?? 0);
                $db->prepare('DELETE FROM permissions WHERE id = ?')->execute([$pid]);
                $msg = 'Permission supprimée.';
                break;
        }
    }
}

$appSortOptions = iam_app_sort_options('applications');
$appSort = iam_list_sort('admin_apps', $appSortOptions, 'nom');
$apps  = $db->query('SELECT * FROM applications ORDER BY ' . $appSortOptions[$appSort][1])->fetchAll();
$perms = $db->query('SELECT p.*, a.name AS app_name FROM permissions p INNER JOIN applications a ON a.id = p.application_id ORDER BY a.name, p.name')->fetchAll();
$permsByApp = [];
foreach ($perms as $p) $permsByApp[$p['application_id']][] = $p;

$activeUsers  = $db->query('SELECT id, first_name, last_name, email FROM users WHERE status = \'active\' ORDER BY last_name')->fetchAll();
$appUsers = [];
$stmt = $db->query('SELECT ur.application_id, u.id AS user_id, u.first_name, u.last_name, u.email, r.id AS role_id, r.name AS role_name
    FROM user_roles ur
    INNER JOIN users u ON u.id = ur.user_id
    INNER JOIN roles r ON r.id = ur.role_id
    ORDER BY u.last_name');
foreach ($stmt->fetchAll() as $row) {
    $appUsers[(int) $row['application_id']][] = $row;
}

$pageTitle = 'Applications';
$active = 'apps';
include __DIR__ . '/_header.php';
?>

<?php
// Calcul du statut de déploiement SSO pour chaque application
function sso_deploy_state(array $app): array
{
    $code = iam_app_code_slug($app['code']);
    $docRoot = $_SERVER['DOCUMENT_ROOT'] ?? '';
    $localPath = iam_local_path_from_url((string) ($app['url'] ?? ''), (string) $docRoot);
    $guardFile = 'iam-sso-' . $code . '.php';

    if (!$localPath) {
        return ['state' => 'remote', 'label' => 'Déploiement manuel', 'class' => 'badge-warning', 'guard_file' => $guardFile, 'path' => null];
    }
    if (!is_dir($localPath)) {
        return ['state' => 'missing', 'label' => 'Dossier introuvable', 'class' => 'badge-muted', 'guard_file' => $guardFile, 'path' => $localPath];
    }

    $guardExists = is_file($localPath . '/' . $guardFile);
    $htProtected = false;
    $htPath = $localPath . '/.htaccess';
    $phpModule = iam_apache_php_module_name();
    if ($phpModule !== null && is_file($htPath)) {
        $ht = (string) @file_get_contents($htPath);
        $htProtected = preg_match(
            '#<IfModule\s+' . preg_quote($phpModule, '#') . '>\s*php_value auto_prepend_file "[^"]*' . preg_quote($guardFile, '#') . '"\s*</IfModule>#i',
            $ht
        ) === 1;
    }

    if ($guardExists && $htProtected) {
        return ['state' => 'deployed', 'label' => 'Active (lien direct protégé)', 'class' => 'badge-success', 'guard_file' => $guardFile, 'path' => $localPath];
    }
    if ($guardExists) {
        return ['state' => 'guard_only', 'label' => 'Fichier présent, .htaccess manquant', 'class' => 'badge-warning', 'guard_file' => $guardFile, 'path' => $localPath];
    }
    return ['state' => 'not_deployed', 'label' => 'Non déployée', 'class' => 'badge-muted', 'guard_file' => $guardFile, 'path' => $localPath];
}

/**
 * Champs du formulaire « Pont de session locale » (SSO → session interne de l'app).
 */
function iam_bridge_ui(array $cfg): void
{
    $r = static function ($k, $d = '') use ($cfg) {
        return htmlspecialchars((string) ($cfg[$k] ?? $d));
    };
    $mapText = '';
    foreach (($cfg['role_map'] ?? []) as $k => $v) {
        $mapText .= $k . ' = ' . $v . "\n";
    }
    // Identifiant unique par formulaire (plusieurs formulaires sur la même page)
    $seq = (int) ($GLOBALS['_iam_bridge_ui_seq'] ?? 0) + 1;
    $GLOBALS['_iam_bridge_ui_seq'] = $seq;
    $dl = 'iamdl' . $seq . '-';
    ?>
    <div class="form-group" style="border:1px solid var(--border); border-radius:10px; padding:12px; margin-bottom:14px; background:rgba(67,97,238,0.04);">
        <div style="font-size:13px; font-weight:600; margin-bottom:6px;">&#128269; Application qui a déjà sa propre connexion ?</div>
        <p style="font-size:12px; color:#64748b; margin:0 0 8px;">Renseignez l'accès à sa base puis cliquez sur « Détecter » : l'IAM remplit les champs ci-dessous automatiquement
        (colonnes trouvées dans la table) et affiche quels utilisateurs IAM feront sauter leur login interne.
        Cas le plus courant : <span class="mono">username IAM ↔ colonne login</span>, rôle depuis la colonne locale.</p>
        <div class="form-row" style="margin-bottom:8px;">
            <div class="form-group"><label>Hôte DB</label><input type="text" name="bridge_db_host" class="form-control" value="<?php echo $r('db_host', 'localhost'); ?>" placeholder="localhost"></div>
            <div class="form-group"><label>Port</label><input type="text" name="bridge_db_port" class="form-control" value="<?php echo $r('db_port', '3306'); ?>"></div>
            <div class="form-group" style="flex:1;"><label>Utilisateur DB</label><input type="text" name="bridge_db_user" class="form-control" value="<?php echo $r('db_user', 'root'); ?>"></div>
            <div class="form-group" style="flex:1;"><label>Mot de passe DB</label><input type="password" name="bridge_db_pass" class="form-control" value="<?php echo $r('db_pass'); ?>" autocomplete="new-password"></div>
        </div>
        <button type="button" class="btn btn-primary btn-sm" onclick="iamBridgeProbe(this)"><i class="fas fa-search"></i> Détecter la structure</button>
        <div class="probe-box" style="margin-top:8px; font-size:12px; min-height:0;"></div>
    </div>
    <div class="form-group" style="margin-top:8px;">
        <label style="display:flex; gap:6px; align-items:center;">
            <input type="checkbox" name="bridge_enabled" <?php echo !empty($cfg['enabled']) ? 'checked' : ''; ?>>
            Créer la session locale de l'application après authentification IAM
        </label>
        <small class="text-muted" style="font-size:12px;">Le garde SSO retrouve l'utilisateur dans la base de l'application et pose
        <span class="mono">user_id / user_login / user_nom / user_role</span> dans la session : la page de connexion propre à l'application est alors sautée.</small>
    </div>
    <div class="form-row">
        <div class="form-group"><label>Base (dbname) *</label><input type="text" name="bridge_db_name" class="form-control" list="<?php echo $dl; ?>dbn" value="<?php echo $r('db_name'); ?>" placeholder="ex : educongo"></div>
        <div class="form-group"><label>Table des utilisateurs *</label><input type="text" name="bridge_table" class="form-control" list="<?php echo $dl; ?>tbl" value="<?php echo $r('table'); ?>" placeholder="ex : utilisateurs"></div>
    </div>
    <div class="form-row">
        <div class="form-group">
            <label>Champ IAM de correspondance</label>
            <select name="bridge_match_iam" class="form-control">
                <?php foreach (['username' => 'username (IAM)', 'email' => 'email (IAM)', 'matricule' => 'matricule (IAM)'] as $mv => $ml): ?>
                    <option value="<?php echo $mv; ?>" <?php echo ($cfg['match_iam'] ?? 'username') === $mv ? 'selected' : ''; ?>><?php echo $ml; ?></option>
                <?php endforeach; ?>
            </select>
        </div>
        <div class="form-group"><label>Colonne de correspondance locale *</label><input type="text" name="bridge_match_local" class="form-control" list="<?php echo $dl; ?>col" value="<?php echo $r('match_local'); ?>" placeholder="ex : login"></div>
    </div>
    <div class="form-row">
        <div class="form-group"><label>Clé user_id (colonne locale)</label><input type="text" name="bridge_key_id" class="form-control" list="<?php echo $dl; ?>col" value="<?php echo $r('key_id', 'id'); ?>"></div>
        <div class="form-group"><label>Clé user_login (colonne locale)</label><input type="text" name="bridge_key_login" class="form-control" list="<?php echo $dl; ?>col" value="<?php echo $r('key_login'); ?>" placeholder="ex : login"></div>
        <div class="form-group"><label>Clé user_nom (colonne locale)</label><input type="text" name="bridge_key_nom" class="form-control" list="<?php echo $dl; ?>col" value="<?php echo $r('key_nom'); ?>" placeholder="ex : nom_complet"></div>
    </div>
    <div class="form-row">
        <div class="form-group">
            <label>Rôle local</label>
            <select name="bridge_role_source" class="form-control">
                <option value="local" <?php echo ($cfg['role_source'] ?? 'local') === 'local' ? 'selected' : ''; ?>>depuis la colonne locale</option>
                <option value="map" <?php echo ($cfg['role_source'] ?? 'local') === 'map' ? 'selected' : ''; ?>>depuis les rôles IAM (mapping)</option>
            </select>
        </div>
        <div class="form-group"><label>Colonne rôle locale (si « colonne locale »)</label><input type="text" name="bridge_key_role" class="form-control" list="<?php echo $dl; ?>col" value="<?php echo $r('key_role'); ?>" placeholder="ex : role"></div>
    </div>
    <div class="form-group">
        <label>Mapping rôles IAM → rôles locaux (une ligne « code = valeur »)</label>
        <textarea name="bridge_role_map" class="form-control" rows="3" placeholder="admin = administrateur&#10;direction = direction"><?php echo htmlspecialchars(rtrim($mapText)); ?></textarea>
    </div>
    <div class="form-group"><label>Rôle par défaut (si mapping sans correspondance)</label><input type="text" name="bridge_role_default" class="form-control" value="<?php echo $r('role_default'); ?>" placeholder="ex : agent"></div>
    <div class="form-group" style="margin-top:12px; border-top:1px dashed var(--border); padding-top:12px;">
        <label style="display:flex; gap:6px; align-items:center;">
            <input type="checkbox" name="bridge_auto_create" <?php echo !empty($cfg['auto_create']) ? 'checked' : ''; ?>>
            Créer automatiquement le compte local s'il manque
        </label>
        <small class="text-muted" style="font-size:12px;">Si le username IAM n'existe pas dans la table locale, il y est créé sur la volée (nom repris de l'IAM, mot de passe aléatoire → le formulaire de connexion interne de l'app ne pourra pas servir).</small>
        <div class="form-row" style="margin-top:8px;">
            <div class="form-group"><label>Rôle attribué au compte créé</label><input type="text" name="bridge_create_role" class="form-control" list="<?php echo $dl; ?>roles" value="<?php echo $r('create_role'); ?>" placeholder="ex : enseignant"></div>
            <div class="form-group"><label>Statut attribué</label><input type="text" name="bridge_create_status" class="form-control" list="<?php echo $dl; ?>sts" value="<?php echo $r('create_status', 'actif'); ?>" placeholder="ex : actif"></div>
        </div>
        <div class="form-row">
            <div class="form-group"><label>Colonne statut locale</label><input type="text" name="bridge_create_status_col" class="form-control" list="<?php echo $dl; ?>col" value="<?php echo $r('create_status_col', 'statut'); ?>" placeholder="ex : statut"></div>
            <div class="form-group"><label>Colonne mot de passe locale</label><input type="text" name="bridge_create_pwd_col" class="form-control" list="<?php echo $dl; ?>col" value="<?php echo $r('create_pwd_col', 'mot_de_passe'); ?>" placeholder="ex : mot_de_passe (vide = ignorer)"></div>
        </div>
    </div>
    <datalist id="<?php echo $dl; ?>dbn" data-bridge="db_name"></datalist>
    <datalist id="<?php echo $dl; ?>tbl" data-bridge="table"></datalist>
    <datalist id="<?php echo $dl; ?>col" data-bridge="cols"></datalist>
    <datalist id="<?php echo $dl; ?>roles" data-bridge="roles"></datalist>
    <datalist id="<?php echo $dl; ?>sts" data-bridge="statuses"></datalist>
    <p class="text-muted" style="font-size:12px;">&#9888;&#65039; Les identifiants DB renseignés seront embarqués dans le fichier garde <span class="mono">iam-sso-&lt;code&gt;.php</span> généré.</p>
    <?php
}
?>

<?php if ($err): ?><div class="alert alert-danger"><?php echo htmlspecialchars($err); ?></div><?php endif; ?>
<?php if ($msg): ?><div class="alert alert-<?php echo $type === 'warning' ? 'warning' : 'success'; ?>"><?php echo htmlspecialchars($msg); ?></div><?php endif; ?>

<div class="d-flex align-center mb-3" style="justify-content:space-between; gap:12px; flex-wrap:wrap;">
    <span class="text-muted"><?php echo count($apps); ?> application(s)</span>
    <?php echo iam_sort_select($appSortOptions, $appSort); ?>
</div>

<div class="cards-grid mb-3">
    <?php foreach ($apps as $a): ?>
        <?php $ssoState = sso_deploy_state($a); ?>
        <?php $applicationRoles = iam_app_roles((int) $a['id']); ?>
        <div class="card">
            <div class="card-body">
                <div class="d-flex align-center gap-2 mb-2">
                    <div class="app-icon" style="width:44px; height:44px; border-radius:10px; background:<?php echo htmlspecialchars($a['color'] ?: '#4361ee'); ?>; font-size:18px; display:flex; align-items:center; justify-content:center; color:#fff;">
                        <i class="fas <?php echo htmlspecialchars($a['icon'] ?: 'fa-cube'); ?>"></i>
                    </div>
                    <div>
                        <strong><?php echo htmlspecialchars($a['name']); ?></strong>
                        <div class="badge <?php echo $a['active'] ? 'badge-success' : 'badge-muted'; ?>"><?php echo $a['active'] ? 'active' : 'inactive'; ?></div>
                        <div class="badge <?php echo $ssoState['class']; ?>" style="margin-left:4px;"><i class="fas fa-link"></i> <?php echo $ssoState['label']; ?></div>
                    </div>
                </div>
                <p class="text-muted" style="font-size:13px;"><?php echo htmlspecialchars($a['description'] ?? ''); ?></p>
                <p class="text-muted" style="font-size:12px;"><i class="fas fa-link"></i> <?php echo htmlspecialchars($a['url']); ?></p>
                <div class="d-flex gap-2 flex-wrap">
                    <button class="btn btn-outline btn-sm" onclick="document.getElementById('editApp-<?php echo (int) $a['id']; ?>').style.display='block';">Modifier</button>
                    <button class="btn btn-outline btn-sm" onclick="document.getElementById('permsApp-<?php echo (int) $a['id']; ?>').style.display='block';">Permissions (<?php echo count($permsByApp[$a['id']] ?? []); ?>)</button>
                    <button class="btn btn-outline btn-sm" onclick="document.getElementById('accessApp-<?php echo (int) $a['id']; ?>').style.display='block';">Accès utilisateurs (<?php echo count($appUsers[$a['id']] ?? []); ?>)</button>
                    <button class="btn btn-outline btn-sm" onclick="document.getElementById('ssoApp-<?php echo (int) $a['id']; ?>').style.display='block';"><i class="fas fa-key"></i> Intégration SSO</button>
                    <?php if (!$a['is_system']): ?>
                        <form method="POST" onsubmit="return confirm('Supprimer ?');">
                            <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                            <input type="hidden" name="action" value="delete">
                            <input type="hidden" name="id" value="<?php echo (int) $a['id']; ?>">
                            <button class="btn btn-danger btn-sm"><i class="fas fa-trash"></i> Supprimer</button>
                        </form>
                    <?php endif; ?>
                </div>

                <!-- Intégration SSO -->
                <div id="ssoApp-<?php echo (int) $a['id']; ?>" style="display:none; margin-top:14px; border-top:1px solid var(--border); padding-top:14px;">
                    <div class="card-title">Intégration SSO automatique</div>
                    <p style="font-size:13px; color:#64748b;">
                        L'accès direct au lien de l'application (<span class="mono"><?php echo htmlspecialchars($a['url']); ?></span>)
                        redirige automatiquement vers l'IAM pour se connecter, puis ramène l'utilisateur sur la page demandée.
                    </p>
                    <table class="table">
                        <tr><th>Statut</th><td><span class="badge <?php echo $ssoState['class']; ?>"><?php echo $ssoState['label']; ?></span></td></tr>
                        <tr><th>Fichier généré</th><td><span class="mono"><?php echo htmlspecialchars($ssoState['guard_file']); ?></span></td></tr>
                        <?php if ($ssoState['path']): ?><tr><th>Dossier local</th><td><span class="mono"><?php echo htmlspecialchars($ssoState['path']); ?></span></td></tr><?php endif; ?>
                    </table>
                    <div class="d-flex gap-2 flex-wrap">
                        <a class="btn btn-primary btn-sm" href="<?php echo IAM_BASE_URL; ?>/admin/download_sso.php?app=<?php echo urlencode($a['code']); ?>"><i class="fas fa-download"></i> Télécharger le fichier d'intégration</a>
                        <?php if ($ssoState['state'] === 'deployed' && (int) $a['active'] === 1): ?>
                            <a class="btn btn-outline btn-sm" href="<?php echo htmlspecialchars($a['url']); ?>" target="_blank" rel="noopener"><i class="fas fa-arrow-up-right-from-square"></i> Tester le parcours SSO</a>
                        <?php endif; ?>
                        <form method="POST">
                            <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                            <input type="hidden" name="action" value="deploy_sso">
                            <input type="hidden" name="id" value="<?php echo (int) $a['id']; ?>">
                            <button class="btn btn-outline btn-sm"><i class="fas fa-sync"></i> Générer / redéployer</button>
                        </form>
                        <?php if ($ssoState['state'] === 'deployed' || $ssoState['state'] === 'guard_only'): ?>
                            <form method="POST" onsubmit="return confirm('Retirer la protection SSO de ce dossier ?');">
                                <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                                <input type="hidden" name="action" value="remove_sso">
                                <input type="hidden" name="id" value="<?php echo (int) $a['id']; ?>">
                                <button class="btn btn-danger btn-sm"><i class="fas fa-unlink"></i> Retirer la protection</button>
                            </form>
                        <?php endif; ?>
                    </div>
                    <div class="form-group" style="margin-top:10px;">
                        <label style="font-size:12px;">Code à inclure dans l'application (si déploiement manuel) :</label>
                        <textarea class="form-control" rows="6" readonly onclick="this.select();">Déposez le fichier « <?php echo $ssoState['guard_file']; ?> » à la racine de l'application (<?php echo htmlspecialchars(IAM_BASE_URL); ?>/admin/download_sso.php?app=<?php echo urlencode($a['code']); ?>).

Le fichier est chargé automatiquement si le serveur gère le .htaccess (auto_prepend_file).
Sinon, ajoutez dans chaque page PHP protégée :
   require_once __DIR__ . '/<?php echo $ssoState['guard_file']; ?>';

Ensuite, un utilisateur accédant directement à <?php echo htmlspecialchars($a['url']); ?> sera automatiquement redirigé vers l'IAM puis ramené sur la page.</textarea>
                    </div>
                </div>

                <!-- Formulaire édition -->
                <div id="editApp-<?php echo (int) $a['id']; ?>" style="display:none; margin-top:14px; border-top:1px solid var(--border); padding-top:14px;">
                    <form method="POST">
                        <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                        <input type="hidden" name="action" value="update">
                        <input type="hidden" name="id" value="<?php echo (int) $a['id']; ?>">
                        <div class="form-group"><label>Nom</label><input type="text" name="name" class="form-control" value="<?php echo htmlspecialchars($a['name']); ?>"></div>
                        <div class="form-group"><label>Description</label><textarea name="description" class="form-control" rows="2"><?php echo htmlspecialchars($a['description'] ?? ''); ?></textarea></div>
                        <div class="form-group"><label>URL</label><input type="text" name="url" class="form-control" value="<?php echo htmlspecialchars($a['url']); ?>"></div>
                        <div class="form-group"><label>Couleur</label><input type="text" name="color" class="form-control" value="<?php echo htmlspecialchars($a['color'] ?? '#4361ee'); ?>"></div>
                        <div class="form-group"><label>Icône (FontAwesome)</label><input type="text" name="icon" class="form-control" value="<?php echo htmlspecialchars($a['icon'] ?? 'fa-cube'); ?>" placeholder="ex : fa-cube"></div>
                        <label style="display:flex; gap:6px; align-items:center; margin-bottom:12px;">
                            <input type="checkbox" name="active" <?php echo $a['active'] ? 'checked' : ''; ?>> Active
                        </label>
                        <label style="display:flex; gap:6px; align-items:center; margin-bottom:12px;" title="Si coché, un utilisateur qui accède directement au lien de l'application devra ressaisir ses identifiants IAM, même s'il a déjà une session. Via le portail, l'accès reste fluide.">
                            <input type="checkbox" name="sso_prompt" <?php echo (int) $a['sso_prompt'] ? 'checked' : ''; ?>> Exiger la ressaisie des identifiants IAM sur accès direct (lien)
                        </label>
                        <details style="margin:14px 0; border-top:1px solid var(--border); padding-top:12px;">
                            <summary style="cursor:pointer; font-weight:600;">Options avancées — compatibilité avec la session locale</summary>
                            <p class="text-muted" style="font-size:12px;">À utiliser uniquement si l’application doit conserver son propre compte et sa propre session. La configuration du pont est intégrée au fichier garde généré.</p>
                            <?php iam_bridge_ui(iam_bridge_config($a)); ?>
                        </details>
                        <button type="submit" class="btn btn-primary btn-sm"><i class="fas fa-save"></i> Enregistrer</button>
                    </form>
                </div>

                <!-- Formulaire permissions -->
                <div id="permsApp-<?php echo (int) $a['id']; ?>" style="display:none; margin-top:14px; border-top:1px solid var(--border); padding-top:14px;">
                    <div class="card-title">Permissions</div>
                    <p class="text-muted" style="font-size:12px;">Les codes sont uniques dans l’IAM et sont utilisés par le code de l’application. Si vous modifiez un code, mettez aussi à jour l’application.</p>
                    <table class="table">
                        <tr><th>Nom</th><th>Code</th><th>Description</th><th>Actions</th></tr>
                        <?php foreach (($permsByApp[$a['id']] ?? []) as $p): ?>
                            <?php $permissionFormId = 'permissionEdit-' . (int) $p['id']; ?>
                            <tr>
                                <td><input form="<?php echo $permissionFormId; ?>" type="text" name="name" class="form-control" value="<?php echo htmlspecialchars($p['name']); ?>" required></td>
                                <td><input form="<?php echo $permissionFormId; ?>" type="text" name="code" class="form-control mono" value="<?php echo htmlspecialchars($p['code']); ?>" required></td>
                                <td><input form="<?php echo $permissionFormId; ?>" type="text" name="description" class="form-control" value="<?php echo htmlspecialchars($p['description'] ?? ''); ?>"></td>
                                <td>
                                    <form id="<?php echo $permissionFormId; ?>" method="POST" style="display:none;">
                                        <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                                        <input type="hidden" name="action" value="update_permission">
                                        <input type="hidden" name="id" value="<?php echo (int) $p['id']; ?>">
                                    </form>
                                    <button form="<?php echo $permissionFormId; ?>" class="btn btn-primary btn-sm"><i class="fas fa-save"></i> Enregistrer</button>
                                    <form method="POST" onsubmit="return confirm('Supprimer cette permission ?');">
                                        <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                                        <input type="hidden" name="action" value="delete_permission">
                                        <input type="hidden" name="id" value="<?php echo (int) $p['id']; ?>">
                                        <button class="btn btn-danger btn-sm"><i class="fas fa-trash"></i> Supprimer</button>
                                    </form>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </table>
                    <form method="POST">
                        <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                        <input type="hidden" name="action" value="add_permission">
                        <input type="hidden" name="application_id" value="<?php echo (int) $a['id']; ?>">
                        <div class="form-row">
                            <div class="form-group"><label>Nom</label><input type="text" name="name" class="form-control" required></div>
                            <div class="form-group"><label>Code</label><input type="text" name="code" class="form-control" required placeholder="ex : app.view"></div>
                        </div>
                        <div class="form-group"><label>Description</label><input type="text" name="description" class="form-control"></div>
                        <button type="submit" class="btn btn-success btn-sm"><i class="fas fa-plus"></i> Ajouter</button>
                    </form>
                </div>

                <!-- Accès utilisateurs -->
                <div id="accessApp-<?php echo (int) $a['id']; ?>" style="display:none; margin-top:14px; border-top:1px solid var(--border); padding-top:14px;">
                    <div class="card-title">Utilisateurs autorisés</div>
                    <table class="table">
                        <tr><th>Utilisateur</th><th>Rôle</th><th></th></tr>
                        <?php foreach (($appUsers[$a['id']] ?? []) as $au): ?>
                            <tr>
                                <td><strong><?php echo htmlspecialchars($au['first_name'] . ' ' . $au['last_name']); ?></strong><br><small class="text-muted"><?php echo htmlspecialchars($au['email']); ?></small></td>
                                <td><span class="badge badge-info"><?php echo htmlspecialchars($au['role_name']); ?></span></td>
                                <td>
                                    <form method="POST" onsubmit="return confirm('Retirer l\'accès de cet utilisateur ?');">
                                        <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                                        <input type="hidden" name="action" value="remove_access">
                                        <input type="hidden" name="application_id" value="<?php echo (int) $a['id']; ?>">
                                        <input type="hidden" name="user_id" value="<?php echo (int) $au['user_id']; ?>">
                                        <button class="btn btn-danger btn-sm"><i class="fas fa-user-minus"></i> Retirer</button>
                                    </form>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </table>
                    <form method="POST">
                        <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                        <input type="hidden" name="action" value="add_access">
                        <input type="hidden" name="application_id" value="<?php echo (int) $a['id']; ?>">
                        <div class="form-row">
                            <div class="form-group">
                                <label>Utilisateur</label>
                                <select name="user_id" class="form-control" required>
                                    <option value="">— Choisir —</option>
                                    <?php foreach ($activeUsers as $u): ?>
                                        <option value="<?php echo (int) $u['id']; ?>"><?php echo htmlspecialchars($u['first_name'] . ' ' . $u['last_name'] . ' (' . $u['email'] . ')'); ?></option>
                                    <?php endforeach; ?>
                                </select>
                            </div>
                            <div class="form-group">
                                <label>Rôle</label>
                                <select name="role_id" class="form-control" required>
                                    <option value="">— Rôle —</option>
                                    <?php foreach ($applicationRoles as $r): ?>
                                        <option value="<?php echo (int) $r['id']; ?>"><?php echo htmlspecialchars($r['name']); ?><?php echo $r['application_id'] === null ? ' (global)' : ''; ?></option>
                                    <?php endforeach; ?>
                                    <?php if (!$applicationRoles): ?>
                                        <option value="" disabled>Aucun rôle défini pour cette application</option>
                                    <?php endif; ?>
                                </select>
                                <?php if (!$applicationRoles): ?>
                                    <small class="text-muted">Créez d’abord un rôle propre à cette application.</small>
                                    <a class="btn btn-outline btn-sm" href="<?php echo IAM_BASE_URL; ?>/admin/roles.php?application_id=<?php echo (int) $a['id']; ?>#role-create"><i class="fas fa-plus"></i> Créer un rôle</a>
                                <?php endif; ?>
                            </div>
                        </div>
                        <button type="submit" class="btn btn-success btn-sm"><i class="fas fa-user-plus"></i> Donner l'accès</button>
                    </form>
                </div>
            </div>
        </div>
    <?php endforeach; ?>

    <style>
        .app-onboarding { grid-column: 1 / -1; width: min(100%, 820px); }
        .app-onboarding-intro { margin: 0 0 20px; color: var(--muted, #64748b); }
        .app-wizard-steps { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 10px; margin: 0 0 24px; padding: 0; }
        .app-wizard-steps [role="listitem"] { display: flex; align-items: center; gap: 9px; min-width: 0; padding: 10px 8px; border-bottom: 2px solid var(--border); color: #64748b; font-size: 13px; }
        .app-wizard-steps [role="listitem"][aria-current="step"] { border-color: var(--primary); color: var(--text, #1e293b); font-weight: 700; }
        .app-wizard-number { display: grid; width: 26px; aspect-ratio: 1; place-items: center; border: 1px solid currentColor; border-radius: 50%; flex: 0 0 auto; }
        .app-wizard-panel[hidden] { display: none; }
        .app-wizard-panel h3 { margin: 0 0 8px; font-size: 18px; }
        .app-wizard-help { margin: -8px 0 18px; color: #64748b; font-size: 13px; }
        .app-wizard-callout { margin: 16px 0; padding: 14px 16px; border-left: 3px solid var(--primary); background: #f5f8ff; }
        .app-wizard-callout p { margin: 5px 0 0; color: #475569; font-size: 13px; }
        .app-wizard-actions { display: flex; justify-content: space-between; gap: 10px; margin-top: 22px; }
        .app-preflight-list { display: grid; gap: 8px; margin: 12px 0 0; padding: 0; list-style: none; }
        .app-preflight-list li { display: grid; grid-template-columns: 110px minmax(0, 1fr); gap: 4px 12px; padding: 10px 12px; border: 1px solid var(--border); border-radius: 6px; }
        .app-preflight-list li span { color: #475569; font-size: 13px; }
        .app-preflight-list li small { grid-column: 2; color: #64748b; }
        .app-preflight-list .check-ok strong { color: #18794e; }
        .app-preflight-list .check-warning strong, .app-preflight-list .check-info strong { color: #9a6700; }
        .app-preflight-list .check-error strong { color: #cf222e; }
        .app-wizard-summary { display: grid; grid-template-columns: 150px minmax(0, 1fr); gap: 10px; margin: 16px 0; }
        .app-wizard-summary dt { color: #64748b; }
        .app-wizard-summary dd { margin: 0; overflow-wrap: anywhere; font-weight: 600; }
        @media (max-width: 640px) {
            .app-wizard-steps { gap: 4px; }
            .app-wizard-steps [role="listitem"] { flex-direction: column; align-items: center; gap: 6px; padding: 8px 4px; text-align: center; font-size: 11px; }
            .app-wizard-steps [role="listitem"] > span:last-child { max-width: 100%; overflow-wrap: anywhere; }
            .app-preflight-list li { grid-template-columns: 1fr; }
            .app-preflight-list li small { grid-column: 1; }
            .app-wizard-summary { grid-template-columns: 1fr; gap: 3px; }
            .app-wizard-summary dd { margin-bottom: 9px; }
        }
    </style>
    <div class="card app-onboarding">
        <div class="card-body">
            <div class="card-title">Ajouter une application</div>
            <p class="app-onboarding-intro">Déclarez l’application, vérifiez son environnement, puis déployez le SSO.</p>
            <div class="app-wizard-steps" role="list" aria-label="Étapes de configuration">
                <div role="listitem" aria-current="step"><span class="app-wizard-number">1</span><span>Application</span></div>
                <div role="listitem"><span class="app-wizard-number">2</span><span>Connexion IAM</span></div>
                <div role="listitem"><span class="app-wizard-number">3</span><span>Vérification</span></div>
            </div>
            <form id="appCreateWizard" method="POST">
                <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                <input type="hidden" name="action" value="create">
                <section class="app-wizard-panel" data-wizard-panel="0">
                    <h3>Informations de l’application</h3>
                    <p class="app-wizard-help">Ces informations servent à identifier l’application dans le portail IAM.</p>
                    <div class="form-group">
                        <label for="newAppName">Nom *</label>
                        <input id="newAppName" type="text" name="name" class="form-control" required maxlength="120" placeholder="ex. Gestion des congés">
                    </div>
                    <div class="form-group">
                        <label for="newAppCode">Code technique *</label>
                        <input id="newAppCode" type="text" name="code" class="form-control mono" required pattern="[a-z0-9]+(-[a-z0-9]+)*" maxlength="80" placeholder="genere-depuis-le-nom" aria-describedby="newAppCodeHelp">
                        <small id="newAppCodeHelp" class="text-muted">Généré à partir du nom; vous pouvez le personnaliser. Lettres minuscules, chiffres et tirets.</small>
                    </div>
                    <div class="form-group">
                        <label for="newAppUrl">URL de l’application *</label>
                        <input id="newAppUrl" type="url" name="url" class="form-control" required placeholder="http://localhost/MonApplication">
                        <small class="text-muted">Utilisez l’adresse que les utilisateurs ouvriront pour accéder à l’application.</small>
                    </div>
                    <div class="form-group">
                        <label for="newAppDescription">Description <span class="text-muted">(facultatif)</span></label>
                        <textarea id="newAppDescription" name="description" class="form-control" rows="2" maxlength="500" placeholder="À quoi sert cette application ?"></textarea>
                    </div>
                    <div class="app-wizard-actions"><span></span><button type="button" class="btn btn-primary" data-wizard-next>Continuer <i class="fas fa-arrow-right"></i></button></div>
                </section>

                <section class="app-wizard-panel" data-wizard-panel="1" hidden>
                    <h3>Connexion IAM</h3>
                    <p class="app-wizard-help">Le SSO IAM-Local est le parcours recommandé pour connecter une application au portail.</p>
                    <div class="app-wizard-callout">
                        <strong><i class="fas fa-shield-halved"></i> SSO IAM-Local</strong>
                        <p>L’utilisateur est redirigé vers IAM, puis revient dans l’application avec un jeton à usage unique. L’installation automatique sera proposée si le serveur le permet.</p>
                    </div>
                    <label style="display:flex; gap:9px; align-items:flex-start; margin:16px 0;">
                        <input type="checkbox" name="sso_prompt" style="margin-top:3px;">
                        <span><strong>Redemander le mot de passe IAM à chaque accès direct</strong><br><small class="text-muted">Désactivé par défaut : une session IAM existante pourra être réutilisée.</small></span>
                    </label>
                    <p class="text-muted" style="font-size:13px;">Besoin d’une intégration OpenID Connect standard ? Les clients OIDC se configurent séparément dans <a href="<?php echo IAM_BASE_URL; ?>/admin/oauth.php">OAuth / OIDC</a>.</p>
                    <div style="margin-top:20px;">
                        <button id="runAppPreflight" type="button" class="btn btn-outline"><i class="fas fa-stethoscope"></i> Vérifier la configuration</button>
                        <div id="appPreflightResult" aria-live="polite" style="margin-top:10px;"></div>
                    </div>
                    <div class="app-wizard-actions">
                        <button type="button" class="btn btn-outline" data-wizard-back><i class="fas fa-arrow-left"></i> Retour</button>
                        <button id="continueAfterPreflight" type="button" class="btn btn-primary" data-wizard-next disabled>Continuer <i class="fas fa-arrow-right"></i></button>
                    </div>
                </section>

                <section class="app-wizard-panel" data-wizard-panel="2" hidden>
                    <h3>Vérification avant création</h3>
                    <p class="app-wizard-help">Vérifiez le récapitulatif. Le serveur répétera les contrôles au moment de l’enregistrement.</p>
                    <dl class="app-wizard-summary">
                        <dt>Application</dt><dd id="reviewAppName"></dd>
                        <dt>Code</dt><dd id="reviewAppCode" class="mono"></dd>
                        <dt>URL</dt><dd id="reviewAppUrl"></dd>
                        <dt>Installation</dt><dd id="reviewInstallMode"></dd>
                    </dl>
                    <label style="display:flex; gap:9px; align-items:flex-start; margin:18px 0;">
                        <input type="checkbox" name="active" style="margin-top:3px;">
                        <span><strong>Activer l’application dès sa création</strong><br><small class="text-muted">Laissez décoché pour attribuer les rôles avant de la rendre accessible.</small></span>
                    </label>
                    <div class="app-wizard-callout">
                        <strong>Après la création</strong>
                        <p>Attribuez un rôle à un utilisateur, activez l’application dans « Modifier », puis utilisez « Tester le parcours SSO ». Les détails d’installation et le téléchargement du garde resteront dans « Intégration SSO ».</p>
                    </div>
                    <div class="app-wizard-actions">
                        <button type="button" class="btn btn-outline" data-wizard-back><i class="fas fa-arrow-left"></i> Retour</button>
                        <button id="createAppSubmit" type="submit" class="btn btn-success"><i class="fas fa-plus"></i> Créer et installer</button>
                    </div>
                </section>
            </form>
        </div>
    </div>
</div>
<script>
function iamEsc(s) {
    return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
async function iamBridgeProbe(btn) {
    const form = btn.closest('form') || document;
    const box = form.querySelector('.probe-box');
    const fd = new FormData();
    fd.set('csrf', (form.querySelector('[name="csrf"]') || {}).value || '');
    for (const n of ['db_host', 'db_port', 'db_name', 'db_user', 'db_pass', 'table', 'match_iam', 'match_local', 'key_role', 'create_status_col']) {
        const el = form.querySelector('[name="bridge_' + n + '"]');
        if (el) fd.set(n, el.value || '');
    }
    if (box) {
        box.style.minHeight = '20px';
        box.innerHTML = '<div class="text-muted"><i class="fas fa-spinner fa-spin"></i> Détection en cours…</div>';
    }
    let d = null;
    try {
        const res = await fetch('bridge_probe.php', { method: 'POST', body: fd });
        d = await res.json();
    } catch (e) {
        d = { ok: false, error: 'Erreur réseau : ' + e.message };
    }
    if (!d || !d.ok) {
        if (box) box.innerHTML = '<div class="alert alert-danger" style="margin-top:8px; margin-bottom:0;">' + iamEsc(d && d.error || 'Erreur inconnue') + '</div>';
        return;
    }
    const fill = (key, values) => {
        const dl = form.querySelector('datalist[data-bridge="' + key + '"]');
        if (dl) dl.innerHTML = (values || []).map((v) => '<option value="' + iamEsc(v) + '">').join('');
    };
    fill('db_name', d.databases);
    fill('table', d.tables);
    fill('cols', d.columns);
    fill('roles', d.key_role_values);
    fill('statuses', d.key_status_col_values);

    const chips = (values, inputName) => {
        if (!(values || []).length) return '';
        return '<div style="margin:4px 0;"><span class="text-muted">Valeurs détectées :</span> ' +
            values.map((v) => '<button type="button" class="btn btn-outline btn-sm" style="margin:2px; padding:2px 8px; font-size:11px;" onclick="var i=this.closest(\'form\').querySelector(\'[name=&quot;' + inputName + '&quot;]\'); if(i){i.value=this.textContent;}">' + iamEsc(v) + '</button>').join('') +
            '</div>';
    };
    let cov = '';
    if (d.match_coverage && d.match_coverage.length) {
        const rows = d.match_coverage.map((u) => {
            const badge = u.found ? '<span class="badge badge-success">reconnu</span>' : '<span class="badge badge-warning">absent (auto-créé si coché)</span>';
            return '<tr><td>' + iamEsc(u.user) + '</td><td>' + iamEsc(u.name) + '</td><td>' + iamEsc(u.needle) + '</td><td>' + badge + '</td></tr>';
        }).join('');
        const foundN = d.match_coverage.filter((u) => u.found).length;
        cov = '<div style="margin-top:8px;"><strong>Compatibilité utilisateurs IAM (' + foundN + '/' + d.match_coverage.length + ' reconnus dans « ' + iamEsc(d.matchCoverageLocal || (form.querySelector('[name="bridge_match_local"]') || {}).value || '') + ' »)</strong>' +
              '<table class="table" style="font-size:11px; margin:6px 0 0;"><tr><th>username</th><th>nom</th><th>valeur locale</th><th></th></tr>' + rows + '</table></div>';
    }
    if (box) box.innerHTML =
        '<div class="alert alert-success" style="margin-top:8px; margin-bottom:0; padding:10px;">' +
        'Connexion OK — base <strong>' + iamEsc(d.connected) + '</strong>' + (d.count ? ', <strong>' + d.count + '</strong> lignes dans la table, <strong>' + (d.columns || []).length + '</strong> colonnes.' : '.') + '</div>' +
        (d.key_role_values ? '<div class="text-muted" style="margin-top:6px;">Rôles détectés (cliquez pour pré-remplir « Rôle attribué ») :</div>' + chips(d.key_role_values, 'bridge_create_role') : '') +
        (d.key_status_col_values ? '<div class="text-muted">Statuts détectés (cliquez pour pré-remplir « Statut ») :</div>' + chips(d.key_status_col_values, 'bridge_create_status') : '') +
        cov;
    form.querySelectorAll('input[list]').forEach((i) => { i.placeholder = '…'; });
}
</script>
<script>
(() => {
    const form = document.getElementById('appCreateWizard');
    if (!form) return;

    const panels = Array.from(form.querySelectorAll('[data-wizard-panel]'));
    const indicators = Array.from(document.querySelectorAll('.app-wizard-steps [role="listitem"]'));
    const nameInput = form.elements.name;
    const codeInput = form.elements.code;
    const urlInput = form.elements.url;
    const runButton = document.getElementById('runAppPreflight');
    const continueButton = document.getElementById('continueAfterPreflight');
    const resultBox = document.getElementById('appPreflightResult');
    let currentStep = 0;
    let preflightResult = null;
    let preflightFingerprint = '';
    let codeCustomized = false;

    const fingerprint = () => [nameInput.value.trim(), codeInput.value.trim(), urlInput.value.trim()].join('|');

    function showStep(step) {
        currentStep = step;
        panels.forEach((panel, index) => { panel.hidden = index !== step; });
        indicators.forEach((indicator, index) => {
            if (index === step) indicator.setAttribute('aria-current', 'step');
            else indicator.removeAttribute('aria-current');
        });

        if (step === 2 && preflightResult) {
            document.getElementById('reviewAppName').textContent = nameInput.value.trim();
            document.getElementById('reviewAppCode').textContent = codeInput.value.trim();
            document.getElementById('reviewAppUrl').textContent = urlInput.value.trim();
            document.getElementById('reviewInstallMode').textContent = preflightResult.mode === 'automatic'
                ? 'Déploiement automatique disponible'
                : 'Installation manuelle à prévoir';
        }
    }

    function clearPreflight() {
        preflightResult = null;
        preflightFingerprint = '';
        continueButton.disabled = true;
        resultBox.replaceChildren();
    }

    function renderPreflight(data) {
        const list = document.createElement('ul');
        list.className = 'app-preflight-list';

        (data.checks || []).forEach((check) => {
            const item = document.createElement('li');
            item.className = 'check-' + check.status;
            const label = document.createElement('strong');
            label.textContent = check.status === 'ok' ? 'Prêt' : check.status === 'error' ? 'À corriger' : check.status === 'warning' ? 'Manuel' : 'Info';
            const title = document.createElement('span');
            title.textContent = check.label;
            const detail = document.createElement('small');
            detail.textContent = check.detail;
            item.append(label, title, detail);
            list.append(item);
        });

        resultBox.replaceChildren(list);
        if (data.ready) {
            const note = document.createElement('p');
            note.className = 'text-muted';
            note.style.fontSize = '13px';
            note.textContent = data.mode === 'automatic'
                ? 'Les contrôles préalables sont bons. Le déploiement automatique sera tenté à la création.'
                : 'Vous pouvez continuer; le fichier d’intégration sera disponible en téléchargement après la création.';
            resultBox.append(note);
        }
    }

    function slugify(value) {
        return value.normalize('NFD').replace(/[\u0300-\u036f]/g, '')
            .toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
    }

    nameInput.addEventListener('input', () => {
        if (!codeCustomized) codeInput.value = slugify(nameInput.value);
        clearPreflight();
    });
    codeInput.addEventListener('input', () => {
        codeCustomized = true;
        clearPreflight();
    });
    urlInput.addEventListener('input', clearPreflight);

    form.querySelectorAll('[data-wizard-next]').forEach((button) => {
        button.addEventListener('click', () => {
            if (currentStep === 0) {
                if (!nameInput.reportValidity() || !codeInput.reportValidity() || !urlInput.reportValidity()) return;
                showStep(1);
                return;
            }
            if (currentStep === 1 && preflightResult && preflightFingerprint === fingerprint()) {
                showStep(2);
            }
        });
    });

    form.querySelectorAll('[data-wizard-back]').forEach((button) => {
        button.addEventListener('click', () => showStep(Math.max(0, currentStep - 1)));
    });

    runButton.addEventListener('click', async () => {
        if (!nameInput.reportValidity() || !codeInput.reportValidity() || !urlInput.reportValidity()) {
            showStep(0);
            return;
        }

        clearPreflight();
        runButton.disabled = true;
        runButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Vérification…';
        const body = new FormData(form);
        body.set('action', 'preflight');

        try {
            const response = await fetch('app_preflight.php', { method: 'POST', body, headers: { Accept: 'application/json' } });
            const data = await response.json();
            renderPreflight(data);
            if (!response.ok || !data.ready) return;
            preflightResult = data;
            preflightFingerprint = fingerprint();
            continueButton.disabled = false;
        } catch (error) {
            const message = document.createElement('p');
            message.className = 'alert alert-danger';
            message.textContent = 'Le diagnostic n’a pas abouti. Vérifiez la session administrateur et réessayez.';
            resultBox.replaceChildren(message);
        } finally {
            runButton.disabled = false;
            runButton.innerHTML = '<i class="fas fa-stethoscope"></i> Vérifier la configuration';
        }
    });

    form.addEventListener('submit', (event) => {
        if (currentStep !== 2 || !preflightResult || preflightFingerprint !== fingerprint()) {
            event.preventDefault();
            clearPreflight();
            showStep(1);
            return;
        }
        document.getElementById('createAppSubmit').disabled = true;
    });
})();
</script>
<?php include __DIR__ . '/_footer.php'; ?>