<?php
require_once __DIR__ . '/_guard.php';

$db   = db();
iam_ensure_roles_application_column($db);
$msg  = '';
$type = 'success';
$err  = '';

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// ── Actions ───────────────────────────────────────────────
$action = $_GET['action'] ?? 'list';
$targetId = (int) ($_GET['id'] ?? 0);

// Export template CSV : agit immédiatement (GET)
if ($action === 'template') {
    $csv = "email;first_name;last_name;username;phone;matricule;organization;department;service;fonction;status\n" .
           "jean.dupont@mel.gov;Jean;Dupont;;+243800000001;MAT-001;DRH;Direction des Ressources Humaines;Gestion du Personnel;Agent;active\n" .
           "nous.voyons@mel.gov;Nouvy;Voyons;;+243800000002;MAT-002;DSI;Direction des Systèmes d'Information;;;active\n";
    header('Content-Type: text/csv; charset=UTF-8');
    header('Content-Disposition: attachment; filename="import_utilisateurs_template.csv"');
    echo "\xEF\xBB\xBF" . $csv;
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf'] ?? '')) {
        $err = 'Session expirée. Réessayez.';
    } else {
        $action = $_POST['action'] ?? '';
        switch ($action) {
            case 'import':
                $file = $_FILES['import_file'] ?? null;
                if (!$file || ($file['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK || !is_uploaded_file($file['tmp_name'])) {
                    $err = 'Fichier CSV manquant ou invalide.';
                } elseif (($file['size'] ?? 0) > 3 * 1024 * 1024) {
                    $err = 'Fichier trop volumineux (max 3 MO).';
                } else {
                    $content = file_get_contents($file['tmp_name']);
                    $parse = iam_parse_csv($content);
                    if ($parse['headers'] === [] || $parse['rows'] === []) {
                        $err = 'Fichier vide ou non reconnu (en-têtes attendues : email;first_name;last_name;...).';
                    } else {
                        $results = ['created' => 0, 'skipped_email' => 0, 'skipped_other' => 0];
                        $lines = [];
                        $genPw = (int) ($_POST['force_reset'] ?? 0) === 1;
                        $defaultStatus = $_POST['import_status'] === 'pending' ? 'pending' : 'active';
                        $ins = $db->prepare('INSERT INTO users (username, email, phone, password_hash, first_name, last_name, matricule, organization_id, department, service, fonction, status, must_change_password, created_by)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)');
                        foreach ($parse['rows'] as $row) {
                            $rec = array_combine($parse['headers'], $row);
                            $email = strtolower(trim($rec['email'] ?? ''));
                            $fn = trim($rec['first_name'] ?? '');
                            $ln = trim($rec['last_name'] ?? '');
                            if ($email === '' || $fn === '' || $ln === '') {
                                $results['skipped_other']++;
                                $lines[] = "Ligne ignorée (e-mail, prénom et nom obligatoires)";
                                continue;
                            }
                            if (iam_find_user($email)) {
                                $results['skipped_email']++;
                                $lines[] = "Ignoré (déjà existant) : $email";
                                continue;
                            }
                            $username = trim($rec['username'] ?? '') !== '' ? trim($rec['username']) : strstr($email, '@', true);
                            if (iam_find_user($username)) {
                                $username = $username . '.' . substr(bin2hex(random_bytes(2)), 0, 4);
                            }
                            $orgId = null;
                            $orgRef = trim($rec['organization'] ?? '');
                            if ($orgRef !== '') {
                                $stmtO = $db->prepare('SELECT id FROM organizations WHERE code = ? OR name = ? LIMIT 1');
                                $stmtO->execute([$orgRef, $orgRef]);
                                $orgId = $stmtO->fetchColumn() ?: null;
                                if (!$orgId) {
                                    // Rapprochement insensible aux accents/casse
                                    static $stripMap = ['à'=>'a','á'=>'a','â'=>'a','ä'=>'a','ã'=>'a','å'=>'a','é'=>'e','è'=>'e','ê'=>'e','ë'=>'e','í'=>'i','ì'=>'i','î'=>'i','ï'=>'i','ó'=>'o','ò'=>'o','ô'=>'o','ö'=>'o','õ'=>'o','ú'=>'u','ù'=>'u','û'=>'u','ü'=>'u','ý'=>'y','ç'=>'c','ñ'=>'n','œ'=>'oe','æ'=>'ae'];
                                    $norm = function ($s) use ($stripMap) { return strtr(mb_strtolower(trim($s)), $stripMap); };
                                    $refN = $norm($orgRef);
                                    foreach ($db->query('SELECT id, code, name FROM organizations') as $o) {
                                        if ($norm((string) $o['code']) === $refN || $norm((string) $o['name']) === $refN) { $orgId = (int) $o['id']; break; }
                                    }
                                }
                            }
                            $pass = $genPw ? iam_random_password() : 'IAM@' . bin2hex(random_bytes(3));
                            $ins->execute([
                                $username, $email,
                                trim($rec['phone'] ?? '') ?: null,
                                iam_hash_password($pass),
                                $fn, $ln,
                                trim($rec['matricule'] ?? '') ?: null,
                                $orgId,
                                trim($rec['department'] ?? '') ?: null,
                                trim($rec['service'] ?? '') ?: null,
                                trim($rec['fonction'] ?? '') ?: null,
                                $defaultStatus,
                                $iamAdmin['id'],
                            ]);
                            $results['created']++;
                            $lines[] = "Créé : $email" . (trim((string) ($rec['organization'] ?? '')) !== '' && !$orgId ? " (organisation « {$rec['organization']} » introuvable)" : "");
                        }
                        iam_audit('import_users', "Import CSV : {$results['created']} créé(s), {$results['skipped_email']} doublon(s) ignoré(s)", $iamAdmin['id'], $iamAdmin['email'], $_SERVER['REMOTE_ADDR'] ?? '', $_SERVER['HTTP_USER_AGENT'] ?? '');
                        $msg = "Import terminé : {$results['created']} créé(s), {$results['skipped_email']} en double, {$results['skipped_other']} invalide(s). "
                             . "Mots de passe : PDF à distribuer. " . implode(' | ', array_slice($lines, 0, 12));
                    }
                }
                break;
            case 'create':
                $email     = trim($_POST['email'] ?? '');
                $username  = trim($_POST['username'] ?? $email);
                $password  = $_POST['password'] ?? '';
                $firstName = trim($_POST['first_name'] ?? '');
                $lastName  = trim($_POST['last_name'] ?? '');
                $phone     = trim($_POST['phone'] ?? '');
                $matricule = trim($_POST['matricule'] ?? '');
                $orgId     = !empty($_POST['organization_id']) ? (int) $_POST['organization_id'] : null;

                if ($email === '' || $firstName === '' || $lastName === '') {
                    $err = 'E-mail, prénom et nom sont obligatoires.';
                } elseif (iam_find_user($email)) {
                    $err = 'Un compte avec cet e-mail existe déjà.';
                } else {
                    $policy = iam_get_password_policy();
                    $pwErrors = iam_validate_password($password, $policy);
                    if (!empty($pwErrors)) {
                        $err = implode(' ', $pwErrors);
                    } else {
                        $hash = iam_hash_password($password);
                        $stmt = $db->prepare('INSERT INTO users (username, email, phone, password_hash, first_name, last_name, matricule, organization_id, department, service, fonction, must_change_password, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)');
                        $stmt->execute([$username, $email, $phone, $hash, $firstName, $lastName, $matricule, $orgId, trim($_POST['department'] ?? '') ?: null, trim($_POST['service'] ?? '') ?: null, trim($_POST['fonction'] ?? '') ?: null, $iamAdmin['id']]);
                        $newId = $db->lastInsertId();
                        $db->prepare('INSERT INTO password_history (user_id, password_hash) VALUES (?, ?)')->execute([$newId, $hash]);
                        iam_set_user_groups($newId, $_POST['groups'] ?? []);

                        // Rôles (format du formulaire : roles[app_id] = role_id)
                        if (isset($_POST['roles']) && is_array($_POST['roles'])) {
                            foreach ($_POST['roles'] as $appId => $roleId) {
                                $appId = (int) $appId; $roleId = (int) $roleId;
                                if ($roleId > 0 && $appId > 0 && iam_role_allowed_for_app($roleId, $appId)) {
                                    $db->prepare('INSERT IGNORE INTO user_roles (user_id, role_id, application_id) VALUES (?, ?, ?)')->execute([$newId, $roleId, $appId]);
                                }
                            }
                        }
                        iam_audit('user_created', "Utilisateur créé: $email", $iamAdmin['id'], $iamAdmin['email'], $_SERVER['REMOTE_ADDR'] ?? '', $_SERVER['HTTP_USER_AGENT'] ?? '');
                        $msg = 'Utilisateur créé avec succès.';
                    }
                }
                break;

            case 'update':
                $targetId = (int) ($_POST['id'] ?? 0);
                if ($targetId <= 0) { $err = 'Utilisateur introuvable.'; break; }
                $stmt = $db->prepare('UPDATE users SET first_name=?, last_name=?, email=?, phone=?, matricule=?, organization_id=?, department=?, service=?, fonction=?, status=?, updated_at=NOW() WHERE id=?');
                $stmt->execute([
                    trim($_POST['first_name'] ?? ''),
                    trim($_POST['last_name'] ?? ''),
                    trim($_POST['email'] ?? ''),
                    trim($_POST['phone'] ?? ''),
                    trim($_POST['matricule'] ?? ''),
                    !empty($_POST['organization_id']) ? (int) $_POST['organization_id'] : null,
                    trim($_POST['department'] ?? '') ?: null,
                    trim($_POST['service'] ?? '') ?: null,
                    trim($_POST['fonction'] ?? '') ?: null,
                    $_POST['status'] ?? 'active',
                    $targetId,
                ]);
                iam_set_user_groups($targetId, $_POST['groups'] ?? []);
                // Rôles (format du formulaire : roles[app_id] = role_id)
                $db->prepare('DELETE FROM user_roles WHERE user_id = ?')->execute([$targetId]);
                if (isset($_POST['roles']) && is_array($_POST['roles'])) {
                    foreach ($_POST['roles'] as $appId => $roleId) {
                        $appId = (int) $appId; $roleId = (int) $roleId;
                        if ($roleId > 0 && $appId > 0 && iam_role_allowed_for_app($roleId, $appId)) {
                            $db->prepare('INSERT IGNORE INTO user_roles (user_id, role_id, application_id) VALUES (?, ?, ?)')->execute([$targetId, $roleId, $appId]);
                        }
                    }
                }
                iam_audit('user_updated', "Utilisateur modifié: {$_POST['email']}", $iamAdmin['id'], $iamAdmin['email'], $_SERVER['REMOTE_ADDR'] ?? '', $_SERVER['HTTP_USER_AGENT'] ?? '');
                $msg = 'Utilisateur mis à jour.';
                break;

            case 'reset_password':
                $targetId = (int) ($_POST['id'] ?? 0);
                $newPass  = $_POST['new_password'] ?? '';
                if ($targetId <= 0) { $err = 'Utilisateur introuvable.'; break; }
                $policy = iam_get_password_policy();
                $pwErrors = iam_validate_password($newPass, $policy);
                if (!empty($pwErrors)) {
                    $err = implode(' ', $pwErrors);
                } else {
                    $h = iam_hash_password($newPass);
                    $db->prepare('UPDATE users SET password_hash=?, must_change_password=0, updated_at=NOW() WHERE id=?')->execute([$h, $targetId]);
                    $db->prepare('INSERT INTO password_history (user_id, password_hash) VALUES (?, ?)')->execute([$targetId, $h]);
                    iam_audit('password_reset', "Mot de passe réinitialisé (admin)", $iam_admin_user['id'], $iam_admin_user['email'], $_SERVER['REMOTE_ADDR'] ?? '', $_SERVER['HTTP_USER_AGENT'] ?? '');
                    $msg = 'Mot de passe réinitialisé.';
                }
                break;

            case 'delete':
                $targetId = (int) ($_POST['id'] ?? 0);
                if ($targetId === 1) { $err = 'Impossible de supprimer l\'administrateur principal.'; }
                else {
                    $del = iam_find_user_by_id($targetId);
                    if ($del) {
                        $db->prepare('DELETE FROM users WHERE id = ?')->execute([$targetId]);
                        iam_audit('user_deleted', "Utilisateur supprimé: {$del['email']}", $iamAdmin['id'], $iamAdmin['email'], $_SERVER['REMOTE_ADDR'] ?? '', $_SERVER['HTTP_USER_AGENT'] ?? '');
                        $msg = 'Utilisateur supprimé.';
                    }
                }
                break;
        }
    }
}

// ── Données ───────────────────────────────────────────────
$page    = max(1, (int) ($_GET['page'] ?? 1));
$perPage = 15;
$search  = trim($_GET['q'] ?? '');
$offset  = ($page - 1) * $perPage;

$where  = '';
$params = [];
if ($search !== '') {
    $where = 'WHERE (u.email LIKE ? OR u.first_name LIKE ? OR u.last_name LIKE ? OR u.matricule LIKE ?)';
    $s = "%$search%";
    $params = [$s, $s, $s, $s];
}

$stmt = $db->prepare("SELECT COUNT(*) FROM users u $where");
$stmt->execute($params);
$total = (int) $stmt->fetchColumn();

$stmt = $db->prepare("SELECT u.*, o.name AS org_name,
        GROUP_CONCAT(DISTINCT CONCAT(r.name, ':', a.name) SEPARATOR ' | ') AS role_apps
        FROM users u
        LEFT JOIN organizations o ON o.id = u.organization_id
        LEFT JOIN user_roles ur ON ur.user_id = u.id
        LEFT JOIN roles r ON r.id = ur.role_id
        LEFT JOIN applications a ON a.id = ur.application_id
        $where
        GROUP BY u.id
        ORDER BY u.last_name LIMIT $perPage OFFSET $offset");
$stmt->execute($params);
$users = $stmt->fetchAll();

$allApps  = $db->query('SELECT id, name, code FROM applications WHERE active = 1 ORDER BY name')->fetchAll();
$orgs     = $db->query('SELECT id, name FROM organizations ORDER BY name')->fetchAll();
$allGroups = iam_group_all();

// Récupérer les rôles d'un utilisateur pour le formulaire d'édition
$editUser = null;
$editRoles = [];
$editGroups = [];
if ($action === 'edit' && $targetId > 0) {
    $stmt = $db->prepare('SELECT * FROM users WHERE id = ?');
    $stmt->execute([$targetId]);
    $editUser = $stmt->fetch();
    if ($editUser) {
        $stmt = $db->prepare('SELECT application_id, role_id FROM user_roles WHERE user_id = ?');
        $stmt->execute([$targetId]);
        foreach ($stmt->fetchAll() as $r) {
            $editRoles[] = ['role_id' => (int) $r['role_id'], 'app_id' => (int) $r['application_id']];
        }
        $editGroups = array_map(fn($g) => (int) $g['id'], iam_user_groups($targetId));
    }
}

$lastPage = (int) ceil($total / $perPage);
$pageTitle = 'Gestion des utilisateurs';
$active = 'users';
include __DIR__ . '/_header.php';
?>
<?php if ($err): ?><div class="alert alert-danger"><?php echo htmlspecialchars($err); ?></div><?php endif; ?>
<?php if ($msg): ?><div class="alert alert-success"><?php echo htmlspecialchars($msg); ?></div><?php endif; ?>

<?php if ($action === 'edit' && $editUser): ?>
    <div class="card">
        <div class="card-body">
            <div class="d-flex justify-between align-center mb-3">
                <div class="card-title">Modifier — <?php echo htmlspecialchars($editUser['email']); ?></div>
                <a href="<?php echo IAM_BASE_URL; ?>/admin/users.php" class="btn btn-outline btn-sm">&larr; Retour</a>
            </div>
            <form method="POST">
                <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                <input type="hidden" name="action" value="update">
                <input type="hidden" name="id" value="<?php echo (int) $editUser['id']; ?>">
                <div class="form-row">
                    <div class="form-group"><label>Prénom</label><input type="text" name="first_name" class="form-control" value="<?php echo htmlspecialchars($editUser['first_name']); ?>" required></div>
                    <div class="form-group"><label>Nom</label><input type="text" name="last_name" class="form-control" value="<?php echo htmlspecialchars($editUser['last_name']); ?>" required></div>
                </div>
                <div class="form-row">
                    <div class="form-group"><label>E-mail</label><input type="email" name="email" class="form-control" value="<?php echo htmlspecialchars($editUser['email']); ?>" required></div>
                    <div class="form-group"><label>Téléphone</label><input type="text" name="phone" class="form-control" value="<?php echo htmlspecialchars($editUser['phone'] ?? ''); ?>"></div>
                </div>
                <div class="form-row">
                    <div class="form-group"><label>Matricule</label><input type="text" name="matricule" class="form-control" value="<?php echo htmlspecialchars($editUser['matricule'] ?? ''); ?>"></div>
                    <div class="form-group">
                        <label>Organisation</label>
                        <select name="organization_id" class="form-control">
                            <option value="">—</option>
                            <?php foreach ($orgs as $o): ?>
                                <option value="<?php echo $o['id']; ?>" <?php echo (int) $editUser['organization_id'] === (int) $o['id'] ? 'selected' : ''; ?>><?php echo htmlspecialchars($o['name']); ?></option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                </div>
                <div class="form-row">
                    <div class="form-group"><label>Direction</label><input type="text" name="department" class="form-control" value="<?php echo htmlspecialchars($editUser['department'] ?? ''); ?>"></div>
                    <div class="form-group"><label>Service</label><input type="text" name="service" class="form-control" value="<?php echo htmlspecialchars($editUser['service'] ?? ''); ?>"></div>
                </div>
                <div class="form-row">
                    <div class="form-group"><label>Fonction</label><input type="text" name="fonction" class="form-control" value="<?php echo htmlspecialchars($editUser['fonction'] ?? ''); ?>"></div>
                </div>
                <div class="form-group">
                    <label>Groupes</label>
                    <div class="d-flex flex-wrap gap-2">
                        <?php if (empty($allGroups)): ?>
                            <small class="text-muted">Aucun groupe. <a href="<?php echo IAM_BASE_URL; ?>/admin/groups.php">Créer des groupes…</a></small>
                        <?php else: foreach ($allGroups as $g): ?>
                            <label style="display:inline-flex; gap:6px; align-items:center; margin-right:14px;">
                                <input type="checkbox" name="groups[]" value="<?php echo (int) $g['id']; ?>" <?php echo in_array((int) $g['id'], $editGroups, true) ? 'checked' : ''; ?>>
                                <?php echo htmlspecialchars($g['name']); ?>
                            </label>
                        <?php endforeach; endif; ?>
                    </div>
                </div>
                <div class="form-group">
                    <label>Statut</label>
                    <select name="status" class="form-control">
                        <?php foreach (['active', 'inactive', 'locked'] as $s): ?>
                            <option value="<?php echo $s; ?>" <?php echo $editUser['status'] === $s ? 'selected' : ''; ?>><?php echo ucfirst($s); ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="card-title mt-3">Rôles par application</div>
                <table class="table">
                    <tr><th>Application</th><th>Rôle</th></tr>
                    <?php foreach ($allApps as $a): ?>
                        <tr>
                            <td><?php echo htmlspecialchars($a['name']); ?></td>
                            <td>
                                <select name="roles[<?php echo $a['id']; ?>]" class="form-control">
                                    <option value="">— Aucun —</option>
                                    <?php foreach (iam_app_roles((int) $a['id']) as $r): ?>
                                        <?php
                                            $selected = false;
                                            foreach ($editRoles as $er) {
                                                if ($er['app_id'] === (int) $a['id'] && $er['role_id'] === (int) $r['id']) { $selected = true; break; }
                                            }
                                        ?>
                                        <option value="<?php echo $r['id']; ?>" <?php echo $selected ? 'selected' : ''; ?>><?php echo htmlspecialchars($r['name']); ?><?php echo $r['application_id'] === null ? ' (global)' : ''; ?></option>
                                    <?php endforeach; ?>
                                </select>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </table>
                <button type="submit" class="btn btn-primary"><i class="fas fa-save"></i> Enregistrer</button>
            </form>
        </div>
    </div>

<?php else: ?>
    <div class="card">
        <div class="card-body">
            <div class="d-flex justify-between align-center mb-3 flex-wrap gap-2">
                <form method="GET" style="display:flex; gap:8px; flex:1; max-width:420px;">
                    <input type="text" name="q" class="form-control" placeholder="Rechercher (nom, email, matricule)..." value="<?php echo htmlspecialchars($search); ?>">
                    <button class="btn btn-outline"><i class="fas fa-magnifying-glass"></i> Rechercher</button>
                </form>
                <button class="btn btn-primary" onclick="document.getElementById('createModal').style.display='block'"><i class="fas fa-plus"></i> Nouvel utilisateur</button>
                <button class="btn btn-outline" onclick="document.getElementById('importModal').style.display='block'"><i class="fas fa-file-import"></i> Importer (CSV)</button>
                <a class="btn btn-outline" href="<?php echo IAM_BASE_URL; ?>/admin/users.php?action=template"><i class="fas fa-download"></i> Modèle CSV</a>
            </div>

            <div class="table-wrap">
                <table class="table">
                    <tr>
                        <th>Utilisateur</th><th>Matricule</th><th>Organisation</th><th>Rôles / Apps</th><th>Statut</th><th>Dernière connexion</th><th>Actions</th>
                    </tr>
                    <?php if (empty($users)): ?>
                        <tr><td colspan="7" class="text-center text-muted">Aucun utilisateur trouvé.</td></tr>
                    <?php else: foreach ($users as $u): ?>
                        <tr>
                            <td>
                                <strong><?php echo htmlspecialchars($u['first_name'] . ' ' . $u['last_name']); ?></strong><br>
                                <small class="text-muted"><?php echo htmlspecialchars($u['email']); ?></small>
                            </td>
                            <td><?php echo htmlspecialchars($u['matricule'] ?? '-'); ?></td>
                            <td><?php echo htmlspecialchars($u['org_name'] ?? '-'); ?></td>
                            <td><small><?php echo htmlspecialchars($u['role_apps'] ?? 'Aucun'); ?></small></td>
                            <td>
                                <?php
                                    $badge = ['active' => 'success', 'inactive' => 'muted', 'locked' => 'danger', 'pending' => 'warning'][$u['status']] ?? 'muted';
                                ?>
                                <span class="badge badge-<?php echo $badge; ?>"><?php echo htmlspecialchars($u['status']); ?></span>
                                <?php if ($u['mfa_enabled']): ?><span class="badge badge-info">MFA</span><?php endif; ?>
                            </td>
                            <td><?php echo htmlspecialchars($u['last_login_at'] ?? '-'); ?></td>
                            <td>
                                <a href="<?php echo IAM_BASE_URL; ?>/admin/users.php?action=edit&id=<?php echo $u['id']; ?>" class="btn btn-outline btn-sm"><i class="fas fa-pen"></i></a>
                                <button class="btn btn-outline btn-sm" onclick="document.getElementById('pwdModal').style.display='block'; document.getElementById('pwdUserId').value=<?php echo (int) $u['id']; ?>;"><i class="fas fa-key"></i> Mot de passe</button>
                                <?php if ((int) $u['id'] !== 1): ?>
                                    <form method="POST" style="display:inline;" onsubmit="return confirm('Supprimer cet utilisateur ?');">
                                        <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                                        <input type="hidden" name="action" value="delete">
                                        <input type="hidden" name="id" value="<?php echo (int) $u['id']; ?>">
                                        <button class="btn btn-danger btn-sm"><i class="fas fa-trash"></i> Supprimer</button>
                                    </form>
                                <?php endif; ?>
                            </td>
                        </tr>
                    <?php endforeach; endif; ?>
                </table>
            </div>

            <?php if ($lastPage > 1): ?>
                <div class="pagination">
                    <?php for ($p = 1; $p <= $lastPage; $p++): ?>
                        <?php if ($p === $page): ?>
                            <span class="current"><?php echo $p; ?></span>
                        <?php else: ?>
                            <a href="?page=<?php echo $p; ?>&q=<?php echo urlencode($search); ?>"><?php echo $p; ?></a>
                        <?php endif; ?>
                    <?php endfor; ?>
                </div>
            <?php endif; ?>
        </div>
    </div>
<?php endif; ?>

<!-- Modal création utilisateur -->
<div id="createModal" style="display:none; position:fixed; inset:0; background:rgba(15,23,42,.55); z-index:1000; overflow-y:auto;" onclick="if(event.target===this)this.style.display='none';">
    <div style="max-width:760px; margin:40px auto; background:#fff; border-radius:14px; padding:26px; box-shadow:0 25px 60px rgba(0,0,0,.3);">
        <h3 style="margin-top:0;">Nouvel utilisateur</h3>
        <form method="POST">
            <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
            <input type="hidden" name="action" value="create">
            <div class="form-row">
                <div class="form-group"><label>Prénom *</label><input type="text" name="first_name" class="form-control" required></div>
                <div class="form-group"><label>Nom *</label><input type="text" name="last_name" class="form-control" required></div>
            </div>
            <div class="form-row">
                <div class="form-group"><label>E-mail *</label><input type="email" name="email" class="form-control" required></div>
                <div class="form-group"><label>Téléphone</label><input type="text" name="phone" class="form-control"></div>
            </div>
            <div class="form-row">
                <div class="form-group"><label>Identifiant (login)</label><input type="text" name="username" class="form-control" placeholder="par défaut = e-mail"></div>
                <div class="form-group"><label>Matricule</label><input type="text" name="matricule" class="form-control"></div>
            </div>
            <div class="form-row">
                <div class="form-group">
                    <label>Organisation</label>
                    <select name="organization_id" class="form-control">
                        <option value="">—</option>
                        <?php foreach ($orgs as $o): ?><option value="<?php echo $o['id']; ?>"><?php echo htmlspecialchars($o['name']); ?></option><?php endforeach; ?>
                    </select>
                </div>
                <div class="form-group"><label>Mot de passe temporaire *</label><input type="password" name="password" class="form-control" required placeholder="Min 8 car. + maj + chiffre + spécial"></div>
            </div>
            <div class="form-row">
                <div class="form-group"><label>Direction</label><input type="text" name="department" class="form-control"></div>
                <div class="form-group"><label>Service</label><input type="text" name="service" class="form-control"></div>
            </div>
            <div class="form-group"><label>Fonction</label><input type="text" name="fonction" class="form-control"></div>
            <div class="form-group">
                <label>Groupes</label>
                <div class="d-flex flex-wrap gap-2">
                    <?php if (empty($allGroups)): ?>
                        <small class="text-muted">Aucun groupe. <a href="<?php echo IAM_BASE_URL; ?>/admin/groups.php">Créer des groupes…</a></small>
                    <?php else: foreach ($allGroups as $g): ?>
                        <label style="display:inline-flex; gap:6px; align-items:center; margin-right:14px;">
                            <input type="checkbox" name="groups[]" value="<?php echo (int) $g['id']; ?>">
                            <?php echo htmlspecialchars($g['name']); ?>
                        </label>
                    <?php endforeach; endif; ?>
                </div>
            </div>
            <div class="card-title">Rôles par application</div>
            <table class="table">
                <tr><th>Application</th><th>Rôle</th></tr>
                <?php foreach ($allApps as $a): ?>
                    <tr>
                        <td><?php echo htmlspecialchars($a['name']); ?></td>
                        <td>
                            <select name="roles[<?php echo $a['id']; ?>]" class="form-control">
                                <option value="">— Aucun —</option>
                                <?php foreach (iam_app_roles((int) $a['id']) as $r): ?>
                                    <option value="<?php echo $r['id']; ?>"><?php echo htmlspecialchars($r['name']); ?><?php echo $r['application_id'] === null ? ' (global)' : ''; ?></option>
                                <?php endforeach; ?>
                            </select>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </table>
            <div class="d-flex gap-2">
                <button type="submit" class="btn btn-primary"><i class="fas fa-save"></i> Créer</button>
                <button type="button" class="btn btn-outline" onclick="document.getElementById('createModal').style.display='none';">Annuler</button>
            </div>
        </form>
    </div>
</div>

<!-- Modal import CSV -->
<div id="importModal" style="display:none; position:fixed; inset:0; background:rgba(15,23,42,.55); z-index:1000;" onclick="if(event.target===this)this.style.display='none';">
    <div style="max-width:520px; margin:100px auto; background:#fff; border-radius:14px; padding:26px;">
        <h3 style="margin-top:0;">Import des utilisateurs (CSV)</h3>
        <p class="text-muted" style="margin-top:0;">Colonnes attendues : <code>email;first_name;last_name;username;phone;matricule;organization;department;service;fonction;status</code>.<br>
        Délimiteur <code>;</code> ou <code>,</code>, encodage UTF-8. Les lignes déjà existantes sont ignorées. <a href="<?php echo IAM_BASE_URL; ?>/admin/users.php?action=template" style="text-decoration:underline;">Télécharger le modèle</a>.</p>
        <form method="POST" enctype="multipart/form-data">
            <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
            <input type="hidden" name="action" value="import">
            <div class="form-group">
                <label>Fichier CSV</label>
                <input type="file" name="import_file" class="form-control" accept=".csv,.txt" required>
            </div>
            <div class="form-row">
                <div class="form-group">
                    <label>Statut des comptes importés</label>
                    <select name="import_status" class="form-control">
                        <option value="active">Actif (connexion possible)</option>
                        <option value="pending">En attente (aucun accès)</option>
                    </select>
                </div>
                <div class="form-group" style="display:flex; align-items:flex-end;">
                    <label style="display:inline-flex; gap:6px; align-items:center;">
                        <input type="checkbox" name="force_reset" value="1"> Mots de passe forts + changement obligatoire
                    </label>
                </div>
            </div>
            <div class="d-flex gap-2">
                <button type="submit" class="btn btn-primary"><i class="fas fa-file-import"></i> Importer</button>
                <button type="button" class="btn btn-outline" onclick="document.getElementById('importModal').style.display='none';">Annuler</button>
            </div>
        </form>
    </div>
</div>

<!-- Modal réinitialisation mot de passe -->
<div id="pwdModal" style="display:none; position:fixed; inset:0; background:rgba(15,23,42,.55); z-index:1000;" onclick="if(event.target===this)this.style.display='none';">
    <div style="max-width:440px; margin:100px auto; background:#fff; border-radius:14px; padding:26px;">
        <h3 style="margin-top:0;">Réinitialiser le mot de passe</h3>
        <form method="POST">
            <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
            <input type="hidden" name="action" value="reset_password">
            <input type="hidden" name="id" id="pwdUserId" value="0">
            <div class="form-group">
                <label>Nouveau mot de passe</label>
                <input type="password" name="new_password" class="form-control" required>
                <div class="form-hint">Min 8 caractères, majuscule, minuscule, chiffre, caractère spécial. Obligatoire au prochain login.</div>
            </div>
            <div class="d-flex gap-2">
                <button type="submit" class="btn btn-primary"><i class="fas fa-key"></i> Réinitialiser</button>
                <button type="button" class="btn btn-outline" onclick="document.getElementById('pwdModal').style.display='none';">Annuler</button>
            </div>
        </form>
    </div>
</div>
<?php include __DIR__ . '/_footer.php'; ?>