<?php
// IAM-Local — Profil utilisateur + changement de mot de passe
require_once __DIR__ . '/includes/functions.php';

iam_session_start();

if (!iam_is_logged_in()) {
    header('Location: ' . IAM_BASE_URL . '/login.php');
    exit;
}

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$user = $_SESSION['iam_user'];
$uid  = (int) $user['id'];
$db   = db();

// Informations complètes
$stmt = $db->prepare('SELECT u.*, o.name AS org_name, o.type AS org_type FROM users u LEFT JOIN organizations o ON o.id = u.organization_id WHERE u.id = ?');
$stmt->execute([$uid]);
$full = $stmt->fetch();

$roles = iam_user_roles($uid);
$apps  = iam_user_apps($uid);
$perms = iam_user_permissions($uid);

$msg  = '';
$type = 'success';
$force = isset($_GET['force']);

// Changement de mot de passe
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf'] ?? '')) {
        $msg = 'Session expirée. Réessayez.';
        $type = 'danger';
    } else {
        $current = $_POST['current_password'] ?? '';
        $new     = $_POST['new_password'] ?? '';
        $confirm = $_POST['confirm_password'] ?? '';

        if (!iam_verify_password($current, $full['password_hash'])) {
            $msg = 'Mot de passe actuel incorrect.';
            $type = 'danger';
        } elseif ($new !== $confirm) {
            $msg = 'Les deux mots de passe ne correspondent pas.';
            $type = 'danger';
        } else {
            $policy = iam_get_password_policy();
            $errors = iam_validate_password($new, $policy);
            // Interdire la réutilisation (historique)
            $historyUsed = iam_check_password_history($uid, $new, (int) $policy['history']);
            if ($historyUsed) {
                $errors[] = "Ce mot de passe a déjà été utilisé récemment. Choisissez un mot de passe différent.";
            }
            if (iam_verify_password($new, $full['password_hash'])) {
                $errors[] = "Le nouveau mot de passe doit être différent du mot de passe actuel.";
            }

            if (!empty($errors)) {
                $msg = implode(' ', $errors);
                $type = 'danger';
            } else {
                iam_update_password($uid, $new);
                $_SESSION['iam_user']['must_change_password'] = false;
                iam_audit('password_changed', 'Changement de mot de passe', $uid, $user['email'], $_SERVER['REMOTE_ADDR'] ?? '', $_SERVER['HTTP_USER_AGENT'] ?? '');
                $msg = 'Mot de passe mis à jour avec succès.';
                $type = 'success';

                // Reprendre le flux interrompu (SSO / accès direct à une app)
                if (!empty($_SESSION['iam_after_force'])) {
                    $after = $_SESSION['iam_after_force'];
                    unset($_SESSION['iam_after_force']);
                    header('Location: ' . $after);
                    exit;
                }
            }
        }
    }
}

// Révocation d'une session
if (isset($_GET['revoke'])) {
    iam_revoke_all_sessions($uid);
    iam_audit('sessions_revoked', 'Toutes les sessions ont été révoquées', $uid, $user['email'], $_SERVER['REMOTE_ADDR'] ?? '', $_SERVER['HTTP_USER_AGENT'] ?? '');
    header('Location: ' . IAM_BASE_URL . '/profile.php');
    exit;
}

$activeSessions = $db->prepare('SELECT * FROM sessions WHERE user_id = ? AND revoked = 0 ORDER BY created_at DESC');
$activeSessions->execute([$uid]);
$sessions = $activeSessions->fetchAll();

$isAdmin = iam_user_is_admin($uid);
?>
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Mon profil — <?php echo htmlspecialchars(IAM_NAME); ?></title>
<link rel="stylesheet" href="<?php echo htmlspecialchars(IAM_BASE_URL); ?>/assets/css/iam.css">
</head>
<body>
<div class="layout">
    <button class="sidebar-toggle" onclick="document.getElementById('mobSidebar').classList.toggle('open')">&#9776; Menu</button>
    <div class="sidebar" id="mobSidebar">
        <div class="sidebar-header">
            <div><img src="<?php echo htmlspecialchars(IAM_BASE_URL); ?>/images/acsi.jpg" class="brand-img" alt="ACSI"></div>
            <div><div class="brand"><?php echo htmlspecialchars(IAM_NAME); ?></div><small>Mon profil</small></div>
        </div>
        <nav class="sidebar-nav">
            <div class="nav-label">Navigation</div>
            <a href="<?php echo IAM_BASE_URL; ?>/portal.php"><i class="fas fa-th-large"></i> Applications</a>
            <a href="<?php echo IAM_BASE_URL; ?>/profile.php" class="active"><i class="fas fa-user-circle"></i> Mon profil</a>
            <?php if ($isAdmin): ?>
                <div class="nav-label">Administration</div>
                <a href="<?php echo IAM_BASE_URL; ?>/admin/"><i class="fas fa-gauge-high"></i> Tableau de bord</a>
                <a href="<?php echo IAM_BASE_URL; ?>/admin/users.php"><i class="fas fa-users"></i> Utilisateurs</a>
                <a href="<?php echo IAM_BASE_URL; ?>/admin/roles.php"><i class="fas fa-shield-halved"></i> Rôles &amp; permissions</a>
                <a href="<?php echo IAM_BASE_URL; ?>/admin/audit.php"><i class="fas fa-scroll"></i> Journal d'audit</a>
            <?php endif; ?>
        </nav>
    </div>

    <div class="main">
        <div class="topbar">
            <h1><i class="fas fa-user-circle"></i> Mon profil</h1>
            <a href="<?php echo IAM_BASE_URL; ?>/logout.php" class="btn btn-danger btn-sm"><i class="fas fa-right-from-bracket"></i> Déconnexion</a>
        </div>

        <?php if ($msg): ?>
            <div class="alert alert-<?php echo $type === 'danger' ? 'danger' : 'success'; ?>"><?php echo htmlspecialchars($msg); ?></div>
        <?php endif; ?>

        <div class="cards-grid">
            <div class="card">
                <div class="card-body">
                    <div class="card-title">Informations personnelles</div>
                    <table class="table">
                        <tr><th>Nom complet</th><td><?php echo htmlspecialchars($full['first_name'] . ' ' . $full['last_name']); ?></td></tr>
                        <tr><th>Identifiant</th><td><?php echo htmlspecialchars($full['username']); ?></td></tr>
                        <tr><th>E-mail</th><td><?php echo htmlspecialchars($full['email']); ?></td></tr>
                        <tr><th>Téléphone</th><td><?php echo htmlspecialchars($full['phone'] ?? '-'); ?></td></tr>
                        <tr><th>Matricule</th><td><?php echo htmlspecialchars($full['matricule'] ?? '-'); ?></td></tr>
                        <tr><th>Organisation</th><td><?php echo htmlspecialchars($full['org_name'] ?? '-'); ?></td></tr>
                        <tr><th>Dernière connexion</th><td><?php echo htmlspecialchars($full['last_login_at'] ?? '-'); ?></td></tr>
                        <tr><th>MFA</th><td><?php echo $full['mfa_enabled'] ? '<span class="badge badge-success">Activé</span>' : '<span class="badge badge-muted">Désactivé</span>'; ?></td></tr>
                    </table>
                </div>
            </div>

            <div class="card">
                <div class="card-body">
                    <div class="card-title">Rôles et applications</div>
                    <?php if (empty($apps)): ?>
                        <p class="text-muted">Aucune application attribuée.</p>
                    <?php else: ?>
                        <?php foreach ($apps as $a): ?>
                            <div class="d-flex justify-between align-center mb-2" style="border-bottom:1px solid var(--border); padding-bottom:8px;">
                                <span><strong><?php echo htmlspecialchars($a['name']); ?></strong></span>
                                <?php
                                    $appRoles = iam_user_roles($uid, (int) $a['id']);
                                    foreach ($appRoles as $r) {
                                        echo '<span class="badge badge-primary">' . htmlspecialchars($r['name']) . '</span> ';
                                    }
                                ?>
                            </div>
                        <?php endforeach; ?>
                    <?php endif; ?>
                    <div class="card-title mt-3">Permissions (<?php echo count($perms); ?>)</div>
                    <?php foreach ($perms as $p): ?>
                        <span class="badge badge-info"><?php echo htmlspecialchars($p['code']); ?></span>
                    <?php endforeach; ?>
                </div>
            </div>
        </div>

        <div class="cards-grid mt-3">
            <div class="card">
                <div class="card-body">
                    <div class="card-title">Changer le mot de passe</div>
                    <form method="POST" action="">
                        <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                        <div class="form-group">
                            <label>Mot de passe actuel</label>
                            <input type="password" name="current_password" class="form-control" required>
                        </div>
                        <div class="form-group">
                            <label>Nouveau mot de passe</label>
                            <input type="password" name="new_password" class="form-control" required>
                            <div class="form-hint">Minimum 8 caractères, majuscule, minuscule, chiffre et caractère spécial.</div>
                        </div>
                        <div class="form-group">
                            <label>Confirmer le nouveau mot de passe</label>
                            <input type="password" name="confirm_password" class="form-control" required>
                        </div>
                        <button type="submit" class="btn btn-primary"><i class="fas fa-key"></i> Mettre à jour</button>
                    </form>
                </div>
            </div>

            <div class="card">
                <div class="card-body">
                    <div class="card-title">Mes sessions actives</div>
                    <?php if (empty($sessions)): ?>
                        <p class="text-muted">Aucune session active.</p>
                    <?php else: ?>
                        <table class="table">
                            <tr><th>IP</th><th>Navigateur</th><th>Créée</th><th>Expire</th></tr>
                            <?php foreach ($sessions as $s): ?>
                                <tr>
                                    <td><?php echo htmlspecialchars($s['ip_address'] ?? '-'); ?></td>
                                    <td><?php echo htmlspecialchars(substr($s['user_agent'] ?? '-', 0, 40)); ?></td>
                                    <td><?php echo htmlspecialchars($s['created_at']); ?></td>
                                    <td><?php echo htmlspecialchars($s['expires_at']); ?></td>
                                </tr>
                            <?php endforeach; ?>
                        </table>
                        <a href="<?php echo IAM_BASE_URL; ?>/profile.php?revoke=1" class="btn btn-danger btn-sm" onclick="return confirm('Révoquer toutes vos sessions ?');">
                            <i class="fas fa-ban"></i> Tout déconnecter ailleurs
                        </a>
                    <?php endif; ?>
                </div>
            </div>
        </div>

        <div class="page-footer">&copy; <?php echo date('Y'); ?> <?php echo htmlspecialchars(IAM_NAME); ?></div>
    </div>
</div>
<script src="https://kit.fontawesome.com/64d58efce2.js" crossorigin="anonymous"></script>
</body>
</html>