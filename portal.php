<?php
// IAM-Local — Portail principal (liste des applications accessibles)
require_once __DIR__ . '/includes/functions.php';

iam_session_start();

if (!iam_is_logged_in()) {
    header('Location: ' . IAM_BASE_URL . '/login.php');
    exit;
}
if (!empty($_SESSION['iam_mfa_required']) && empty($_SESSION['iam_mfa_verified'])) {
    header('Location: ' . IAM_BASE_URL . '/mfa.php');
    exit;
}

$user = $_SESSION['iam_user'];
$apps = iam_user_apps((int) $user['id']);
$isAdmin = iam_user_is_admin((int) $user['id']);
$roles = iam_user_roles((int) $user['id']);

// Générer un lien SSO par application
function sso_launch_url(string $url): string {
    return htmlspecialchars($url . (strpos($url, '?') !== false ? '&' : '?') . 'sso=1');
}

$now = time();
?>
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Portail — <?php echo htmlspecialchars(IAM_NAME); ?></title>
<link rel="stylesheet" href="<?php echo htmlspecialchars(IAM_BASE_URL); ?>/assets/css/iam.css">
</head>
<body>
<div class="layout">
    <button class="sidebar-toggle" onclick="document.body.classList.toggle('sidebar-open'); document.getElementById('mobSidebar').classList.toggle('open')">&#9776; Menu</button>
    <div class="sidebar" id="mobSidebar">
        <div class="sidebar-header">
            <div>
                <img src="<?php echo htmlspecialchars(IAM_BASE_URL); ?>/images/acsi.jpg" class="brand-img" alt="ACSI">
            </div>
            <div>
                <div class="brand"><?php echo htmlspecialchars(IAM_NAME); ?></div>
                <small><?php echo htmlspecialchars(IAM_TAGLINE); ?></small>
            </div>
        </div>
        <nav class="sidebar-nav">
            <div class="nav-label">Navigation</div>
            <a href="<?php echo IAM_BASE_URL; ?>/portal.php" class="active"><i class="fas fa-th-large"></i> Applications</a>
            <a href="<?php echo IAM_BASE_URL; ?>/profile.php"><i class="fas fa-user-circle"></i> Mon profil</a>
            <?php if ($isAdmin): ?>
                <div class="nav-label">Administration</div>
                <a href="<?php echo IAM_BASE_URL; ?>/admin/"><i class="fas fa-gauge-high"></i> Tableau de bord</a>
                <a href="<?php echo IAM_BASE_URL; ?>/admin/users.php"><i class="fas fa-users"></i> Utilisateurs</a>
                <a href="<?php echo IAM_BASE_URL; ?>/admin/roles.php"><i class="fas fa-shield-halved"></i> Rôles &amp; permissions</a>
                <a href="<?php echo IAM_BASE_URL; ?>/admin/apps.php"><i class="fas fa-cubes"></i> Applications</a>
                <a href="<?php echo IAM_BASE_URL; ?>/admin/organizations.php"><i class="fas fa-sitemap"></i> Organisations</a>
                <a href="<?php echo IAM_BASE_URL; ?>/admin/sessions.php"><i class="fas fa-clock-rotate-left"></i> Sessions</a>
                <a href="<?php echo IAM_BASE_URL; ?>/admin/audit.php"><i class="fas fa-scroll"></i> Journal d'audit</a>
                <a href="<?php echo IAM_BASE_URL; ?>/admin/settings.php"><i class="fas fa-gear"></i> Paramètres</a>
            <?php endif; ?>
        </nav>
    </div>

    <div class="main">
        <div class="topbar">
            <div>
                <h1><i class="fas fa-th-large"></i> Mes applications</h1>
            </div>
            <div class="user-badge">
                <a href="<?php echo IAM_BASE_URL; ?>/profile.php" class="d-flex align-center gap-2" style="color:#334155;">
                    <div class="avatar"><?php echo htmlspecialchars(strtoupper(substr($user['first_name'] ?? 'U', 0, 1) . substr($user['last_name'] ?? '', 0, 1))); ?></div>
                    <div>
                        <div style="font-weight:600; font-size:13px;">
                            <?php echo htmlspecialchars(trim(($user['first_name'] ?? '') . ' ' . ($user['last_name'] ?? ''))); ?>
                        </div>
                        <div class="text-muted" style="font-size:12px;"><?php echo htmlspecialchars($user['email'] ?? ''); ?></div>
                    </div>
                </a>
                <a href="<?php echo IAM_BASE_URL; ?>/logout.php" class="btn btn-danger btn-sm" title="Se déconnecter">
                    <i class="fas fa-right-from-bracket"></i> Déconnexion
                </a>
            </div>
        </div>

        <?php if (!empty($_SESSION['iam_user']['must_change_password'])): ?>
            <div class="alert alert-warning">
                <i class="fas fa-triangle-exclamation"></i>
                Vous devez <a href="<?php echo IAM_BASE_URL; ?>/profile.php?force=1">changer votre mot de passe</a> avant de poursuivre.
            </div>
        <?php endif; ?>

        <div class="cards-grid">
            <?php foreach ($apps as $a): ?>
                <?php
                    $color = $a['color'] ?: '#4361ee';
                    $ssoUrl = htmlspecialchars($a['url'] . (strpos($a['url'], '?') !== false ? '&' : '?') . 'sso=1');
                ?>
                <div class="app-card">
                    <div class="d-flex align-center gap-2">
                        <div class="app-icon" style="background:<?php echo htmlspecialchars($color); ?>">
                            <i class="fas <?php echo htmlspecialchars($a['icon'] ?: 'fa-cube'); ?>"></i>
                        </div>
                        <div>
                            <span class="badge badge-info" style="margin-left:auto;"><?php echo htmlspecialchars($a['code']); ?></span>
                        </div>
                    </div>
                    <h3><?php echo htmlspecialchars($a['name']); ?></h3>
                    <p><?php echo htmlspecialchars($a['description'] ?? ''); ?></p>
                    <a class="btn btn-primary app-link" href="<?php echo IAM_BASE_URL; ?>/sso/authorize.php?app=<?php echo urlencode($a['code']); ?>&return=<?php echo urlencode($a['url']); ?>">
                        <i class="fas fa-arrow-right-to-bracket"></i> Accéder
                    </a>
                </div>
            <?php endforeach; ?>
        </div>

        <div class="card mt-3">
            <div class="card-body">
                <div class="card-title">Mes rôles</div>
                <?php if (empty($roles)): ?>
                    <span class="text-muted">Aucun rôle attribué.</span>
                <?php else: ?>
                    <?php foreach ($roles as $r): ?>
                        <span class="badge badge-primary"><?php echo htmlspecialchars($r['name']); ?></span>
                    <?php endforeach; ?>
                <?php endif; ?>
            </div>
        </div>

        <div class="page-footer">
            &copy; <?php echo date('Y'); ?> <?php echo htmlspecialchars(IAM_NAME); ?> — Authentification unique (SSO) &middot; <?php echo count($apps); ?> application(s) connectée(s)
        </div>
    </div>
</div>
<script src="https://kit.fontawesome.com/64d58efce2.js" crossorigin="anonymous"></script>
</body>
</html>