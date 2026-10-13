<?php
// Layout admin : entête + menu latéral
// Attend : $pageTitle, $active (clé du menu)

$active = $active ?? '';
$iamAdmin = $GLOBALS['iam_admin'] ?? [];
$menu = [
    'dashboard'   => ['Tableau de bord', 'fa-gauge-high', 'index.php'],
    'users'       => ['Utilisateurs', 'fa-users', 'users.php'],
    'groups'      => ['Groupes', 'fa-layer-group', 'groups.php'],
    'roles'       => ['Rôles &amp; permissions', 'fa-shield-halved', 'roles.php'],
    'apps'        => ['Applications', 'fa-cubes', 'apps.php'],
    'organizations' => ['Organisations', 'fa-sitemap', 'organizations.php'],
    'sessions'    => ['Sessions', 'fa-clock-rotate-left', 'sessions.php'],
    'audit'       => ['Journal d\'audit', 'fa-scroll', 'audit.php'],
    'email'       => ['E-mail &amp; MFA', 'fa-envelope', 'email.php'],
    'oauth'       => ['OAuth / OIDC', 'fa-lock-open', 'oidc_apps.php'],
    'settings'    => ['Paramètres', 'fa-gear', 'settings.php'],
];
?>
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title><?php echo htmlspecialchars($pageTitle); ?> — <?php echo htmlspecialchars(IAM_NAME); ?></title>
<link rel="stylesheet" href="<?php echo IAM_BASE_URL; ?>/assets/css/iam.css">
</head>
<body>
<div class="layout">
    <button class="sidebar-toggle" onclick="document.getElementById('adminSidebar').classList.toggle('open')">&#9776; Menu</button>
    <div class="sidebar" id="adminSidebar">
        <div class="sidebar-header">
            <div><img src="<?php echo htmlspecialchars(IAM_BASE_URL); ?>/images/acsi.jpg" class="brand-img" alt="ACSI"></div>
            <div>
                <div class="brand"><?php echo htmlspecialchars(IAM_NAME); ?></div>
                <small>Console d'administration</small>
            </div>
        </div>
        <nav class="sidebar-nav">
            <?php foreach ($menu as $key => $m): ?>
                <a href="<?php echo IAM_BASE_URL; ?>/admin/<?php echo $m[2]; ?>" class="<?php echo $active === $key ? 'active' : ''; ?>">
                    <i class="fas <?php echo $m[1]; ?>"></i> <?php echo $m[0]; ?>
                </a>
            <?php endforeach; ?>
            <div class="nav-label">Portail</div>
            <a href="<?php echo IAM_BASE_URL; ?>/portal.php"><i class="fas fa-th-large"></i> Retour au portail</a>
            <a href="<?php echo IAM_BASE_URL; ?>/logout.php"><i class="fas fa-right-from-bracket"></i> Déconnexion</a>
        </nav>
    </div>

    <div class="main">
        <div class="topbar">
            <h1><?php echo htmlspecialchars($pageTitle); ?></h1>
            <div class="user-badge">
                <div class="avatar"><?php echo htmlspecialchars(strtoupper(substr(($iamAdmin['first_name'] ?? 'A'), 0, 1) . substr(($iamAdmin['last_name'] ?? ''), 0, 1))); ?></div>
                <div>
                    <div style="font-weight:600; font-size:13px;"><?php echo htmlspecialchars(trim(($iamAdmin['first_name'] ?? '') . ' ' . ($iamAdmin['last_name'] ?? ''))); ?></div>
                    <div class="text-muted" style="font-size:12px;">Administrateur</div>
                </div>
            </div>
        </div>