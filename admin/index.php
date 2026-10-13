<?php
require_once __DIR__ . '/_guard.php';

$db = db();

// Statistiques
$totalUsers   = (int) $db->query('SELECT COUNT(*) FROM users')->fetchColumn();
$totalApps    = (int) $db->query('SELECT COUNT(*) FROM applications')->fetchColumn();
$totalRoles   = (int) $db->query('SELECT COUNT(*) FROM roles')->fetchColumn();
$totalLogs    = (int) $db->query('SELECT COUNT(*) FROM audit_logs')->fetchColumn();
$activeUsers  = (int) $db->query("SELECT COUNT(*) FROM users WHERE status = 'active'")->fetchColumn();
$activeSessions = (int) $db->query('SELECT COUNT(*) FROM sessions WHERE revoked = 0')->fetchColumn();
$mfaUsers     = (int) $db->query('SELECT COUNT(*) FROM users WHERE mfa_enabled = 1')->fetchColumn();

// Dernières connexions
$recentUsers = $db->query('SELECT first_name, last_name, email, last_login_at FROM users WHERE last_login_at IS NOT NULL ORDER BY last_login_at DESC LIMIT 8')->fetchAll();

// Répartition par application
$appUsers = $db->query('SELECT a.name, COUNT(DISTINCT ur.user_id) AS cnt FROM applications a LEFT JOIN user_roles ur ON ur.application_id = a.id GROUP BY a.id ORDER BY cnt DESC')->fetchAll();

// Applications accessibles par l'admin
$adminId = (int) $_SESSION['iam_user']['id'];
$adminApps = $db->query("SELECT a.code, a.name, a.description, a.url, a.color, a.icon FROM applications a INNER JOIN user_roles ur ON ur.application_id = a.id WHERE ur.user_id = $adminId AND a.active = 1 ORDER BY a.name")->fetchAll();

$pageTitle = 'Tableau de bord';
$active = 'dashboard';
include __DIR__ . '/_header.php';
?>
<div class="cards-grid">
    <div class="card">
        <div class="card-body stat-card">
            <div class="stat-icon" style="background:linear-gradient(135deg,#4361ee,#3a0ca3);"><i class="fas fa-users"></i></div>
            <div>
                <div class="stat-value"><?php echo $totalUsers; ?></div>
                <div class="stat-label">Utilisateurs</div>
            </div>
        </div>
    </div>
    <div class="card">
        <div class="card-body stat-card">
            <div class="stat-icon" style="background:linear-gradient(135deg,#2ec4b6,#0f766e);"><i class="fas fa-user-check"></i></div>
            <div>
                <div class="stat-value"><?php echo $activeUsers; ?></div>
                <div class="stat-label">Comptes actifs</div>
            </div>
        </div>
    </div>
    <div class="card">
        <div class="card-body stat-card">
            <div class="stat-icon" style="background:linear-gradient(135deg,#f4a261,#b45309);"><i class="fas fa-cubes"></i></div>
            <div>
                <div class="stat-value"><?php echo $totalApps; ?></div>
                <div class="stat-label">Applications</div>
            </div>
        </div>
    </div>
    <div class="card">
        <div class="card-body stat-card">
            <div class="stat-icon" style="background:linear-gradient(135deg,#e71d36,#99101f);"><i class="fas fa-shield-halved"></i></div>
            <div>
                <div class="stat-value"><?php echo $totalRoles; ?></div>
                <div class="stat-label">Rôles</div>
            </div>
        </div>
    </div>
    <div class="card">
        <div class="card-body stat-card">
            <div class="stat-icon" style="background:linear-gradient(135deg,#8b5cf6,#5b21b6);"><i class="fas fa-plug"></i></div>
            <div>
                <div class="stat-value"><?php echo $activeSessions; ?></div>
                <div class="stat-label">Sessions actives</div>
            </div>
        </div>
    </div>
    <div class="card">
        <div class="card-body stat-card">
            <div class="stat-icon" style="background:linear-gradient(135deg,#06b6d4,#0e7490);"><i class="fas fa-shield"></i></div>
            <div>
                <div class="stat-value"><?php echo $mfaUsers; ?></div>
                <div class="stat-label">MFA activé</div>
            </div>
        </div>
    </div>
    <div class="card">
        <div class="card-body stat-card">
            <div class="stat-icon" style="background:linear-gradient(135deg,#64748b,#334155);"><i class="fas fa-scroll"></i></div>
            <div>
                <div class="stat-value"><?php echo $totalLogs; ?></div>
                <div class="stat-label">Événements journalisés</div>
            </div>
        </div>
    </div>
</div>

<div class="cards-grid mt-3">
    <div class="card">
        <div class="card-body">
            <div class="card-title">Mes applications</div>
            <?php if (empty($adminApps)): ?>
                <p class="text-muted">Aucune application accessible.</p>
            <?php else: ?>
                <div class="d-flex flex-wrap gap-2">
                    <?php foreach ($adminApps as $app):
                        $ssoLink = IAM_BASE_URL . '/sso/authorize.php?app=' . urlencode($app['code']) . '&return=' . urlencode($app['url']);
                    ?>
                        <a href="<?php echo htmlspecialchars($ssoLink); ?>" class="btn btn-outline d-flex align-center gap-2" style="flex:1 1 220px; min-width:0;">
                            <span class="app-icon" style="width:28px;height:28px;font-size:13px;background:<?php echo htmlspecialchars($app['color'] ?: '#4361ee'); ?>">
                                <i class="fas <?php echo htmlspecialchars($app['icon'] ?: 'fa-cube'); ?>"></i>
                            </span>
                            <span>
                                <span style="font-weight:600;"><?php echo htmlspecialchars($app['name']); ?></span><br>
                                <small class="text-muted"><?php echo htmlspecialchars($app['code']); ?></small>
                            </span>
                        </a>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>
        </div>
    </div>

    <div class="card">
        <div class="card-body">
            <div class="card-title">Utilisateurs par application</div>
            <table class="table">
                <tr><th>Application</th><th>Utilisateurs</th></tr>
                <?php foreach ($appUsers as $row): ?>
                    <tr>
                        <td><?php echo htmlspecialchars($row['name']); ?></td>
                        <td><span class="badge badge-info"><?php echo (int) $row['cnt']; ?></span></td>
                    </tr>
                <?php endforeach; ?>
            </table>
        </div>
    </div>
</div>

<div class="cards-grid mt-3">
    <div class="card">
        <div class="card-body">
            <div class="card-title">Dernières connexions</div>
            <?php if (empty($recentUsers)): ?>
                <p class="text-muted">Aucune connexion enregistrée.</p>
            <?php else: ?>
                <table class="table">
                    <tr><th>Utilisateur</th><th>Le</th></tr>
                    <?php foreach ($recentUsers as $u): ?>
                        <tr>
                            <td><?php echo htmlspecialchars($u['first_name'] . ' ' . $u['last_name']); ?><br><small class="text-muted"><?php echo htmlspecialchars($u['email']); ?></small></td>
                            <td><?php echo htmlspecialchars($u['last_login_at']); ?></td>
                        </tr>
                    <?php endforeach; ?>
                </table>
            <?php endif; ?>
        </div>
    </div>
</div>

<div class="mt-3 d-flex gap-2 flex-wrap">
    <a href="<?php echo IAM_BASE_URL; ?>/admin/users.php" class="btn btn-primary"><i class="fas fa-users"></i> Gérer les utilisateurs</a>
    <a href="<?php echo IAM_BASE_URL; ?>/admin/roles.php" class="btn btn-outline"><i class="fas fa-shield-halved"></i> Rôles &amp; permissions</a>
    <a href="<?php echo IAM_BASE_URL; ?>/admin/apps.php" class="btn btn-outline"><i class="fas fa-cubes"></i> Applications</a>
    <a href="<?php echo IAM_BASE_URL; ?>/admin/audit.php" class="btn btn-outline"><i class="fas fa-scroll"></i> Journal d'audit</a>
</div>
<?php include __DIR__ . '/_footer.php'; ?>