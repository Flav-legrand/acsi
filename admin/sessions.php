<?php
require_once __DIR__ . '/_guard.php';

$db = db();
$msg = '';
$err = '';

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf'] ?? '')) {
        $err = 'Session expirée.';
    } else {
        $action = $_POST['action'] ?? '';
        if ($action === 'revoke') {
            $sid = (int) ($_POST['sid'] ?? 0);
            iam_revoke_session($sid);
            iam_audit('session_revoked', "Session révoquée #$sid", $iamAdmin['id'], $iamAdmin['email'], $_SERVER['REMOTE_ADDR'] ?? '', $_SERVER['HTTP_USER_AGENT'] ?? '');
            $msg = 'Session révoquée.';
        } elseif ($action === 'revoke_all_user') {
            $uid = (int) ($_POST['uid'] ?? 0);
            iam_revoke_all_sessions($uid);
            iam_audit('sessions_revoked', "Toutes les sessions de l'utilisateur #$uid révoquées", $iamAdmin['id'], $iamAdmin['email'], $_SERVER['REMOTE_ADDR'] ?? '', $_SERVER['HTTP_USER_AGENT'] ?? '');
            $msg = 'Toutes les sessions de cet utilisateur ont été révoquées.';
        }
    }
}

$page    = max(1, (int) ($_GET['page'] ?? 1));
$perPage = 25;
$offset  = ($page - 1) * $perPage;
$uidFilter = (int) ($_GET['user_id'] ?? 0);

if ($uidFilter > 0) {
    $stmt = $db->prepare('SELECT COUNT(*) FROM sessions WHERE user_id = ?');
    $stmt->execute([$uidFilter]);
    $total = (int) $stmt->fetchColumn();
    $stmt = $db->prepare("SELECT s.*, u.email, u.first_name, u.last_name FROM sessions s INNER JOIN users u ON u.id = s.user_id WHERE s.user_id = ? ORDER BY s.created_at DESC LIMIT $perPage OFFSET $offset");
    $stmt->execute([$uidFilter]);
} else {
    $total = (int) $db->query('SELECT COUNT(*) FROM sessions')->fetchColumn();
    $stmt = $db->query("SELECT s.*, u.email, u.first_name, u.last_name FROM sessions s INNER JOIN users u ON u.id = s.user_id ORDER BY s.created_at DESC LIMIT $perPage OFFSET $offset");
}
$sessions = $stmt->fetchAll();
$lastPage = (int) ceil($total / $perPage);

$activeUsers = $db->query('SELECT id, email FROM users ORDER BY email')->fetchAll();

$pageTitle = 'Sessions';
$active = 'sessions';
include __DIR__ . '/_header.php';
?>
<?php if ($err): ?><div class="alert alert-danger"><?php echo htmlspecialchars($err); ?></div><?php endif; ?>
<?php if ($msg): ?><div class="alert alert-success"><?php echo htmlspecialchars($msg); ?></div><?php endif; ?>

<div class="card">
    <div class="card-body">
        <form method="GET" class="d-flex gap-2 mb-3 flex-wrap">
            <select name="user_id" class="form-control" style="max-width:320px;">
                <option value="0">— Tous les utilisateurs —</option>
                <?php foreach ($activeUsers as $u): ?>
                    <option value="<?php echo (int) $u['id']; ?>" <?php echo $uidFilter === (int) $u['id'] ? 'selected' : ''; ?>><?php echo htmlspecialchars($u['email']); ?></option>
                <?php endforeach; ?>
            </select>
            <button class="btn btn-primary"><i class="fas fa-filter"></i> Filtrer</button>
        </form>

        <div class="table-wrap">
            <table class="table">
                <tr><th>Utilisateur</th><th>IP</th><th>Navigateur</th><th>Créée</th><th>Dernière activité</th><th>Expire</th><th>Statut</th><th>Actions</th></tr>
                <?php if (empty($sessions)): ?>
                    <tr><td colspan="8" class="text-center text-muted">Aucune session.</td></tr>
                <?php else: foreach ($sessions as $s): ?>
                    <tr>
                        <td><?php echo htmlspecialchars($s['first_name'] . ' ' . $s['last_name']); ?><br><small class="text-muted"><?php echo htmlspecialchars($s['email']); ?></small></td>
                        <td><span class="mono"><?php echo htmlspecialchars($s['ip_address'] ?? '-'); ?></span></td>
                        <td><small class="text-muted"><?php echo htmlspecialchars(substr($s['user_agent'] ?? '-', 0, 38)); ?></small></td>
                        <td><?php echo htmlspecialchars($s['created_at']); ?></td>
                        <td><?php echo htmlspecialchars($s['last_active_at']); ?></td>
                        <td><?php echo htmlspecialchars($s['expires_at']); ?></td>
                        <td>
                            <?php if ($s['revoked']): ?>
                                <span class="badge badge-muted">révoquée</span>
                            <?php elseif (strtotime($s['expires_at']) < time()): ?>
                                <span class="badge badge-warning">expirée</span>
                            <?php else: ?>
                                <span class="badge badge-success">active</span>
                            <?php endif; ?>
                        </td>
                        <td>
                            <?php if (!$s['revoked']): ?>
                                <form method="POST" style="display:inline;" onsubmit="return confirm('Révoquer cette session ?');">
                                    <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                                    <input type="hidden" name="action" value="revoke">
                                    <input type="hidden" name="sid" value="<?php echo (int) $s['id']; ?>">
                                    <button class="btn btn-danger btn-sm" title="Révoquer"><i class="fas fa-ban"></i> Révoquer</button>
                                </form>
                            <?php endif; ?>
                            <form method="POST" style="display:inline;" onsubmit="return confirm('Révoquer toutes les sessions de cet utilisateur ?');">
                                <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                                <input type="hidden" name="action" value="revoke_all_user">
                                <input type="hidden" name="uid" value="<?php echo (int) $s['user_id']; ?>">
                                <button class="btn btn-outline btn-sm" title="Tout révoquer"><i class="fas fa-signs-post"></i> Tout révoquer</button>
                            </form>
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
                        <a href="?page=<?php echo $p; ?>&user_id=<?php echo $uidFilter; ?>"><?php echo $p; ?></a>
                    <?php endif; ?>
                <?php endfor; ?>
            </div>
        <?php endif; ?>
    </div>
</div>
<?php include __DIR__ . '/_footer.php'; ?>