<?php
require_once __DIR__ . '/_guard.php';

$db = db();

$page    = max(1, (int) ($_GET['page'] ?? 1));
$perPage = 30;
$search  = trim($_GET['q'] ?? '');
$action  = trim($_GET['action'] ?? '');
$offset  = ($page - 1) * $perPage;

$where  = '';
$params = [];
$conditions = [];
if ($search !== '') {
    $conditions[] = '(al.email LIKE ? OR al.action LIKE ? OR al.details LIKE ? OR al.ip_address LIKE ? OR al.application LIKE ? OR al.country LIKE ?)';
    $s = "%$search%";
    $params = [$s, $s, $s, $s, $s, $s];
}
if ($action !== '') {
    $conditions[] = 'al.action = ?';
    $params[] = $action;
}
if (!empty($conditions)) $where = 'WHERE ' . implode(' AND ', $conditions);

$stmt = $db->prepare("SELECT COUNT(*) FROM audit_logs al $where");
$stmt->execute($params);
$total = (int) $stmt->fetchColumn();

$stmt = $db->prepare("SELECT al.*, u.username FROM audit_logs al LEFT JOIN users u ON u.id = al.user_id $where ORDER BY al.created_at DESC LIMIT $perPage OFFSET $offset");
$stmt->execute($params);
$logs = $stmt->fetchAll();

$lastPage = (int) ceil($total / $perPage);

// Actions disponibles pour le filtre
$distinctActions = $db->query('SELECT DISTINCT action FROM audit_logs ORDER BY action')->fetchAll(PDO::FETCH_COLUMN);

$pageTitle = 'Journal d\'audit';
$active = 'audit';
include __DIR__ . '/_header.php';
?>
<div class="card">
    <div class="card-body">
        <form method="GET" class="d-flex gap-2 mb-3 flex-wrap">
            <input type="text" name="q" class="form-control" style="max-width:340px;" placeholder="Rechercher..." value="<?php echo htmlspecialchars($search); ?>">
            <select name="action" class="form-control" style="max-width:220px;">
                <option value="">— Toutes les actions —</option>
                <?php foreach ($distinctActions as $a): ?>
                    <option value="<?php echo htmlspecialchars($a); ?>" <?php echo $action === $a ? 'selected' : ''; ?>><?php echo htmlspecialchars($a); ?></option>
                <?php endforeach; ?>
            </select>
            <button class="btn btn-primary"><i class="fas fa-magnifying-glass"></i> Filtrer</button>
            <?php if ($search !== '' || $action !== ''): ?>
                <a href="<?php echo IAM_BASE_URL; ?>/admin/audit.php" class="btn btn-outline">Effacer</a>
            <?php endif; ?>
        </form>

        <div class="table-wrap">
            <table class="table">
                <tr><th>Date</th><th>Action</th><th>Utilisateur</th><th>Détails</th><th>Application</th><th>IP / Pays</th><th>Navigateur</th></tr>
                <?php if (empty($logs)): ?>
                    <tr><td colspan="7" class="text-center text-muted">Aucun événement.</td></tr>
                <?php else: foreach ($logs as $l): ?>
                    <tr>
                        <td><?php echo htmlspecialchars($l['created_at']); ?></td>
                        <td><span class="badge badge-info"><?php echo htmlspecialchars($l['action']); ?></span></td>
                        <td>
                            <?php echo htmlspecialchars($l['email'] ?? '-'); ?>
                            <?php if ($l['username']): ?><br><small class="text-muted">@<?php echo htmlspecialchars($l['username']); ?></small><?php endif; ?>
                        </td>
                        <td style="max-width:300px;"><small><?php echo htmlspecialchars($l['details'] ?? ''); ?></small></td>
                        <td><?php echo $l['application'] ? '<span class="badge badge-muted">' . htmlspecialchars($l['application']) . '</span>' : '<span class="text-muted">-</span>'; ?></td>
                        <td>
                            <span class="mono"><?php echo htmlspecialchars($l['ip_address'] ?? '-'); ?></span>
                            <?php if ($l['country']): ?><br><small class="text-muted"><?php echo htmlspecialchars($l['country']); ?></small><?php endif; ?>
                        </td>
                        <td><small class="text-muted"><?php echo htmlspecialchars(substr($l['user_agent'] ?? '-', 0, 38)); ?></small></td>
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
                        <a href="?page=<?php echo $p; ?>&q=<?php echo urlencode($search); ?>&action=<?php echo urlencode($action); ?>"><?php echo $p; ?></a>
                    <?php endif; ?>
                <?php endfor; ?>
            </div>
        <?php endif; ?>

        <p class="text-muted mt-2"><?php echo $total; ?> événement(s) journalisé(s).</p>
    </div>
</div>
<?php include __DIR__ . '/_footer.php'; ?>