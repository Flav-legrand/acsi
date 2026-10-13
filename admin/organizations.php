<?php
require_once __DIR__ . '/_guard.php';

$db  = db();
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
        switch ($action) {
            case 'create':
                $name = trim($_POST['name'] ?? '');
                $code = trim($_POST['code'] ?? '');
                $type = $_POST['type'] ?? 'direction';
                $parent = !empty($_POST['parent_id']) ? (int) $_POST['parent_id'] : null;
                if ($name === '') { $err = 'Le nom est obligatoire.'; break; }
                $db->prepare('INSERT INTO organizations (name, code, type, parent_id) VALUES (?, ?, ?, ?)')->execute([$name, $code, $type, $parent]);
                iam_audit('org_created', "Organisation créée: $name", $iamAdmin['id'], $iamAdmin['email'], $_SERVER['REMOTE_ADDR'] ?? '', $_SERVER['HTTP_USER_AGENT'] ?? '');
                $msg = 'Organisation créée.';
                break;

            case 'update':
                $id = (int) ($_POST['id'] ?? 0);
                $db->prepare('UPDATE organizations SET name=?, code=?, type=?, parent_id=? WHERE id=?')
                   ->execute([
                       trim($_POST['name'] ?? ''), trim($_POST['code'] ?? ''), $_POST['type'] ?? 'direction',
                       !empty($_POST['parent_id']) ? (int) $_POST['parent_id'] : null, $id,
                   ]);
                $msg = 'Organisation mise à jour.';
                break;

            case 'delete':
                $id = (int) ($_POST['id'] ?? 0);
                $userCount = (int) $db->query("SELECT COUNT(*) FROM users WHERE organization_id = $id")->fetchColumn();
                if ($userCount > 0) { $err = 'Cette organisation contient des utilisateurs. Déplacez-les d\'abord.'; break; }
                $db->prepare('DELETE FROM organizations WHERE id = ?')->execute([$id]);
                $msg = 'Organisation supprimée.';
                break;
        }
    }
}

$orgs = $db->query("SELECT o.*, (SELECT COUNT(*) FROM users u WHERE u.organization_id = o.id) AS users_count, p.name AS parent_name
                    FROM organizations o LEFT JOIN organizations p ON p.id = o.parent_id
                    ORDER BY o.name")->fetchAll();

// Construire un arbre
function org_tree(array $orgs, ?int $parent): array {
    $nodes = [];
    foreach ($orgs as $o) {
        if ($o['parent_id'] === $parent) {
            $children = org_tree($orgs, (int) $o['id']);
            include_folder($o, $children, $nodes);
        }
    }
    return $nodes;
}
function include_folder(&$o, $children, &$nodes) {
    $o['_children'] = $children;
    $nodes[] = $o;
}

$types = ['ministere', 'direction_generale', 'direction', 'service', 'bureau', 'autre'];
$pageTitle = 'Organisations';
$active = 'organizations';
include __DIR__ . '/_header.php';
?>
<?php if ($err): ?><div class="alert alert-danger"><?php echo htmlspecialchars($err); ?></div><?php endif; ?>
<?php if ($msg): ?><div class="alert alert-success"><?php echo htmlspecialchars($msg); ?></div><?php endif; ?>

<div class="cards-grid">
    <div class="card">
        <div class="card-body">
            <div class="card-title">Structure organisationnelle</div>
            <?php
            $childrenById = [];
            foreach ($orgs as $o) {
                $childrenById[(int) $o['parent_id']][] = $o;
            }
            function render_org_row(array $o, array &$childrenById, int $depth = 0): void {
                $pad = $depth > 0 ? str_repeat('<span class="text-muted">&#9492;&#9472;</span>&nbsp;&nbsp;', $depth - 1) . '<span class="text-muted">&#9492;&#9472;&#9472;</span>&nbsp;&nbsp;' : '';
                echo '<tr>';
                echo '<td>' . $pad . htmlspecialchars($o['name']) . '</td>';
                echo '<td>' . htmlspecialchars($o['code'] ?? '-') . '</td>';
                echo '<td><span class="badge badge-info">' . htmlspecialchars($o['type']) . '</span></td>';
                echo '<td>' . htmlspecialchars($o['parent_name'] ?? '<span class="text-muted">Racine</span>') . '</td>';
                echo '<td><span class="badge badge-primary">' . (int) $o['users_count'] . '</span></td>';
                echo '<td><button class="btn btn-outline btn-sm" onclick="document.getElementById(\'editOrg-' . (int) $o['id'] . '\').style.display=\'block\'"><i class="fas fa-pen"></i> Modifier</button></td>';
                echo '</tr>';
                if (isset($childrenById[(int) $o['id']])) {
                    foreach ($childrenById[(int) $o['id']] as $child) render_org_row($child, $childrenById, $depth + 1);
                }
            }
            ?>
            <div class="table-wrap">
            <table class="table">
                <tr><th>Nom</th><th>Code</th><th>Type</th><th>Parent</th><th>Utilisateurs</th><th>Actions</th></tr>
                <?php if (empty($orgs)): ?>
                    <tr><td colspan="6" class="text-center text-muted">Aucune organisation.</td></tr>
                <?php else: ?>
                    <?php foreach ($orgs as $o): if ($o['parent_id'] === null) render_org_row($o, $childrenById, 0); endforeach; ?>
                <?php endif; ?>
            </table>
            </div>
        </div>
    </div>

    <div class="card">
        <div class="card-body">
            <div class="card-title">Nouvelle organisation</div>
            <form method="POST">
                <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                <input type="hidden" name="action" value="create">
                <div class="form-group"><label>Nom *</label><input type="text" name="name" class="form-control" required></div>
                <div class="form-row">
                    <div class="form-group"><label>Code</label><input type="text" name="code" class="form-control"></div>
                    <div class="form-group">
                        <label>Type</label>
                        <select name="type" class="form-control">
                            <?php foreach ($types as $t): ?><option value="<?php echo $t; ?>"><?php echo ucwords(str_replace('_', ' ', $t)); ?></option><?php endforeach; ?>
                        </select>
                    </div>
                </div>
                <div class="form-group">
                    <label>Organisation parente</label>
                    <select name="parent_id" class="form-control">
                        <option value="">— Aucune (racine) —</option>
                        <?php foreach ($orgs as $o): ?><option value="<?php echo $o['id']; ?>"><?php echo htmlspecialchars($o['name']); ?></option><?php endforeach; ?>
                    </select>
                </div>
                <button type="submit" class="btn btn-success"><i class="fas fa-plus"></i> Créer</button>
            </form>
        </div>
    </div>
</div>

<?php foreach ($orgs as $o): ?>
    <div id="editOrg-<?php echo (int) $o['id']; ?>" style="display:none; position:fixed; inset:0; background:rgba(15,23,42,.55); z-index:1000;" onclick="if(event.target===this)this.style.display='none';">
        <div style="max-width:440px; margin:80px auto; background:#fff; border-radius:14px; padding:24px;">
            <h3 style="margin-top:0;">Modifier — <?php echo htmlspecialchars($o['name']); ?></h3>
            <form method="POST">
                <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                <input type="hidden" name="action" value="update">
                <input type="hidden" name="id" value="<?php echo (int) $o['id']; ?>">
                <div class="form-group"><label>Nom</label><input type="text" name="name" class="form-control" value="<?php echo htmlspecialchars($o['name']); ?>"></div>
                <div class="form-row">
                    <div class="form-group"><label>Code</label><input type="text" name="code" class="form-control" value="<?php echo htmlspecialchars($o['code'] ?? ''); ?>"></div>
                    <div class="form-group">
                        <label>Type</label>
                        <select name="type" class="form-control">
                            <?php foreach ($types as $t): ?>
                                <option value="<?php echo $t; ?>" <?php echo $o['type'] === $t ? 'selected' : ''; ?>><?php echo ucwords(str_replace('_', ' ', $t)); ?></option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                </div>
                <div class="form-group">
                    <label>Parent</label>
                    <select name="parent_id" class="form-control">
                        <option value="">— Racine —</option>
                        <?php foreach ($orgs as $po): if ((int) $po['id'] !== (int) $o['id']): ?>
                            <option value="<?php echo $po['id']; ?>" <?php echo (int) $o['parent_id'] === (int) $po['id'] ? 'selected' : ''; ?>><?php echo htmlspecialchars($po['name']); ?></option>
                        <?php endif; endforeach; ?>
                    </select>
                </div>
                <div class="d-flex gap-2">
                    <button type="submit" class="btn btn-primary">Enregistrer</button>
                    <button type="button" class="btn btn-outline" onclick="document.getElementById('editOrg-<?php echo (int) $o['id']; ?>').style.display='none';">Fermer</button>
                </div>
            </form>
        </div>
    </div>
<?php endforeach; ?>
<?php include __DIR__ . '/_footer.php'; ?>