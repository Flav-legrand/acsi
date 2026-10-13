<?php
require_once __DIR__ . '/_guard.php';

$db   = db();
$msg  = '';
$type = 'success';
$err  = '';

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$action = $_GET['action'] ?? 'list';
$targetId = (int) ($_GET['id'] ?? 0);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf'] ?? '')) {
        $err = 'Session expirée. Réessayez.';
    } else {
        $targetId = (int) ($_POST['id'] ?? $targetId);
        $a = $_POST['action'] ?? '';
        switch ($a) {
            case 'create':
                $name = trim($_POST['name'] ?? '');
                $desc = trim($_POST['description'] ?? '');
                if ($name === '') {
                    $err = 'Le nom du groupe est obligatoire.';
                } elseif (iam_group_by_name($name)) {
                    $err = 'Un groupe avec ce nom existe déjà.';
                } else {
                    $db->prepare('INSERT INTO `groups` (name, description) VALUES (?, ?)')->execute([$name, $desc]);
                    iam_audit('group_created', "Groupe créé: $name", $iamAdmin['id'], $iamAdmin['email'], $_SERVER['REMOTE_ADDR'] ?? '', $_SERVER['HTTP_USER_AGENT'] ?? '');
                    $msg = 'Groupe créé.';
                }
                break;

            case 'rename':
                $name = trim($_POST['name'] ?? '');
                $desc = trim($_POST['description'] ?? '');
                if ($targetId <= 0 || $name === '') {
                    $err = 'Paramètres invalides.';
                } else {
                    $existing = iam_group_by_name($name);
                    if ($existing && (int) $existing['id'] !== $targetId) {
                        $err = 'Un groupe avec ce nom existe déjà.';
                    } else {
                        $db->prepare('UPDATE `groups` SET name=?, description=? WHERE id=?')->execute([$name, $desc, $targetId]);
                        iam_audit('group_updated', "Groupe modifié: $name", $iamAdmin['id'], $iamAdmin['email'], $_SERVER['REMOTE_ADDR'] ?? '', $_SERVER['HTTP_USER_AGENT'] ?? '');
                        $msg = 'Groupe mis à jour.';
                    }
                }
                break;

            case 'members':
                // Tableau : checkbox membres par ligne (users gérés dans users.php)
                if ($targetId <= 0) { $err = 'Groupe introuvable.'; break; }
                $ids = isset($_POST['members']) && is_array($_POST['members']) ? array_map('intval', $_POST['members']) : [];
                $db->prepare('DELETE FROM user_groups WHERE group_id = ?')->execute([$targetId]);
                $ins = $db->prepare('INSERT IGNORE INTO user_groups (user_id, group_id) VALUES (?, ?)');
                foreach ($ids as $uid) {
                    if ($uid > 0) $ins->execute([$uid, $targetId]);
                }
                iam_audit('group_members', "Membres du groupe #{ $targetId} mis à jour: " . count($ids), $iamAdmin['id'], $iamAdmin['email'], $_SERVER['REMOTE_ADDR'] ?? '', $_SERVER['HTTP_USER_AGENT'] ?? '');
                $msg = 'Membres du groupe mis à jour.';
                break;

            case 'delete':
                $db->prepare('DELETE FROM `groups` WHERE id = ?')->execute([$targetId]);
                iam_audit('group_deleted', "Groupe supprimé #$targetId", $iamAdmin['id'], $iamAdmin['email'], $_SERVER['REMOTE_ADDR'] ?? '', $_SERVER['HTTP_USER_AGENT'] ?? '');
                $msg = 'Groupe supprimé.';
                break;
        }
    }
}

$groups = iam_group_all();
$activeUsers = $db->query('SELECT id, first_name, last_name, email FROM users WHERE status = \'active\' ORDER BY last_name')->fetchAll();

$editGroup = null;
$editMembers = [];
if ($action === 'edit' && $targetId > 0) {
    $editGroup = $db->prepare('SELECT * FROM `groups` WHERE id = ?'); $editGroup->execute([$targetId]);
    $editGroup = $editGroup->fetch();
    if ($editGroup) {
        $stmt = $db->prepare('SELECT user_id FROM user_groups WHERE group_id = ?'); $stmt->execute([$targetId]);
        $editMembers = array_map(fn($r) => (int) $r['user_id'], $stmt->fetchAll());
    }
}

$pageTitle = 'Gestion des groupes';
$active = 'groups';
include __DIR__ . '/_header.php';
?>
<?php if ($err): ?><div class="alert alert-danger"><?php echo htmlspecialchars($err); ?></div><?php endif; ?>
<?php if ($msg): ?><div class="alert alert-success"><?php echo htmlspecialchars($msg); ?></div><?php endif; ?>

<?php if ($action === 'edit' && $editGroup): ?>
    <div class="card">
        <div class="card-body">
            <div class="d-flex justify-between align-center mb-3">
                <div class="card-title">Modifier — <?php echo htmlspecialchars($editGroup['name']); ?></div>
                <a href="<?php echo IAM_BASE_URL; ?>/admin/groups.php" class="btn btn-outline btn-sm">&larr; Retour</a>
            </div>
            <form method="POST" style="max-width:520px;">
                <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                <input type="hidden" name="action" value="rename">
                <input type="hidden" name="id" value="<?php echo (int) $editGroup['id']; ?>">
                <div class="form-group"><label>Nom</label><input type="text" name="name" class="form-control" value="<?php echo htmlspecialchars($editGroup['name']); ?>" required></div>
                <div class="form-group"><label>Description</label><input type="text" name="description" class="form-control" value="<?php echo htmlspecialchars($editGroup['description'] ?? ''); ?>"></div>
                <button type="submit" class="btn btn-primary"><i class="fas fa-save"></i> Enregistrer</button>
            </form>

            <form method="POST" class="mt-3">
                <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                <input type="hidden" name="action" value="members">
                <input type="hidden" name="id" value="<?php echo (int) $editGroup['id']; ?>">
                <div class="card-title">Membres (<?php echo count($editMembers); ?>)</div>
                <div class="table-wrap">
                    <table class="table">
                        <tr><th style="width:40px;"></th><th>Agent</th><th>E-mail</th></tr>
                        <?php foreach ($activeUsers as $u): ?>
                            <tr>
                                <td><input type="checkbox" name="members[]" value="<?php echo (int) $u['id']; ?>" <?php echo in_array((int) $u['id'], $editMembers, true) ? 'checked' : ''; ?>></td>
                                <td><strong><?php echo htmlspecialchars($u['first_name'] . ' ' . $u['last_name']); ?></strong></td>
                                <td><?php echo htmlspecialchars($u['email']); ?></td>
                            </tr>
                        <?php endforeach; ?>
                        <?php if (empty($activeUsers)): ?>
                            <tr><td colspan="3" class="text-center text-muted">Aucun utilisateur actif.</td></tr>
                        <?php endif; ?>
                    </table>
                </div>
                <button type="submit" class="btn btn-primary mt-2"><i class="fas fa-users"></i> Mettre à jour les membres</button>
            </form>
        </div>
    </div>

<?php else: ?>
    <div class="card">
        <div class="card-body">
            <div class="d-flex justify-between align-center mb-3">
                <div class="card-title">Groupes d'utilisateurs</div>
                <button class="btn btn-primary" onclick="document.getElementById('groupModal').style.display='block'"><i class="fas fa-plus"></i> Nouveau groupe</button>
            </div>
            <div class="table-wrap">
                <table class="table">
                    <tr><th>Nom</th><th>Description</th><th>Membres</th><th>Créé le</th><th>Actions</th></tr>
                    <?php if (empty($groups)): ?>
                        <tr><td colspan="5" class="text-center text-muted">Aucun groupe. Créez-en un pour regrouper des agents.</td></tr>
                    <?php else: foreach ($groups as $g): ?>
                        <tr>
                            <td><strong><?php echo htmlspecialchars($g['name']); ?></strong></td>
                            <td><?php echo htmlspecialchars($g['description'] ?? '-'); ?></td>
                            <td><span class="badge badge-info"><?php echo (int) $g['members']; ?></span></td>
                            <td><?php echo htmlspecialchars($g['created_at']); ?></td>
                            <td>
                                <a href="<?php echo IAM_BASE_URL; ?>/admin/groups.php?action=edit&id=<?php echo (int) $g['id']; ?>" class="btn btn-outline btn-sm"><i class="fas fa-pen"></i></a>
                                <form method="POST" style="display:inline;" onsubmit="return confirm('Supprimer ce groupe (les appartenances aussi) ?');">
                                    <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                                    <input type="hidden" name="action" value="delete">
                                    <input type="hidden" name="id" value="<?php echo (int) $g['id']; ?>">
                                    <button class="btn btn-danger btn-sm"><i class="fas fa-trash"></i> Supprimer</button>
                                </form>
                            </td>
                        </tr>
                    <?php endforeach; endif; ?>
                </table>
            </div>
            <p class="text-muted" style="margin-bottom:0;">Les groupes sont attribués aux utilisateurs depuis <a href="<?php echo IAM_BASE_URL; ?>/admin/users.php" style="text-decoration:underline;">Gestion des utilisateurs</a>, ou ici via « Modifier ».</p>
        </div>
    </div>
<?php endif; ?>

<div id="groupModal" style="display:none; position:fixed; inset:0; background:rgba(15,23,42,.55); z-index:1000;" onclick="if(event.target===this)this.style.display='none';">
    <div style="max-width:440px; margin:100px auto; background:#fff; border-radius:14px; padding:26px;">
        <h3 style="margin-top:0;">Nouveau groupe</h3>
        <form method="POST">
            <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
            <input type="hidden" name="action" value="create">
            <div class="form-group"><label>Nom *</label><input type="text" name="name" class="form-control" required></div>
            <div class="form-group"><label>Description</label><input type="text" name="description" class="form-control"></div>
            <div class="d-flex gap-2">
                <button type="submit" class="btn btn-primary"><i class="fas fa-save"></i> Créer</button>
                <button type="button" class="btn btn-outline" onclick="document.getElementById('groupModal').style.display='none';">Annuler</button>
            </div>
        </form>
    </div>
</div>
<?php include __DIR__ . '/_footer.php'; ?>