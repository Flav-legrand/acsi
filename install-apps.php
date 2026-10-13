<?php
// IAM-Local — Enregistrement des applications métier
//   Gestion du Personnel  (Django / Python)  -> app 4  « gestion-personnel »
//   Contrôle Maintenance  (React + Express)  -> app 5  « controle-maintenance »
//
// Crée les applications, leurs permissions, étend les profils de rôles
// globaux existants et enregistre les rôles propres à la Maintenance.
//
// Usage : http://localhost/IAM-Local/install-apps.php
// Idempotent : le script peut être relancé sans dupliquer.
// ============================================================
require_once __DIR__ . '/includes/functions.php';

$messages = [];
$sqlFile  = __DIR__ . '/sql/seed-apps-metier.sql';

// Les profils globaux existent déjà : on ne les recrée pas, on les étend.
iam_ensure_roles_application_column(db());

$db = db();

// ---------- Résolution des placeholders ----------
$adm = $db->query("SELECT u.id, u.email, u.password_hash
                   FROM users u
                   INNER JOIN user_roles ur ON ur.user_id = u.id
                   INNER JOIN roles r ON r.id = ur.role_id
                   WHERE r.code = 'admin' AND u.status = 'active'
                   ORDER BY u.id LIMIT 1")->fetch();

if (!$adm) {
    $messages[] = ['type' => 'danger',
        'text' => 'Aucun administrateur actif trouvé. Lancez d\'abord install.php.'];
}
$adminHash = $adm['password_hash'] ?? '';

// ---------- Exécution sur POST ----------
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $adm) {
    $raw = file_get_contents($sqlFile);
    if ($raw === false) {
        $messages[] = ['type' => 'danger', 'text' => 'Fichier sql/seed-apps-metier.sql introuvable.'];
    } else {
        $sql = strtr($raw, [
            '{{BASE_URL}}'           => IAM_BASE_URL,
            '{{DEMO_PASSWORD_HASH}}' => $adminHash,
            '{{DEMO_EMAIL}}'         => $adm['email'],
            '{{WITH_DEMO}}'          => isset($_POST['with_demo']) ? '1' : '0',
        ]);
        $errors = 0;
        foreach (apps_split_sql($sql) as $stmt) {
            if ($stmt === '') { continue; }
            if (preg_match('/^USE\s+/i', $stmt)) { $stmt = 'USE `' . DB_NAME . '`'; }
            try {
                $db->exec($stmt);
            } catch (PDOException $e) {
                $errors++;
                $messages[] = ['type' => 'warning',
                    'text' => 'Ignoré : ' . $e->getMessage() . ' — ' . substr(preg_replace('/\s+/', ' ', $stmt), 0, 90)];
            }
        }

        // Matrice de référence des 8 rôles sur les 5 applications
        // (Présence, Salaire, IAM Admin, Personnel, Maintenance) :
        // reconstruite après seed-apps-metier.sql pour garantir un
        // état cohérent et reproductible, quel que soit l'historique.
        $matrixFile = __DIR__ . '/sql/seed-roles-matrix.sql';
        $matrixRaw  = file_exists($matrixFile) ? file_get_contents($matrixFile) : false;
        if ($matrixRaw === false) {
            $messages[] = ['type' => 'warning', 'text' => 'Fichier sql/seed-roles-matrix.sql introuvable : matrice des rôles non reconstruite.'];
        } else {
            $matrixSql = strtr($matrixRaw, ['{{BASE_URL}}' => IAM_BASE_URL]);
            foreach (apps_split_sql($matrixSql) as $stmt) {
                if ($stmt === '') { continue; }
                if (preg_match('/^USE\s+/i', $stmt)) { $stmt = 'USE `' . DB_NAME . '`'; }
                try {
                    $db->exec($stmt);
                } catch (PDOException $e) {
                    $errors++;
                    $messages[] = ['type' => 'warning',
                        'text' => 'Matrice ignoré : ' . $e->getMessage() . ' — ' . substr(preg_replace('/\s+/', ' ', $stmt), 0, 90)];
                }
            }
        }

        $messages[] = $errors === 0
            ? ['type' => 'success', 'text' => 'Applications enregistrées : permissions, matrice des 8 rôles et comptes créés.']
            : ['type' => 'warning', 'text' => "Enregistrement terminé avec $errors instruction(s) ignorée(s)."];
    }
}

/**
 * Découpe un script SQL en instructions, en ignorant les commentaires
 * et en préservant les guillemets (chaînes et identifiants MySQL).
 */
function apps_split_sql(string $sql): array
{
    $statements = []; $cur = '';
    $len = strlen($sql);
    $inS = $inD = $inB = $inLine = $inBlock = false;
    for ($i = 0; $i < $len; $i++) {
        $ch   = $sql[$i];
        $next = $i + 1 < $len ? $sql[$i + 1] : '';
        if ($inLine)  { if ($ch === "\n") { $inLine = false; $cur .= $ch; } continue; }
        if ($inBlock) { if ($ch === '*' && $next === '/') { $inBlock = false; $i++; } continue; }
        if ($inS) {
            $cur .= $ch;
            if ($ch === '\\') { if ($next !== '') { $cur .= $next; $i++; } continue; }
            if ($ch === "'") { if ($next === "'") { $cur .= $next; $i++; } else { $inS = false; } }
            continue;
        }
        if ($inD) {
            $cur .= $ch;
            if ($ch === '\\') { if ($next !== '') { $cur .= $next; $i++; } continue; }
            if ($ch === '"') { if ($next === '"') { $cur .= $next; $i++; } else { $inD = false; } }
            continue;
        }
        if ($inB) { $cur .= $ch; if ($ch === '`') { $inB = false; } continue; }
        if ($ch === '-' && $next === '-') { $inLine = true; $i++; continue; }
        if ($ch === '/' && $next === '*') { $inBlock = true; $i++; continue; }
        if ($ch === "'") { $inS = true; $cur .= $ch; continue; }
        if ($ch === '"') { $inD = true; $cur .= $ch; continue; }
        if ($ch === '`') { $inB = true; $cur .= $ch; continue; }
        if ($ch === ';') { $statements[] = trim($cur); $cur = ''; continue; }
        $cur .= $ch;
    }
    if (trim($cur) !== '') { $statements[] = trim($cur); }
    return $statements;
}

// ============================================================
//  Lecture de l'état courant : matrice rôles × applications
// ============================================================
$targetApps = ['gestion-personnel' => 'Gestion du Personnel (Django)',
               'controle-maintenance' => 'Contrôle Maintenance (React)'];
$urls       = ['gestion-personnel' => 'http://localhost:8000',
               'controle-maintenance' => 'http://localhost:5173'];

$apps = [];
foreach ($db->query("SELECT id, code, name, url, color, icon FROM applications
                     WHERE code IN ('gestion-personnel','controle-maintenance')
                     ORDER BY id") as $a) {
    $apps[$a['code']] = $a;
}
$appIds = array_map('intval', array_values(array_column($apps, 'id')));

// permissions des deux applications, par application
$permsByApp = [];
if ($appIds) {
    $in = implode(',', $appIds);
    foreach ($db->query("SELECT id, application_id, code FROM permissions
                         WHERE application_id IN ($in) ORDER BY id") as $p) {
        $permsByApp[(int) $p['application_id']][$p['code']] = true;
    }
}

// tous les rôles : globaux + ceux propres aux deux applications
$roles = [];
if ($appIds) {
    $in = implode(',', $appIds);
    $stmt = $db->query("SELECT DISTINCT r.id, r.application_id, r.name, r.code, r.description
                        FROM roles r
                        LEFT JOIN role_permissions rp ON rp.role_id = r.id
                        LEFT JOIN permissions p ON p.id = rp.permission_id
                        WHERE r.application_id IS NULL OR r.application_id IN ($in)
                        ORDER BY r.application_id IS NULL DESC, r.id");
} else {
    $stmt = $db->query("SELECT id, application_id, name, code, description FROM roles
                        WHERE application_id IS NULL ORDER BY id");
}
foreach ($stmt as $r) { $roles[] = $r; }

// permissions accordées à chaque rôle, par application
$granted = [];
foreach ($roles as $r) {
    foreach ($db->query("SELECT p.application_id, p.code
                         FROM role_permissions rp
                         INNER JOIN permissions p ON p.id = rp.permission_id
                         WHERE rp.role_id = " . (int) $r['id']) as $g) {
        $granted[$r['id']][(int) $g['application_id']][] = $g['code'];
    }
}

// nombre de comptes par rôle sur les deux applications
$nbUsers = [];
if ($appIds) {
    $in = implode(',', $appIds);
    foreach ($db->query("SELECT ur.role_id, COUNT(*) n FROM user_roles ur
                         WHERE ur.application_id IN ($in)
                         GROUP BY ur.role_id") as $u) {
        $nbUsers[(int) $u['role_id']] = (int) $u['n'];
    }
}

// raccourcis d'affichage des codes de permission
$short = fn(string $code): string => preg_replace('/^(rh|mnt)\./', '', $code);
$appColor = fn(int $id): string => $id === 4 ? '#0d6efd' : '#fd7e14';
?>
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Applications métier — <?php echo htmlspecialchars(IAM_NAME); ?></title>
<link rel="stylesheet" href="<?php echo htmlspecialchars(IAM_BASE_URL); ?>/assets/css/iam.css">
<style>
  .matrix td { vertical-align: top; font-size: 12.5px; }
  .chips { display: flex; flex-wrap: wrap; gap: 4px; }
  .chip {
    display: inline-block; padding: 1px 7px; border-radius: 10px;
    background: #eef2f7; color: #334155; font-size: 11.5px;
    font-family: ui-monospace, Consolas, monospace; white-space: nowrap;
  }
  .chip.full { background: #dcfce7; color: #14532d; font-weight: 600; }
  .chip.read { background: #e0e7ff; color: #312e81; }
  .perm-none { color: #94a3b8; font-style: italic; }
</style>
</head>
<body>
<div class="container" style="max-width:1200px;margin:0 auto;padding:24px 16px;">

    <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;margin-bottom:20px;">
        <div>
            <h1 style="margin:0;">Applications métier</h1>
            <p class="text-muted" style="margin:4px 0 0;font-size:14px;max-width:760px;">
                Enregistre <strong>Gestion du Personnel</strong> (Django) et
                <strong>Contrôle Maintenance</strong> (React + Express) dans l'IAM,
                et étend les profils de rôles globaux existants avec les permissions
                de ces deux applications.
            </p>
        </div>
        <div style="display:flex;gap:8px;">
            <a class="btn btn-secondary" href="<?php echo IAM_BASE_URL; ?>/admin/roles.php">Rôles &amp; permissions</a>
            <a class="btn btn-secondary" href="<?php echo IAM_BASE_URL; ?>/admin/apps.php">Applications</a>
        </div>
    </div>

    <?php foreach ($messages as $m): ?>
        <div class="alert alert-<?php echo $m['type']; ?>"><?php echo htmlspecialchars($m['text']); ?></div>
    <?php endforeach; ?>

    <!-- ============ Applications ============ -->
    <div class="card" style="padding:0;margin-bottom:22px;overflow:hidden;">
        <table class="table" style="margin:0;">
            <thead><tr>
                <th>Application</th><th>Code</th><th>URL</th>
                <th style="text-align:center;">Permissions</th><th style="text-align:center;">Rôles</th><th>État</th>
            </tr></thead>
            <tbody>
            <?php foreach ($targetApps as $code => $label):
                $app  = $apps[$code] ?? null;
                $np   = $app ? count($permsByApp[(int) $app['id']] ?? []) : 0;
                $nr   = 0;
                foreach ($roles as $r) { if ($app && (int) $r['application_id'] === (int) $app['id']) { $nr++; } }
            ?>
                <tr>
                    <td>
                        <strong><i class="fas <?php echo htmlspecialchars($app['icon'] ?? 'cubes'); ?>"
                            style="color:<?php echo htmlspecialchars($app['color'] ?? '#94a3b8'); ?>"></i>
                            <?php echo htmlspecialchars($label); ?></strong>
                    </td>
                    <td><code><?php echo htmlspecialchars($code); ?></code></td>
                    <td><code><?php echo htmlspecialchars($urls[$code]); ?></code></td>
                    <td style="text-align:center;"><?php echo $app ? $np : '—'; ?></td>
                    <td style="text-align:center;"><?php echo $app ? $nr : '—'; ?></td>
                    <td>
                        <?php if ($app): ?>
                            <span class="badge badge-success">Enregistrée</span>
                        <?php else: ?>
                            <span class="badge badge-secondary">Non enregistrée</span>
                        <?php endif; ?>
                    </td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>

    <!-- ============ Matrice rôles × applications ============ -->
    <h2 style="margin:26px 0 6px;font-size:17px;">Matrice des vues par rôle</h2>
    <p class="text-muted" style="font-size:13px;margin:0 0 12px;">
        Un profil de rôle est transversal : le même compte obtient une vue
        <em>différente</em> selon l'application, car chaque application ne reçoit
        que les permissions qui lui appartiennent.
        <span class="chip read">lecture</span>
        <span class="chip">écriture</span>
        <span class="chip full">CRUD complet</span>
    </p>

    <div class="card" style="padding:0;overflow:hidden;">
        <table class="table matrix" style="margin:0;">
            <thead><tr>
                <th style="width:210px;">Rôle</th>
                <th>Gestion du Personnel (Django)</th>
                <th>Contrôle Maintenance (React)</th>
                <th style="text-align:center;width:80px;">Comptes</th>
            </tr></thead>
            <tbody>
            <?php foreach ($roles as $r):
                $isGlobal = $r['application_id'] === null;
                $row = '<tr><td><strong>' . htmlspecialchars($r['name']) . '</strong><br>'
                     . '<code style="font-size:12px;">' . htmlspecialchars($r['code']) . '</code>'
                     . ($isGlobal ? '<br><span class="text-muted" style="font-size:11.5px;">profil global</span>'
                                  : '<br><span class="text-muted" style="font-size:11.5px;">rôle de l\'application</span>')
                     . '</td>';
                foreach ($apps as $code => $app) {
                    $aid  = (int) $app['id'];
                    $g    = $granted[$r['id']][$aid] ?? [];
                    $nb   = count($permsByApp[$aid] ?? []);
                    $full = $nb > 0 && count($g) === $nb;
                    $row .= '<td><div class="chips">';
                    if (!$g) {
                        $row .= '<span class="perm-none">aucun accès</span>';
                    } else {
                        foreach ($g as $pc) {
                            $row .= '<span class="chip' . ($full ? ' full' : '') . '">' . htmlspecialchars($short($pc)) . '</span>';
                        }
                    }
                    $row .= '</div></td>';
                }
                $row .= '<td style="text-align:center;">' . ($nbUsers[(int)$r['id']] ?? 0) . '</td></tr>';
                echo $row;
            endforeach; ?>
            </tbody>
        </table>
    </div>

    <!-- ============ Installation ============ -->
    <?php if ($adm): ?>
    <h2 style="margin:28px 0 10px;font-size:17px;">Installation</h2>
    <form method="post" onsubmit="return confirm('Enregistrer les deux applications et étendre les profils de rôles ?');">
        <label style="display:block;margin-bottom:10px;font-size:14px;">
            <input type="checkbox" name="with_demo" value="1" style="margin-right:8px;">
            Créer aussi 3 comptes de démonstration
            (<code>demo.rh@local</code>, <code>demo.maint@local</code>, <code>demo.agent@local</code>)
            pour visualiser les trois vues — même mot de passe que
            <strong><?php echo htmlspecialchars($adm['email']); ?></strong>
        </label>
        <button type="submit" class="btn btn-primary">
            <i class="fas fa-bolt"></i>
            <?php echo $apps ? 'Ré-enregistrer (idempotent)' : 'Enregistrer les applications'; ?>
        </button>
    </form>
    <?php endif; ?>

    <p style="margin-top:28px;" class="text-muted">
        Sources : <code>sql/seed-apps-metier.sql</code> ·
        App Django : <code>GestionPersonnelDjango/</code> ·
        App React : <code>ControleMaintenance/</code>
    </p>
</div>
</body>
</html>
