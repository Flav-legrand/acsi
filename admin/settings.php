<?php
require_once __DIR__ . '/_guard.php';

$db = db();
$msg = '';

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$policy = iam_get_password_policy();

$apiCors = '*';
$apiGeoip = false;
try {
    $v = $db->query("SELECT s_value FROM settings WHERE s_key = 'cors_origins'")->fetchColumn();
    if ($v !== false && trim($v) !== '') $apiCors = $v;
    $g = $db->query("SELECT s_value FROM settings WHERE s_key = 'geoip_lookup'")->fetchColumn();
    $apiGeoip = ($g === '1');
} catch (\Throwable $e) {}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf'] ?? '')) {
        $msg = 'Session expirée.';
    } else {
        foreach (['min_length', 'history', 'expiration_days', 'lockout_threshold', 'lockout_minutes', 'session_lifetime', 'idle_timeout'] as $key) {
            if (isset($_POST[$key])) {
                $v = max(0, (int) $_POST[$key]);
                $db->prepare("UPDATE password_policy SET $key = ? WHERE id = 1")->execute([$v]);
            }
        }
        foreach (['require_upper', 'require_lower', 'require_digit', 'require_special'] as $key) {
            $db->prepare("UPDATE password_policy SET $key = ? WHERE id = 1")->execute([isset($_POST[$key]) ? 1 : 0]);
        }
        $apiSettings = [
            'cors_origins'  => trim((string) ($_POST['cors_origins'] ?? '*')),
            'geoip_lookup'  => isset($_POST['geoip_lookup']) ? '1' : '0',
        ];
        foreach ($apiSettings as $k => $v) {
            $db->prepare('INSERT INTO settings (s_key, s_value) VALUES (?, ?) ON DUPLICATE KEY UPDATE s_value = VALUES(s_value)')->execute([$k, $v]);
        }
        iam_audit('policy_updated', 'Paramètres IAM modifiés', $iamAdmin['id'], $iamAdmin['email'], $_SERVER['REMOTE_ADDR'] ?? '', $_SERVER['HTTP_USER_AGENT'] ?? '');
        $msg = 'Paramètres enregistrés.';
        $policy = iam_get_password_policy();
        $apiCors = '*';
        $apiGeoip = false;
        try {
            $v = $db->query("SELECT s_value FROM settings WHERE s_key = 'cors_origins'")->fetchColumn();
            if ($v !== false && trim($v) !== '') $apiCors = $v;
            $g = $db->query("SELECT s_value FROM settings WHERE s_key = 'geoip_lookup'")->fetchColumn();
            $apiGeoip = ($g === '1');
        } catch (\Throwable $e) {}
    }
}

function yesno(int $v): string { return $v ? 'checked' : ''; }

$pageTitle = 'Paramètres';
$active = 'settings';
include __DIR__ . '/_header.php';
?>
<?php if ($msg): ?><div class="alert alert-success"><?php echo htmlspecialchars($msg); ?></div><?php endif; ?>

<div class="cards-grid">
    <div class="card">
        <div class="card-body">
            <div class="card-title"><i class="fas fa-key"></i> Politique de mot de passe</div>
            <form method="POST" id="policyForm">
                <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                <div class="form-row">
                    <div class="form-group">
                        <label>Longueur minimale</label>
                        <input type="number" name="min_length" class="form-control" value="<?php echo (int) $policy['min_length']; ?>" min="4" max="32">
                    </div>
                    <div class="form-group">
                        <label>Historique (nb de mots de passe mémorisés)</label>
                        <input type="number" name="history" class="form-control" value="<?php echo (int) $policy['history']; ?>" min="0" max="20">
                    </div>
                </div>
                <div class="form-row">
                    <div class="form-group">
                        <label>Expiration (jours)</label>
                        <input type="number" name="expiration_days" class="form-control" value="<?php echo (int) $policy['expiration_days']; ?>" min="0">
                        <div class="form-hint">0 = jamais expiré</div>
                    </div>
                    <div class="form-group">
                        <label>Verrouillage après (tentatives échouées)</label>
                        <input type="number" name="lockout_threshold" class="form-control" value="<?php echo (int) $policy['lockout_threshold']; ?>" min="1">
                    </div>
                </div>
                <div class="form-row">
                    <div class="form-group">
                        <label>Durée de verrouillage (minutes)</label>
                        <input type="number" name="lockout_minutes" class="form-control" value="<?php echo (int) $policy['lockout_minutes']; ?>" min="1">
                    </div>
                    <div class="form-group">
                        <label>Durée de session (secondes)</label>
                        <input type="number" name="session_lifetime" class="form-control" value="<?php echo (int) SESSION_LIFETIME; ?>" min="60">
                    </div>
                </div>
                <div class="form-group">
                    <label>Durée avant inactivité (secondes)</label>
                    <input type="number" name="idle_timeout" class="form-control" value="<?php echo (int) IDLE_TIMEOUT; ?>" min="60">
                </div>
                <div class="card-title mt-3">Complexité exigée</div>
                <label style="display:flex; gap:6px; align-items:center; margin-bottom:8px;">
                    <input type="checkbox" name="require_upper" <?php echo yesno((int) $policy['require_upper']); ?>> Au moins une lettre majuscule
                </label>
                <label style="display:flex; gap:6px; align-items:center; margin-bottom:8px;">
                    <input type="checkbox" name="require_lower" <?php echo yesno((int) $policy['require_lower']); ?>> Au moins une lettre minuscule
                </label>
                <label style="display:flex; gap:6px; align-items:center; margin-bottom:8px;">
                    <input type="checkbox" name="require_digit" <?php echo yesno((int) $policy['require_digit']); ?>> Au moins un chiffre
                </label>
                <label style="display:flex; gap:6px; align-items:center; margin-bottom:16px;">
                    <input type="checkbox" name="require_special" <?php echo yesno((int) $policy['require_special']); ?>> Au moins un caractère spécial
                </label>
                <button type="submit" class="btn btn-primary"><i class="fas fa-save"></i> Enregistrer la politique</button>
            </form>
        </div>
    </div>

    <div class="card">
        <div class="card-body">
            <div class="card-title"><i class="fas fa-gear"></i> Informations plateforme</div>
            <table class="table">
                <tr><th>Nom</th><td><?php echo htmlspecialchars(IAM_NAME); ?></td></tr>
                <tr><th>Version</th><td><?php echo htmlspecialchars(IAM_VERSION); ?></td></tr>
                <tr><th>URL</th><td><?php echo htmlspecialchars(IAM_BASE_URL); ?></td></tr>
                <tr><th>Base de données</th><td><?php echo htmlspecialchars(DB_NAME); ?></td></tr>
                <tr><th>SMTP</th><td>
                    <?php if (!empty(SMTP_USER)): ?>
                        <span class="badge badge-success">configuré</span> <?php echo htmlspecialchars(SMTP_USER); ?>
                    <?php else: ?>
                        <span class="badge badge-warning">non configuré</span> <small>(OTP affiché en démo)</small>
                    <?php endif; ?>
                </td></tr>
            </table>
            <div class="card-title mt-3">Politique active</div>
            <ul style="font-size:13.5px;">
                <li>Longueur minimale : <strong><?php echo (int) $policy['min_length']; ?></strong> caractères</li>
                <li>Historique : <strong><?php echo (int) $policy['history']; ?></strong> mots de passe</li>
                <li>Expiration : <strong><?php echo (int) $policy['expiration_days']; ?></strong> jours</li>
                <li>Verrouillage : après <strong><?php echo (int) $policy['lockout_threshold']; ?></strong> échecs pendant <strong><?php echo (int) $policy['lockout_minutes']; ?></strong> minutes</li>
            </ul>
        </div>
    </div>

    <div class="card">
        <div class="card-body">
            <div class="card-title"><i class="fas fa-globe"></i> API &amp; sécurité</div>
            <form method="POST" id="apiForm">
                <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                <div class="form-group">
                    <label>Origines autorisées (CORS) — liste séparée par des virgules</label>
                    <input type="text" name="cors_origins" class="form-control" value="<?php echo htmlspecialchars($apiCors); ?>" placeholder="*">
                    <div class="form-hint">Ex : https://app.monchantier.ci, http://localhost:8080 — <code>*</code> = toutes les origines (API publique).</div>
                </div>
                <label style="display:flex; gap:6px; align-items:center; margin-bottom:16px;">
                    <input type="checkbox" name="geoip_lookup" <?php echo $apiGeoip ? 'checked' : ''; ?>> Rechercher le pays des adresses IP publiques (service ip-api.com, pas de stockage)
                </label>
                <div class="form-hint" style="margin-bottom:10px;">
                    Protection anti brute-force par IP : <strong><?php echo IP_RATE_MAX_ATTEMPTS; ?></strong> échecs max / <?php echo IP_RATE_WINDOW_MINUTES; ?> min (applicable aux pages et API de connexion).
                </div>
                <button type="submit" class="btn btn-primary"><i class="fas fa-save"></i> Enregistrer</button>
            </form>
        </div>
    </div>
</div>
<?php include __DIR__ . '/_footer.php'; ?>