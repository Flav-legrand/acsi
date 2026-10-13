<?php
// IAM-Local — Fonctions utilitaires : authentification, audit, jetons, validation

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/config_bootstrap.php';

/* ========================================================
   SESSION
   ======================================================== */

function iam_session_start(): void
{
    if (session_status() === PHP_SESSION_NONE) {
        session_name(SESSION_COOKIE_NAME);
        ini_set('session.cookie_httponly', 1);
        ini_set('session.use_strict_mode', 1);
        session_start();
    }
}

function iam_is_logged_in(): bool
{
    iam_session_start();
    if (empty($_SESSION['iam_user'])) return false;
    if (empty($_SESSION['iam_last_active'])) return false;
    $policy = iam_get_password_policy();
    $idle = ($policy['idle_timeout'] ?? IDLE_TIMEOUT) > 0 ? (int) $policy['idle_timeout'] : IDLE_TIMEOUT;
    if (time() - $_SESSION['iam_last_active'] > $idle) {
        iam_session_destroy();
        return false;
    }
    $_SESSION['iam_last_active'] = time();
    return true;
}

function iam_session_destroy(): void
{
    iam_session_start();
    $uid = $_SESSION['iam_user']['id'] ?? null;
    if ($uid && !empty($_SESSION['iam_session_token'])) {
        try {
            $db = db();
            $stmt = $db->prepare('UPDATE sessions SET revoked = 1 WHERE user_id = ? AND session_token = ? AND revoked = 0');
            $stmt->execute([$uid, $_SESSION['iam_session_token']]);
        } catch (\Throwable $e) {}
    }
    session_destroy();
}

/* ========================================================
   MOT DE PASSE
   ======================================================== */

function iam_hash_password(string $password): string
{
    return password_hash($password, PASSWORD_BCRYPT);
}

function iam_verify_password(string $password, string $hash): bool
{
    return password_verify($password, $hash);
}

function iam_get_password_policy(): array
{
    $db = db();
    $policy = $db->query('SELECT * FROM password_policy WHERE id = 1')->fetch();
    if (!$policy) {
        return [
            'min_length'        => 8,
            'require_upper'     => 1,
            'require_lower'     => 1,
            'require_digit'     => 1,
            'require_special'   => 1,
            'history'           => 5,
            'expiration_days'   => 90,
            'lockout_threshold' => 5,
            'lockout_minutes'   => 30,
            'session_lifetime'  => SESSION_LIFETIME,
            'idle_timeout'      => IDLE_TIMEOUT,
        ];
    }
    return $policy;
}

function iam_validate_password(string $password, array $policy = []): array
{
    if (empty($policy)) $policy = iam_get_password_policy();
    $errors = [];
    if (strlen($password) < $policy['min_length'])
        $errors[] = "Le mot de passe doit faire au moins {$policy['min_length']} caractères.";
    if ($policy['require_upper'] && !preg_match('/[A-Z]/', $password))
        $errors[] = "Le mot de passe doit contenir au moins une majuscule.";
    if ($policy['require_lower'] && !preg_match('/[a-z]/', $password))
        $errors[] = "Le mot de passe doit contenir au moins une minuscule.";
    if ($policy['require_digit'] && !preg_match('/[0-9]/', $password))
        $errors[] = "Le mot de passe doit contenir au moins un chiffre.";
    if ($policy['require_special'] && !preg_match('/[^A-Za-z0-9]/', $password))
        $errors[] = "Le mot de passe doit contenir au moins un caractère spécial.";
    return $errors;
}

function iam_check_password_history(int $user_id, string $new_password, int $historyCount): bool
{
    $db = db();
    $stmt = $db->prepare('SELECT password_hash FROM password_history WHERE user_id = ? ORDER BY id DESC LIMIT ?');
    $stmt->execute([$user_id, $historyCount]);
    while ($row = $stmt->fetch()) {
        if (password_verify($new_password, $row['password_hash'])) {
            return true;
        }
    }
    return false;
}

/**
 * Le mot de passe de l'utilisateur est-il expiré ?
 * expiration_days <= 0 signifie "jamais" (désactivé).
 */
function iam_password_expired(int $userId): bool
{
    $policy = iam_get_password_policy();
    $days   = (int) $policy['expiration_days'];
    if ($days <= 0) return false;
    $db = db();
    $stmt = $db->prepare('SELECT created_at FROM password_history WHERE user_id = ? ORDER BY id DESC LIMIT 1');
    $stmt->execute([$userId]);
    $last = $stmt->fetchColumn();
    if (!$last) return false;
    return strtotime((string) $last) + $days * 86400 < time();
}

function iam_update_password(int $user_id, string $password): bool
{
    $db = db();
    $hash = iam_hash_password($password);
    $policy = iam_get_password_policy();
    $stmt = $db->prepare('UPDATE users SET password_hash = ?, must_change_password = 0, updated_at = NOW() WHERE id = ?');
    $ok = $stmt->execute([$hash, $user_id]);
    if ($ok) {
        $stmt2 = $db->prepare('INSERT INTO password_history (user_id, password_hash) VALUES (?, ?)');
        $stmt2->execute([$user_id, $hash]);
    }
    return $ok;
}

/* ========================================================
   UTILISATEURS
   ======================================================== */

function iam_find_user(string $identifier): ?array
{
    $db = db();
    $stmt = $db->prepare('SELECT * FROM users WHERE email = ? OR username = ? OR phone = ? LIMIT 1');
    $stmt->execute([$identifier, $identifier, $identifier]);
    return $stmt->fetch() ?: null;
}

function iam_find_user_by_id(int $id): ?array
{
    $db = db();
    $stmt = $db->prepare('SELECT * FROM users WHERE id = ? LIMIT 1');
    $stmt->execute([$id]);
    return $stmt->fetch() ?: null;
}

/* ========================================================
   GROUPES
   ======================================================== */

function iam_group_all(): array
{
    $db = db();
    $stmt = $db->query('SELECT g.*, COUNT(ug.user_id) AS members FROM `groups` g LEFT JOIN user_groups ug ON ug.group_id = g.id GROUP BY g.id ORDER BY g.name');
    return $stmt ? $stmt->fetchAll() : [];
}

function iam_group_by_name(string $name): ?array
{
    $db = db();
    $stmt = $db->prepare('SELECT * FROM `groups` WHERE name = ? LIMIT 1');
    $stmt->execute([$name]);
    return $stmt->fetch() ?: null;
}

function iam_user_groups(int $userId): array
{
    $db = db();
    $stmt = $db->prepare('SELECT g.id, g.name FROM `groups` g INNER JOIN user_groups ug ON ug.group_id = g.id WHERE ug.user_id = ? ORDER BY g.name');
    $stmt->execute([$userId]);
    return $stmt->fetchAll();
}

function iam_set_user_groups(int $userId, array $ids): void
{
    $db = db();
    $ids = array_values(array_unique(array_filter(array_map('intval', $ids), fn($i) => $i > 0)));
    $db->prepare('DELETE FROM user_groups WHERE user_id = ?')->execute([$userId]);
    $ins = $db->prepare('INSERT IGNORE INTO user_groups (user_id, group_id) VALUES (?, ?)');
    foreach ($ids as $gid) {
        $ins->execute([$userId, $gid]);
    }
}

/* ========================================================
   OUTILS D'IMPORT
   ======================================================== */

function iam_random_password(): string
{
    $policy = iam_get_password_policy();
    $pool = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%';
    $len = max((int) $policy['min_length'], 12);
    $pw = '';
    if ($policy['require_upper']) $pw .= chr(66 + random_int(0, 23));
    if ($policy['require_lower']) $pw .= chr(98 + random_int(0, 23));
    if ($policy['require_digit']) $pw .= chr(50 + random_int(0, 7));
    if ($policy['require_special']) $pw .= ['!', '@', '#', '$', '%'][random_int(0, 4)];
    for ($i = strlen($pw); $i < $len; $i++) {
        $pw .= $pool[random_int(0, strlen($pool) - 1)];
    }
    return str_shuffle($pw);
}

/**
 * Parse un CSV UTF-8 (délimiteur auto `;` ou `,`, guillemets, CRLF, BOM).
 * Retourne [headers => [], rows => []].
 */
function iam_parse_csv(string $text): array
{
    $text = str_replace("\xEF\xBB\xBF", '', $text);
    $text = str_replace(["\r\n", "\r"], "\n", $text);
    $firstLine = strtok($text, "\n");
    if (substr_count($firstLine ?: '', ';') >= substr_count($firstLine ?: '', ',')) {
        $delim = ';';
    } else {
        $delim = ',';
    }
    $rows = [];
    foreach (explode("\n", $text) as $line) {
        $line = rtrim($line, "\n");
        if (trim($line) === '') continue;
        $cells = [];
        $cur = '';
        $inQuotes = false;
        $len = strlen($line);
        for ($i = 0; $i < $len; $i++) {
            $ch = $line[$i];
            if ($ch === '"') {
                if ($inQuotes && isset($line[$i + 1]) && $line[$i + 1] === '"') {
                    $cur .= '"';
                    $i++;
                } else {
                    $inQuotes = !$inQuotes;
                }
            } elseif ($ch === $delim && !$inQuotes) {
                $cells[] = trim($cur);
                $cur = '';
            } else {
                $cur .= $ch;
            }
        }
        $cells[] = trim($cur);
        $rows[] = $cells;
    }
    if (empty($rows)) return ['headers' => [], 'rows' => []];
    $headers = array_map(fn($h) => strtolower(str_replace([' ', '-'], '_', trim($h))), $rows[0]);
    return ['headers' => $headers, 'rows' => array_slice($rows, 1)];
}

/**
 * Tris proposés pour les listes d'applications : clé => [libellé, ORDER BY].
 * $a : alias SQL de la table applications. La clé vient de l'URL : seules
 * les clés de cette liste sont acceptées (jamais de SQL venant du client).
 */
function iam_app_sort_options(string $a = 'a', bool $withStatus = true): array
{
    $options = [
        'nom'      => ['Nom (A → Z)', "$a.name ASC"],
        'nom_desc' => ['Nom (Z → A)', "$a.name DESC"],
        'recent'   => ['Date d’ajout (récentes d’abord)', "$a.created_at DESC, $a.id DESC"],
        'ancien'   => ['Date d’ajout (anciennes d’abord)', "$a.created_at ASC, $a.id ASC"],
        'code'     => ['Code technique', "$a.code ASC"],
    ];
    if ($withStatus) {
        $options['statut'] = ['Statut (actives d’abord)', "$a.active DESC, $a.name ASC"];
    }
    return $options;
}

/**
 * Tri choisi pour une liste : paramètre ?tri=… validé, sinon dernier choix
 * mémorisé en session pour cette liste, sinon $default.
 */
function iam_list_sort(string $list, array $options, string $default): string
{
    $asked = (string) ($_GET['tri'] ?? '');
    if ($asked !== '' && isset($options[$asked])) {
        if (session_status() === PHP_SESSION_ACTIVE) $_SESSION['iam_sort'][$list] = $asked;
        return $asked;
    }
    $saved = (string) ($_SESSION['iam_sort'][$list] ?? '');
    return isset($options[$saved]) ? $saved : $default;
}

/** Liste déroulante « Trier par » (formulaire GET, envoi au changement). */
function iam_sort_select(array $options, string $current, array $keep = []): string
{
    $html = '<form method="GET" class="d-flex align-center gap-2" style="margin:0;">';
    foreach ($keep as $name => $value) {
        if ($name === 'tri' || $name === 'page' || is_array($value)) continue;
        $html .= '<input type="hidden" name="' . htmlspecialchars((string) $name) . '" value="' . htmlspecialchars((string) $value) . '">';
    }
    $html .= '<label for="iam-tri" class="text-muted" style="font-size:13px; white-space:nowrap;"><i class="fas fa-arrow-down-wide-short"></i> Trier par</label>'
           . '<select id="iam-tri" name="tri" class="form-control" style="width:auto;" onchange="this.form.submit()">';
    foreach ($options as $key => [$label]) {
        $html .= '<option value="' . htmlspecialchars($key) . '"' . ($key === $current ? ' selected' : '') . '>' . htmlspecialchars($label) . '</option>';
    }
    return $html . '</select><noscript><button class="btn btn-outline btn-sm">OK</button></noscript></form>';
}

function iam_user_apps(int $user_id, string $sort = 'nom'): array
{
    $options = iam_app_sort_options('a', false);
    $orderBy = ($options[$sort] ?? $options['nom'])[1];
    $db = db();
    $stmt = $db->prepare('SELECT a.id, a.code, a.name, a.description, a.url, a.logo, a.color, a.icon, a.is_system, a.created_at
        FROM applications a
        INNER JOIN user_roles ur ON ur.application_id = a.id AND ur.user_id = ?
        WHERE a.active = 1
        GROUP BY a.id
        ORDER BY ' . $orderBy);
    $stmt->execute([$user_id]);
    return $stmt->fetchAll();
}

function iam_user_roles(int $user_id, ?int $app_id = null): array
{
    $db = db();
    if ($app_id !== null) {
        $stmt = $db->prepare('SELECT r.id, r.name, r.code
            FROM roles r INNER JOIN user_roles ur ON ur.role_id = r.id
            WHERE ur.user_id = ? AND ur.application_id = ?');
        $stmt->execute([$user_id, $app_id]);
    } else {
        $stmt = $db->prepare('SELECT r.id, r.name, r.code
            FROM roles r INNER JOIN user_roles ur ON ur.role_id = r.id
            WHERE ur.user_id = ?
            GROUP BY r.id');
        $stmt->execute([$user_id]);
    }
    return $stmt->fetchAll();
}

function iam_user_permissions(int $user_id, ?int $app_id = null): array
{
    $db = db();
    if ($app_id !== null) {
        // ur.application_id est volontairement filtré : une permission
        // n'est accordée que sur l'application pour laquelle le rôle a
        // été attribué. Sans ce filtre, un rôle global attribué sur
        // l'application A appliquerait aussi ses permissions sur
        // l'application B pour laquelle il n'a jamais été attribué.
        $stmt = $db->prepare('SELECT DISTINCT p.id, p.code, p.name, p.description
            FROM permissions p
            INNER JOIN role_permissions rp ON rp.permission_id = p.id
            INNER JOIN user_roles ur ON ur.role_id = rp.role_id
            WHERE ur.user_id = ? AND ur.application_id = ? AND p.application_id = ?');
        $stmt->execute([$user_id, $app_id, $app_id]);
    } else {
        $stmt = $db->prepare('SELECT DISTINCT p.id, p.code, p.name, p.application_id
            FROM permissions p
            INNER JOIN role_permissions rp ON rp.permission_id = p.id
            INNER JOIN user_roles ur ON ur.role_id = rp.role_id
            WHERE ur.user_id = ?');
        $stmt->execute([$user_id]);
    }
    return $stmt->fetchAll();
}

function iam_user_has_permission(int $user_id, string $permissionCode, ?int $app_id = null): bool
{
    $db = db();
    if ($app_id !== null) {
        $stmt = $db->prepare('SELECT COUNT(*) FROM role_permissions rp
            INNER JOIN user_roles ur ON ur.role_id = rp.role_id
            INNER JOIN permissions p ON p.id = rp.permission_id
            WHERE ur.user_id = ? AND ur.application_id = ? AND p.code = ? AND p.application_id = ?');
        $stmt->execute([$user_id, $app_id, $permissionCode, $app_id]);
    } else {
        $stmt = $db->prepare('SELECT COUNT(*) FROM role_permissions rp
            INNER JOIN user_roles ur ON ur.role_id = rp.role_id
            INNER JOIN permissions p ON p.id = rp.permission_id
            WHERE ur.user_id = ? AND p.code = ?');
        $stmt->execute([$user_id, $permissionCode]);
    }
    return $stmt->fetchColumn() > 0;
}

/**
 * L'utilisateur porte-t-il au moins un rôle sur l'application ?
 * Le rôle doit être attribué SUR cette application (user_roles) ET
 * appartenir à cette application (roles.application_id) : un rôle
 * d'une autre application rattaché par erreur ne donne pas l'accès.
 * Aucune exception pour l'administrateur IAM : il doit lui aussi
 * porter un rôle sur l'application pour s'y connecter en OAuth/OIDC.
 */
function iam_user_has_role_on_application(int $user_id, int $app_id): bool
{
    if ($app_id <= 0) return false;
    $stmt = db()->prepare('SELECT COUNT(*) FROM user_roles ur
        INNER JOIN roles r ON r.id = ur.role_id
        WHERE ur.user_id = ? AND ur.application_id = ? AND r.application_id = ?');
    $stmt->execute([$user_id, $app_id, $app_id]);
    return (int) $stmt->fetchColumn() > 0;
}

/* ========================================================
   RÔLES PAR APPLICATION (client roles — modèle Keycloak)
   ======================================================== */

/**
 * Migration auto : ajoute roles.application_id si la base existe déjà
 * (installée avant la notion de rôles par application) et fait
 * correspondre la clé unique (application_id, code).
 */
function iam_ensure_roles_application_column(PDO $db): void
{
    static $done = false;
    if ($done) return;
    $done = true;

    $stmt = $db->prepare("SELECT COUNT(*) FROM information_schema.columns
        WHERE table_schema = DATABASE() AND table_name = 'roles' AND column_name = 'application_id'");
    $stmt->execute();
    if ((int) $stmt->fetchColumn() === 0) {
        $db->exec("ALTER TABLE roles ADD COLUMN application_id INT NULL COMMENT 'NULL = rôle global de la plateforme, sinon id de l''application propriétaire' AFTER id");
    }

    $stmt = $db->prepare("SELECT COUNT(*) FROM information_schema.table_constraints
        WHERE constraint_schema = DATABASE() AND table_name = 'roles' AND constraint_name = 'fk_role_app'");
    $stmt->execute();
    if ((int) $stmt->fetchColumn() === 0) {
        try { $db->exec("ALTER TABLE roles ADD CONSTRAINT fk_role_app FOREIGN KEY (application_id) REFERENCES applications(id) ON DELETE CASCADE"); }
        catch (\Throwable $e) {}
    }

    $stmt = $db->prepare("SELECT COUNT(*) FROM information_schema.statistics
        WHERE table_schema = DATABASE() AND table_name = 'roles' AND index_name = 'uq_role_app_code'");
    $stmt->execute();
    if ((int) $stmt->fetchColumn() === 0) {
        try { $db->exec('ALTER TABLE roles DROP INDEX uq_role_code'); } catch (\Throwable $e) {}
        try { $db->exec('ALTER TABLE roles ADD UNIQUE KEY uq_role_app_code (application_id, code)'); } catch (\Throwable $e) {}
    }
}

/**
 * Rôles disponibles pour une application :
 *  - les rôles propres à cette application (client roles),
 *  - + les rôles globaux de la plateforme (application_id NULL).
 * Pour $appId = null : seuls les rôles globaux.
 */
function iam_app_roles(?int $appId): array
{
    iam_ensure_roles_application_column(db());
    $db = db();
    if ($appId !== null) {
        // Tous les rôles sont locaux : seuls les rôles de l'application
        // sont attribuables sur celle-ci.
        $stmt = $db->prepare('SELECT * FROM roles WHERE application_id = ? ORDER BY name');
        $stmt->execute([$appId]);
    } else {
        $stmt = $db->query('SELECT * FROM roles ORDER BY name');
    }
    return $stmt->fetchAll();
}

/**
 * Ce rôle peut-il être attribué sur cette application ?
 * Tous les rôles sont locaux : il doit appartenir à l'application.
 */
function iam_role_allowed_for_app(int $roleId, int $appId): bool
{
    iam_ensure_roles_application_column(db());
    $db = db();
    $stmt = $db->prepare('SELECT COUNT(*) FROM roles WHERE id = ? AND application_id = ?');
    $stmt->execute([$roleId, $appId]);
    return (int) $stmt->fetchColumn() > 0;
}

/* ========================================================
   LOGIN / LOCKOUT / SESSION
   ======================================================== */

function iam_record_login_attempt(string $identifier, string $ip, string $ua, bool $success): void
{
    $db = db();
    $stmt = $db->prepare('INSERT INTO login_attempts (identifier, ip_address, user_agent, success) VALUES (?, ?, ?, ?)');
    $stmt->execute([$identifier, $ip, $ua, $success ? 1 : 0]);
}

function iam_get_failed_attempts(string $identifier): int
{
    $db = db();
    $stmt = $db->prepare('SELECT COUNT(*) FROM login_attempts
        WHERE identifier = ? AND success = 0 AND created_at > DATE_SUB(NOW(), INTERVAL ? MINUTE)');
    $stmt->execute([$identifier, LOCKOUT_MINUTES]);
    return (int) $stmt->fetchColumn();
}

function iam_increment_failed_attempts(int $user_id): void
{
    $db = db();
    $stmt = $db->prepare('UPDATE users SET failed_attempts = failed_attempts + 1, updated_at = NOW() WHERE id = ?');
    $stmt->execute([$user_id]);
}

function iam_lock_user(int $user_id, int $minutes): void
{
    $db = db();
    $stmt = $db->prepare('UPDATE users SET status = \'locked\', locked_until = DATE_ADD(NOW(), INTERVAL ? MINUTE), updated_at = NOW() WHERE id = ?');
    $stmt->execute([$minutes, $user_id]);
}

function iam_is_locked(array $user): bool
{
    if ($user['status'] === 'locked') {
        if ($user['locked_until'] && strtotime($user['locked_until']) > time()) return true;
        // Déverrouillage automatique expiré
        iam_unlock_user((int) $user['id']);
        return false;
    }
    return false;
}

function iam_unlock_user(int $user_id): void
{
    $db = db();
    $stmt = $db->prepare('UPDATE users SET status = \'active\', locked_until = NULL, failed_attempts = 0, updated_at = NOW() WHERE id = ?');
    $stmt->execute([$user_id]);
}

function iam_reset_failed_attempts(int $user_id): void
{
    $db = db();
    $stmt = $db->prepare('UPDATE users SET failed_attempts = 0, updated_at = NOW() WHERE id = ?');
    $stmt->execute([$user_id]);
}

function iam_create_session(int $user_id, string $ip, string $ua): string
{
    $db = db();
    $policy = iam_get_password_policy();
    $lifetime = ($policy['session_lifetime'] ?? SESSION_LIFETIME) > 0 ? (int) $policy['session_lifetime'] : SESSION_LIFETIME;
    $token = bin2hex(random_bytes(32));
    $expires = date('Y-m-d H:i:s', time() + $lifetime);
    $stmt = $db->prepare('INSERT INTO sessions (user_id, session_token, ip_address, user_agent, expires_at) VALUES (?, ?, ?, ?, ?)');
    $stmt->execute([$user_id, $token, $ip, substr($ua, 0, 255), $expires]);
    return $token;
}

function iam_touch_session(int $user_id, string $token): void
{
    $db = db();
    $policy = iam_get_password_policy();
    $lifetime = ($policy['session_lifetime'] ?? SESSION_LIFETIME) > 0 ? (int) $policy['session_lifetime'] : SESSION_LIFETIME;
    $stmt = $db->prepare('UPDATE sessions SET last_active_at = NOW(), expires_at = DATE_ADD(NOW(), INTERVAL ? SECOND) WHERE user_id = ? AND session_token = ? AND revoked = 0');
    $stmt->execute([$lifetime, $user_id, $token]);
}

function iam_revoke_all_sessions(int $user_id): void
{
    $db = db();
    $stmt = $db->prepare('UPDATE sessions SET revoked = 1 WHERE user_id = ? AND revoked = 0');
    $stmt->execute([$user_id]);
}

function iam_revoke_session(int $sessionId): void
{
    $db = db();
    $stmt = $db->prepare('UPDATE sessions SET revoked = 1 WHERE id = ?');
    $stmt->execute([$sessionId]);
}

/* ========================================================
   SSO TOKENS (usage unique, expiration courte)
   ======================================================== */

function iam_create_sso_token(int $user_id, int $appId, string $returnUrl, string $ip, string $ua): string
{
    $db = db();
    $token = bin2hex(random_bytes(32));
    $expires = date('Y-m-d H:i:s', time() + SSO_TOKEN_LIFETIME);
    $stmt = $db->prepare('INSERT INTO sso_tokens (token, user_id, application_id, return_url, expires_at, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?)');
    $stmt->execute([$token, $user_id, $appId, $returnUrl, $expires, $ip, substr($ua, 0, 255)]);
    return $token;
}

function iam_consume_sso_token(string $token, string $ip, string $ua): ?array
{
    $db = db();
    $db->beginTransaction();
    try {
        $stmt = $db->prepare('SELECT * FROM sso_tokens
            WHERE token = ? AND consumed_at IS NULL
            LIMIT 1 FOR UPDATE');
        $stmt->execute([$token]);
        $row = $stmt->fetch();
        if (!$row || strtotime($row['expires_at']) < time()) {
            $db->commit();
            return null;
        }

        $stmt = $db->prepare('UPDATE sso_tokens
            SET consumed_at = NOW(), ip_address = ?, user_agent = ?
            WHERE id = ? AND consumed_at IS NULL');
        $stmt->execute([$ip, substr($ua, 0, 255), $row['id']]);
        if ($stmt->rowCount() !== 1) {
            $db->rollBack();
            return null;
        }

        $db->commit();
        return $row;
    } catch (Throwable $e) {
        if ($db->inTransaction()) {
            $db->rollBack();
        }
        throw $e;
    }
}

/* ========================================================
   JOURNAL D'AUDIT
   ======================================================== */

function iam_audit(string $action, ?string $details = null, ?int $userId = null, ?string $email = null, string $ip = '', string $ua = '', ?string $application = null): void
{
    $db = db();
    $application = $application !== null ? $application : ($GLOBALS['iam_audit_app'] ?? '');
    $country = iam_ip_country($ip);
    $stmt = $db->prepare('INSERT INTO audit_logs (user_id, email, action, details, ip_address, user_agent, application, country) VALUES (?, ?, ?, ?, ?, ?, ?, ?)');
    $stmt->execute([$userId, $email, $action, $details, substr($ip, 0, 45), substr($ua, 0, 255), $application !== '' ? substr($application, 0, 80) : null, $country]);
}

/* ========================================================
   MFA / OTP
   ======================================================== */

function iam_generate_otp(int $userId, string $method = 'email'): string
{
    $db = db();
    $code = str_pad((string) random_int(0, 999999), OTP_LENGTH, '0', STR_PAD_LEFT);
    $hash = iam_hash_password($code);
    $expires = gmdate('Y-m-d H:i:s', time() + OTP_LIFETIME);

    // Invalider les anciens codes non utilisés
    $stmt = $db->prepare('UPDATE otp_codes SET used = 1 WHERE user_id = ? AND used = 0');
    $stmt->execute([$userId]);

    $stmt2 = $db->prepare('INSERT INTO otp_codes (user_id, code_hash, method, expires_at) VALUES (?, ?, ?, ?)');
    $stmt2->execute([$userId, $hash, $method, $expires]);
    return $code;
}

function iam_verify_otp(int $userId, string $code): bool
{
    $db = db();
    $stmt = $db->prepare('SELECT * FROM otp_codes WHERE user_id = ? AND used = 0 AND expires_at > UTC_TIMESTAMP() ORDER BY id DESC LIMIT 1');
    $stmt->execute([$userId]);
    $row = $stmt->fetch();
    if (!$row) return false;

    $valid = iam_verify_password($code, $row['code_hash']);
    if ($valid) {
        $stmt2 = $db->prepare('UPDATE otp_codes SET used = 1 WHERE id = ?');
        $stmt2->execute([$row['id']]);
    }
    return $valid;
}

/* ========================================================
   JWT SIMPLIFIÉ (token opaque signé HMAC-SHA256)
   ======================================================== */

function iam_sign_token(array $payload): string
{
    $secret = hash_hmac('sha256', IAM_JWT_SECRET, true);
    $header = base64_url_encode(json_encode(['alg' => 'HS256', 'typ' => 'JWT']));
    $body   = base64_url_encode(json_encode($payload));
    $sig    = base64_url_encode(hash_hmac('sha256', "$header.$body", $secret, true));
    return "$header.$body.$sig";
}

function iam_verify_token(string $token): ?array
{
    $parts = explode('.', $token);
    if (count($parts) !== 3) return null;
    [$header, $body, $sig] = $parts;
    $secret = hash_hmac('sha256', IAM_JWT_SECRET, true);
    $expected = base64_url_encode(hash_hmac('sha256', "$header.$body", $secret, true));
    if (!hash_equals($expected, $sig)) return null;
    $payload = json_decode(base64_url_decode($body), true);
    if (!$payload) return null;
    if (isset($payload['exp']) && $payload['exp'] < time()) return null;
    return $payload;
}

function base64_url_encode(string $data): string
{
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

function base64_url_decode(string $data): string
{
    return base64_decode(strtr($data, '-_', '+/') . str_repeat('=', 3 - (3 + strlen($data)) % 4));
}

/* ========================================================
   RECAPTCHA / RATE LIMITING
   ======================================================== */

if (!defined('IP_RATE_MAX_ATTEMPTS'))   define('IP_RATE_MAX_ATTEMPTS', 60);   // échecs max par adresse IP
if (!defined('IP_RATE_WINDOW_MINUTES')) define('IP_RATE_WINDOW_MINUTES', 15); // fenêtre (minutes)

function iam_rate_limit(int $userId, int $maxAttempts, int $windowMinutes): bool
{
    $db = db();
    $stmt = $db->prepare('SELECT COUNT(*) FROM login_attempts
        WHERE identifier = (SELECT email FROM users WHERE id = ?) AND success = 0 AND created_at > DATE_SUB(NOW(), INTERVAL ? MINUTE)');
    $stmt->execute([$userId, $windowMinutes]);
    return $stmt->fetchColumn() < $maxAttempts;
}

/**
 * Rate limiting par adresse IP (protection des logins non identifiés).
 * Seuil volontairement permissif pour les réseaux partagés (proxy/NAT scolaire).
 */
function iam_rate_limit_ip(string $ip, int $maxAttempts, int $windowMinutes): bool
{
    if ($ip === '') return true;
    $db = db();
    $stmt = $db->prepare('SELECT COUNT(*) FROM login_attempts
        WHERE ip_address = ? AND success = 0 AND created_at > DATE_SUB(NOW(), INTERVAL ? MINUTE)');
    $stmt->execute([$ip, $windowMinutes]);
    return (int) $stmt->fetchColumn() < $maxAttempts;
}

/**
 * Pays (géolocalisation) pour le journal d'audit.
 * - IP privée/loopback => "Réseau local" (enregistré toujours)
 * - IP publique => service ip-api.com UNIQUEMENT si paramètre geoip_lookup='1'
 */
function iam_ip_country(string $ip): ?string
{
    if ($ip === '' || $ip === '::1') return 'Réseau local';
    try {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
            return 'Réseau local';
        }
    } catch (\Throwable $e) {
        return 'Réseau local';
    }

    if (!isset($GLOBALS['__iam_ip_country_cache'])) $GLOBALS['__iam_ip_country_cache'] = [];
    $cache =& $GLOBALS['__iam_ip_country_cache'];
    if (array_key_exists($ip, $cache)) return $cache[$ip];

    try {
        $db = db();
        $enabled = $db->query("SELECT s_value FROM settings WHERE s_key = 'geoip_lookup'")->fetchColumn();
    } catch (\Throwable $e) {
        $enabled = '';
    }
    if ($enabled !== '1') {
        $cache[$ip] = null;
        return null;
    }

    $ctx = stream_context_create(['http' => ['timeout' => 2, 'ignore_errors' => true]]);
    $json = @file_get_contents('http://ip-api.com/json/' . rawurlencode($ip) . '?fields=status,country', false, $ctx);
    if ($json) {
        $d = json_decode($json, true);
        if (!empty($d['status']) && $d['status'] === 'success' && !empty($d['country'])) {
            $cache[$ip] = $d['country'];
            return $d['country'];
        }
    }
    $cache[$ip] = null;
    return null;
}

/* ========================================================
   PERMISSIONS DIRECTES DE L'ADMIN
   ======================================================== */

function iam_user_is_admin(int $userId): bool
{
    // Tous les rôles sont désormais LOCAUX à une application :
    // l'administration de la plateforme est portée par le rôle 'admin'
    // attribué sur l'application IAM (« iam-admin »). Un rôle 'admin'
    // porté par une autre application ne donne AUCUN droit sur l'IAM.
    // is_system = 1 : un rôle 'admin' métier créé sur une autre app ne
    // peut pas usurper l'administration même si l'app était renommée.
    static $cache = [];
    if (array_key_exists($userId, $cache)) return $cache[$userId];
    $stmt = db()->prepare('SELECT COUNT(*) FROM user_roles ur
        INNER JOIN roles r ON r.id = ur.role_id
        INNER JOIN applications a ON a.id = ur.application_id
        WHERE ur.user_id = ? AND r.code = ? AND r.is_system = 1
          AND (a.code = ? OR a.is_system = 1)');
    $stmt->execute([$userId, 'admin', IAM_ADMIN_APP_CODE]);
    return $cache[$userId] = $stmt->fetchColumn() > 0;
}

/* ========================================================
   INTERFACES API : JSON RESPONSE
   ======================================================== */

/**
 * Origines autorisées pour CORS (paramètre 'cors_origins',
 * valeurs séparées par des virgules ; '*' = toutes).
 */
function iam_cors_allowed_origins(): array
{
    static $origins = null;
    if ($origins !== null) return $origins;
    $v = '*';
    try {
        $db = db();
        $s = $db->query("SELECT s_value FROM settings WHERE s_key = 'cors_origins'")->fetchColumn();
        if ($s !== false && trim((string) $s) !== '') $v = (string) $s;
    } catch (\Throwable $e) {}
    $origins = array_values(array_filter(array_map('trim', explode(',', $v)), fn($o) => $o !== ''));
    return $origins;
}

function iam_cors_headers(): void
{
    $origin  = $_SERVER['HTTP_ORIGIN'] ?? '';
    $allowed = iam_cors_allowed_origins();
    if (in_array('*', $allowed, true)) {
        header('Access-Control-Allow-Origin: *');
    } elseif ($origin !== '' && in_array(rtrim($origin, '/'), $allowed, true)) {
        header('Access-Control-Allow-Origin: ' . $origin);
        header('Vary: Origin');
    }
    header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
    header('Access-Control-Allow-Headers: Authorization, Content-Type, X-Requested-With, X-IAM-Device');
    header('Access-Control-Max-Age: 86400');
    header('Access-Control-Expose-Headers: X-RateLimit-Remaining, X-RateLimit-Reset');
}

function api_json_response(array $data, int $httpCode = 200): never
{
    iam_cors_headers();
    http_response_code($httpCode);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

/**
 * Finalise une connexion réussie : crée la session, émet access_token
 * + refresh_token et construit la réponse standard (utilisé par
 * api/login.php et api/mfa/verify.php).
 */
function iam_build_login_response(array $user, string $ip, string $ua): array
{
    $sessionToken = iam_create_session((int) $user['id'], $ip, $ua);

    $_SESSION['iam_user'] = [
        'id'        => (int) $user['id'],
        'username'  => $user['username'],
        'email'     => $user['email'],
        'first_name'=> $user['first_name'],
        'last_name' => $user['last_name'],
        'photo'     => $user['photo'],
        'matricule' => $user['matricule'],
        'mfa_enabled' => (bool) $user['mfa_enabled'],
    ];
    $_SESSION['iam_session_token'] = $sessionToken;
    $_SESSION['iam_last_active']   = time();
    $_SESSION['iam_mfa_verified']  = true;

    $accessToken = iam_sign_token([
        'sub'   => $user['id'],
        'uid'   => (int) $user['id'],
        'email' => $user['email'],
        'iat'   => time(),
        'exp'   => time() + 3600,
    ]);

    $refreshToken = bin2hex(random_bytes(32));
    $stmt = db()->prepare('INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 30 DAY))');
    $stmt->execute([(int) $user['id'], $refreshToken]);

    return [
        'success'      => true,
        'access_token' => $accessToken,
        'refresh_token'=> $refreshToken,
        'token_type'   => 'Bearer',
        'expires_in'   => 3600,
        'user' => [
            'id'         => (int) $user['id'],
            'username'   => $user['username'],
            'email'      => $user['email'],
            'first_name' => $user['first_name'],
            'last_name'  => $user['last_name'],
            'phone'      => $user['phone'] ?? '',
            'photo'      => $user['photo'],
            'matricule'  => $user['matricule'],
            'organization_id' => $user['organization_id'] ?? null,
        ],
        'mfa_verified' => true,
        'must_change_password' => (bool) $user['must_change_password'],
        'apps' => iam_user_apps((int) $user['id']),
    ];
}

function api_request_body(): array
{
    $raw = file_get_contents('php://input');
    $data = json_decode($raw, true);
    return is_array($data) ? $data : [];
}

function api_require_auth(): array
{
    iam_session_start();
    $token = $_SESSION['iam_session_token'] ?? null;
    $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';

    if ($authHeader && preg_match('/^Bearer\s+(.+)$/i', $authHeader, $m)) {
        $payload = iam_verify_token($m[1]);
        if ($payload && isset($payload['uid'])) {
            $user = iam_find_user_by_id((int) $payload['uid']);
            if ($user && $user['status'] === 'active') return $user;
        }
    }

    if ($token && !empty($_SESSION['iam_user']['id'])) {
        $user = iam_find_user_by_id((int) $_SESSION['iam_user']['id']);
        if ($user && $user['status'] === 'active') {
            iam_touch_session($user['id'], $token);
            return $user;
        }
    }

    api_json_response(['error' => 'Authentification requise.'], 401);
}

/* ========================================================
   PARAMÈTRE HTTP QUERY
   ======================================================== */

function input(string $key, $default = null)
{
    return $_REQUEST[$key] ?? $default;
}

/* ========================================================
   API — Bootstrap CORS automatique + pré-vol OPTIONS
   (exécuté pour tout script sous /api/)
   ======================================================== */

if (strpos($_SERVER['SCRIPT_NAME'] ?? '', '/api/') !== false) {
    iam_cors_headers();
    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'OPTIONS') {
        http_response_code(204);
        exit;
    }
}