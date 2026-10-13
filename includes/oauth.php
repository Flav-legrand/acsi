<?php
// IAM-Local — Serveur OAuth 2.0 / OIDC
// Requiert includes/functions.php

if (!function_exists('iam_oauth_current_key')) {

function iam_oauth_ensure_client_schema(): void
{
    static $ready = false;
    if ($ready) return;

    $db = db();
    $hasColumn = static function (string $column) use ($db): bool {
        $stmt = $db->prepare('SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = ? AND column_name = ?');
        $stmt->execute(['oauth_clients', $column]);
        return (int) $stmt->fetchColumn() > 0;
    };

    $legacySecretColumn = $hasColumn('client_secret_hash');
    if ($legacySecretColumn && !$hasColumn('client_secret')) {
        $db->exec('ALTER TABLE oauth_clients CHANGE COLUMN client_secret_hash client_secret VARCHAR(255) NULL');
    }
    if ($hasColumn('post_logout_redirect_uris') && !$hasColumn('post_logout_uris')) {
        $db->exec('ALTER TABLE oauth_clients CHANGE COLUMN post_logout_redirect_uris post_logout_uris TEXT NULL');
    }

    $columns = [
        'application_id' => 'INT NULL',
        'slug' => 'VARCHAR(100) NULL',
        'description' => 'TEXT NULL',
        'platform' => "VARCHAR(40) NOT NULL DEFAULT 'other'",
        'platform_version' => 'VARCHAR(50) NULL',
        'client_type' => "ENUM('confidential','public') NOT NULL DEFAULT 'confidential'",
        'client_secret' => 'VARCHAR(255) NULL',
        'base_url' => 'VARCHAR(500) NULL',
        'logo_url' => 'VARCHAR(255) NULL',
        'post_logout_uris' => 'TEXT NULL',
        'scopes' => 'TEXT NULL',
        'access_token_ttl' => 'INT UNSIGNED NOT NULL DEFAULT 3600',
        'refresh_token_ttl_days' => 'INT UNSIGNED NOT NULL DEFAULT 30',
        'token_lifetime' => 'INT UNSIGNED NOT NULL DEFAULT 3600',
        'refresh_lifetime' => 'INT UNSIGNED NOT NULL DEFAULT 2592000',
        'refresh_enabled' => 'TINYINT(1) NOT NULL DEFAULT 1',
        'pkce_required' => 'TINYINT(1) NOT NULL DEFAULT 0',
        'role_mappings' => 'TEXT NULL',
        'jit_provisioning' => 'TINYINT(1) NOT NULL DEFAULT 0',
        'is_active' => 'TINYINT(1) NOT NULL DEFAULT 1',
        'last_used_at' => 'DATETIME NULL',
        'updated_at' => 'DATETIME NULL',
    ];
    $added = [];
    foreach ($columns as $name => $definition) {
        if (!$hasColumn($name)) {
            $db->exec("ALTER TABLE oauth_clients ADD COLUMN `$name` $definition");
            $added[$name] = true;
        }
    }

    if (isset($added['client_type'])) {
        $db->exec("UPDATE oauth_clients SET client_type = IF(client_secret IS NULL OR client_secret = '', 'public', 'confidential')");
    }
    if (isset($added['is_active'])) $db->exec('UPDATE oauth_clients SET is_active = active');
    if (isset($added['token_lifetime'])) $db->exec('UPDATE oauth_clients SET token_lifetime = access_token_ttl');
    if (isset($added['refresh_lifetime'])) $db->exec('UPDATE oauth_clients SET refresh_lifetime = refresh_token_ttl_days * 86400');
    if (isset($added['description'])) $db->exec('UPDATE oauth_clients SET description = name');
    $db->exec("UPDATE oauth_clients SET platform = CASE platform WHEN 'flutter' THEN 'mobile' WHEN 'service' THEN 'other' WHEN 'spa' THEN 'nextjs' ELSE platform END WHERE platform IN ('flutter','service','spa')");
    if ($legacySecretColumn || isset($added['client_type'])) {
        $db->exec("UPDATE oauth_clients SET client_type = IF(client_secret IS NULL OR client_secret = '', 'public', 'confidential')");
    }
    if ((isset($added['is_active']) || $legacySecretColumn) && $hasColumn('active')) $db->exec('UPDATE oauth_clients SET is_active = active');

    $legacyClients = $db->query("SELECT id, name FROM oauth_clients WHERE slug IS NULL OR slug = ''")->fetchAll(PDO::FETCH_ASSOC);
    $slugUpdate = $db->prepare('UPDATE oauth_clients SET slug=? WHERE id=?');
    foreach ($legacyClients as $legacyClient) {
        $baseSlug = strtolower(trim((string) preg_replace('/[^a-zA-Z0-9]+/', '-', $legacyClient['name']), '-'));
        $slug = substr($baseSlug !== '' ? $baseSlug : 'client', 0, 80) . '-' . (int) $legacyClient['id'];
        $slugUpdate->execute([$slug, (int) $legacyClient['id']]);
    }
    $indexSlug = $db->query("SELECT COUNT(*) FROM information_schema.statistics WHERE table_schema=DATABASE() AND table_name='oauth_clients' AND index_name='uq_oauth_client_slug'")->fetchColumn();
    if (!(int) $indexSlug) $db->exec('CREATE UNIQUE INDEX uq_oauth_client_slug ON oauth_clients (slug)');

    $jsonTypes = [];
    $typeQuery = $db->prepare('SELECT data_type FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name=? AND column_name=?');
    foreach (['redirect_uris', 'post_logout_uris', 'scopes', 'grant_types'] as $column) {
        $typeQuery->execute(['oauth_clients', $column]);
        $jsonTypes[$column] = strtolower((string) $typeQuery->fetchColumn());
    }
    $needsJsonMigration = (bool) array_diff($jsonTypes, ['json', 'longtext']);
    if ($needsJsonMigration) {
        $scopeColumn = $hasColumn('scope') ? 'scope' : "'' AS legacy_scope";
        $legacyLists = $db->query('SELECT id, redirect_uris, post_logout_uris, ' . $scopeColumn . ', scopes, grant_types, refresh_enabled FROM oauth_clients')->fetchAll(PDO::FETCH_ASSOC);
        $listUpdate = $db->prepare('UPDATE oauth_clients SET redirect_uris=?, post_logout_uris=?, scopes=?, grant_types=? WHERE id=?');
        foreach ($legacyLists as $legacy) {
            $normalise = static function ($value, array $fallback = []): array {
                $decoded = json_decode((string) $value, true);
                if (is_array($decoded)) return array_values($decoded);
                if (is_string($value) && $value !== '') return array_values(array_filter(array_map('trim', explode(',', $value))));
                return $fallback;
            };
            $scopeList = $normalise($legacy['scopes'] ?? null);
            if (!$scopeList) $scopeList = array_values(array_filter(array_map('trim', explode(' ', (string) ($legacy['scope'] ?? $legacy['legacy_scope'] ?? ''))))) ?: ['profile'];
            $grants = $normalise($legacy['grant_types'] ?? null);
            if ((int) $legacy['refresh_enabled'] === 1 && in_array('authorization_code', $grants, true) && !in_array('refresh_token', $grants, true)) {
                $grants[] = 'refresh_token';
            }
            $listUpdate->execute([
                json_encode($normalise($legacy['redirect_uris'] ?? null)),
                json_encode($normalise($legacy['post_logout_uris'] ?? null)),
                json_encode($scopeList),
                json_encode($grants),
                (int) $legacy['id'],
            ]);
        }
        $db->exec('ALTER TABLE oauth_clients MODIFY redirect_uris JSON NOT NULL, MODIFY post_logout_uris JSON NULL, MODIFY scopes JSON NOT NULL, MODIFY grant_types JSON NOT NULL');
    }

    $db->exec('CREATE TABLE IF NOT EXISTS oauth_client_events (
        id INT AUTO_INCREMENT PRIMARY KEY,
        client_id VARCHAR(64) NOT NULL,
        user_id INT NULL,
        event VARCHAR(40) NOT NULL,
        ip_address VARCHAR(45) NULL,
        user_agent VARCHAR(255) NULL,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        KEY idx_oauth_event_client (client_id, created_at),
        KEY idx_oauth_event_user (user_id, created_at)
    ) ENGINE=InnoDB');
    $index = $db->query("SELECT COUNT(*) FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'oauth_clients' AND index_name = 'idx_oauth_application'")->fetchColumn();
    if (!(int) $index) $db->exec('CREATE INDEX idx_oauth_application ON oauth_clients (application_id)');
    $constraint = $db->query("SELECT COUNT(*) FROM information_schema.table_constraints WHERE constraint_schema = DATABASE() AND table_name = 'oauth_clients' AND constraint_name = 'fk_oauth_application'")->fetchColumn();
    if (!(int) $constraint) {
        $db->exec('ALTER TABLE oauth_clients ADD CONSTRAINT fk_oauth_application FOREIGN KEY (application_id) REFERENCES applications(id) ON DELETE SET NULL');
    }
    $ready = true;
}

function iam_oauth_log_event(string $clientId, ?int $userId, string $event): void
{
    iam_oauth_ensure_client_schema();
    $db = db();
    $db->prepare('INSERT INTO oauth_client_events (client_id, user_id, event, ip_address, user_agent) VALUES (?, ?, ?, ?, ?)')
       ->execute([$clientId, $userId, $event, $_SERVER['REMOTE_ADDR'] ?? null, substr((string) ($_SERVER['HTTP_USER_AGENT'] ?? ''), 0, 255)]);
    $db->prepare('UPDATE oauth_clients SET last_used_at = UTC_TIMESTAMP() WHERE client_id = ?')->execute([$clientId]);
}

function iam_oauth_openssl_config(): ?string
{
    static $candidates = null;
    if ($candidates === null) {
        $candidates = [];
        $bin = defined('PHP_BINDIR') ? PHP_BINDIR : '';
        if ($bin !== '') {
            $candidates[] = $bin . '/extras/ssl/openssl.cnf';
            $candidates[] = $bin . '/../extras/ssl/openssl.cnf';
            $candidates[] = $bin . '/../php/openssl.cnf';
        }
        $candidates[] = 'C:/wamp64/scripts/httpsFiles/openssl.cnf';
        $candidates[] = 'C:/wamp64/bin/apache/apache2.4.65/conf/openssl.cnf';
        // Balayage des distributions PHP WAMP
        foreach (glob('C:/wamp64/bin/php/*/extras/ssl/openssl.cnf') ?: [] as $p) $candidates[] = $p;
        $candidates = array_values(array_unique($candidates));
    }
    foreach ($candidates as $p) {
        if (is_file($p)) return $p;
    }
    return null;
}

function iam_oauth_new_rsa_key(): array
{
    $opts = ['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA];
    $cfg = iam_oauth_openssl_config();
    if ($cfg !== null) $opts['config'] = $cfg;
    $res = @openssl_pkey_new($opts);
    if (!$res) {
        $opts2 = ['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA];
        $res = @openssl_pkey_new($opts2);
    }
    if (!$res) {
        throw new RuntimeException('Impossible de générer la clé RSA OAuth (openssl_pkey_new).');
    }
    openssl_pkey_export($res, $privPem, null, $opts);
    $pub = openssl_pkey_get_details($res);
    if (!$pub) throw new RuntimeException('Détails de la clé RSA indisponibles.');
    return [$privPem, $pub['key']];
}

function iam_oauth_current_key(): array
{
    $db = db();
    $row = $db->query('SELECT * FROM oauth_keys WHERE active = 1 ORDER BY id DESC LIMIT 1')->fetch();
    if ($row) return $row;

    // Génération de la première clé
    [$privPem, $pubPem] = iam_oauth_new_rsa_key();
    $kid = bin2hex(random_bytes(8));
    $stmt = $db->prepare('INSERT INTO oauth_keys (kid, priv_pem, pub_pem, alg, active) VALUES (?, ?, ?, ?, 1)');
    $stmt->execute([$kid, $privPem, $pubPem, 'RS256']);
    return $db->query('SELECT * FROM oauth_keys WHERE kid = ' . $db->quote($kid))->fetch();
}

function iam_oauth_rotate_key(): array
{
    $db = db();
    $db->exec('UPDATE oauth_keys SET active = 0');
    [$privPem, $pubPem] = iam_oauth_new_rsa_key();
    $kid = bin2hex(random_bytes(8));
    $db->prepare('INSERT INTO oauth_keys (kid, priv_pem, pub_pem, alg, active) VALUES (?, ?, ?, ?, 1)')
       ->execute([$kid, $privPem, $pubPem, 'RS256']);
    return $db->query('SELECT * FROM oauth_keys WHERE kid = ' . $db->quote($kid))->fetch();
}

function iam_oauth_jwks(): array
{
    $db = db();
    $keys = [];
    foreach ($db->query('SELECT kid, pub_pem, alg FROM oauth_keys ORDER BY active DESC, id DESC') as $row) {
        $details = openssl_pkey_get_details(openssl_pkey_get_public($row['pub_pem']));
        $keys[] = [
            'kty' => 'RSA',
            'use' => 'sig',
            'kid' => $row['kid'],
            'alg' => $row['alg'],
            'n'   => base64_url_encode($details['rsa']['n']),
            'e'   => base64_url_encode($details['rsa']['e']),
        ];
    }
    return $keys;
}

function iam_oauth_jwt_rs256(array $payload, array $key, int $ttl): string
{
    $header = base64_url_encode(json_encode(['alg' => 'RS256', 'typ' => 'JWT', 'kid' => $key['kid']]));
    $payload['exp'] = time() + $ttl;
    $payload['iat'] = time();
    $body = base64_url_encode(json_encode($payload));
    openssl_sign("$header.$body", $sig, openssl_pkey_get_private($key['priv_pem']), OPENSSL_ALGO_SHA256);
    return "$header.$body." . base64_url_encode($sig);
}

function iam_oauth_jwt_decode(string $token): ?array
{
    $parts = explode('.', $token);
    if (count($parts) !== 3) return null;
    [$h, $b, $s] = $parts;
    $header = json_decode(base64_url_decode($h), true);
    if (!$header || ($header['alg'] ?? '') !== 'RS256') return null;
    $db = db();
    $stmt = $db->prepare('SELECT priv_pem, pub_pem, alg FROM oauth_keys WHERE kid = ?');
    $stmt->execute([$header['kid'] ?? '']);
    $key = $stmt->fetch();
    if (!$key) return null;
    $ok = openssl_verify("$h.$b", base64_url_decode($s), openssl_pkey_get_public($key['pub_pem']), OPENSSL_ALGO_SHA256);
    if ($ok !== 1) return null;
    $payload = json_decode(base64_url_decode($b), true);
    if (!$payload) return null;
    if (isset($payload['exp']) && $payload['exp'] < time()) return null;
    return $payload;
}

function iam_oauth_client(?string $clientId): ?array
{
    if ($clientId === null || $clientId === '') return null;
    iam_oauth_ensure_client_schema();
    $db = db();
    $stmt = $db->prepare('SELECT * FROM oauth_clients WHERE client_id = ? LIMIT 1');
    $stmt->execute([$clientId]);
    return $stmt->fetch() ?: null;
}

function iam_oauth_client_is_public(array $client): bool
{
    return ($client['client_type'] ?? 'confidential') === 'public';
}

function iam_oauth_client_allows_grant(array $client, string $grant): bool
{
    $grants = json_decode((string) ($client['grant_types'] ?? '[]'), true);
    if (!is_array($grants)) $grants = array_map('trim', explode(',', (string) ($client['grant_types'] ?? '')));
    return in_array($grant, $grants, true);
}

function iam_oauth_client_allows_scopes(array $client, string $scope, array $supported): bool
{
    $requested = array_values(array_unique(array_filter(explode(' ', trim($scope)))));
    $configured = json_decode((string) ($client['scopes'] ?? ''), true);
    if (!is_array($configured)) {
        $configuredValue = trim((string) ($client['scope'] ?? '')) ?: 'openid profile email';
        $configured = array_values(array_unique(array_filter(explode(' ', $configuredValue))));
    }
    return $requested !== []
        && array_diff($requested, $supported) === []
        && array_diff($requested, $configured) === [];
}

function iam_oauth_pkce_request_allowed(array $client, string $challenge, string $method): bool
{
    if (iam_oauth_client_is_public($client)) {
        return preg_match('/^[A-Za-z0-9_-]{43}$/', $challenge) === 1
            && strtoupper($method) === 'S256';
    }

    if (!empty($client['pkce_required'])) {
        return preg_match('/^[A-Za-z0-9_-]{43}$/', $challenge) === 1
            && strtoupper($method) === 'S256';
    }

    return $challenge === '' || in_array(strtolower($method), ['s256', 'plain'], true);
}

function iam_oauth_client_redirects(array $client): array
{
    $uris = json_decode($client['redirect_uris'] ?? '[]', true);
    return is_array($uris) ? array_values($uris) : [];
}

function iam_oauth_redirect_ok(array $client, string $redirectUri): bool
{
    return $redirectUri !== '' && in_array($redirectUri, iam_oauth_client_redirects($client), true);
}

function iam_oauth_client_auth(): ?array
{
    // Authentification du client : Basic (Authorization) ou POST (client_id + client_secret)
    $raw = $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if (preg_match('/Basic\s+(.+)$/i', $raw, $m)) {
        $dec = base64_decode(trim($m[1]));
        if ($dec !== false && strpos($dec, ':') !== false) {
            [$c, $s] = explode(':', $dec, 2);
            return [trim($c), trim($s)];
        }
    }
    if (isset($_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW'])) {
        return [trim($_SERVER['PHP_AUTH_USER']), trim($_SERVER['PHP_AUTH_PW'])];
    }
    $c = trim($_POST['client_id'] ?? '');
    $s = trim($_POST['client_secret'] ?? '');
    return ($c !== '') ? [$c, $s] : null;
}

function iam_oauth_issue_tokens(array $client, int $userId, string $scope, ?string $nonce = null, int $authTime = 0): array
{
    $db = db();
    $key = iam_oauth_current_key();
    $accessTtl = max(60, min(86400, (int) ($client['token_lifetime'] ?? $client['access_token_ttl'] ?? 3600)));
    $refreshTtl = max(60, min(31536000, (int) ($client['refresh_lifetime'] ?? ((int) ($client['refresh_token_ttl_days'] ?? 30) * 86400))));
    $scope = trim($scope) ?: 'profile';

    $wantsRoles = in_array('roles', explode(' ', $scope), true);
    $roles = $wantsRoles ? iam_oauth_user_roles($client, $userId) : [];
    // Permissions de l'application liée au client (scope « roles »),
    // calculées comme api/sso/validate.php : une seule source de droits
    // pour le SSO maison et pour OIDC.
    $permissions = $wantsRoles ? iam_oauth_user_permissions($client, $userId) : [];

    $access = iam_oauth_jwt_rs256([
        'iss' => IAM_BASE_URL,
        'sub' => (string) $userId,
        'aud' => $client['client_id'],
        'scope' => $scope,
        ...($roles ? ['roles' => $roles] : []),
        ...($permissions ? ['permissions' => $permissions] : []),
    ], $key, $accessTtl);

    $refreshEnabled = (!array_key_exists('refresh_enabled', $client) || (int) $client['refresh_enabled'] === 1)
        && in_array('offline_access', explode(' ', $scope), true);
    $refreshToken = null;
    if ($refreshEnabled) {
        $refreshToken = bin2hex(random_bytes(40));
        $expiresAt = gmdate('Y-m-d H:i:s', time() + $refreshTtl);
        $stmt = $db->prepare('INSERT INTO refresh_tokens (user_id, token, client_id, scope, expires_at) VALUES (?, ?, ?, ?, ?)');
        $stmt->execute([$userId, $refreshToken, $client['client_id'], $scope, $expiresAt]);
    }

    $result = [
        'access_token'  => $access,
        'token_type'    => 'Bearer',
        'expires_in'    => $accessTtl,
        'scope'         => $scope,
    ];
    if ($refreshToken !== null) $result['refresh_token'] = $refreshToken;

    if (in_array('openid', explode(' ', $scope), true)) {
        $user = iam_find_user_by_id($userId);
        $idPayload = [
            'iss' => IAM_BASE_URL,
            'sub' => (string) $userId,
            'aud' => $client['client_id'],
            'auth_time' => $authTime ?: time(),
        ];
        if ($nonce) $idPayload['nonce'] = $nonce;
        if ($roles) $idPayload['roles'] = $roles;
        if ($permissions) $idPayload['permissions'] = $permissions;
        $idPayload['jit_provisioning'] = (int) ($client['jit_provisioning'] ?? 0) === 1;
        if ($user && in_array('profile', explode(' ', $scope), true)) {
            $idPayload['name']  = trim(($user['first_name'] ?? '') . ' ' . ($user['last_name'] ?? ''));
            $idPayload['given_name'] = $user['first_name'] ?? '';
            $idPayload['family_name'] = $user['last_name'] ?? '';
            $idPayload['preferred_username'] = $user['username'] ?? '';
        }
        if ($user && in_array('email', explode(' ', $scope), true)) {
            $idPayload['email'] = $user['email'] ?? '';
            $idPayload['email_verified'] = true;
        }
        $result['id_token'] = iam_oauth_jwt_rs256($idPayload, $key, $accessTtl);
    }
    iam_oauth_log_event((string) $client['client_id'], $userId, 'token_issued');
    return $result;
}

function iam_oauth_user_roles(array $client, int $userId): array
{
    $db = db();
    $applicationId = (int) ($client['application_id'] ?? 0);
    if ($applicationId > 0) {
        $stmt = $db->prepare('SELECT r.code FROM user_roles ur INNER JOIN roles r ON r.id = ur.role_id WHERE ur.user_id = ? AND ur.application_id = ? ORDER BY r.code');
        $stmt->execute([$userId, $applicationId]);
    } else {
        $stmt = $db->prepare('SELECT r.code FROM user_roles ur INNER JOIN roles r ON r.id = ur.role_id WHERE ur.user_id = ? ORDER BY r.code');
        $stmt->execute([$userId]);
    }
    $roles = array_column($stmt->fetchAll(PDO::FETCH_ASSOC), 'code');
    $mappings = json_decode((string) ($client['role_mappings'] ?? ''), true);
    if (is_array($mappings) && $mappings) {
        $roles = array_map(static fn($role) => (string) ($mappings[$role] ?? $role), $roles);
    }
    return array_values(array_unique($roles));
}

/**
 * Codes de permission de l'utilisateur sur l'application liée au client.
 *
 * Même règle que api/sso/validate.php :
 *   - permissions accordées par ses rôles SUR CETTE application ;
 *   - joker « * » s'il est administrateur de la plateforme IAM ou s'il
 *     porte le rôle « admin » de cette application.
 * Un client sans application liée (application_id NULL) ne reçoit
 * aucune permission : on ne saurait pas de quelle application parler.
 */
function iam_oauth_user_permissions(array $client, int $userId): array
{
    $applicationId = (int) ($client['application_id'] ?? 0);
    if ($applicationId <= 0) return [];

    $codes = array_column(iam_user_permissions($userId, $applicationId), 'code');
    $roleCodes = array_column(iam_user_roles($userId, $applicationId), 'code');
    if (iam_user_is_admin($userId) || in_array('admin', $roleCodes, true)) {
        $codes[] = '*';
    }
    $codes = array_values(array_unique(array_map('strval', $codes)));
    sort($codes);
    return $codes;
}

function iam_oauth_error(int $status, string $error, string $desc = ''): void
{
    http_response_code($status);
    header('Content-Type: application/json');
    echo json_encode(['error' => $error, 'error_description' => $desc]);
    exit;
}

} // fin if !function_exists