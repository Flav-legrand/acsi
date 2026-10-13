<?php
declare(strict_types=1);

final class OAuthClientService
{
    private PDO $db;
    private ?string $plainSecret = null;

    public function __construct(?PDO $db = null)
    {
        $this->db = $db ?? db();
    }

    public function generateClientId(): string
    {
        return 'app_' . bin2hex(random_bytes(16));
    }

    public function generateClientSecret(): string
    {
        return rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    }

    public function hashSecret(string $plain): string
    {
        return password_hash($plain, PASSWORD_BCRYPT);
    }

    public function createClient(array $data): OAuthClient
    {
        iam_oauth_ensure_client_schema();
        $type = (string) ($data['client_type'] ?? 'confidential');
        if (!in_array($type, ['confidential', 'public'], true)) {
            throw new InvalidArgumentException('Type de client invalide.');
        }
        $baseUrl = rtrim(trim((string) ($data['base_url'] ?? '')), '/');
        $baseParts = parse_url($baseUrl);
        $baseScheme = strtolower((string) ($baseParts['scheme'] ?? ''));
        $baseHost = strtolower((string) ($baseParts['host'] ?? ''));
        $baseIsLocal = in_array($baseHost, ['localhost', '127.0.0.1', '::1'], true);
        $isProduction = strtolower((string) (getenv('APP_ENV') ?: getenv('IAM_ENVIRONMENT') ?: 'production')) === 'production';
        if (!$baseParts || !in_array($baseScheme, ['https', 'http'], true) || $baseHost === ''
            || isset($baseParts['user']) || isset($baseParts['pass']) || str_contains($baseUrl, '*')
            || ($isProduction && $baseScheme !== 'https' && !$baseIsLocal)) {
            throw new InvalidArgumentException('URL de base invalide; HTTPS est obligatoire en production.');
        }
        $redirects = array_values(array_unique((array) ($data['redirect_uris'] ?? [])));
        $logoutUris = array_values(array_unique((array) ($data['post_logout_uris'] ?? [])));
        foreach (array_merge($redirects, $logoutUris) as $uri) {
            if (!$this->validateRedirectUri((string) $uri, $type)) {
                throw new InvalidArgumentException('URI de redirection invalide : ' . $uri);
            }
        }
        if (in_array('authorization_code', (array) ($data['grant_types'] ?? []), true) && !$redirects) {
            throw new InvalidArgumentException('Un client Authorization Code doit avoir au moins une redirect URI.');
        }

        $secret = $type === 'confidential' ? $this->generateClientSecret() : null;
        $this->plainSecret = $secret;
        $clientId = $this->generateClientId();
        $slug = $this->uniqueSlug((string) ($data['slug'] ?? $data['name'] ?? 'application'));
        $clientData = [
            'application_id' => $data['application_id'] ?? null,
            'name' => trim((string) ($data['name'] ?? '')),
            'slug' => $slug,
            'description' => trim((string) ($data['description'] ?? '')),
            'platform' => (string) ($data['platform'] ?? 'other'),
            'platform_version' => $data['platform_version'] ?? null,
            'client_type' => $type,
            'client_id' => $clientId,
            'client_secret' => $secret !== null ? $this->hashSecret($secret) : null,
            'redirect_uris' => json_encode($redirects, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR),
            'post_logout_uris' => json_encode($logoutUris, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR),
            'scopes' => json_encode(array_values((array) ($data['scopes'] ?? ['openid', 'profile', 'email'])), JSON_THROW_ON_ERROR),
            'grant_types' => json_encode(array_values((array) ($data['grant_types'] ?? ['authorization_code', 'refresh_token'])), JSON_THROW_ON_ERROR),
            'token_lifetime' => max(60, min(86400, (int) ($data['token_lifetime'] ?? 3600))),
            'refresh_lifetime' => max(60, min(31536000, (int) ($data['refresh_lifetime'] ?? 2592000))),
            'base_url' => $baseUrl,
            'logo_url' => $data['logo_url'] ?? null,
            'is_active' => !empty($data['is_active']) ? 1 : 0,
            'refresh_enabled' => !empty($data['refresh_enabled']) ? 1 : 0,
            'pkce_required' => $type === 'public' || !empty($data['pkce_required']) ? 1 : 0,
            'role_mappings' => json_encode((array) ($data['role_mappings'] ?? []), JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR),
            'jit_provisioning' => !empty($data['jit_provisioning']) ? 1 : 0,
        ];

        if ($clientData['name'] === '' || strlen($clientData['name']) > 120) {
            throw new InvalidArgumentException('Nom du client requis (120 caractères maximum).');
        }
        $columns = array_keys($clientData);
        $sql = 'INSERT INTO oauth_clients (`' . implode('`,`', $columns) . '`) VALUES (' . implode(',', array_fill(0, count($columns), '?')) . ')';
        $this->db->prepare($sql)->execute(array_values($clientData));
        $clientData['id'] = (int) $this->db->lastInsertId();
        $clientData['created_at'] = gmdate('Y-m-d H:i:s');
        return new OAuthClient($clientData);
    }

    public function regenerateSecret(OAuthClient $client): string
    {
        if ($client->get('client_type') !== 'confidential') {
            throw new InvalidArgumentException('Un client public ne possède pas de secret.');
        }
        $secret = $this->generateClientSecret();
        $this->db->prepare('UPDATE oauth_clients SET client_secret=?, updated_at=UTC_TIMESTAMP() WHERE id=?')
            ->execute([$this->hashSecret($secret), (int) $client->get('id')]);
        $this->db->prepare('UPDATE refresh_tokens SET revoked=1 WHERE client_id=? AND revoked=0')
            ->execute([(string) $client->get('client_id')]);
        iam_oauth_log_event((string) $client->get('client_id'), null, 'secret_rotated');
        return $secret;
    }

    public function takePlainSecretOnce(): ?string
    {
        $secret = $this->plainSecret;
        $this->plainSecret = null;
        return $secret;
    }

    public function validateRedirectUri(string $uri, string $clientType = 'confidential'): bool
    {
        if ($uri === '' || str_contains($uri, '*')) return false;
        $parts = parse_url($uri);
        if (!$parts || isset($parts['user']) || isset($parts['pass']) || isset($parts['fragment'])) return false;
        $scheme = strtolower((string) ($parts['scheme'] ?? ''));
        $host = strtolower((string) ($parts['host'] ?? ''));
        $isLocal = in_array($host, ['localhost', '127.0.0.1', '::1'], true);
        $production = strtolower((string) (getenv('APP_ENV') ?: getenv('IAM_ENVIRONMENT') ?: 'production')) === 'production';
        if (in_array($scheme, ['https', 'http'], true)) {
            return $host !== '' && ($scheme === 'https' || $isLocal || !$production);
        }
        return $clientType === 'public' && $host !== ''
            && preg_match('/^[a-z][a-z0-9+.-]*$/', $scheme) === 1
            && !in_array($scheme, ['javascript', 'data', 'file'], true);
    }

    private function uniqueSlug(string $value): string
    {
        $slug = strtolower(trim((string) preg_replace('/[^a-zA-Z0-9]+/', '-', $value), '-'));
        $slug = substr($slug !== '' ? $slug : 'application', 0, 80);
        $candidate = $slug;
        $suffix = 2;
        $check = $this->db->prepare('SELECT COUNT(*) FROM oauth_clients WHERE slug=?');
        while (true) {
            $check->execute([$candidate]);
            if (!(int) $check->fetchColumn()) return $candidate;
            $ending = '-' . $suffix++;
            $candidate = substr($slug, 0, 100 - strlen($ending)) . $ending;
        }
    }
}