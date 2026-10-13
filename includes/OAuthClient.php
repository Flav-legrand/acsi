<?php
declare(strict_types=1);

final class OAuthClient
{
    private array $attributes;

    public function __construct(array $attributes)
    {
        $this->attributes = $attributes;
    }

    public function get(string $key, $default = null)
    {
        return $this->attributes[$key] ?? $default;
    }

    public function toArray(): array
    {
        $safe = $this->attributes;
        unset($safe['client_secret'], $safe['client_secret_hash']);
        return $safe;
    }

    public function verifySecret(string $plain): bool
    {
        $hash = (string) ($this->attributes['client_secret'] ?? '');
        return $hash !== '' && password_verify($plain, $hash);
    }

    public function getPlatformLabelAttribute(): string
    {
        $registry = IamLocal\Platforms\IamServiceProvider::platforms();
        return $registry->has((string) $this->get('platform'))
            ? $registry->get((string) $this->get('platform'))->getLabel()
            : 'Autre';
    }

    public function getPlatformIconAttribute(): string
    {
        $registry = IamLocal\Platforms\IamServiceProvider::platforms();
        return $registry->has((string) $this->get('platform'))
            ? $registry->get((string) $this->get('platform'))->getIcon()
            : 'fa-cubes';
    }

    public static function active(): array
    {
        $stmt = db()->query('SELECT * FROM oauth_clients WHERE is_active=1 ORDER BY name');
        return array_map(static fn(array $row) => new self($row), $stmt->fetchAll(PDO::FETCH_ASSOC));
    }

    public static function byPlatform(string $platform): array
    {
        $stmt = db()->prepare('SELECT * FROM oauth_clients WHERE platform=? ORDER BY name');
        $stmt->execute([$platform]);
        return array_map(static fn(array $row) => new self($row), $stmt->fetchAll(PDO::FETCH_ASSOC));
    }
}