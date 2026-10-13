<?php
declare(strict_types=1);

namespace IamLocal\Platforms;

use InvalidArgumentException;

final class PlatformRegistry
{
    private array $platforms = [];

    public function register(PlatformInterface $platform): void
    {
        $key = $platform->getKey();
        if (isset($this->platforms[$key])) {
            throw new InvalidArgumentException('Platform already registered: ' . $key);
        }
        $this->platforms[$key] = $platform;
    }

    public function get(string $key): PlatformInterface
    {
        if (!$this->has($key)) {
            throw new InvalidArgumentException('Unknown platform: ' . $key);
        }
        return $this->platforms[$key];
    }

    public function all(): array
    {
        return $this->platforms;
    }

    public function has(string $key): bool
    {
        return isset($this->platforms[$key]);
    }
}