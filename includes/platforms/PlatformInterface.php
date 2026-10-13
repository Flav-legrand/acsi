<?php
declare(strict_types=1);

namespace IamLocal\Platforms;

interface PlatformInterface
{
    public function getKey(): string;
    public function getLabel(): string;
    public function getIcon(): string;
    public function getDescription(): string;
    public function getDefaultClientType(): string;
    public function getDefaultRedirectUris(): array;
    public function getDefaultPostLogoutUris(): array;
    public function getDefaultScopes(): array;
    public function getDefaultGrantTypes(): array;
    public function getEnvTemplate(array $client): string;
    public function getConfigTemplate(array $client): string;
    public function getInstallCommand(): ?string;
    public function getStarterUrl(): ?string;
    public function getDocsUrl(): ?string;
}