<?php
declare(strict_types=1);

namespace IamLocal\Platforms;

final class OtherPlatform extends AbstractPlatform
{
    public function getKey(): string { return 'other'; }
    public function getLabel(): string { return 'Autre'; }
    public function getIcon(): string { return 'fa-cubes'; }
    public function getDescription(): string { return 'Client OIDC générique; renseignez manuellement les URI.'; }
    public function getDefaultClientType(): string { return 'confidential'; }
    public function getDefaultRedirectUris(): array { return []; }
    public function getDefaultScopes(): array { return ['openid', 'profile', 'email']; }
    public function getDefaultGrantTypes(): array { return ['authorization_code', 'refresh_token']; }
    public function getConfigTemplate(array $client): string
    {
        return '// Configure Authorization Code using the IAM OIDC discovery document at /.well-known/openid-configuration.php.';
    }
}