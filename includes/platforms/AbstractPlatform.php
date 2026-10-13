<?php
declare(strict_types=1);

namespace IamLocal\Platforms;

abstract class AbstractPlatform implements PlatformInterface
{
    protected function value(array $client, string $key, string $fallback = ''): string
    {
        return (string) ($client[$key] ?? $fallback);
    }

    protected function callback(string $path): array
    {
        return ['{base_url}' . $path];
    }

    public function getDefaultPostLogoutUris(): array
    {
        return ['{base_url}/'];
    }

    public function getDefaultScopes(): array
    {
        return ['openid', 'profile', 'email', 'roles'];
    }

    public function getDefaultGrantTypes(): array
    {
        return ['authorization_code', 'refresh_token'];
    }

    public function getEnvTemplate(array $client): string
    {
        return implode("\n", [
            'IAM_OIDC_ISSUER=' . $this->value($client, 'issuer'),
            'IAM_OIDC_CLIENT_ID=' . $this->value($client, 'client_id'),
            'IAM_OIDC_CLIENT_SECRET=' . $this->value($client, 'client_secret'),
            'IAM_OIDC_REDIRECT_URI=' . (($client['redirect_uris'][0] ?? '')),
            'IAM_OIDC_POST_LOGOUT_URI=' . (($client['post_logout_uris'][0] ?? '')),
            'IAM_OIDC_SCOPES="' . implode(' ', (array) ($client['scopes'] ?? [])) . '"',
        ]) . "\n";
    }

    public function getConfigTemplate(array $client): string
    {
        return '// Configure OIDC using IAM_OIDC_ISSUER, IAM_OIDC_CLIENT_ID and the callback URI.';
    }

    public function getInstallCommand(): ?string
    {
        return null;
    }

    public function getStarterUrl(): ?string
    {
        return null;
    }

    public function getDocsUrl(): ?string
    {
        return null;
    }
}