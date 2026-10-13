<?php
declare(strict_types=1);

namespace IamLocal\Platforms;

/**
 * Adaptateur Laravel, aligné sur le squelette produit par
 * tools/generateur-app (pile laravel) : routes /callback et /logged-out,
 * vérification des JWT par firebase/php-jwt (JWKS), PKCE S256.
 */
final class LaravelPlatform extends AbstractPlatform
{
    public function getKey(): string { return 'laravel'; }
    public function getLabel(): string { return 'Laravel'; }
    public function getIcon(): string { return 'logos/laravel.svg'; }
    public function getDescription(): string { return 'Application Laravel avec callback serveur, secret confidentiel et PKCE (squelette : tools/generateur-app, pile laravel).'; }
    public function getDefaultClientType(): string { return 'confidential'; }
    public function getDefaultRedirectUris(): array { return $this->callback('/callback'); }
    public function getDefaultPostLogoutUris(): array { return ['{base_url}/logged-out']; }
    public function getDefaultScopes(): array { return ['openid', 'profile', 'email', 'roles', 'offline_access']; }
    public function getDefaultGrantTypes(): array { return ['authorization_code', 'refresh_token']; }
    public function getInstallCommand(): ?string { return 'composer require firebase/php-jwt:^6.10'; }
    public function getStarterUrl(): ?string { return 'https://laravel.com/docs/11.x'; }
    public function getDocsUrl(): ?string { return 'https://openid.net/specs/openid-connect-core-1_0.html'; }
    public function getConfigTemplate(array $client): string
    {
        return "// config/services.php (squelette complet : tools/generateur-app, pile laravel)\n'iam' => [\n    'mode' => env('IAM_AUTH_MODE', 'oidc'),\n    'base_url' => env('IAM_BASE_URL'),\n    'issuer' => env('IAM_OIDC_ISSUER'),\n    'client_id' => env('IAM_OIDC_CLIENT_ID'),\n    'client_secret' => env('IAM_OIDC_CLIENT_SECRET'),\n    'redirect_uri' => env('IAM_OIDC_REDIRECT_URI'),\n    'post_logout_redirect_uri' => env('IAM_OIDC_POST_LOGOUT_URI'),\n    'scopes' => env('IAM_OIDC_SCOPES', 'openid profile email roles offline_access'),\n],";
    }
}
