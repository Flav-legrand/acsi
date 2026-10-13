<?php
declare(strict_types=1);

namespace IamLocal\Platforms;

final class PhpPlatform extends AbstractPlatform
{
    public function getKey(): string { return 'php'; }
    public function getLabel(): string { return 'PHP pur'; }
    public function getIcon(): string { return 'logos/php.svg'; }
    public function getDescription(): string { return 'Application PHP utilisant le client OAuth2 League.'; }
    public function getDefaultClientType(): string { return 'confidential'; }
    public function getDefaultRedirectUris(): array { return $this->callback('/callback.php'); }
    public function getInstallCommand(): ?string { return 'composer require league/oauth2-client'; }
    public function getStarterUrl(): ?string { return 'https://www.php.net/docs.php'; }
    public function getDocsUrl(): ?string { return 'https://oauth2-client.thephpleague.com/'; }
    public function getConfigTemplate(array $client): string
    {
        return "<?php\n// callback.php\nrequire __DIR__ . '/vendor/autoload.php';\n\$provider = new \\League\\OAuth2\\Client\\Provider\\GenericProvider([\n    'clientId' => getenv('IAM_OIDC_CLIENT_ID'),\n    'clientSecret' => getenv('IAM_OIDC_CLIENT_SECRET'),\n    'redirectUri' => getenv('IAM_OIDC_REDIRECT_URI'),\n    'urlAuthorize' => getenv('IAM_OIDC_ISSUER') . '/oauth.php',\n    'urlAccessToken' => getenv('IAM_OIDC_ISSUER') . '/api/oauth/token.php',\n    'urlResourceOwnerDetails' => getenv('IAM_OIDC_ISSUER') . '/api/oauth/userinfo.php',\n]);";
    }
}