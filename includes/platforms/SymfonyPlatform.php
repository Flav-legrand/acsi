<?php
declare(strict_types=1);

namespace IamLocal\Platforms;

final class SymfonyPlatform extends AbstractPlatform
{
    public function getKey(): string { return 'symfony'; }
    public function getLabel(): string { return 'Symfony'; }
    public function getIcon(): string { return 'logos/symfony.svg'; }
    public function getDescription(): string { return 'Application Symfony utilisant un client OAuth2 serveur.'; }
    public function getDefaultClientType(): string { return 'confidential'; }
    public function getDefaultRedirectUris(): array { return $this->callback('/auth/iam/callback'); }
    public function getInstallCommand(): ?string { return 'composer require knpuniversity/oauth2-client-bundle'; }
    public function getStarterUrl(): ?string { return 'https://symfony.com/doc/current/index.html'; }
    public function getDocsUrl(): ?string { return 'https://github.com/knpuniversity/oauth2-client-bundle'; }
    public function getConfigTemplate(array $client): string
    {
        return "# config/packages/knpu_oauth2_client.yaml\nknpu_oauth2_client:\n  clients:\n    iam:\n      type: generic\n      provider_class: League\\\\OAuth2\\\\Client\\\\Provider\\\\GenericProvider\n      client_id: '%env(IAM_OIDC_CLIENT_ID)%'\n      client_secret: '%env(IAM_OIDC_CLIENT_SECRET)%'\n      redirect_route: app_iam_callback\n      redirect_params: {}\n      provider_options:\n        urlAuthorize: '%env(IAM_OIDC_ISSUER)%/oauth.php'\n        urlAccessToken: '%env(IAM_OIDC_ISSUER)%/api/oauth/token.php'\n        urlResourceOwnerDetails: '%env(IAM_OIDC_ISSUER)%/api/oauth/userinfo.php'";
    }
}