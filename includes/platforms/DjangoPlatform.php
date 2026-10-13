<?php
declare(strict_types=1);

namespace IamLocal\Platforms;

final class DjangoPlatform extends AbstractPlatform
{
    public function getKey(): string { return 'django'; }
    public function getLabel(): string { return 'Django'; }
    public function getIcon(): string { return 'logos/django.svg'; }
    public function getDescription(): string { return 'Application Django avec client confidentiel côté serveur.'; }
    public function getDefaultClientType(): string { return 'confidential'; }
    public function getDefaultRedirectUris(): array { return $this->callback('/oidc/callback/'); }
    public function getInstallCommand(): ?string { return 'pip install mozilla-django-oidc'; }
    public function getStarterUrl(): ?string { return 'https://docs.djangoproject.com/'; }
    public function getDocsUrl(): ?string { return 'https://mozilla-django-oidc.readthedocs.io/'; }
    public function getConfigTemplate(array $client): string
    {
        return "# settings.py\nINSTALLED_APPS += ['mozilla_django_oidc']\nAUTHENTICATION_BACKENDS = ['mozilla_django_oidc.auth.OIDCAuthenticationBackend']\nOIDC_RP_CLIENT_ID = os.environ['IAM_OIDC_CLIENT_ID']\nOIDC_RP_CLIENT_SECRET = os.environ['IAM_OIDC_CLIENT_SECRET']\nOIDC_OP_AUTHORIZATION_ENDPOINT = os.environ['IAM_OIDC_ISSUER'] + '/oauth.php'\nOIDC_OP_TOKEN_ENDPOINT = os.environ['IAM_OIDC_ISSUER'] + '/api/oauth/token.php'\nOIDC_OP_USER_ENDPOINT = os.environ['IAM_OIDC_ISSUER'] + '/api/oauth/userinfo.php'\nOIDC_OP_JWKS_ENDPOINT = os.environ['IAM_OIDC_ISSUER'] + '/api/oauth/jwks.php'\nLOGIN_REDIRECT_URL = '/'";
    }
}