<?php
declare(strict_types=1);

namespace IamLocal\Platforms;

final class SpringPlatform extends AbstractPlatform
{
    public function getKey(): string { return 'spring'; }
    public function getLabel(): string { return 'Spring'; }
    public function getIcon(): string { return 'logos/spring.svg'; }
    public function getDescription(): string { return 'Application Spring Security avec client OAuth2 serveur.'; }
    public function getDefaultClientType(): string { return 'confidential'; }
    public function getDefaultRedirectUris(): array { return $this->callback('/login/oauth2/code/iam'); }
    public function getInstallCommand(): ?string { return 'Add spring-boot-starter-oauth2-client to pom.xml'; }
    public function getStarterUrl(): ?string { return 'https://spring.io/projects/spring-boot'; }
    public function getDocsUrl(): ?string { return 'https://docs.spring.io/spring-security/reference/servlet/oauth2/login/index.html'; }
    public function getConfigTemplate(array $client): string
    {
        return "# application.yml\nspring:\n  security:\n    oauth2:\n      client:\n        registration:\n          iam:\n            provider: iam\n            client-id: \${IAM_OIDC_CLIENT_ID}\n            client-secret: \${IAM_OIDC_CLIENT_SECRET}\n            authorization-grant-type: authorization_code\n            redirect-uri: \${IAM_OIDC_REDIRECT_URI}\n            scope: openid,profile,email\n        provider:\n          iam:\n            authorization-uri: \${IAM_OIDC_ISSUER}/oauth.php\n            token-uri: \${IAM_OIDC_ISSUER}/api/oauth/token.php\n            user-info-uri: \${IAM_OIDC_ISSUER}/api/oauth/userinfo.php\n            user-name-attribute: sub";
    }
}