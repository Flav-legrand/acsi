<?php
declare(strict_types=1);

namespace IamLocal\Platforms;

final class NodeJsPlatform extends AbstractPlatform
{
    public function getKey(): string { return 'nodejs'; }
    public function getLabel(): string { return 'Node.js'; }
    public function getIcon(): string { return 'logos/nodejs.svg'; }
    public function getDescription(): string { return 'Service Node.js utilisant un client OIDC confidentiel.'; }
    public function getDefaultClientType(): string { return 'confidential'; }
    public function getDefaultRedirectUris(): array { return $this->callback('/auth/iam/callback'); }
    public function getInstallCommand(): ?string { return 'npm install openid-client'; }
    public function getStarterUrl(): ?string { return 'https://nodejs.org/docs/latest/api/'; }
    public function getDocsUrl(): ?string { return 'https://github.com/panva/openid-client'; }
    public function getConfigTemplate(array $client): string
    {
        return "// oidc.mjs (openid-client v6)\nimport * as oidc from 'openid-client';\n\nconst issuer = await oidc.discovery(\n  new URL(process.env.IAM_OIDC_ISSUER),\n  process.env.IAM_OIDC_CLIENT_ID,\n  process.env.IAM_OIDC_CLIENT_SECRET,\n);\n\nexport const oidcConfig = issuer; // Use authorizationCodeGrant() in the callback route.";
    }
}