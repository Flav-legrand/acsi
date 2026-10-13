<?php
declare(strict_types=1);

namespace IamLocal\Platforms;

final class NextJsPlatform extends AbstractPlatform
{
    public function getKey(): string { return 'nextjs'; }
    public function getLabel(): string { return 'Next.js'; }
    public function getIcon(): string { return 'logos/nextjs.svg'; }
    public function getDescription(): string { return 'Application web publique utilisant Authorization Code + PKCE.'; }
    public function getDefaultClientType(): string { return 'public'; }
    public function getDefaultRedirectUris(): array { return $this->callback('/api/auth/callback/iam'); }
    public function getDefaultGrantTypes(): array { return ['authorization_code', 'refresh_token']; }
    public function getInstallCommand(): ?string { return 'npm install next-auth'; }
    public function getStarterUrl(): ?string { return 'https://nextjs.org/docs'; }
    public function getDocsUrl(): ?string { return 'https://authjs.dev/getting-started/providers/generic-oidc'; }
    public function getConfigTemplate(array $client): string
    {
        return "// auth.ts\nimport NextAuth from 'next-auth';\n\nexport const { handlers, auth, signIn, signOut } = NextAuth({\n  providers: [{\n    id: 'iam',\n    name: 'Mon IAM',\n    type: 'oidc',\n    issuer: process.env.IAM_OIDC_ISSUER,\n    clientId: process.env.IAM_OIDC_CLIENT_ID,\n    clientSecret: process.env.IAM_OIDC_CLIENT_SECRET,\n    checks: ['pkce', 'state', 'nonce'],\n  }],\n});";
    }
}