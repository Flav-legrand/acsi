<?php
declare(strict_types=1);

namespace IamLocal\Platforms;

final class GoPlatform extends AbstractPlatform
{
    public function getKey(): string { return 'go'; }
    public function getLabel(): string { return 'Go'; }
    public function getIcon(): string { return 'logos/go.svg'; }
    public function getDescription(): string { return 'Application Go utilisant oauth2 et go-oidc.'; }
    public function getDefaultClientType(): string { return 'confidential'; }
    public function getDefaultRedirectUris(): array { return $this->callback('/auth/callback'); }
    public function getInstallCommand(): ?string { return 'go get github.com/coreos/go-oidc/v3/oidc golang.org/x/oauth2'; }
    public function getStarterUrl(): ?string { return 'https://go.dev/doc/'; }
    public function getDocsUrl(): ?string { return 'https://github.com/coreos/go-oidc'; }
    public function getConfigTemplate(array $client): string
    {
        return "// oidc.go\nprovider, err := oidc.NewProvider(ctx, os.Getenv(\"IAM_OIDC_ISSUER\"))\nif err != nil { return err }\noauthConfig := oauth2.Config{\n    ClientID: os.Getenv(\"IAM_OIDC_CLIENT_ID\"),\n    ClientSecret: os.Getenv(\"IAM_OIDC_CLIENT_SECRET\"),\n    RedirectURL: os.Getenv(\"IAM_OIDC_REDIRECT_URI\"),\n    Endpoint: provider.Endpoint(),\n    Scopes: strings.Fields(os.Getenv(\"IAM_OIDC_SCOPES\")),\n}";
    }
}