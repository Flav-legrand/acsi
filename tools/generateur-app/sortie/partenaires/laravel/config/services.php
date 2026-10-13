<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Third Party Services
    |--------------------------------------------------------------------------
    |
    | This file is for storing the credentials for third party services such
    | as Mailgun, Postmark, AWS and more. This file provides the de facto
    | location for this type of information, allowing packages to have
    | a conventional file to locate the various service credentials.
    |
    */

    'postmark' => [
        'token' => env('POSTMARK_TOKEN'),
    ],

    'ses' => [
        'key' => env('AWS_ACCESS_KEY_ID'),
        'secret' => env('AWS_SECRET_ACCESS_KEY'),
        'region' => env('AWS_DEFAULT_REGION', 'us-east-1'),
    ],

    'resend' => [
        'key' => env('RESEND_KEY'),
    ],

    'slack' => [
        'notifications' => [
            'bot_user_oauth_token' => env('SLACK_BOT_USER_OAUTH_TOKEN'),
            'channel' => env('SLACK_BOT_USER_DEFAULT_CHANNEL'),
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | IAM-Local (« IAM ACSI ») — Gestion des Partenaires
    |--------------------------------------------------------------------------
    |
    | Généré le 2026-10-13. Toutes les valeurs viennent du .env (voir
    | .env.example). Le secret client n'est JAMAIS écrit ici en dur.
    |
    */

    'iam' => [
        // Voie de connexion par défaut de /login : oidc (recommandé) | sso
        'mode' => env('IAM_AUTH_MODE', 'oidc'),

        // URL publique de l'IAM (navigateur) = IAM_BASE_URL côté IAM.
        'base_url' => env('IAM_BASE_URL', 'http://localhost/IAM-Local'),
        // URL vue par le serveur Laravel, si différente (conteneur, proxy).
        'internal_url' => env('IAM_INTERNAL_URL'),
        // Émetteur attendu dans les jetons (claim iss). Défaut : base_url.
        'issuer' => env('IAM_OIDC_ISSUER'),

        // Code de l'application dans l'IAM (table applications.code).
        'app_code' => env('IAM_APP_CODE', 'partenaires'),

        // Client OIDC (table oauth_clients).
        'client_id' => env('IAM_OIDC_CLIENT_ID', 'iam-laravel-partenaires'),
        'client_secret' => env('IAM_OIDC_CLIENT_SECRET'),
        'redirect_uri' => env('IAM_OIDC_REDIRECT_URI', 'http://localhost:8001/callback'),
        'post_logout_redirect_uri' => env('IAM_OIDC_POST_LOGOUT_URI', 'http://localhost:8001/logged-out'),
        'scopes' => env('IAM_OIDC_SCOPES', 'openid profile email roles offline_access'),

        // SSO maison : ressaisie forcée des identifiants IAM (prompt=login)
        // et durée de vie de la session locale (aucun jeton à revérifier).
        'sso_prompt' => (bool) env('IAM_SSO_PROMPT', false),
        'sso_session_ttl' => (int) env('IAM_SSO_SESSION_TTL', 28800),

        // Aucune permission reçue → lecture seule (*.view) plutôt que rien.
        'readonly_fallback' => (bool) env('IAM_READONLY_FALLBACK', true),

        'jwks_cache_ttl' => (int) env('IAM_JWKS_CACHE_TTL', 3600),
        'http_timeout' => (int) env('IAM_HTTP_TIMEOUT', 10),
        'verify_tls' => (bool) env('IAM_VERIFY_TLS', true),
    ],

];
