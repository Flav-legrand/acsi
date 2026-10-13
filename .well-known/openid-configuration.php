<?php
// IAM-Local — Découverte OIDC à la racine (l'issuer est IAM_BASE_URL)
require_once __DIR__ . '/../includes/functions.php';

header('Content-Type: application/json; charset=utf-8');
echo json_encode([
    'issuer' => IAM_BASE_URL,
    'authorization_endpoint' => IAM_BASE_URL . '/oauth.php',
    'token_endpoint' => IAM_BASE_URL . '/api/oauth/token.php',
    'userinfo_endpoint' => IAM_BASE_URL . '/api/oauth/userinfo.php',
    'jwks_uri' => IAM_BASE_URL . '/api/oauth/jwks.php',
    'end_session_endpoint' => IAM_BASE_URL . '/logout.php',
    'response_types_supported' => ['code'],
    'response_modes_supported' => ['query', 'fragment'],
    'grant_types_supported' => ['authorization_code', 'refresh_token', 'client_credentials'],
    'subject_types_supported' => ['public'],
    'id_token_signing_alg_values_supported' => ['RS256'],
    'scopes_supported' => ['openid', 'profile', 'email', 'roles', 'offline_access'],
    'token_endpoint_auth_methods_supported' => ['client_secret_basic', 'client_secret_post', 'none'],
    'code_challenge_methods_supported' => ['S256', 'plain'],
    'claims_supported' => ['sub', 'name', 'given_name', 'family_name', 'preferred_username', 'email', 'email_verified', 'employee_number', 'department', 'organization_unit', 'title', 'phone_number', 'roles', 'permissions'],
]);