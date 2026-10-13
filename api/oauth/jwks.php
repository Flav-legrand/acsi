<?php
// IAM-Local — JWKS (clés publiques de signature OIDC)
require_once __DIR__ . '/../../includes/functions.php';
require_once __DIR__ . '/../../includes/oauth.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: public, max-age=3600');
iam_oauth_current_key();
echo json_encode(['keys' => iam_oauth_jwks()]);