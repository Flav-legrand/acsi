<?php
// IAM-Local — API REST : GET /api/sso/app_config.php?code=gestion-presence
// Configuration publique d'une application, consommée par les applications
// clientes pour adapter leur garde SSO (ex : exiger la ressaisie des
// identifiants sur accès direct selon le paramètre graphique sso_prompt).
require_once __DIR__ . '/../../includes/functions.php';

$appCode = trim(input('code', ''));
if ($appCode === '') {
    api_json_response(['error' => 'code requis.'], 422);
}

$db = db();
$stmt = $db->prepare('SELECT code, name, url, active, sso_prompt FROM applications WHERE code = ? LIMIT 1');
$stmt->execute([$appCode]);
$app = $stmt->fetch();

if (!$app) {
    api_json_response(['error' => 'Application inconnue.'], 404);
}

api_json_response([
    'code'       => $app['code'],
    'name'       => $app['name'],
    'url'        => $app['url'],
    'active'     => (bool) $app['active'],
    'sso_prompt' => (bool) $app['sso_prompt'],
]);