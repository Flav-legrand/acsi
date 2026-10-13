<?php
// IAM-Local — Admin : Télécharger le fichier d'intégration SSO d'une application
// Usage : /admin/download_sso.php?app=CODE
require_once __DIR__ . '/_guard.php';
require_once __DIR__ . '/_sso_generator.php';

$code = trim($_GET['app'] ?? '');
if ($code === '') {
    http_response_code(400);
    die('Paramètre app manquant.');
}

$stmt = db()->prepare('SELECT * FROM applications WHERE code = ? LIMIT 1');
$stmt->execute([$code]);
$app = $stmt->fetch();
if (!$app) {
    http_response_code(404);
    die('Application introuvable.');
}

$codeSlug   = iam_app_code_slug($code);
$guardFile  = 'iam-sso-' . $codeSlug . '.php';
$content    = iam_build_guard_content($app);

header('Content-Type: application/octet-stream; charset=utf-8');
header('Content-Disposition: attachment; filename="' . $guardFile . '"');
header('Content-Length: ' . strlen($content));
header('Cache-Control: no-store');
echo $content;
exit;