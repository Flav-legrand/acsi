<?php
require_once __DIR__ . '/_guard.php';
require_once __DIR__ . '/_sso_generator.php';

header('Content-Type: application/json; charset=utf-8');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['ready' => false, 'error' => 'Requête POST requise.']);
    exit;
}

if (!hash_equals($_SESSION['csrf_token'] ?? '', (string) ($_POST['csrf'] ?? ''))) {
    http_response_code(403);
    echo json_encode(['ready' => false, 'error' => 'Session expirée. Rechargez le formulaire.']);
    exit;
}

$result = iam_app_preflight(
    db(),
    iam_app_code_slug((string) ($_POST['code'] ?? '')),
    (string) ($_POST['name'] ?? ''),
    (string) ($_POST['url'] ?? '')
);

echo json_encode($result, JSON_UNESCAPED_UNICODE);