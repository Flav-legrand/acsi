<?php
// IAM-Local — API REST : POST /api/logout.php
require_once __DIR__ . '/../includes/functions.php';
iam_session_start();

$user = $_SESSION['iam_user'] ?? null;
$token = $_SESSION['iam_session_token'] ?? null;
$ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
$ua = $_SERVER['HTTP_USER_AGENT'] ?? '';

if ($user && $token) {
    iam_audit('logout', 'Déconnexion', (int) $user['id'], $user['email'] ?? '', $ip, $ua);
    // iam_touch_session et NON iam_create_session : create_session
    // INSÈRE une nouvelle ligne dans sessions, si bien que chaque
    // déconnexion laissait en base une session orpheline, jamais
    // révoquée et valable pendant session_lifetime. Elle apparaissait
    // dans Administration > Sessions comme une session active que
    // personne ne détenait.
    iam_touch_session((int) $user['id'], $token);
    $db = db();
    $stmt = $db->prepare('UPDATE sessions SET revoked = 1 WHERE user_id = ? AND session_token = ? AND revoked = 0');
    $stmt->execute([(int) $user['id'], $token]);
}

iam_session_destroy();
api_json_response(['success' => true, 'message' => 'Déconnexion réussie.']);
