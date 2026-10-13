<?php
// IAM-Local — API REST : POST /api/refresh.php
// Corps JSON: { refresh_token }
require_once __DIR__ . '/../includes/functions.php';

$body = api_request_body();
$refreshToken = $body['refresh_token'] ?? '';
if (empty($refreshToken)) api_json_response(['error' => 'refresh_token requis.'], 422);

$db = db();
$stmt = $db->prepare('SELECT rt.*, u.email FROM refresh_tokens rt INNER JOIN users u ON u.id = rt.user_id WHERE rt.token = ? LIMIT 1');
$stmt->execute([$refreshToken]);
$row = $stmt->fetch();

if (!$row || $row['revoked'] || strtotime($row['expires_at']) < time()) {
    api_json_response(['error' => 'Token de rafraîchissement invalide ou expiré.'], 401);
}

// Révoquer l'ancien refresh token
$db->prepare('UPDATE refresh_tokens SET revoked = 1 WHERE id = ?')->execute([$row['id']]);

// Nouveau refresh token
$newRefresh = bin2hex(random_bytes(32));
$db->prepare('INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 30 DAY))')
   ->execute([$row['user_id'], $newRefresh]);

$accessToken = iam_sign_token([
    'sub'   => $row['user_id'],
    'uid'   => (int) $row['user_id'],
    'email' => $row['email'],
    'iat'   => time(),
    'exp'   => time() + 3600,
]);

iam_audit('token_refresh', null, (int) $row['user_id'], $row['email'], $_SERVER['REMOTE_ADDR'] ?? '', $_SERVER['HTTP_USER_AGENT'] ?? '');

api_json_response([
    'success'       => true,
    'access_token'  => $accessToken,
    'refresh_token' => $newRefresh,
    'token_type'    => 'Bearer',
    'expires_in'    => 3600,
]);
