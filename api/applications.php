<?php
// IAM-Local — API REST : GET /api/applications.php
require_once __DIR__ . '/../includes/functions.php';

$user = api_require_auth();
$apps = iam_user_apps($user['id']);
api_json_response(['applications' => $apps]);
