<?php
// IAM-Local — Point d'entrée
require_once __DIR__ . '/includes/functions.php';

iam_session_start();

if (!iam_is_logged_in()) {
    header('Location: ' . IAM_BASE_URL . '/login.php');
    exit;
}
if (!empty($_SESSION['iam_mfa_required']) && empty($_SESSION['iam_mfa_verified'])) {
    header('Location: ' . IAM_BASE_URL . '/mfa.php');
    exit;
}
header('Location: ' . IAM_BASE_URL . '/portal.php');
exit;