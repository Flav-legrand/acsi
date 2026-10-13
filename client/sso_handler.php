<?php
/**
 * IAM-Local — Point de callback SSO pour les applications clientes
 *
 * Reçoit le sso_token via ?sso_token=xxx ou ?token=xxx
 * Valide le token via l'API IAM et redirige vers l'application.
 *
 * Placer dans le répertoire de l'application cliente (ex: GestionPresnceAdenIAM/sso_handler.php)
 * ou dans le dossier client/ d'IAM-Local pour un usage partagé.
 */

// ── Le fichier iam_client.php doit être accessible ──────────
// Adapter le chemin selon l'emplacement de ce fichier
$iamClientPath = __DIR__ . '/iam_client.php';
if (!file_exists($iamClientPath)) {
    // Fallback : chercher dans IAM-Local/client/
    $iamClientPath = dirname(__DIR__) . '/IAM-Local/client/iam_client.php';
}

if (!file_exists($iamClientPath)) {
    http_response_code(500);
    echo '<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Erreur SSO</title></head><body>';
    echo '<h1>Erreur SSO</h1>';
    echo '<p>Fichier iam_client.php introuvable. Vérifiez la configuration.</p>';
    echo '</body></html>';
    exit;
}

require_once $iamClientPath;

// ── Récupérer le token ──────────────────────────────────────
$token = $_GET['sso_token'] ?? $_GET['token'] ?? '';
$token = trim($token);

if (empty($token)) {
    http_response_code(400);
    echo '<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Erreur SSO</title></head><body>';
    echo '<h1>Erreur : Token manquant</h1>';
    echo '<p>Aucun jeton SSO n\'a été fourni dans la requête.</p>';
    echo '<p><a href="javascript:history.back()">Retour</a></p>';
    echo '</body></html>';
    exit;
}

// ── Tenter la connexion via SSO ─────────────────────────────
$success = iam_client_login_with_sso_token($token);

if ($success) {
    // Déterminer l'URL de redirection
    $returnUrl = $_SESSION['iam_return_url'] ?? null;
    unset($_SESSION['iam_return_url']);

    if (empty($returnUrl)) {
        // Rediriger vers la page d'accueil de l'application
        $returnUrl = '/';
    }

    header('Location: ' . $returnUrl);
    exit;
}

// ── Échec ───────────────────────────────────────────────────
http_response_code(401);
echo '<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Erreur SSO</title></head><body>';
echo '<h1>Échec de l\'authentification SSO</h1>';
echo '<p>Le jeton SSO est invalide ou a expiré.</p>';
echo '<p>Causes possibles :</p>';
echo '<ul>';
echo '<li>Le jeton a expiré (durée de vie limitée)</li>';
echo '<li>Le jeton a déjà été utilisé</li>';
echo '<li>L\'application n\'est pas enregistrée dans l\'IAM</li>';
echo '</ul>';
echo '<p><a href="javascript:history.back()">Retour</a></p>';
echo '</body></html>';
exit;
