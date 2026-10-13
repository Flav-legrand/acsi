<?php
// IAM-Local — Page MFA (vérification par code OTP)
require_once __DIR__ . '/includes/functions.php';
require_once __DIR__ . '/includes/mailer.php';

iam_session_start();

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// URL de retour (accès direct) à conserver après vérification
$returnParam = $_GET['return'] ?? '';
$returnUrl   = (strncmp($returnParam, IAM_BASE_URL, strlen(IAM_BASE_URL)) === 0) ? $returnParam : '';

// Il faut être en cours de connexion (login réalisé, MFA en attente)
if (empty($_SESSION['iam_user']['id'])) {
    header('Location: ' . IAM_BASE_URL . '/login.php');
    exit;
}

// Récupérer le code OTP (envoi unique)
if (empty($_SESSION['iam_mfa_otp_sent'])) {
    $otp = iam_generate_otp((int) $_SESSION['iam_user']['id'], 'email');
    $html = "<h3>" . htmlspecialchars(IAM_NAME) . " — Code de vérification</h3>
             <p>Votre code OTP est : <strong>$otp</strong></p>
             <p>Ce code expire dans 5 minutes.</p>";
    iam_send_email($_SESSION['iam_user']['email'], IAM_NAME . ' — Code de vérification', $html);
    $_SESSION['iam_mfa_otp_sent'] = true;
    $_SESSION['iam_mfa_resend_at'] = time() + 60;
    $demo = $otp; // affiché en mode démo (SMTP non configuré)
}

$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf'] ?? '')) {
        $error = 'Session expirée. Réessayez.';
    } else {
        $code = trim($_POST['code'] ?? '');
        if (iam_verify_otp((int) $_SESSION['iam_user']['id'], $code)) {
            unset($_SESSION['iam_otp_failures']);
            $_SESSION['iam_mfa_verified'] = true;
            unset($_SESSION['iam_mfa_otp_sent']);
            iam_audit('mfa_verified', 'MFA par email vérifié', (int) $_SESSION['iam_user']['id'], $_SESSION['iam_user']['email'] ?? '', $_SERVER['REMOTE_ADDR'] ?? '', $_SERVER['HTTP_USER_AGENT'] ?? '');
            header('Location: ' . ($returnUrl ?: IAM_BASE_URL . '/portal.php'));
            exit;
        }
        $_SESSION['iam_otp_failures'] = ($_SESSION['iam_otp_failures'] ?? 0) + 1;
        if ($_SESSION['iam_otp_failures'] >= OTP_MAX_TRIES) {
            iam_audit('mfa_lockout', 'Verrouillage MFA : trop d\'essais OTP', (int) $_SESSION['iam_user']['id'], $_SESSION['iam_user']['email'] ?? '', $_SERVER['REMOTE_ADDR'] ?? '', $_SERVER['HTTP_USER_AGENT'] ?? '');
            session_destroy();
            header('Location: ' . IAM_BASE_URL . '/login.php?msg=mfa_lockout');
            exit;
        }
        $error = 'Code invalide ou expiré. Vérifiez le code reçu.';
    }
}

// Renvoi du code
if (isset($_GET['resend'])) {
    $otp = iam_generate_otp((int) $_SESSION['iam_user']['id'], 'email');
    $html = "<h3>" . htmlspecialchars(IAM_NAME) . " — Code de vérification</h3><p>Votre code OTP est : <strong>$otp</strong></p>";
    iam_send_email($_SESSION['iam_user']['email'], IAM_NAME . ' — Code de vérification', $html);
    $_SESSION['iam_mfa_resend_at'] = time() + 60;
    $demo = $otp;
}
?>
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Vérification — <?php echo htmlspecialchars(IAM_NAME); ?></title>
<link rel="stylesheet" href="<?php echo htmlspecialchars(IAM_BASE_URL); ?>/assets/css/iam.css">
</head>
<body class="auth-body">
<div class="auth-card">
    <div class="auth-logo">
        <div class="logo-badge"><img src="<?php echo htmlspecialchars(IAM_BASE_URL); ?>/images/acsi.jpg" alt="ACSI"></div>
        <h1>Vérification en deux étapes</h1>
        <p>Un code a été envoyé à <strong><?php echo htmlspecialchars($_SESSION['iam_user']['email']); ?></strong></p>
    </div>

    <?php if ($error): ?>
        <div class="alert alert-danger"><i class="fas fa-circle-exclamation"></i> <?php echo htmlspecialchars($error); ?></div>
    <?php endif; ?>

    <!-- Affichage du code en mode démo si SMTP non configuré -->
    <?php if (!iam_mail_configured() && !empty($demo)): ?>
        <div class="alert alert-warning">
            <strong>Mode démonstration</strong> — SMTP non configuré.<br>
            Votre code OTP : <span class="mono" style="font-size:18px; font-weight:700;"><?php echo htmlspecialchars($demo); ?></span>
        </div>
    <?php endif; ?>

    <form method="POST" action="">
        <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
        <div class="form-group">
            <label for="code">Code à 6 chiffres</label>
            <input type="text" id="code" name="code" class="form-control otp-input" inputmode="numeric" maxlength="6" placeholder="••••••" required autofocus>
        </div>
        <button type="submit" class="btn btn-primary btn-lg btn-block">
            <i class="fas fa-check"></i> Vérifier et continuer
        </button>
    </form>

    <div class="auth-footer">
        <a href="<?php echo IAM_BASE_URL; ?>/mfa.php?resend=1">Renvoyer le code</a> &middot;
        <a href="<?php echo IAM_BASE_URL; ?>/logout.php">Annuler</a>
    </div>
</div>
<script src="https://kit.fontawesome.com/64d58efce2.js" crossorigin="anonymous"></script>
</body>
</html>