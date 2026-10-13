<?php
// IAM-Local — Connexion sans mot de passe (téléphone ou e-mail + code OTP)
require_once __DIR__ . '/includes/functions.php';
require_once __DIR__ . '/includes/mailer.php';

iam_session_start();

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$returnParam = $_GET['return'] ?? $_POST['return'] ?? '';
$returnUrl   = (strncmp($returnParam, IAM_BASE_URL, strlen(IAM_BASE_URL)) === 0) ? $returnParam : '';

if (iam_is_logged_in()) {
    header('Location: ' . IAM_BASE_URL . '/portal.php');
    exit;
}

$error   = '';
$notice  = '';
$step    = $_POST['step'] ?? ($_SESSION['iam_otpuid'] ? 'code' : 'send');
$ip      = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
$ua      = $_SERVER['HTTP_USER_AGENT'] ?? '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf'] ?? '')) {
        $error = 'Session expirée. Réessayez.';
    } elseif ($step === 'send') {
        $identifier = trim($_POST['identifier'] ?? '');
        if ($identifier === '') {
            $error = 'Saisissez votre e-mail ou votre numéro de téléphone.';
        } elseif (!iam_rate_limit_ip($ip, IP_RATE_MAX_ATTEMPTS, IP_RATE_WINDOW_MINUTES)) {
            iam_audit('ip_rate_limited', 'Rate-limit IP (login OTP)', null, $identifier, $ip, $ua);
            $error = 'Trop de tentatives depuis cette adresse IP. Réessayez plus tard.';
        } else {
            $user = iam_find_user($identifier);
            if (!$user) {
                // Ne pas révéler l'existence d'un compte : message neutre
                $notice = 'Si un compte correspond à cet identifiant, un code de connexion a été envoyé.';
            } elseif ($user['status'] !== 'active') {
                $notice = 'Si un compte correspond à cet identifiant, un code de connexion a été envoyé.';
            } elseif (iam_is_locked($user)) {
                $notice = 'Si un compte correspond à cet identifiant, un code de connexion a été envoyé.';
            } else {
                $otp = iam_generate_otp((int) $user['id'], 'email');
                $html = "<h3>" . htmlspecialchars(IAM_NAME) . " — Connexion sans mot de passe</h3>
                         <p>Votre code de connexion est : <strong>$otp</strong></p>
                         <p>Ce code expire dans 5 minutes. Si vous n'êtes pas à l'origine de cette demande, ignorez ce message.</p>";
                iam_send_email($user['email'], IAM_NAME . ' — Votre code de connexion', $html);
                $_SESSION['iam_otpuid']   = (int) $user['id'];
                $_SESSION['iam_otpmail']  = $user['email'];
                $_SESSION['iam_otp_return'] = $returnUrl;
                $_SESSION['iam_otp_sent_at'] = time();
                $demo = $otp;
                $notice = 'Code de connexion envoyé.';
            }
        }
    } elseif ($step === 'code') {
        $uid = (int) ($_SESSION['iam_otpuid'] ?? 0);
        $code = trim($_POST['code'] ?? '');
        if ($uid <= 0) {
            $error = 'Session de connexion expirée. Reprenez depuis le début.';
            unset($_SESSION['iam_otpuid']);
        } elseif (iam_verify_otp($uid, $code)) {
            $user = iam_find_user_by_id($uid);
            if (!$user || $user['status'] !== 'active') {
                $error = 'Impossible de vous connecter (compte indisponible).';
            } else {
                unset($_SESSION['iam_otp_failures']);
                // Validation complète de la session
                iam_reset_failed_attempts($uid);
                iam_record_login_attempt($user['email'], $ip, $ua, true);

                $db = db();
                $db->prepare('UPDATE users SET last_login_at = NOW(), last_login_ip = ? WHERE id = ?')->execute([$ip, $user['id']]);
                iam_audit('login_success', 'Connexion par code OTP (téléphone/e-mail)', (int) $user['id'], $user['email'], $ip, $ua);

                $sessionToken = iam_create_session((int) $user['id'], $ip, $ua);
                $_SESSION['iam_user'] = [
                    'id' => (int) $user['id'],
                    'username' => $user['username'],
                    'email' => $user['email'],
                    'first_name' => $user['first_name'],
                    'last_name' => $user['last_name'],
                    'photo' => $user['photo'],
                    'matricule' => $user['matricule'],
                    'organization_id' => $user['organization_id'],
                    'must_change_password' => (bool) $user['must_change_password'],
                ];
                $_SESSION['iam_session_token'] = $sessionToken;
                $_SESSION['iam_last_active']   = time();
                $_SESSION['iam_mfa_verified']  = true;
                $out = $_SESSION['iam_otp_return'] ?? '';
                unset($_SESSION['iam_otpuid'], $_SESSION['iam_otpmail'], $_SESSION['iam_otp_return'], $_SESSION['iam_otp_sent_at']);

                if (iam_password_expired((int) $user['id'])) {
                    if ($out) { $_SESSION['iam_after_force'] = $out; }
                    header('Location: ' . IAM_BASE_URL . '/profile.php?force=1&expired=1');
                    exit;
                }
                header('Location: ' . ($out ?: IAM_BASE_URL . '/portal.php'));
                exit;
            }
        } else {
            $_SESSION['iam_otp_failures'] = ($_SESSION['iam_otp_failures'] ?? 0) + 1;
            if ($_SESSION['iam_otp_failures'] >= OTP_MAX_TRIES) {
                iam_audit('mfa_lockout', 'Verrouillage login OTP : trop d\'essais', (int) $uid, '', $ip, $ua);
                unset($_SESSION['iam_otpuid'], $_SESSION['iam_otp_failures']);
                $error = 'Trop de codes invalides. Recommencez.';
                $step = 'send';
            } else {
                $error = 'Code invalide ou expiré. Vérifiez le code reçu.';
            }
        }
    }
}

// Renvoi du code
if (isset($_GET['resend']) && !empty($_SESSION['iam_otpuid'])) {
    $otp = iam_generate_otp((int) $_SESSION['iam_otpuid'], 'email');
    $html = "<h3>" . htmlspecialchars(IAM_NAME) . " — Connexion sans mot de passe</h3><p>Votre code de connexion est : <strong>$otp</strong></p>";
    iam_send_email($_SESSION['iam_otpmail'], IAM_NAME . ' — Votre code de connexion', $html);
    $_SESSION['iam_otp_sent_at'] = time();
    $demo = $otp;
    $notice = 'Code renvoyé.';
}
?>
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Connexion sans mot de passe — <?php echo htmlspecialchars(IAM_NAME); ?></title>
<link rel="stylesheet" href="<?php echo htmlspecialchars(IAM_BASE_URL); ?>/assets/css/iam.css">
</head>
<body class="auth-body">
<div class="auth-card">
    <div class="auth-logo">
        <div class="logo-badge"><img src="<?php echo htmlspecialchars(IAM_BASE_URL); ?>/images/acsi.jpg" alt="ACSI"></div>
        <h1>Connexion par code</h1>
        <?php if ($step === 'code' && !empty($_SESSION['iam_otpmail'])): ?>
            <p>Un code a été envoyé à <strong><?php echo htmlspecialchars($_SESSION['iam_otpmail']); ?></strong></p>
        <?php else: ?>
            <p>Connectez-vous sans mot de passe avec votre e-mail ou votre numéro de téléphone.</p>
        <?php endif; ?>
    </div>

    <?php if ($error): ?>
        <div class="alert alert-danger"><i class="fas fa-circle-exclamation"></i> <?php echo htmlspecialchars($error); ?></div>
    <?php endif; ?>
    <?php if ($notice): ?>
        <div class="alert alert-info"><i class="fas fa-circle-check"></i> <?php echo htmlspecialchars($notice); ?></div>
    <?php endif; ?>

    <?php if (!iam_mail_configured() && !empty($demo)): ?>
        <div class="alert alert-warning">
            <strong>Mode démonstration</strong> — SMTP non configuré.<br>
            Votre code : <span class="mono" style="font-size:18px; font-weight:700;"><?php echo htmlspecialchars($demo); ?></span>
        </div>
    <?php endif; ?>

    <?php if (empty($_SESSION['iam_otpuid'])): ?>
        <form method="POST" action="">
            <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
            <input type="hidden" name="step" value="send">
            <input type="hidden" name="return" value="<?php echo htmlspecialchars($returnParam); ?>">
            <div class="form-group">
                <label for="identifier">E-mail ou téléphone</label>
                <div class="input-icon">
                    <i class="fas fa-mobile-screen"></i>
                    <input type="text" id="identifier" name="identifier" class="form-control" placeholder="ex : +243 800 000 001 ou nom@exemple.com" required autofocus>
                </div>
            </div>
            <button type="submit" class="btn btn-primary btn-lg btn-block">
                <i class="fas fa-paper-plane"></i> Recevoir un code
            </button>
        </form>
    <?php else: ?>
        <form method="POST" action="">
            <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
            <input type="hidden" name="step" value="code">
            <input type="hidden" name="return" value="<?php echo htmlspecialchars($_SESSION['iam_otp_return'] ?? $returnParam); ?>">
            <div class="form-group">
                <label for="code">Code à 6 chiffres</label>
                <input type="text" id="code" name="code" class="form-control otp-input" inputmode="numeric" maxlength="6" placeholder="••••••" required autofocus>
            </div>
            <button type="submit" class="btn btn-primary btn-lg btn-block">
                <i class="fas fa-check"></i> Vérifier et me connecter
            </button>
        </form>
    <?php endif; ?>

    <div class="auth-footer">
        <?php if ($step !== 'send' && !empty($_SESSION['iam_otpuid'])): ?>
            <a href="<?php echo IAM_BASE_URL; ?>/otp_login.php?resend=1">Renvoyer le code</a> &middot;
        <?php endif; ?>
        <a href="<?php echo IAM_BASE_URL; ?>/login.php">Retour à la connexion classique</a>
    </div>
</div>
<script src="https://kit.fontawesome.com/64d58efce2.js" crossorigin="anonymous"></script>
</body>
</html>