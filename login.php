<?php
// IAM-Local — Page de connexion
require_once __DIR__ . '/includes/functions.php';

iam_session_start();

// CSRF : générer / récupérer
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$error  = '';
$notice = '';
$identifier = '';

// Accès direct : retourner vers cet URL après connexion (+ forcer la ressaisie)
$returnParam = $_GET['return'] ?? $_POST['return'] ?? '';
$prompt      = isset($_GET['prompt']) || !empty($_POST['prompt']);
$returnUrl   = (strncmp($returnParam, IAM_BASE_URL, strlen(IAM_BASE_URL)) === 0) ? $returnParam : '';

if (isset($_GET['msg']) && $_GET['msg'] === 'logout') {
    $notice = 'Déconnexion réussie.';
}

// Déjà connecté ? (sauf si connexion forcée -> on affiche le formulaire)
if (iam_is_logged_in() && !$prompt) {
    if (!empty($_SESSION['iam_mfa_required']) && empty($_SESSION['iam_mfa_verified'])) {
        header('Location: ' . IAM_BASE_URL . '/mfa.php' . ($returnUrl ? '?return=' . urlencode($returnUrl) : ''));
        exit;
    }
    header('Location: ' . IAM_BASE_URL . '/portal.php');
    exit;
}

// Traitement du formulaire
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf'] ?? '')) {
        $error = 'Session expirée. Réessayez.';
    } else {
        $identifier = trim($_POST['identifier'] ?? '');
        $password   = $_POST['password'] ?? '';
        $ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
        $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';

        if ($identifier === '' || $password === '') {
            $error = 'Veuillez saisir votre identifiant et votre mot de passe.';
        } else {
            $ipBlocked = !iam_rate_limit_ip($ip, IP_RATE_MAX_ATTEMPTS, IP_RATE_WINDOW_MINUTES);
            $user = iam_find_user($identifier);
            if ($ipBlocked) {
                iam_audit('ip_rate_limited', 'Limite rate-limit IP atteinte', null, $identifier, $ip, $ua);
                $error = 'Trop de tentatives depuis cette adresse IP. Réessayez plus tard.';
            } elseif (!$user) {
                iam_record_login_attempt($identifier, $ip, $ua, false);
                $error = 'Identifiants incorrects.';
            } elseif (!iam_rate_limit((int) $user['id'], MAX_LOGIN_ATTEMPTS, LOCKOUT_MINUTES)) {
                $error = 'Trop de tentatives. Réessayez plus tard.';
            } elseif ($user['status'] === 'inactive' || $user['status'] === 'pending') {
                $error = 'Compte désactivé ou en attente de validation.';
            } elseif (iam_is_locked($user)) {
                iam_record_login_attempt($identifier, $ip, $ua, false);
                $error = 'Compte temporairement verrouillé. Réessayez plus tard.';
            } elseif (!iam_verify_password($password, $user['password_hash'])) {
                iam_record_login_attempt($identifier, $ip, $ua, false);
                iam_increment_failed_attempts((int) $user['id']);
                $policy = iam_get_password_policy();
                $failed = iam_get_failed_attempts($user['email']);
                if ($failed >= $policy['lockout_threshold']) {
                    iam_lock_user((int) $user['id'], $policy['lockout_minutes']);
                    iam_audit('account_locked', "Verrouillage après $failed tentatives", (int) $user['id'], $user['email'], $ip, $ua);
                    $error = 'Trop de tentatives échouées. Compte verrouillé.';
                } else {
                    $error = 'Identifiants incorrects.';
                }
            } else {
                // Succès
                iam_reset_failed_attempts((int) $user['id']);
                iam_record_login_attempt($identifier, $ip, $ua, true);

                $db = db();
                $db->prepare('UPDATE users SET last_login_at = NOW(), last_login_ip = ? WHERE id = ?')
                   ->execute([$ip, $user['id']]);

                iam_audit('login_success', 'Connexion au portail IAM', (int) $user['id'], $user['email'], $ip, $ua);

                $sessionToken = iam_create_session((int) $user['id'], $ip, $ua);

                $_SESSION['iam_user'] = [
                    'id'            => (int) $user['id'],
                    'username'      => $user['username'],
                    'email'         => $user['email'],
                    'first_name'    => $user['first_name'],
                    'last_name'     => $user['last_name'],
                    'photo'         => $user['photo'],
                    'matricule'     => $user['matricule'],
                    'organization_id' => $user['organization_id'],
                    'must_change_password' => (bool) $user['must_change_password'],
                ];
                $_SESSION['iam_session_token'] = $sessionToken;
                $_SESSION['iam_last_active']   = time();

                if ((MFA_FORCE_ALL && !iam_user_is_admin((int) $user['id'])) || (bool) $user['mfa_enabled']) {
                    $_SESSION['iam_mfa_required'] = true;
                    unset($_SESSION['iam_mfa_verified']);
                    header('Location: ' . IAM_BASE_URL . '/mfa.php' . ($returnUrl ? '?return=' . urlencode($returnUrl) : ''));
                    exit;
                } else {
                    $_SESSION['iam_mfa_verified'] = true;
                }

                // Mot de passe expiré (politique expiration_days)
                if (iam_password_expired((int) $user['id'])) {
                    if ($returnUrl) { $_SESSION['iam_after_force'] = $returnUrl; }
                    header('Location: ' . IAM_BASE_URL . '/profile.php?force=1&expired=1');
                    exit;
                }

                // Accès direct : retourner vers l'application demandée
                if ($returnUrl) {
                    header('Location: ' . $returnUrl);
                    exit;
                }

                header('Location: ' . IAM_BASE_URL . '/portal.php');
                exit;
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Connexion — <?php echo htmlspecialchars(IAM_NAME); ?></title>
<link rel="stylesheet" href="<?php echo htmlspecialchars(IAM_BASE_URL); ?>/assets/css/iam.css">
</head>
<body class="auth-body">
<div class="auth-card">
    <div class="auth-logo">
        <div class="logo-badge"><img src="<?php echo htmlspecialchars(IAM_BASE_URL); ?>/images/acsi.jpg" alt="ACSI"></div>
        <h1><?php echo htmlspecialchars(IAM_NAME); ?></h1>
        <p>Plateforme d'identité et d'accès — <?php echo htmlspecialchars(IAM_NAME); ?></p>
    </div>

    <?php if ($error): ?>
        <div class="alert alert-danger"><i class="fas fa-circle-exclamation"></i> <?php echo htmlspecialchars($error); ?></div>
    <?php endif; ?>
    <?php if ($notice): ?>
        <div class="alert alert-info"><i class="fas fa-circle-check"></i> <?php echo htmlspecialchars($notice); ?></div>
    <?php endif; ?>

    <form method="POST" action="">
        <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
        <input type="hidden" name="return" value="<?php echo htmlspecialchars($returnParam); ?>">
        <input type="hidden" name="prompt" value="<?php echo $prompt ? '1' : ''; ?>">
        <div class="form-group">
            <label for="identifier">Adresse e-mail ou identifiant</label>
            <div class="input-icon">
                <i class="fas fa-user"></i>
                <input type="text" id="identifier" name="identifier" class="form-control" placeholder="ex : nom@exemple.com" value="<?php echo htmlspecialchars($identifier); ?>" required autofocus>
            </div>
        </div>
        <div class="form-group">
            <label for="password">Mot de passe</label>
            <div class="input-icon">
                <i class="fas fa-lock"></i>
                <input type="password" id="password" name="password" class="form-control" placeholder="Votre mot de passe" required>
            </div>
        </div>
        <button type="submit" class="btn btn-primary btn-lg btn-block">
            <i class="fas fa-sign-in-alt"></i> Se connecter
        </button>
    </form>

    <div class="auth-footer">
        <a href="<?php echo IAM_BASE_URL; ?>/otp_login.php">Connexion sans mot de passe (téléphone / code)</a> &middot;
        &copy; <?php echo date('Y'); ?> <?php echo htmlspecialchars(IAM_NAME); ?> — Accès applications par SSO
    </div>
</div>
<script src="https://kit.fontawesome.com/64d58efce2.js" crossorigin="anonymous"></script>
</body>
</html>