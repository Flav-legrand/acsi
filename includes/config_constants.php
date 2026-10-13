<?php
// IAM-Local — Liste des constantes de configuration attendues.
// Sans dépendance : utilisée par includes/config_bootstrap.php (contrôle à
// chaque requête) et par install.php (contrôle du fichier généré).
// Référence commentée : config/config.template.php.

if (!function_exists('iam_required_config_constants')) {
    function iam_required_config_constants(): array
    {
        return [
            'IAM_BASE_URL', 'IAM_ADMIN_APP_CODE', 'IAM_NAME', 'IAM_VERSION', 'IAM_TAGLINE',
            'DB_HOST', 'DB_USER', 'DB_PASS', 'DB_NAME', 'DB_PORT',
            'SESSION_LIFETIME', 'IDLE_TIMEOUT', 'SESSION_COOKIE_NAME', 'SSO_TOKEN_LIFETIME',
            'IAM_JWT_SECRET',
            'OTP_LENGTH', 'OTP_LIFETIME', 'OTP_MAX_TRIES', 'MFA_FORCE_ALL',
            'MAX_LOGIN_ATTEMPTS', 'LOCKOUT_MINUTES',
            'SMTP_HOST', 'SMTP_PORT', 'SMTP_USER', 'SMTP_PASS', 'SMTP_FROM', 'SMTP_FROM_NAME',
            'OAUTH_GOOGLE_CLIENT_ID', 'OAUTH_GOOGLE_CLIENT_SECRET',
            'OAUTH_MICROSOFT_CLIENT_ID', 'OAUTH_MICROSOFT_CLIENT_SECRET',
            'UPLOAD_DIR', 'MAX_UPLOAD_SIZE',
        ];
    }
}
