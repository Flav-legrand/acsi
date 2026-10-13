<?php
// IAM-Local — Envoyer un e-mail (SMTP classique ou OAuth2 : Gmail, Outlook/Office365)
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/db.php';

$iamAutoload = __DIR__ . '/../vendor/autoload.php';
if (file_exists($iamAutoload)) {
    require_once $iamAutoload;
}

function iam_smtp_config(): array
{
    $defaults = [
        'host'      => SMTP_HOST,
        'port'      => SMTP_PORT,
        'user'      => SMTP_USER,
        'pass'      => SMTP_PASS,
        'from'      => SMTP_FROM,
        'from_name' => SMTP_FROM_NAME,
    ];
    try {
        $db = db();
        $rows = $db->query('SELECT s_key, s_value FROM settings WHERE s_key LIKE \'smtp\\_%\' ESCAPE \'\\\\\'')->fetchAll();
        foreach ($rows as $row) {
            $k = str_replace('smtp_', '', $row['s_key']);
            if ($row['s_value'] !== '' && array_key_exists($k, $defaults)) {
                $defaults[$k] = $row['s_value'];
            }
        }
    } catch (\Throwable $e) {
        // table absente (pré-installation) : constantes par défaut
    }
    return $defaults;
}

function iam_smtp_configured(): bool
{
    $cfg = iam_smtp_config();
    return !empty($cfg['user']) && !empty($cfg['pass']);
}

function iam_save_smtp_config(array $values): void
{
    $db = db();
    $current = iam_smtp_config();
    $keys = ['host', 'port', 'user', 'pass', 'from', 'from_name'];
    foreach ($keys as $k) {
        if (!array_key_exists($k, $values)) continue;
        $v = trim((string) $values[$k]);
        // Garder le mot de passe existant si le champ est laissé vide
        if ($k === 'pass' && $v === '') {
            $v = $current['pass'];
        }
        $stmt = $db->prepare('INSERT INTO settings (s_key, s_value) VALUES (?, ?) ON DUPLICATE KEY UPDATE s_value = VALUES(s_value)');
        $stmt->execute(['smtp_' . $k, $v]);
    }
}

// ------------------------------------------------------------
// OAUTH2 — fournisseurs (Gmail, Outlook/Office365...)
// ------------------------------------------------------------

function iam_oauth_providers(): array
{
    return [
        'google' => [
            'label'       => 'Google / Gmail',
            'icon'        => 'fab fa-google',
            'authorize'   => 'https://accounts.google.com/o/oauth2/v2/auth',
            'token'       => 'https://oauth2.googleapis.com/token',
            'resource'    => 'https://www.googleapis.com/oauth2/v1/userinfo',
            'scopes'      => ['https://www.googleapis.com/auth/gmail.send', 'openid', 'email', 'profile'],
            'auth_params' => ['access_type' => 'offline', 'prompt' => 'consent'],
            'smtp_host'   => 'smtp.gmail.com',
            'smtp_port'   => 465,
            'smtp_secure' => 'ssl',
            'help'        => 'console.cloud.google.com : activer la Gmail API puis créer un ID client OAuth de type « application Web ».',
        ],
        'microsoft' => [
            'label'       => 'Microsoft / Outlook',
            'icon'        => 'fab fa-microsoft',
            'authorize'   => 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
            'token'       => 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
            'resource'    => 'https://graph.microsoft.com/v1.0/me',
            'scopes'      => ['offline_access', 'openid', 'email', 'profile', 'https://outlook.office.com/SMTP.Send', 'https://graph.microsoft.com/User.Read'],
            'auth_params' => ['prompt' => 'consent'],
            'smtp_host'   => 'smtp.office365.com',
            'smtp_port'   => 587,
            'smtp_secure' => 'tls',
            'help'        => 'portal.azure.com : Azure Active Directory, inscription d\'une application, ajouter l\'URI de redirection Web.',
        ],
    ];
}

function iam_oauth_config(string $provider): array
{
    $defaults = [
        'client_id'     => defined('OAUTH_GOOGLE_CLIENT_ID') && $provider === 'google' ? (string) OAUTH_GOOGLE_CLIENT_ID : '',
        'client_secret' => defined('OAUTH_GOOGLE_CLIENT_SECRET') && $provider === 'google' ? (string) OAUTH_GOOGLE_CLIENT_SECRET : '',
        'refresh_token' => '',
        'email'         => '',
    ];
    if ($provider === 'microsoft') {
        $defaults['client_id']     = defined('OAUTH_MICROSOFT_CLIENT_ID') ? (string) OAUTH_MICROSOFT_CLIENT_ID : '';
        $defaults['client_secret'] = defined('OAUTH_MICROSOFT_CLIENT_SECRET') ? (string) OAUTH_MICROSOFT_CLIENT_SECRET : '';
    }
    try {
        $db = db();
        $stmt = $db->prepare('SELECT s_key, s_value FROM settings WHERE s_key LIKE ?');
        $stmt->execute(['oauth_' . $provider . '_%']);
        foreach ($stmt->fetchAll() as $row) {
            $k = substr($row['s_key'], strlen('oauth_' . $provider . '_'));
            if (in_array($k, ['refresh_token', 'email'], true)) {
                $row['s_value'] = $row['s_value'] !== '' ? $row['s_value'] : $defaults[$k];
            }
            if ($row['s_value'] !== '' && array_key_exists($k, $defaults)) {
                $defaults[$k] = $row['s_value'];
            }
        }
    } catch (\Throwable $e) {
        // table absente
    }
    return $defaults;
}

function iam_oauth_configured(string $provider): bool
{
    $c = iam_oauth_config($provider);
    return !empty($c['client_id']) && !empty($c['client_secret']) && !empty($c['refresh_token']) && !empty($c['email']);
}

function iam_oauth_ready(string $provider): bool
{
    $c = iam_oauth_config($provider);
    return !empty($c['client_id']) && !empty($c['client_secret']) && !empty($c['refresh_token']);
}

function iam_oauth_save_credentials(string $provider, string $clientId, string $clientSecret): void
{
    $db = db();
    foreach (['client_id' => $clientId, 'client_secret' => $clientSecret] as $k => $v) {
        $stmt = $db->prepare('INSERT INTO settings (s_key, s_value) VALUES (?, ?) ON DUPLICATE KEY UPDATE s_value = VALUES(s_value)');
        $stmt->execute(['oauth_' . $provider . '_' . $k, trim($v)]);
    }
}

function iam_oauth_save_token(string $provider, string $refreshToken, string $email): void
{
    $db = db();
    foreach (['refresh_token' => $refreshToken, 'email' => $email] as $k => $v) {
        $stmt = $db->prepare('INSERT INTO settings (s_key, s_value) VALUES (?, ?) ON DUPLICATE KEY UPDATE s_value = VALUES(s_value)');
        $stmt->execute(['oauth_' . $provider . '_' . $k, trim($v)]);
    }
    // Le fournisseur connecté devient le mode d'envoi actif
    $stmt = $db->prepare('INSERT INTO settings (s_key, s_value) VALUES (\'oauth_mode\', ?) ON DUPLICATE KEY UPDATE s_value = VALUES(s_value)');
    $stmt->execute([$provider]);
}

function iam_oauth_clear(string $provider): void
{
    $db = db();
    $stmt = $db->prepare('DELETE FROM settings WHERE s_key LIKE ?');
    $stmt->execute(['oauth_' . $provider . '_%']);
    $stmt = $db->query('SELECT s_value FROM settings WHERE s_key = \'oauth_mode\'');
    if ($stmt->fetchColumn() === $provider) {
        $db->exec("DELETE FROM settings WHERE s_key = 'oauth_mode'");
    }
}

function iam_oauth_mode(): string
{
    try {
        $db = db();
        $stmt = $db->query('SELECT s_value FROM settings WHERE s_key = \'oauth_mode\'');
        $mode = $stmt->fetchColumn();
        if ($mode && array_key_exists($mode, iam_oauth_providers()) && iam_oauth_ready($mode)) {
            return $mode;
        }
    } catch (\Throwable $e) {
    }
    return '';
}

function iam_oauth_redirect_uri(): string
{
    return IAM_BASE_URL . '/oauth/callback.php';
}

function iam_oauth_provider_instance(string $provider): \League\OAuth2\Client\Provider\GenericProvider
{
    $providers = iam_oauth_providers();
    if (!isset($providers[$provider])) {
        throw new \RuntimeException('Fournisseur OAuth inconnu : ' . $provider);
    }
    $meta = $providers[$provider];
    $c = iam_oauth_config($provider);
    return new \League\OAuth2\Client\Provider\GenericProvider([
        'clientId'                => $c['client_id'],
        'clientSecret'            => $c['client_secret'],
        'redirectUri'             => iam_oauth_redirect_uri(),
        'urlAuthorize'            => $meta['authorize'],
        'urlAccessToken'          => $meta['token'],
        'urlResourceOwnerDetails' => $meta['resource'],
    ]);
}

function iam_oauth_auth_url(string $provider, string $state = ''): string
{
    $providers = iam_oauth_providers();
    $meta = $providers[$provider];
    $instance = iam_oauth_provider_instance($provider);
    $options = array_merge(['scope' => $meta['scopes']], $meta['auth_params']);
    if ($state !== '') {
        $options['state'] = $state;
    }
    return $instance->getAuthorizationUrl($options);
}

function iam_oauth_exchange_code(string $provider, string $code): array
{
    $instance = iam_oauth_provider_instance($provider);
    $token = $instance->getAccessToken('authorization_code', ['code' => $code]);
    $refresh = $token->getRefreshToken();
    if (!$refresh) {
        return [false, 'Aucun refresh token fourni. Réessayez la connexion (consentement requis).'];
    }
    $email = '';
    try {
        $owner = $instance->getResourceOwner($token);
        $data = $owner->toArray();
        $email = $data['email'] ?? $data['mail'] ?? $data['userPrincipalName'] ?? $data['preferred_username'] ?? '';
    } catch (\Throwable $e) {
        $email = '';
    }
    return [true, $refresh, $email];
}

function iam_mail_configured(): bool
{
    return iam_oauth_mode() !== '' || iam_smtp_configured();
}

function iam_mail_mode_label(): string
{
    $mode = iam_oauth_mode();
    if ($mode !== '') {
        return iam_oauth_providers()[$mode]['label'] . ' (OAuth2)';
    }
    if (iam_smtp_configured()) {
        return 'SMTP classique';
    }
    return 'Démonstration (code affiché à l\'écran)';
}

function iam_send_email(string $to, string $subject, string $htmlBody): bool
{
    [$ok, $err] = iam_try_send_email($to, $subject, $htmlBody);
    if ($err !== '') {
        error_log("[IAM-Local] Erreur envoi mail : $err");
        return $ok;
    }
    return $ok;
}

function iam_test_smtp(): array
{
    $db = db();
    $admin = $GLOBALS['iam_admin'] ?? [];
    $to = $admin['email'] ?? 'admin@localhost';
    [$ok, $err] = iam_try_send_email($to, IAM_NAME . ' — Test SMTP', '<h3>' . htmlspecialchars(IAM_NAME) . '</h3><p>Test réussi : le serveur SMTP envoie correctement les e-mails.</p>');
    return [$ok, $err, $to];
}

function iam_try_send_email(string $to, string $subject, string $htmlBody): array
{
    $mailerPath = __DIR__ . '/../vendor/autoload.php';
    if (!file_exists($mailerPath)) {
        $cfg = iam_smtp_config();
        $headers  = "MIME-Version: 1.0\r\n";
        $headers .= "Content-type: text/html; charset=utf-8\r\n";
        if (!empty($cfg['user']) && !empty($cfg['pass'])) {
            $headers .= "From: " . ($cfg['from_name'] ?: 'IAM') . " <" . ($cfg['from'] ?: $cfg['user']) . ">\r\n";
        }
        $ok = @mail($to, $subject, $htmlBody, $headers);
        return [$ok, $ok ? '' : 'mail() natif renvoyé false (serveur SMTP local absent)'];
    }

    require_once $mailerPath;
    $mail = new \PHPMailer\PHPMailer\PHPMailer(true);
    try {
        $mail->isSMTP();

        // Mode OAuth2 Gmail (prioritaire)
        $oauthMode = iam_oauth_mode();
        if ($oauthMode !== '') {
            $meta = iam_oauth_providers()[$oauthMode];
            $c = iam_oauth_config($oauthMode);
            $provider = new \League\OAuth2\Client\Provider\GenericProvider([
                'clientId'                => $c['client_id'],
                'clientSecret'            => $c['client_secret'],
                'redirectUri'             => iam_oauth_redirect_uri(),
                'urlAuthorize'            => $meta['authorize'],
                'urlAccessToken'          => $meta['token'],
                'urlResourceOwnerDetails' => $meta['resource'],
            ]);
            $mail->Host = $meta['smtp_host'];
            $mail->Port = (int) $meta['smtp_port'];
            $mail->SMTPSecure = $meta['smtp_secure'] === 'tls'
                ? \PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_STARTTLS
                : \PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_SMTPS;
            $mail->SMTPAuth = true;
            $mail->AuthType = 'XOAUTH2';
            $mail->Username = $c['email'];
            $mail->setOAuth(new \PHPMailer\PHPMailer\OAuth([
                'provider'     => $provider,
                'clientId'     => $c['client_id'],
                'clientSecret' => $c['client_secret'],
                'refreshToken' => $c['refresh_token'],
                'userName'     => $c['email'],
            ]));
            $mail->setFrom($c['email'], iam_smtp_config()['from_name'] ?: 'IAM ' . IAM_NAME);
        } else {
            // Mode SMTP classique (login/mot de passe)
            $cfg = iam_smtp_config();
            if (empty($cfg['user']) || empty($cfg['pass'])) {
                // Mode démo : on log l'OTP au lieu de l'envoyer
                error_log("[IAM-Local] OTP pour $to : $htmlBody");
                return [true, ''];
            }
            $mail->Host       = $cfg['host'];
            $mail->SMTPAuth   = true;
            $mail->Username   = $cfg['user'];
            $mail->Password   = $cfg['pass'];
            $mail->Port       = (int) $cfg['port'];
            if ((int) $cfg['port'] === 587) {
                $mail->SMTPSecure = \PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_STARTTLS;
            } elseif ((int) $cfg['port'] === 465) {
                $mail->SMTPSecure = \PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_SMTPS;
            } else {
                $mail->SMTPSecure = '';
                $mail->SMTPAutoTLS = true;
            }
            $mail->setFrom($cfg['from'] ?: $cfg['user'], $cfg['from_name'] ?: 'IAM ' . IAM_NAME);
        }

        $mail->Timeout = 15;
        $mail->addAddress($to);
        $mail->isHTML(true);
        $mail->CharSet = 'UTF-8';
        $mail->Subject = $subject;
        $mail->Body    = $htmlBody;
        $mail->send();
        return [true, ''];
    } catch (\Throwable $e) {
        return [false, $e->getMessage()];
    }
}