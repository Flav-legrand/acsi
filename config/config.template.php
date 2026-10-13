<?php
// ============================================================================
// IAM-Local — Modèle de configuration centrale (config/config.template.php)
//
// install.php copie ce fichier vers config/config.php et remplace chaque
// valeur précédée d'un marqueur /*@NOM*/ par la valeur saisie à
// l'installation. Les secrets (base de données, clé JWT, SMTP) sont écrits
// à part dans config/config.local.php, non versionné.
//
// Ce modèle est la RÉFÉRENCE de toutes les constantes attendues :
// includes/config_bootstrap.php vérifie leur présence à chaque requête
// (iam_check_config_integrity) et affiche la liste des manquantes.
// ============================================================================

// Secrets locaux (non versionnés) : DB_*, IAM_JWT_SECRET, SMTP_USER/PASS…
if (is_file(__DIR__ . '/config.local.php')) {
    require_once __DIR__ . '/config.local.php';
}

// ── Plateforme ──────────────────────────────────────────────────────────────
define('IAM_BASE_URL',       /*@IAM_BASE_URL*/ 'http://localhost/IAM-Local');
// Code de l'application IAM dont le rôle local 'admin' porte l'administration
// de la plateforme (les rôles ne sont plus globaux).
define('IAM_ADMIN_APP_CODE', 'iam-admin');
define('IAM_NAME',           /*@IAM_NAME*/ 'IAM ACSI');
define('IAM_VERSION',        '1.0.3');
define('IAM_TAGLINE',        'Portail d acces securise aux applications');

// ── Base de données (valeurs réelles dans config.local.php) ─────────────────
defined('DB_HOST') || define('DB_HOST', 'localhost');
defined('DB_USER') || define('DB_USER', 'root');
defined('DB_PASS') || define('DB_PASS', '');
defined('DB_NAME') || define('DB_NAME', 'iam_local');
defined('DB_PORT') || define('DB_PORT', '3306');

// ── Session ─────────────────────────────────────────────────────────────────
define('SESSION_LIFETIME',     3600);   // durée de vie max d'une session IAM (s)
define('SESSION_IDLE_TIMEOUT', 1800);   // inactivité max avant déconnexion (s)
define('IDLE_TIMEOUT',         SESSION_IDLE_TIMEOUT); // nom utilisé par le code
define('SESSION_COOKIE_NAME',  'iam_session');

// ── SSO maison ──────────────────────────────────────────────────────────────
define('SSO_TOKEN_LIFETIME', 60);       // durée de vie d'un jeton SSO (s)

// ── JWT (valeur réelle dans config.local.php, générée à l'installation) ─────
defined('IAM_JWT_SECRET') || define('IAM_JWT_SECRET', '');

// ── MFA ─────────────────────────────────────────────────────────────────────
// Politique ACTUELLE, à conserver :
//   - MFA_FORCE_ALL = true : code e-mail exigé à la connexion pour tous les
//     comptes NON administrateurs (et pour tout compte ayant activé sa MFA) ;
//   - les administrateurs IAM sont exemptés. Cette exemption est codée dans
//     login.php, api/login.php et oauth.php :
//         (MFA_FORCE_ALL && !iam_user_is_admin($id)) || $user['mfa_enabled']
//     C'est un choix volontaire : ne pas la retirer.
define('MFA_FORCE_ALL',     true);
// Documente l'exemption ci-dessus. INFORMATIF : la mettre à false ne rend
// PAS la MFA obligatoire pour les admins (la condition n'est pas lue ici).
define('MFA_EXEMPT_ADMINS', true);
define('MFA_CODE_TTL',      300);       // validité du code MFA (s)
define('MFA_MAX_ATTEMPTS',  5);         // essais avant invalidation du code
define('OTP_LENGTH',        6);
define('OTP_LIFETIME',      MFA_CODE_TTL);     // nom utilisé par le code
define('OTP_MAX_TRIES',     MFA_MAX_ATTEMPTS); // nom utilisé par le code

// ── Anti force brute ────────────────────────────────────────────────────────
define('LOGIN_MAX_ATTEMPTS',    5);     // échecs avant blocage du compte
define('LOGIN_LOCKOUT_MINUTES', 30);    // durée du blocage (min)
define('MAX_LOGIN_ATTEMPTS',    LOGIN_MAX_ATTEMPTS);    // nom utilisé par le code
define('LOCKOUT_MINUTES',       LOGIN_LOCKOUT_MINUTES); // nom utilisé par le code

// ── Mots de passe ───────────────────────────────────────────────────────────
// Valeurs par défaut de référence. La politique EFFECTIVE (historique,
// expiration, complexité, seuil de verrouillage) est stockée dans la table
// password_policy et se règle dans Administration > Politique de sécurité.
define('PASSWORD_HISTORY_SIZE', 5);     // derniers mots de passe interdits
define('PASSWORD_EXPIRY_DAYS',  90);    // expiration (jours, 0 = jamais)

// ── SMTP (envoi des codes MFA) ──────────────────────────────────────────────
define('SMTP_HOST',      'smtp.gmail.com');
define('SMTP_PORT',      465);
defined('SMTP_USER') || define('SMTP_USER', '');
defined('SMTP_PASS') || define('SMTP_PASS', '');
define('SMTP_FROM',      '');
define('SMTP_FROM_NAME', /*@SMTP_FROM_NAME*/ 'IAM ACSI');

// ── OAuth2 fournisseurs mail (envoi MFA via Gmail ou Outlook) ───────────────
define('OAUTH_GOOGLE_CLIENT_ID',    '');
defined('OAUTH_GOOGLE_CLIENT_SECRET') || define('OAUTH_GOOGLE_CLIENT_SECRET', '');
define('OAUTH_MICROSOFT_CLIENT_ID', '');
defined('OAUTH_MICROSOFT_CLIENT_SECRET') || define('OAUTH_MICROSOFT_CLIENT_SECRET', '');

// ── Upload ──────────────────────────────────────────────────────────────────
define('UPLOAD_DIR',      __DIR__ . '/uploads/');
define('MAX_UPLOAD_SIZE', 2 * 1024 * 1024); // 2 Mo
