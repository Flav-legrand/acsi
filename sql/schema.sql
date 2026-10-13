-- ============================================================
--  IAM-LOCAL — Schéma de la base de données
--  Plateforme IAM (Identity & Access Management) native PHP
--  Base de données : iam_local
-- ============================================================

CREATE DATABASE IF NOT EXISTS iam_local
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE iam_local;

-- ------------------------------------------------------------
-- Organisations (hiérarchie : Ministère > Direction > Service > Bureau)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS organizations (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  parent_id     INT NULL,
  name          VARCHAR(190) NOT NULL,
  code          VARCHAR(50)  NULL,
  type          ENUM('ministere','direction_generale','direction','service','bureau','autre') NOT NULL DEFAULT 'direction',
  active        TINYINT(1) NOT NULL DEFAULT 1,
  created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  CONSTRAINT fk_org_parent FOREIGN KEY (parent_id) REFERENCES organizations(id) ON DELETE SET NULL,
  INDEX idx_org_parent (parent_id)
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- Utilisateurs
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
  id                  INT AUTO_INCREMENT PRIMARY KEY,
  username            VARCHAR(100) NOT NULL,
  email               VARCHAR(190) NOT NULL,
  phone               VARCHAR(30)  NULL,
  password_hash       VARCHAR(255) NOT NULL,
  first_name          VARCHAR(100) NOT NULL,
  last_name           VARCHAR(100) NOT NULL,
  photo               VARCHAR(255) NULL,
  matricule           VARCHAR(50)  NULL,
  organization_id     INT          NULL,
  department          VARCHAR(100) NULL,
  service             VARCHAR(100) NULL,
  fonction            VARCHAR(100) NULL,
  status              ENUM('active','inactive','locked','pending') NOT NULL DEFAULT 'active',
  mfa_enabled         TINYINT(1) NOT NULL DEFAULT 0,
  must_change_password TINYINT(1) NOT NULL DEFAULT 1,
  failed_attempts     INT NOT NULL DEFAULT 0,
  locked_until        DATETIME NULL,
  last_login_at       DATETIME NULL,
  last_login_ip       VARCHAR(45) NULL,
  created_by          INT NULL,
  created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uq_email (email),
  UNIQUE KEY uq_username (username),
  INDEX idx_users_org (organization_id),
  CONSTRAINT fk_users_org FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- Politique de mot de passe (1 ligne par config)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS password_policy (
  id                 INT PRIMARY KEY,
  min_length         INT NOT NULL DEFAULT 8,
  require_upper      TINYINT(1) NOT NULL DEFAULT 1,
  require_lower      TINYINT(1) NOT NULL DEFAULT 1,
  require_digit      TINYINT(1) NOT NULL DEFAULT 1,
  require_special    TINYINT(1) NOT NULL DEFAULT 1,
  history            INT NOT NULL DEFAULT 5,
  expiration_days    INT NOT NULL DEFAULT 90,
  lockout_threshold  INT NOT NULL DEFAULT 5,
  lockout_minutes    INT NOT NULL DEFAULT 30,
  session_lifetime   INT NOT NULL DEFAULT 3600,
  idle_timeout       INT NOT NULL DEFAULT 1800,
  updated_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- Historique des mots de passe
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS password_history (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  user_id       INT NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_pwh_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_pwh_user (user_id)
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- Applications (enregistrées dans l'IAM)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS applications (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  code        VARCHAR(50)  NOT NULL,
  name        VARCHAR(190) NOT NULL,
  description TEXT NULL,
  url         VARCHAR(255) NOT NULL,
  logo        VARCHAR(255) NULL,
  color       VARCHAR(20)  NULL,
  icon        VARCHAR(100) NULL,
  client_id   VARCHAR(100) NULL,
  client_secret VARCHAR(255) NULL,
  redirect_uri  VARCHAR(255) NULL,
  scopes        VARCHAR(255) NULL,
  active      TINYINT(1) NOT NULL DEFAULT 1,
  sso_prompt  TINYINT(1) NOT NULL DEFAULT 1 COMMENT '1 = exiger la ressaisie des identifiants IAM sur accès direct (lien) ; 0 = accès seamless si session IAM valide',
  is_system   TINYINT(1) NOT NULL DEFAULT 0,
  bridge_config TEXT NULL COMMENT 'Pont de session locale (JSON) : DB app, champs de correspondance, clés de session, mapping de rôles',
  created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_app_code (code)
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- Rôles (RBAC)
--  application_id NULL => rôle GLOBAL de la plateforme (realm role),
--  sinon rôle APPARTENANT à une application (client role à la Keycloak).
--  Le même code peut exister dans plusieurs applications.
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS roles (
  id             INT AUTO_INCREMENT PRIMARY KEY,
  application_id INT NULL COMMENT 'NULL = rôle global de la plateforme, sinon id de l''application propriétaire',
  name           VARCHAR(100) NOT NULL,
  code           VARCHAR(50)  NOT NULL,
  description    TEXT NULL,
  is_system      TINYINT(1) NOT NULL DEFAULT 0,
  created_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_role_app_code (application_id, code),
  CONSTRAINT fk_role_app FOREIGN KEY (application_id) REFERENCES applications(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- Permissions
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS permissions (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  application_id INT NULL,
  name        VARCHAR(190) NOT NULL,
  code        VARCHAR(100) NOT NULL,
  description TEXT NULL,
  UNIQUE KEY uq_perm_code (code),
  CONSTRAINT fk_perm_app FOREIGN KEY (application_id) REFERENCES applications(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- Liaison Rôle <-> Permission
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS role_permissions (
  role_id       INT NOT NULL,
  permission_id INT NOT NULL,
  PRIMARY KEY (role_id, permission_id),
  CONSTRAINT fk_rp_role FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
  CONSTRAINT fk_rp_perm FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- Liaison Utilisateur <-> Rôle <-> Application
-- (un utilisateur possède N rôles répartis sur N applications)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS user_roles (
  id             INT AUTO_INCREMENT PRIMARY KEY,
  user_id        INT NOT NULL,
  role_id        INT NOT NULL,
  application_id INT NOT NULL,
  created_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_ur_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  CONSTRAINT fk_ur_role FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
  CONSTRAINT fk_ur_app  FOREIGN KEY (application_id) REFERENCES applications(id) ON DELETE CASCADE,
  UNIQUE KEY uq_ur (user_id, role_id, application_id)
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- Sessions
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sessions (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  user_id       INT NOT NULL,
  session_token VARCHAR(255) NOT NULL,
  ip_address    VARCHAR(45) NULL,
  user_agent    VARCHAR(255) NULL,
  created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at    DATETIME NOT NULL,
  last_active_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  revoked       TINYINT(1) NOT NULL DEFAULT 0,
  CONSTRAINT fk_sess_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  UNIQUE KEY uq_session_token (session_token),
  INDEX idx_sess_user (user_id),
  INDEX idx_sess_exp (expires_at)
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- Jetons SSO à usage unique (échange IAM <-> Application par URL)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sso_tokens (
  id           INT AUTO_INCREMENT PRIMARY KEY,
  token        VARCHAR(255) NOT NULL,
  user_id      INT NOT NULL,
  application_id INT NOT NULL,
  return_url   VARCHAR(500) NULL,
  created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at   DATETIME NOT NULL,
  consumed_at  DATETIME NULL,
  ip_address   VARCHAR(45) NULL,
  user_agent   VARCHAR(255) NULL,
  CONSTRAINT fk_st_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  CONSTRAINT fk_st_app  FOREIGN KEY (application_id) REFERENCES applications(id) ON DELETE CASCADE,
  UNIQUE KEY uq_sso_token (token),
  INDEX idx_st_user (user_id),
  INDEX idx_st_exp (expires_at)
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- Jetons de rafraîchissement (API)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS refresh_tokens (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  user_id     INT NOT NULL,
  token       VARCHAR(255) NOT NULL,
  client_id   VARCHAR(64) NULL,
  scope       VARCHAR(255) NULL,
  created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at  DATETIME NOT NULL,
  revoked     TINYINT(1) NOT NULL DEFAULT 0,
  CONSTRAINT fk_rt_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  UNIQUE KEY uq_refresh_token (token)
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- Serveur OAuth 2.0 / OIDC
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS oauth_clients (
  id                INT AUTO_INCREMENT PRIMARY KEY,
  application_id    INT NULL,
  name              VARCHAR(120) NOT NULL,
  slug              VARCHAR(100) NOT NULL,
  description       TEXT NULL,
  platform          VARCHAR(40) NOT NULL DEFAULT 'other',
  platform_version  VARCHAR(50) NULL,
  client_type       ENUM('confidential','public') NOT NULL DEFAULT 'confidential',
  client_id         VARCHAR(100) NOT NULL,
  client_secret     VARCHAR(255) NULL,
  redirect_uris     JSON NOT NULL,
  post_logout_uris  JSON NULL,
  scopes            JSON NOT NULL,
  grant_types       JSON NOT NULL,
  token_lifetime    INT UNSIGNED NOT NULL DEFAULT 3600,
  refresh_lifetime  INT UNSIGNED NOT NULL DEFAULT 2592000,
  base_url          VARCHAR(255) NOT NULL,
  logo_url          VARCHAR(255) NULL,
  is_active         TINYINT(1) NOT NULL DEFAULT 1,
  last_used_at      DATETIME NULL,
  created_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  refresh_enabled   TINYINT(1) NOT NULL DEFAULT 1,
  pkce_required     TINYINT(1) NOT NULL DEFAULT 0,
  role_mappings     JSON NULL,
  jit_provisioning  TINYINT(1) NOT NULL DEFAULT 0,
  UNIQUE KEY uq_oauth_client (client_id),
  UNIQUE KEY uq_oauth_client_slug (slug),
  KEY idx_oauth_application (application_id),
  CONSTRAINT fk_oauth_application FOREIGN KEY (application_id) REFERENCES applications(id) ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS oauth_client_events (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  client_id   VARCHAR(64) NOT NULL,
  user_id     INT NULL,
  event       VARCHAR(40) NOT NULL,
  ip_address  VARCHAR(45) NULL,
  user_agent  VARCHAR(255) NULL,
  created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_oauth_event_client (client_id, created_at),
  KEY idx_oauth_event_user (user_id, created_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS oauth_codes (
  id                   INT AUTO_INCREMENT PRIMARY KEY,
  code                 VARCHAR(128) NOT NULL,
  client_id            VARCHAR(64) NOT NULL,
  user_id              INT NOT NULL,
  redirect_uri         VARCHAR(500) NULL,
  scope                VARCHAR(255) NULL,
  code_challenge       VARCHAR(128) NULL,
  code_challenge_method VARCHAR(10) NULL,
  nonce                VARCHAR(128) NULL,
  expires_at           DATETIME NOT NULL,
  used                 TINYINT(1) NOT NULL DEFAULT 0,
  UNIQUE KEY uq_oauth_code (code),
  CONSTRAINT fk_oc_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS oauth_keys (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  kid         VARCHAR(32) NOT NULL,
  priv_pem    TEXT NOT NULL,
  pub_pem     TEXT NOT NULL,
  alg         VARCHAR(10) NOT NULL DEFAULT 'RS256',
  active      TINYINT(1) NOT NULL DEFAULT 1,
  created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_kid (kid)
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- Périphériques MFA
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS mfa_devices (
  id           INT AUTO_INCREMENT PRIMARY KEY,
  user_id      INT NOT NULL,
  method       ENUM('email','sms','totp') NOT NULL DEFAULT 'email',
  secret       VARCHAR(255) NULL,
  destination  VARCHAR(190) NULL,
  confirmed_at DATETIME NULL,
  created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_mfa_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_mfa_user (user_id)
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- Codes OTP en attente de vérification (MFA)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS otp_codes (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  user_id     INT NOT NULL,
  code_hash   VARCHAR(255) NOT NULL,
  method      ENUM('email','sms','totp') NOT NULL DEFAULT 'email',
  expires_at  DATETIME NOT NULL,
  used        TINYINT(1) NOT NULL DEFAULT 0,
  created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_otp_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_otp_user (user_id)
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- Tentatives de connexion (anti force brute)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS login_attempts (
  id           INT AUTO_INCREMENT PRIMARY KEY,
  identifier   VARCHAR(190) NOT NULL,
  ip_address   VARCHAR(45) NULL,
  user_agent   VARCHAR(255) NULL,
  success      TINYINT(1) NOT NULL DEFAULT 0,
  created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_la_idf (identifier),
  INDEX idx_la_ip (ip_address),
  INDEX idx_la_created (created_at)
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- Journal d'audit
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_logs (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  user_id     INT NULL,
  email       VARCHAR(190) NULL,
  action      VARCHAR(100) NOT NULL,
  details     TEXT NULL,
  ip_address  VARCHAR(45) NULL,
  user_agent  VARCHAR(255) NULL,
  application VARCHAR(80)  NULL,
  country     VARCHAR(80)  NULL,
  created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_audit_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
  INDEX idx_audit_user (user_id),
  INDEX idx_audit_action (action),
  INDEX idx_audit_created (created_at),
  INDEX idx_audit_app (application)
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- Jetons "se souvenir de moi"
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS remember_tokens (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  user_id     INT NOT NULL,
  token_hash  VARCHAR(255) NOT NULL,
  expires_at  DATETIME NOT NULL,
  created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_rem_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  UNIQUE KEY uq_rem_token (token_hash)
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- Paramètres clé/valeur de la plateforme
--
-- Consommée par admin/settings.php (politique API, origines CORS,
-- GeoIP), par admin/email.php (SMTP) et par includes/mailer.php.
-- Elle était lue et écrite par le code mais n'était créée par AUCUN
-- script d'installation : toute installation neuve plantait donc sur
-- « Table 'iam_local.settings' doesn't exist » à la première
-- validation du formulaire Paramètres ou de la page Email.
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS settings (
  s_key   VARCHAR(100) NOT NULL PRIMARY KEY,
  s_value TEXT NULL
) ENGINE=InnoDB;

INSERT INTO settings (s_key, s_value) VALUES
  ('cors_origins',  '*'),
  ('geoip_lookup',  '0'),
  ('api_rate_limit','120')
ON DUPLICATE KEY UPDATE s_key = VALUES(s_key);

-- ------------------------------------------------------------
-- Mise à niveau : ajouter les colonnes de personnalisation
-- (erreurs "colonne déjà existante" ignorées par l'installateur)
-- ------------------------------------------------------------
ALTER TABLE applications
  ADD COLUMN icon VARCHAR(100) NULL,
  ADD COLUMN is_system TINYINT(1) NOT NULL DEFAULT 0,
  ADD COLUMN bridge_config TEXT NULL COMMENT 'Pont de session locale (JSON) : DB app, champs de correspondance, clés de session, mapping de rôles';

ALTER TABLE audit_logs
  ADD COLUMN application VARCHAR(80) NULL AFTER user_agent,
  ADD COLUMN country VARCHAR(80) NULL AFTER application,
  ADD INDEX idx_audit_app (application);

-- Lot 2 : champs de poste (direction / service / fonction)
ALTER TABLE users
  ADD COLUMN department VARCHAR(100) NULL AFTER organization_id,
  ADD COLUMN service VARCHAR(100) NULL AFTER department,
  ADD COLUMN fonction VARCHAR(100) NULL AFTER service;

-- Lot 2 : groupes d'utilisateurs
CREATE TABLE IF NOT EXISTS `groups` (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  name        VARCHAR(100) NOT NULL,
  description VARCHAR(255) NULL,
  created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_group_name (name)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS user_groups (
  user_id  INT NOT NULL,
  group_id INT NOT NULL,
  PRIMARY KEY (user_id, group_id),
  CONSTRAINT fk_ug_user  FOREIGN KEY (user_id)  REFERENCES users(id)   ON DELETE CASCADE,
  CONSTRAINT fk_ug_group FOREIGN KEY (group_id) REFERENCES `groups`(id) ON DELETE CASCADE
) ENGINE=InnoDB;