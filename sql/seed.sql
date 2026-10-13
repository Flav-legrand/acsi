-- ============================================================
--  IAM-LOCAL — Données système (obligatoires, vierges de tout métier)
--  Placeholders remplacés par l'installateur :
--    {{BASE_URL}}, {{ADMIN_USERNAME}}, {{ADMIN_EMAIL}}, {{ADMIN_PHONE}},
--    {{ADMIN_FIRST_NAME}}, {{ADMIN_LAST_NAME}}, {{ADMIN_MATRICULE}},
--    {{ADMIN_PASSWORD_HASH}}
--  Les données métier optionnelles (démonstration) sont dans seed-demo.sql.
-- ============================================================

USE iam_local;

-- ------------------------------------------------------------
-- Politique de mot de passe par défaut
-- ------------------------------------------------------------
INSERT INTO password_policy (id, min_length, require_upper, require_lower, require_digit, require_special, history, expiration_days, lockout_threshold, lockout_minutes, session_lifetime, idle_timeout)
VALUES (1, 8, 1, 1, 1, 1, 5, 90, 5, 30, 3600, 1800);

-- ------------------------------------------------------------
-- Application "IAM — Administration" (système, non supprimable)
-- ------------------------------------------------------------
INSERT INTO applications (id, code, name, description, url, client_id, redirect_uri, scopes, color, icon, active, is_system) VALUES
(3, 'iam-admin', 'IAM — Administration', 'Console d''administration de la plateforme IAM',
   '{{BASE_URL}}/admin', NULL, NULL, 'openid profile email roles', '#6f42c1', 'fa-shield-halved', 1, 1);

-- ------------------------------------------------------------
-- RÔLES LOCAUX de l'application IAM (3) — 100% client roles
--
--  Les rôles ne sont plus globaux : chaque application possède ses
--  propres exemplaires. Le rôle 'admin' de l'application IAM porte
--  l'administration de la plateforme (voir IAM_ADMIN_APP_CODE).
--  Idempotence : clé unique (application_id, code).
-- ------------------------------------------------------------
INSERT INTO roles (name, code, description, is_system, application_id) VALUES
('Administrateur',  'admin',           'Accès complet : CRUD sur l''application et administration de l''IAM', 1, 3),
('Gestionnaire RH', 'gestionnaire_rh', 'Profil opérationnel : saisie, gestion et validation sur les applications métier', 1, 3),
('Agent',           'agent',           'Utilisateur simple : CONSULTATION UNIQUEMENT, aucune écriture', 1, 3),
('Auditeur',        'auditeur',        'Consultation et export sur l''application, y compris le journal d''audit IAM', 1, 3);

-- Identifiants stables des 4 profils, réutilisés par seed-apps-metier.sql
-- plutôt que des identifiants codés en dur : c'est la collision
-- d'identifiants (7 à 10 partagées avec seed-demo.sql) qui avait
-- écrasé silencieusement les rôles des applications de démonstration.
-- Les profils globaux sont donc toujours recherché par code, jamais par id.

-- ------------------------------------------------------------
-- Permissions — Application IAM Admin (3)
-- ------------------------------------------------------------
INSERT INTO permissions (id, application_id, name, code, description) VALUES
(15, 3, 'Administrer l''IAM', 'iam.admin', 'Administration complète de la plateforme IAM'),
(16, 3, 'Gérer les utilisateurs', 'users.manage', 'Créer, modifier, supprimer des utilisateurs'),
(17, 3, 'Gérer les rôles', 'roles.manage', 'Gérer les rôles et permissions'),
(18, 3, 'Voir les journaux', 'audit.view', 'Consulter le journal d''audit');

-- ------------------------------------------------------------
-- Rôle Administrateur (local IAM) : toutes les permissions IAM
-- ------------------------------------------------------------
INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
  FROM roles r CROSS JOIN permissions p
 WHERE r.code = 'admin' AND r.application_id = 3
   AND p.code IN ('iam.admin', 'users.manage', 'roles.manage', 'audit.view');

-- Auditeur (local IAM) : consultation du journal d'audit
INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
  FROM roles r CROSS JOIN permissions p
 WHERE r.code = 'auditeur' AND r.application_id = 3
   AND p.code IN ('audit.view');

-- ------------------------------------------------------------
-- Utilisateur administrateur par défaut (créé par l'installateur)
-- ------------------------------------------------------------
INSERT INTO users (id, username, email, phone, password_hash, first_name, last_name, matricule, organization_id, status, mfa_enabled, must_change_password)
VALUES (1, '{{ADMIN_USERNAME}}', '{{ADMIN_EMAIL}}', '{{ADMIN_PHONE}}',
        '{{ADMIN_PASSWORD_HASH}}',
        '{{ADMIN_FIRST_NAME}}', '{{ADMIN_LAST_NAME}}', '{{ADMIN_MATRICULE}}', NULL, 'active', 0, 0);

INSERT INTO password_history (user_id, password_hash)
VALUES (1, '{{ADMIN_PASSWORD_HASH}}');

-- ------------------------------------------------------------
-- Rôle de l'administrateur : 'admin' attribué sur l'application IAM
-- ------------------------------------------------------------
INSERT IGNORE INTO user_roles (user_id, role_id, application_id)
SELECT u.id, r.id, 3
  FROM users u CROSS JOIN roles r
 WHERE u.id = 1 AND r.code = 'admin' AND r.application_id = 3;