-- ============================================================
--  IAM-LOCAL — Données de DÉMONSTRATION (import optionnel)
--  Exemples : organisation ADEN, applications Gestion Présence / Salaire.
--  À remplacer librement par les vraies applications.
--
--  Modèle « rôles par application » (client roles, comme Keycloak) :
--    - chaque application possède ses PROPRES rôles (application_id non NULL) ;
--    - le rôle global « admin » (application_id NULL) reste attribuable
--      sur n'importe quelle application (realm role).
--  Toutes ces applications sont marquées is_system=0 : l'admin
--  peut les supprimer depuis l'interface.
-- ============================================================

USE iam_local;

-- ------------------------------------------------------------
-- Organisation de démonstration : ADEN (exemple)
-- ------------------------------------------------------------
INSERT INTO organizations (id, parent_id, name, code, type) VALUES
(1, NULL, 'ADEN — Agence de Développement de l''Économie Numérique', 'ADEN', 'direction_generale'),
(2, 1,    'Direction des Ressources Humaines', 'DRH', 'direction'),
(3, 2,    'Service Gestion du Personnel', 'SGP', 'service'),
(4, 2,    'Service des Salaires & Paie', 'SSP', 'service'),
(5, 1,    'Direction des Systèmes d''Information', 'DSI', 'direction'),
(6, 5,    'Service Support & Sécurité', 'SSS', 'service');

-- Raccorder l'administrateur par défaut à la DSI (démo)
UPDATE users SET organization_id = 5 WHERE id = 1;

-- ------------------------------------------------------------
-- Applications de démonstration
-- ------------------------------------------------------------
INSERT INTO applications (id, code, name, description, url, client_id, redirect_uri, scopes, color, icon, active, is_system) VALUES
(1, 'gestion-presence', 'Gestion des Présences', 'Suivi et gestion des présences du personnel',
   '{{BASE_URL}}/GestionPresnceAdenIAM', 'iam-native-presence', '{{BASE_URL}}/GestionPresnceAdenIAM/sso-login.php',
   'openid profile email roles', '#1a7f37', 'fa-clock', 1, 0),
(2, 'gestion-salaire', 'Gestion des Salaires', 'Élaboration, validation et paiement des salaires',
   '{{BASE_URL}}/GestionSalaireAden', 'iam-native-salaire', '{{BASE_URL}}/GestionSalaireAden/sso-login.php',
   'openid profile email roles', '#1a237e', 'fa-money-bill-wave', 1, 0);

-- ------------------------------------------------------------
-- Permissions — Application Présence (1)
-- ------------------------------------------------------------
INSERT INTO permissions (id, application_id, name, code, description) VALUES
(1,  1, 'Voir les présences',      'presence.view',     'Consulter les présences du personnel'),
(2,  1, 'Enregistrer présences',   'presence.record',   'Enregistrer les présences'),
(3,  1, 'Modifier présences',      'presence.edit',     'Modifier les présences'),
(4,  1, 'Valider présences',       'presence.validate', 'Valider les présences'),
(5,  1, 'Voir le personnel',       'personnel.view',    'Consulter la liste du personnel'),
(6,  1, 'Gérer le personnel',      'personnel.manage',  'Créer, modifier, supprimer le personnel'),
(7,  1, 'Voir statistiques',       'stats.view',         'Consulter les statistiques et graphiques');

-- ------------------------------------------------------------
-- Permissions — Application Salaire (2)
-- ------------------------------------------------------------
INSERT INTO permissions (id, application_id, name, code, description) VALUES
(8,  2, 'Voir les salaires',     'salary.view',     'Consulter les bulletins et salaires'),
(9,  2, 'Élaborer les salaires', 'salary.manage',   'Créer et calculer les bulletins'),
(10, 2, 'Valider les salaires',  'salary.validate', 'Valider les bulletins de paie'),
(11, 2, 'Payer les salaires',    'salary.pay',      'Exécuter les paiements'),
(12, 2, 'Gérer les employés',    'employe.manage',  'Gérer les employés (CRUD)'),
(13, 2, 'Gérer les rubriques',   'rubrique.manage', 'Gérer les rubriques de paie'),
(14, 2, 'Exporter PDF',          'export.pdf',      'Exporter les bulletins en PDF');

-- ------------------------------------------------------------
-- Rôles de l'application PRÉSENCE (1) — client roles
--  (le code peut être réutilisé dans une autre application)
-- ------------------------------------------------------------
INSERT INTO roles (id, application_id, name, code, description, is_system) VALUES
(7,  1, 'Directeur Présence',      'directeur_presence',      'Direction et validation des présences', 0),
(8,  1, 'Gestionnaire Présence',   'gestionnaire_presence',   'Gestion complète des présences', 0),
(9,  1, 'Chef de Service Présence','chef_service_presence',   'Supervision d''un service', 0),
(10, 1, 'Agent Présence',          'agent_presence',          'Saisie / consultation des présences', 0),
(11, 1, 'Auditeur Présence',       'auditeur_presence',       'Consultation et audit des présences', 0);

INSERT INTO role_permissions (role_id, permission_id) VALUES
(7, 1), (7, 4), (7, 5), (7, 7),
(8, 1), (8, 2), (8, 3), (8, 4), (8, 5), (8, 6), (8, 7),
(9, 1), (9, 2), (9, 5), (9, 7),
(10, 1),
(11, 1), (11, 5);

-- ------------------------------------------------------------
-- Rôles de l'application SALAIRE (2) — client roles
-- ------------------------------------------------------------
INSERT INTO roles (id, application_id, name, code, description, is_system) VALUES
(12, 2, 'Directeur Salaire',       'directeur_salaire',       'Direction et validation de la paie', 0),
(13, 2, 'Gestionnaire Salaire',    'gestionnaire_salaire',    'Élaboration complète de la paie', 0),
(14, 2, 'Chef de Service Salaire', 'chef_service_salaire',    'Supervision de la paie', 0),
(15, 2, 'Agent Salaire',           'agent_salaire',           'Consultation de la paie', 0),
(16, 2, 'Auditeur Salaire',        'auditeur_salaire',        'Consultation et audit de la paie', 0);

INSERT INTO role_permissions (role_id, permission_id) VALUES
(12, 8), (12, 10), (12, 14),
(13, 8), (13, 9), (13, 10), (13, 12), (13, 13), (13, 14),
(14, 8), (14, 9),
(15, 8),
(16, 8), (16, 14);

-- ------------------------------------------------------------
-- Rôle GLOBAL « admin » (id 1) de l'administrateur sur les apps de démo
--  (un rôle global est attribuable sur n'importe quelle application)
-- ------------------------------------------------------------
INSERT INTO user_roles (user_id, role_id, application_id) VALUES
(1, 1, 1),   -- admin (global) sur Présence
(1, 1, 2);   -- admin (global) sur Salaire

-- ------------------------------------------------------------
-- Utilisateur de démonstration : accès à UNE SEULE application
--  Il peut ouvrir Gestion des Présences, mais PAS Gestion des Salaires.
--  Mot de passe : celui saisi pour l'administrateur (hash placeholder).
-- ------------------------------------------------------------
INSERT INTO users (username, email, phone, password_hash, first_name, last_name, matricule, organization_id, status, mfa_enabled, must_change_password)
VALUES ('gestionnaire_rh', 'gestionnaire.rh@aden.dz', '', '{{DEMO_PASSWORD_HASH}}',
        'Gestionnaire', 'RH', 'ADEN-0002', 3, 'active', 0, 0);

INSERT INTO password_history (user_id, password_hash)
SELECT u.id, u.password_hash FROM users u WHERE u.email = 'gestionnaire.rh@aden.dz';

-- Rôle « Gestionnaire Présence » (app 1) uniquement — aucun rôle Salaire
INSERT INTO user_roles (user_id, role_id, application_id)
SELECT u.id, 8, 1 FROM users u WHERE u.email = 'gestionnaire.rh@aden.dz';
