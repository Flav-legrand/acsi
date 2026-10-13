-- ============================================================
--  IAM-LOCAL — MATRICE DE RÉFÉRENCE DES RÔLES (source de vérité)
--  Modèle SANS RÔLES GLOBAUX : les 8 rôles existent en exemplaire
--  LOCAL sur chaque application (client roles, comme Keycloak).
--
--  ── LES 8 RÔLES (répliqués par application) ──────────────────
--  admin            toutes les permissions de l'app (+ administration
--                   IAM quand l'app est « iam-admin »)
--  gestionnaire_rh  saisie/validation RH (Présence, Salaire, Personnel),
--                   lecture seule sur Maintenance
--  agent            CONSULTATION SEULE
--  auditeur         consultation + export, y compris audit IAM
--  employe     (app 4) 3 : annuaire + ses propres congés
--  technicien  (app 5) 6 : ses interventions + lecture équipe/stock
--  operateur   (app 5) 3 : signale une panne, suit ses demandes
--  magasinier  (app 5) 5 : stock de pièces, aucune intervention
--
--  ── GARANTIES ────────────────────────────────────────────────
--  - Idempotent et reproductible (DELETE + INSERT IGNORE) :
--    chaque exécution reconstruit exactement la matrice.
--  - Tout est résolu par CODE (jamais par identifiant).
--  - Les rôles des applications non métier (démo, test) reçoivent
--    un petit jeu de permissions génériques utilisé par leur garde SSO.
--  - Ne touche PAS aux attributions (user_roles) : gérées par l'admin
--    depuis la console IAM.
-- ============================================================

USE iam_local;

-- ------------------------------------------------------------
-- 1. Filet : applications de référence (créées si absentes,
--    jamais écrasées si elles existent déjà).
-- ------------------------------------------------------------
INSERT INTO applications (code, name, description, url, client_id, redirect_uri, scopes, color, icon, active, is_system)
SELECT t.code, t.name, t.description, t.url, t.client_id, t.redirect_uri, t.scopes, t.color, t.icon, 1, t.is_system
FROM (
  SELECT 'gestion-presence' AS code, 'Gestion des Présences' AS name,
         'Suivi et gestion des présences du personnel' AS description,
         '{{BASE_URL}}/GestionPresnceAdenIAM' AS url,
         'iam-native-presence' AS client_id,
         '{{BASE_URL}}/GestionPresnceAdenIAM/sso-login.php' AS redirect_uri,
         'openid profile email roles' AS scopes, '#1a7f37' AS color, 'fa-clock' AS icon, 0 AS is_system
  UNION ALL SELECT 'gestion-salaire', 'Gestion des Salaires',
         'Élaboration, validation et paiement des salaires',
         '{{BASE_URL}}/GestionSalaireAden', 'iam-native-salaire',
         '{{BASE_URL}}/GestionSalaireAden/sso-login.php',
         'openid profile email roles', '#1a237e', 'fa-money-bill-wave', 0
  UNION ALL SELECT 'iam-admin', 'IAM — Administration',
         'Console d''administration de la plateforme IAM',
         '{{BASE_URL}}/admin', NULL, NULL,
         'openid profile email roles', '#6f42c1', 'fa-shield-halved', 1
  UNION ALL SELECT 'gestion-personnel', 'Gestion du Personnel',
         'Effectifs, carrières, congés, évaluations et organigramme',
      'http://localhost:8000/auth/callback', 'iam-native-personnel',
         'http://localhost:8000/auth/callback',
         'openid profile email roles', '#0d6efd', 'fa-user-tie', 0
  UNION ALL SELECT 'controle-maintenance', 'Contrôle Maintenance',
         'Parc équipement, interventions, pièces détachées et équipe technique',
         'http://localhost:5173', 'iam-native-maintenance',
         'http://localhost:5173/auth/callback',
         'openid profile email roles', '#fd7e14', 'fa-screwdriver-wrench', 0
) t
WHERE NOT EXISTS (SELECT 1 FROM applications a WHERE a.code = t.code);

UPDATE applications
   SET url = 'http://localhost:8000/auth/callback'
 WHERE code = 'gestion-personnel';

-- ------------------------------------------------------------
-- 2. Filet : permissions des 5 applications de référence.
--    Toute permission dont l'application a disparu est ré-ancrée.
-- ------------------------------------------------------------
INSERT INTO permissions (application_id, name, code, description)
SELECT a.id, t.name, t.code, t.description
FROM (
  -- Application 1 : Gestion des Présences (7)
  SELECT 'gestion-presence' AS app_code, 'Voir les présences' AS name, 'presence.view' AS code, 'Consulter les présences du personnel' AS description
  UNION ALL SELECT 'gestion-presence', 'Enregistrer présences', 'presence.record', 'Enregistrer les présences'
  UNION ALL SELECT 'gestion-presence', 'Modifier présences', 'presence.edit', 'Modifier les présences'
  UNION ALL SELECT 'gestion-presence', 'Valider présences', 'presence.validate', 'Valider les présences'
  UNION ALL SELECT 'gestion-presence', 'Voir le personnel', 'personnel.view', 'Consulter la liste du personnel'
  UNION ALL SELECT 'gestion-presence', 'Gérer le personnel', 'personnel.manage', 'Créer, modifier, supprimer le personnel'
  UNION ALL SELECT 'gestion-presence', 'Voir statistiques', 'stats.view', 'Consulter les statistiques et graphiques'
  -- Application 2 : Gestion des Salaires (7)
  UNION ALL SELECT 'gestion-salaire', 'Voir les salaires', 'salary.view', 'Consulter les bulletins et salaires'
  UNION ALL SELECT 'gestion-salaire', 'Élaborer les salaires', 'salary.manage', 'Créer et calculer les bulletins'
  UNION ALL SELECT 'gestion-salaire', 'Valider les salaires', 'salary.validate', 'Valider les bulletins de paie'
  UNION ALL SELECT 'gestion-salaire', 'Payer les salaires', 'salary.pay', 'Exécuter les paiements'
  UNION ALL SELECT 'gestion-salaire', 'Gérer les employés', 'employe.manage', 'Gérer les employés (CRUD)'
  UNION ALL SELECT 'gestion-salaire', 'Gérer les rubriques', 'rubrique.manage', 'Gérer les rubriques de paie'
  UNION ALL SELECT 'gestion-salaire', 'Exporter PDF', 'export.pdf', 'Exporter les bulletins en PDF'
  -- Application 3 : IAM Admin (4)
  UNION ALL SELECT 'iam-admin', 'Administrer l''IAM', 'iam.admin', 'Administration complète de la plateforme IAM'
  UNION ALL SELECT 'iam-admin', 'Gérer les utilisateurs', 'users.manage', 'Créer, modifier, supprimer des utilisateurs'
  UNION ALL SELECT 'iam-admin', 'Gérer les rôles', 'roles.manage', 'Gérer les rôles et permissions'
  UNION ALL SELECT 'iam-admin', 'Voir les journaux', 'audit.view', 'Consulter le journal d''audit'
  -- Application 4 : Gestion du Personnel (17)
  UNION ALL SELECT 'gestion-personnel', 'Consulter le personnel', 'rh.personnel.view', 'Consulter les fiches des agents'
  UNION ALL SELECT 'gestion-personnel', 'Créer un agent', 'rh.personnel.create', 'Enregistrer un nouvel agent'
  UNION ALL SELECT 'gestion-personnel', 'Modifier un agent', 'rh.personnel.edit', 'Modifier les informations d''un agent'
  UNION ALL SELECT 'gestion-personnel', 'Supprimer un agent', 'rh.personnel.delete', 'Supprimer ou archiver un agent'
  UNION ALL SELECT 'gestion-personnel', 'Valider un dossier agent', 'rh.personnel.validate', 'Valider les dossiers administratifs'
  UNION ALL SELECT 'gestion-personnel', 'Consulter les congés', 'rh.conge.view', 'Consulter les demandes de congé'
  UNION ALL SELECT 'gestion-personnel', 'Gérer les congés', 'rh.conge.manage', 'Saisir, modifier et annuler un congé'
  UNION ALL SELECT 'gestion-personnel', 'Valider les congés', 'rh.conge.validate', 'Approuver ou refuser un congé'
  UNION ALL SELECT 'gestion-personnel', 'Consulter les carrières', 'rh.carriere.view', 'Consulter les actes de carrière'
  UNION ALL SELECT 'gestion-personnel', 'Gérer les carrières', 'rh.carriere.manage', 'Saisir les actes de carrière'
  UNION ALL SELECT 'gestion-personnel', 'Valider les carrières', 'rh.carriere.validate', 'Valider les actes de carrière'
  UNION ALL SELECT 'gestion-personnel', 'Consulter les évaluations', 'rh.evaluation.view', 'Consulter les évaluations'
  UNION ALL SELECT 'gestion-personnel', 'Gérer les évaluations', 'rh.evaluation.manage', 'Saisir les évaluations annuelles'
  UNION ALL SELECT 'gestion-personnel', 'Consulter l''organigramme', 'rh.structure.view', 'Consulter la structure administrative'
  UNION ALL SELECT 'gestion-personnel', 'Gérer l''organigramme', 'rh.structure.manage', 'Créer et modifier les structures'
  UNION ALL SELECT 'gestion-personnel', 'Voir les statistiques RH', 'rh.stats.view', 'Consulter les tableaux de bord RH'
  UNION ALL SELECT 'gestion-personnel', 'Exporter les données RH', 'rh.export', 'Exporter listes et fiches en CSV'
  -- Application 5 : Contrôle Maintenance (16)
  UNION ALL SELECT 'controle-maintenance', 'Consulter les équipements', 'mnt.equipement.view', 'Consulter le parc équipement'
  UNION ALL SELECT 'controle-maintenance', 'Gérer le parc équipement', 'mnt.equipement.manage', 'Créer, modifier, retirer un équipement'
  UNION ALL SELECT 'controle-maintenance', 'Consulter les interventions', 'mnt.intervention.view', 'Consulter les interventions et bons de travail'
  UNION ALL SELECT 'controle-maintenance', 'Créer une intervention', 'mnt.intervention.create', 'Signaler une panne ou ouvrir une intervention'
  UNION ALL SELECT 'controle-maintenance', 'Modifier une intervention', 'mnt.intervention.edit', 'Modifier le rapport et l''avancement'
  UNION ALL SELECT 'controle-maintenance', 'Supprimer une intervention', 'mnt.intervention.delete', 'Supprimer une intervention'
  UNION ALL SELECT 'controle-maintenance', 'Clôturer une intervention', 'mnt.intervention.validate', 'Valider et clôturer une intervention'
  UNION ALL SELECT 'controle-maintenance', 'Affecter un technicien', 'mnt.intervention.assign', 'Affecter ou réaffecter un technicien'
  UNION ALL SELECT 'controle-maintenance', 'Consulter les pièces', 'mnt.piece.view', 'Consulter le stock de pièces détachées'
  UNION ALL SELECT 'controle-maintenance', 'Gérer les pièces', 'mnt.piece.manage', 'Entrées, sorties et réapprovisionnement'
  UNION ALL SELECT 'controle-maintenance', 'Consulter les techniciens', 'mnt.technicien.view', 'Consulter l''équipe technique'
  UNION ALL SELECT 'controle-maintenance', 'Gérer les techniciens', 'mnt.technicien.manage', 'Administrer l''équipe technique'
  UNION ALL SELECT 'controle-maintenance', 'Consulter les fournisseurs', 'mnt.fournisseur.view', 'Consulter le référentiel fournisseurs'
  UNION ALL SELECT 'controle-maintenance', 'Gérer les fournisseurs', 'mnt.fournisseur.manage', 'Administrer les fournisseurs'
  UNION ALL SELECT 'controle-maintenance', 'Voir les statistiques', 'mnt.stats.view', 'Consulter les KPI et tableaux de bord'
  UNION ALL SELECT 'controle-maintenance', 'Exporter les données', 'mnt.export', 'Exporter les listes en CSV'
) t
JOIN applications a ON a.code = t.app_code
LEFT JOIN permissions p ON p.code = t.code AND p.application_id = a.id
WHERE p.id IS NULL;

-- Permissions génériques des applications PHP sans catalogue métier.
-- Leur garde SSO les utilise pour distinguer lecture, écriture et export.
INSERT INTO permissions (application_id, name, code, description)
SELECT a.id, t.name, CONCAT(REPLACE(a.code, '-', '_'), '.', t.suffix), t.description
FROM applications a
CROSS JOIN (
  SELECT 'Consulter l''application' AS name, 'view' AS suffix, 'Accéder aux vues en lecture seule' AS description
  UNION ALL SELECT 'Gérer l''application', 'manage', 'Créer, modifier et supprimer les données'
  UNION ALL SELECT 'Exporter les données', 'export', 'Exporter les données de l''application'
) t
LEFT JOIN permissions p ON p.application_id = a.id
  AND p.code = CONCAT(REPLACE(a.code, '-', '_'), '.', t.suffix)
WHERE a.code IN ('educongo-copie', 'app-test-sso', 'iam-sso-demo')
  AND p.id IS NULL;

-- Ré-ancrer les permissions orphelines (application supprimée par le passé)
UPDATE permissions p
  JOIN (SELECT 'presence.view' code, 'gestion-presence' app
        UNION ALL SELECT 'presence.record', 'gestion-presence'
        UNION ALL SELECT 'presence.edit', 'gestion-presence'
        UNION ALL SELECT 'presence.validate', 'gestion-presence'
        UNION ALL SELECT 'personnel.view', 'gestion-presence'
        UNION ALL SELECT 'personnel.manage', 'gestion-presence'
        UNION ALL SELECT 'stats.view', 'gestion-presence'
        UNION ALL SELECT 'salary.view', 'gestion-salaire'
        UNION ALL SELECT 'salary.manage', 'gestion-salaire'
        UNION ALL SELECT 'salary.validate', 'gestion-salaire'
        UNION ALL SELECT 'salary.pay', 'gestion-salaire'
        UNION ALL SELECT 'employe.manage', 'gestion-salaire'
        UNION ALL SELECT 'rubrique.manage', 'gestion-salaire'
        UNION ALL SELECT 'export.pdf', 'gestion-salaire'
        UNION ALL SELECT 'iam.admin', 'iam-admin'
        UNION ALL SELECT 'users.manage', 'iam-admin'
        UNION ALL SELECT 'roles.manage', 'iam-admin'
        UNION ALL SELECT 'audit.view', 'iam-admin'
        UNION ALL SELECT 'rh.personnel.view', 'gestion-personnel'
        UNION ALL SELECT 'rh.personnel.create', 'gestion-personnel'
        UNION ALL SELECT 'rh.personnel.edit', 'gestion-personnel'
        UNION ALL SELECT 'rh.personnel.delete', 'gestion-personnel'
        UNION ALL SELECT 'rh.personnel.validate', 'gestion-personnel'
        UNION ALL SELECT 'rh.conge.view', 'gestion-personnel'
        UNION ALL SELECT 'rh.conge.manage', 'gestion-personnel'
        UNION ALL SELECT 'rh.conge.validate', 'gestion-personnel'
        UNION ALL SELECT 'rh.carriere.view', 'gestion-personnel'
        UNION ALL SELECT 'rh.carriere.manage', 'gestion-personnel'
        UNION ALL SELECT 'rh.carriere.validate', 'gestion-personnel'
        UNION ALL SELECT 'rh.evaluation.view', 'gestion-personnel'
        UNION ALL SELECT 'rh.evaluation.manage', 'gestion-personnel'
        UNION ALL SELECT 'rh.structure.view', 'gestion-personnel'
        UNION ALL SELECT 'rh.structure.manage', 'gestion-personnel'
        UNION ALL SELECT 'rh.stats.view', 'gestion-personnel'
        UNION ALL SELECT 'rh.export', 'gestion-personnel'
        UNION ALL SELECT 'mnt.equipement.view', 'controle-maintenance'
        UNION ALL SELECT 'mnt.equipement.manage', 'controle-maintenance'
        UNION ALL SELECT 'mnt.intervention.view', 'controle-maintenance'
        UNION ALL SELECT 'mnt.intervention.create', 'controle-maintenance'
        UNION ALL SELECT 'mnt.intervention.edit', 'controle-maintenance'
        UNION ALL SELECT 'mnt.intervention.delete', 'controle-maintenance'
        UNION ALL SELECT 'mnt.intervention.validate', 'controle-maintenance'
        UNION ALL SELECT 'mnt.intervention.assign', 'controle-maintenance'
        UNION ALL SELECT 'mnt.piece.view', 'controle-maintenance'
        UNION ALL SELECT 'mnt.piece.manage', 'controle-maintenance'
        UNION ALL SELECT 'mnt.technicien.view', 'controle-maintenance'
        UNION ALL SELECT 'mnt.technicien.manage', 'controle-maintenance'
        UNION ALL SELECT 'mnt.fournisseur.view', 'controle-maintenance'
        UNION ALL SELECT 'mnt.fournisseur.manage', 'controle-maintenance'
        UNION ALL SELECT 'mnt.stats.view', 'controle-maintenance'
        UNION ALL SELECT 'mnt.export', 'controle-maintenance'
       ) m ON m.code = p.code
  JOIN applications a ON a.code = m.app
  LEFT JOIN applications cur ON cur.id = p.application_id
SET p.application_id = a.id
WHERE cur.id IS NULL;

-- ------------------------------------------------------------
-- 3. Filet : les 4 profils standards sur CHAQUE application
--    (créés s'ils manquent, y compris sur les apps test/démo).
-- ------------------------------------------------------------
INSERT INTO roles (application_id, name, code, description, is_system)
SELECT a.id, t.name, t.code, t.description, 1
FROM applications a
CROSS JOIN (
  SELECT 'Administrateur'  AS name, 'admin'           AS code, 'Accès complet : CRUD sur l''application et administration de l''IAM' AS description
  UNION ALL SELECT 'Gestionnaire RH', 'gestionnaire_rh', 'Profil opérationnel : saisie, gestion et validation sur les applications métier'
  UNION ALL SELECT 'Agent', 'agent', 'Utilisateur simple : CONSULTATION UNIQUEMENT, aucune écriture'
  UNION ALL SELECT 'Auditeur', 'auditeur', 'Consultation et export sur l''application, y compris le journal d''audit IAM'
) t
WHERE NOT EXISTS (SELECT 1 FROM roles r WHERE r.code = t.code AND r.application_id = a.id);

-- ------------------------------------------------------------
-- 4. Filet : les 4 rôles métier locaux (créés si absents).
-- ------------------------------------------------------------
INSERT INTO roles (application_id, name, code, description, is_system)
SELECT a.id, t.name, t.code, t.description, 0
FROM (
  SELECT 'gestion-personnel' AS app_code, 'Employé' AS name, 'employe' AS code, 'Consulte l''annuaire et gère ses propres demandes de congé' AS description
  UNION ALL SELECT 'controle-maintenance', 'Technicien', 'technicien', 'Réalise et met à jour ses interventions et celles de son équipe'
  UNION ALL SELECT 'controle-maintenance', 'Exploitant', 'operateur', 'Signale une panne et suit ses demandes'
  UNION ALL SELECT 'controle-maintenance', 'Magasinier', 'magasinier', 'Gère le stock de pièces et les mouvements'
) t
JOIN applications a ON a.code = t.app_code
WHERE NOT EXISTS (SELECT 1 FROM roles r WHERE r.code = t.code AND r.application_id = a.id);

-- ------------------------------------------------------------
-- 5. RECONSTRUCTION de la matrice : on efface d'abord les droits
--    des rôles des 5 applications de référence pour qu'une
--    réexécution donne EXACTEMENT la matrice.
-- ------------------------------------------------------------
DELETE rp
  FROM role_permissions rp
  JOIN roles r ON r.id = rp.role_id
  JOIN applications a ON a.id = r.application_id
 WHERE a.code IN ('gestion-presence', 'gestion-salaire', 'iam-admin',
                  'gestion-personnel', 'controle-maintenance');

-- ── admin : toutes les permissions de son application ──
INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
  FROM roles r
  JOIN applications a ON a.id = r.application_id
  JOIN permissions p ON p.application_id = a.id
 WHERE r.code = 'admin'
;

-- Les permissions génériques des apps sans catalogue métier suivent aussi
-- la matrice standard.
INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
  FROM roles r
  JOIN applications a ON a.id = r.application_id
  JOIN permissions p ON p.application_id = a.id
 WHERE a.code IN ('educongo-copie', 'app-test-sso', 'iam-sso-demo')
   AND ((r.code = 'admin')
     OR (r.code = 'gestionnaire_rh' AND p.code IN (CONCAT(REPLACE(a.code, '-', '_'), '.view'), CONCAT(REPLACE(a.code, '-', '_'), '.manage')))
     OR (r.code = 'agent' AND p.code = CONCAT(REPLACE(a.code, '-', '_'), '.view'))
     OR (r.code = 'auditeur' AND p.code IN (CONCAT(REPLACE(a.code, '-', '_'), '.view'), CONCAT(REPLACE(a.code, '-', '_'), '.export'))));

-- ── gestionnaire_rh : saisie/validation RH, lecture Maintenance ──
INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
  FROM roles r
  JOIN applications a ON a.id = r.application_id
  JOIN permissions p ON p.application_id = a.id
 WHERE r.code = 'gestionnaire_rh'
   AND a.code IN ('gestion-presence', 'gestion-salaire', 'gestion-personnel', 'controle-maintenance')
   AND p.code IN (
     'presence.view', 'presence.record', 'presence.edit', 'presence.validate',
     'personnel.view', 'personnel.manage', 'stats.view',
     'salary.view', 'salary.manage', 'salary.validate',
     'employe.manage', 'rubrique.manage', 'export.pdf',
     'rh.personnel.view', 'rh.personnel.create', 'rh.personnel.edit', 'rh.personnel.validate',
     'rh.conge.view', 'rh.conge.manage', 'rh.conge.validate',
     'rh.carriere.view', 'rh.carriere.manage', 'rh.carriere.validate',
     'rh.evaluation.view', 'rh.evaluation.manage',
     'rh.structure.view', 'rh.structure.manage',
     'rh.stats.view', 'rh.export',
     'mnt.equipement.view', 'mnt.intervention.view', 'mnt.stats.view', 'mnt.export');

-- ── agent : CONSULTATION SEULE ──
INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
  FROM roles r
  JOIN applications a ON a.id = r.application_id
  JOIN permissions p ON p.application_id = a.id
 WHERE r.code = 'agent'
   AND a.code IN ('gestion-presence', 'gestion-salaire', 'gestion-personnel', 'controle-maintenance')
   AND p.code IN ('presence.view', 'salary.view', 'rh.personnel.view', 'rh.conge.view',
                  'mnt.equipement.view', 'mnt.intervention.view');

-- ── auditeur : consultation + export, audit IAM inclus ──
INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
  FROM roles r
  JOIN applications a ON a.id = r.application_id
  JOIN permissions p ON p.application_id = a.id
 WHERE r.code = 'auditeur'
   AND a.code IN ('gestion-presence', 'gestion-salaire', 'iam-admin',
                  'gestion-personnel', 'controle-maintenance')
   AND p.code IN (
     'personnel.view', 'presence.view', 'salary.view', 'audit.view',
     'rh.personnel.view', 'rh.conge.view', 'rh.carriere.view',
     'rh.evaluation.view', 'rh.structure.view', 'rh.stats.view', 'rh.export',
     'mnt.equipement.view', 'mnt.intervention.view', 'mnt.piece.view',
     'mnt.technicien.view', 'mnt.fournisseur.view', 'mnt.stats.view', 'mnt.export');

-- ── employe (app 4) : annuaire + ses propres congés ──
INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
  FROM roles r
  JOIN applications a ON a.id = r.application_id
  JOIN permissions p ON p.application_id = a.id
 WHERE r.code = 'employe' AND a.code = 'gestion-personnel'
   AND p.code IN ('rh.personnel.view', 'rh.conge.view', 'rh.conge.manage');

-- ── technicien (app 5) : ses interventions ──
INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
  FROM roles r
  JOIN applications a ON a.id = r.application_id
  JOIN permissions p ON p.application_id = a.id
 WHERE r.code = 'technicien' AND a.code = 'controle-maintenance'
   AND p.code IN ('mnt.equipement.view', 'mnt.intervention.view', 'mnt.intervention.create',
                  'mnt.intervention.edit', 'mnt.piece.view', 'mnt.technicien.view');

-- ── operateur (app 5) : signalement de panne ──
INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
  FROM roles r
  JOIN applications a ON a.id = r.application_id
  JOIN permissions p ON p.application_id = a.id
 WHERE r.code = 'operateur' AND a.code = 'controle-maintenance'
   AND p.code IN ('mnt.equipement.view', 'mnt.intervention.view', 'mnt.intervention.create');

-- ── magasinier (app 5) : stock de pièces ──
INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
  FROM roles r
  JOIN applications a ON a.id = r.application_id
  JOIN permissions p ON p.application_id = a.id
 WHERE r.code = 'magasinier' AND a.code = 'controle-maintenance'
   AND p.code IN ('mnt.equipement.view', 'mnt.intervention.view',
                  'mnt.piece.view', 'mnt.piece.manage', 'mnt.technicien.view');

-- ------------------------------------------------------------
-- 6. Filet : l'application IAM doit toujours exposer le rôle
--    'admin', et l'administrateur principal (id 1) doit le
--    détenir — c'est ce qui porte l'accès à la console /admin.
-- ------------------------------------------------------------
INSERT IGNORE INTO user_roles (user_id, role_id, application_id)
SELECT 1, r.id, a.id
  FROM roles r
  JOIN applications a ON a.id = r.application_id
 WHERE r.code = 'admin' AND r.is_system = 1
   AND (a.code = 'iam-admin' OR a.is_system = 1)
   AND EXISTS (SELECT 1 FROM users u WHERE u.id = 1);
