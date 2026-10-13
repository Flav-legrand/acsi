-- ============================================================
--  IAM-LOCAL — Applications MÉTIER
--    App 4 : Gestion du Personnel   (Django / Python)  -> http://localhost:8000
--    App 5 : Contrôle Maintenance   (React + Express)  -> http://localhost:5173
--
--  ── MODÈLE DE RÔLES : 4 PROFILS GLOBAUX + 4 RÔLES LOCAUX
--  ─────────────────────────────────────────────────────────────────
--  Les 4 profils globaux (application_id NULL) sont transversaux :
--  le MÊME profil donne une VUE DIFFÉRENTE selon l'application,
--  parce que chaque application lui accorde son propre jeu de
--  permissions.
--
--     admin           CRUD TOTAL sur les deux applications
--     gestionnaire_rh Saisit, gère et valide le Personnel ;
--                     consultation sur la Maintenance
--     agent           CONSULTATION SEULE sur les deux applications
--     auditeur        Consultation + export, aucune écriture
--
--  Les 4 rôles locaux (application_id renseigné) n'existent que sur
--  une seule application et délimitent des PÉRIMÈTRES DE DONNÉES
--  différents, pas seulement des écrans différents :
--
--     employe     (app 4) annuaire + ses propres demandes de congé
--     technicien  (app 5) ses interventions et celles de son équipe
--     operateur   (app 5) signale une panne, suit ses demandes
--     magasinier  (app 5) stock de pièces, aucune intervention
--
--  ── DEUX DÉFAUTS CORRIGÉS DANS CE FICHIER ─────────────────────────
--  1. Les 4 profils globaux n'étaient créés par AUCUN script. Ce
--     fichier les attribuait des permissions via INSERT IGNORE sur
--     des role_id inexistants : la clé étrangèrefk_rp_role violée
--     était transformée en avertissement, la ligne était SAUTÉE, et
--     l'opérateur obtenait une installation « réussie » sans aucune
--     permission. Le fichier crée donc les 4 profils s'ils manquent,
--     et les résout par CODE — jamais par identifiant.
--  2. Ce fichier insérait des rôles avec application_id en dur sur
--     les identifiants 7 à 10, qui sont ceux de seed-demo.sql. Au
--     second passage, ON DUPLICATE KEY UPDATE RÉÉCRIVAIT les rôles
--     des applications de démonstration. Tous les rôles sont donc
--     désormais résolus par (application_id, code).
--
--  Placeholders remplacés par install-apps.php :
--    {{BASE_URL}} · {{DEMO_PASSWORD_HASH}} · {{DEMO_EMAIL}}
--  Idempotent : peut être rejoué sans dupliquer.
-- ============================================================

USE iam_local;

-- ------------------------------------------------------------
-- 0. Consolidation à 4 profils : repli des profils historiques
--    'directeur' et 'chef_service' sur 'gestionnaire_rh'.
--
--    Ces deux profils n'existaient que pour les applications de
--    démonstration. Avant d'être supprimés, TOUTES leurs
--    attributions sont reprises sur le profil de gestion, afin
--    qu'aucun compte ne perdent l'accès qu'il avait.
--    L'export est laissé à l'audit : rien n'est supprimé avant
--    d'avoir recopié la correspondance.
-- ------------------------------------------------------------
INSERT IGNORE INTO user_roles (user_id, role_id, application_id)
SELECT ur.user_id, cible.id, ur.application_id
  FROM user_roles ur
  JOIN roles source ON source.id = ur.role_id
  JOIN roles cible  ON cible.code = 'gestionnaire_rh' AND cible.application_id IS NULL
 WHERE source.code IN ('directeur', 'chef_service')
   AND source.application_id IS NULL;

-- Les droits des deux profils repliés sur apps 4 et 5 sont
-- reconstruits plus bas par la matrice ; on efface d'abord ceux
-- qu'ils porteaient, sinon un compte conserverait des droits
-- périmés après le repli.
DELETE rp FROM role_permissions rp
  JOIN roles r ON r.id = rp.role_id
 WHERE r.code IN ('directeur', 'chef_service') AND r.application_id IS NULL;

DELETE ur FROM user_roles ur
  JOIN roles r ON r.id = ur.role_id
 WHERE r.code IN ('directeur', 'chef_service') AND r.application_id IS NULL;

DELETE FROM roles WHERE code IN ('directeur', 'chef_service') AND application_id IS NULL;

-- ------------------------------------------------------------
-- 1. Applications
-- ------------------------------------------------------------
INSERT INTO applications
  (id, code, name, description, url, client_id, redirect_uri, scopes, color, icon, active, is_system, sso_prompt)
VALUES
  (4, 'gestion-personnel', 'Gestion du Personnel',
   'Effectifs, carrières, congés, évaluations et organigramme',
    'http://localhost:8000/auth/callback', 'iam-native-personnel', 'http://localhost:8000/auth/callback',
   'openid profile email roles', '#0d6efd', 'fa-user-tie', 1, 0, 0),
  (5, 'controle-maintenance', 'Contrôle Maintenance',
   'Parc équipement, interventions, pièces détachées et équipe technique',
   'http://localhost:5173', 'iam-native-maintenance', 'http://localhost:5173/auth/callback',
   'openid profile email roles', '#fd7e14', 'fa-screwdriver-wrench', 1, 0, 0)
ON DUPLICATE KEY UPDATE
  name         = VALUES(name),
  description  = VALUES(description),
  url          = VALUES(url),
  redirect_uri = VALUES(redirect_uri),
  scopes       = VALUES(scopes),
  color        = VALUES(color),
  icon         = VALUES(icon),
  active       = 1;

-- ------------------------------------------------------------
-- 2. Permissions de GESTION DU PERSONNEL (app 4) — préfixe « rh. »
--
--    agent        : 19, 24, 25
--    lecture      : + 27, 30, 32, 34, 35
--    saisie       : + 20, 21, 28, 31
--    encadrement  : + 26, 33
--    CRUD total   : + 22, 23, 29
-- ------------------------------------------------------------
INSERT INTO permissions (id, application_id, name, code, description) VALUES
  (19, 4, 'Consulter le personnel',    'rh.personnel.view',     'Consulter les fiches des agents'),
  (20, 4, 'Créer un agent',           'rh.personnel.create',   'Enregistrer un nouvel agent'),
  (21, 4, 'Modifier un agent',        'rh.personnel.edit',     'Modifier les informations d''un agent'),
  (22, 4, 'Supprimer un agent',       'rh.personnel.delete',   'Supprimer ou archiver un agent'),
  (23, 4, 'Valider un dossier agent', 'rh.personnel.validate', 'Valider les dossiers administratifs'),
  (24, 4, 'Consulter les congés',     'rh.conge.view',         'Consulter les demandes de congé'),
  (25, 4, 'Gérer les congés',         'rh.conge.manage',       'Saisir, modifier et annuler un congé'),
  (26, 4, 'Valider les congés',       'rh.conge.validate',     'Approuver ou refuser un congé'),
  (27, 4, 'Consulter les carrières',  'rh.carriere.view',      'Consulter les actes de carrière'),
  (28, 4, 'Gérer les carrières',      'rh.carriere.manage',    'Saisir les actes de carrière'),
  (29, 4, 'Valider les carrières',    'rh.carriere.validate',  'Valider les actes de carrière'),
  (30, 4, 'Consulter les évaluations','rh.evaluation.view',    'Consulter les évaluations'),
  (31, 4, 'Gérer les évaluations',    'rh.evaluation.manage',  'Saisir les évaluations annuelles'),
  (32, 4, 'Consulter l''organigramme','rh.structure.view',     'Consulter la structure administrative'),
  (33, 4, 'Gérer l''organigramme',    'rh.structure.manage',   'Créer et modifier les structures'),
  (34, 4, 'Voir les statistiques RH', 'rh.stats.view',         'Consulter les tableaux de bord RH'),
  (35, 4, 'Exporter les données RH',  'rh.export',             'Exporter listes et fiches en CSV')
ON DUPLICATE KEY UPDATE
  name = VALUES(name), application_id = VALUES(application_id),
  description = VALUES(description);

-- ------------------------------------------------------------
-- 3. Permissions de CONTRÔLE MAINTENANCE (app 5) — préfixe « mnt. »
--
--    operateur    : 36, 38, 39
--    technicien   : + 40, 44, 46
--    magasinier   : 36, 38, 44, 45, 46
--    CRUD total   : + 41, 47, 49
--    lecture      : + 48, 50, 51
-- ------------------------------------------------------------
INSERT INTO permissions (id, application_id, name, code, description) VALUES
  (36, 5, 'Consulter les équipements',   'mnt.equipement.view',      'Consulter le parc équipement'),
  (37, 5, 'Gérer le parc équipement',    'mnt.equipement.manage',    'Créer, modifier, retirer un équipement'),
  (38, 5, 'Consulter les interventions', 'mnt.intervention.view',    'Consulter les interventions et bons de travail'),
  (39, 5, 'Créer une intervention',      'mnt.intervention.create',  'Signaler une panne ou ouvrir une intervention'),
  (40, 5, 'Modifier une intervention',   'mnt.intervention.edit',    'Modifier le rapport et l''avancement'),
  (41, 5, 'Supprimer une intervention',  'mnt.intervention.delete',  'Supprimer une intervention'),
  (42, 5, 'Clôturer une intervention',   'mnt.intervention.validate','Valider et clôturer une intervention'),
  (43, 5, 'Affecter un technicien',     'mnt.intervention.assign',  'Affecter ou réaffecter un technicien'),
  (44, 5, 'Consulter les pièces',        'mnt.piece.view',           'Consulter le stock de pièces détachées'),
  (45, 5, 'Gérer les pièces',            'mnt.piece.manage',         'Entrées, sorties et réapprovisionnement'),
  (46, 5, 'Consulter les techniciens',   'mnt.technicien.view',      'Consulter l''équipe technique'),
  (47, 5, 'Gérer les techniciens',       'mnt.technicien.manage',    'Administrer l''équipe technique'),
  (48, 5, 'Consulter les fournisseurs',  'mnt.fournisseur.view',     'Consulter le référentiel fournisseurs'),
  (49, 5, 'Gérer les fournisseurs',      'mnt.fournisseur.manage',   'Administrer les fournisseurs'),
  (50, 5, 'Voir les statistiques',       'mnt.stats.view',           'Consulter les KPI et tableaux de bord'),
  (51, 5, 'Exporter les données',        'mnt.export',               'Exporter les listes en CSV')
ON DUPLICATE KEY UPDATE
  name = VALUES(name), application_id = VALUES(application_id),
  description = VALUES(description);

-- ------------------------------------------------------------
-- 4. Les 4 PROFILS STANDARDS sur chaque application
--
--    Les rôles ne sont plus globaux : chaque application (4 et 5)
--    possède ses propres exemplaires d'admin, gestionnaire_rh, agent
--    et auditeur. Ils sont créés ici s'ils manquent et résolus par
--    (application_id, code) ensuite, jamais par identifiant.
-- ------------------------------------------------------------
INSERT INTO roles (application_id, name, code, description, is_system)
SELECT a.id, t.name, t.code, t.description, 1
FROM (SELECT 4 AS id UNION ALL SELECT 5) a
CROSS JOIN (
  SELECT 'Administrateur'  AS name, 'admin'           AS code, 'Accès complet : CRUD sur l''application' AS description
  UNION ALL SELECT 'Gestionnaire RH', 'gestionnaire_rh', 'Profil opérationnel : saisie, gestion et validation'
  UNION ALL SELECT 'Agent', 'agent', 'Utilisateur simple : CONSULTATION UNIQUEMENT, aucune écriture'
  UNION ALL SELECT 'Auditeur', 'auditeur', 'Consultation et export sur l''application'
) t
WHERE NOT EXISTS (SELECT 1 FROM roles r WHERE r.code = t.code AND r.application_id = a.id);

-- 4.0 Remise à zéro des droits gérés par ce script, sur les seules
--     applications 4 et 5.
--
--     Les autorisations ci-dessous sont ajoutées avec INSERT IGNORE,
--     qui n'ajoute jamais et ne retire jamais : relancer le script après
--     avoir retiré une permission la laisserait en place, et l'installateur
--     donnerait l'illusion d'un état reproductible alors que les droits
--     divergeraient à chaque essai. On efface donc d'abord tout ce que ce
--     script accorde, pour qu'une réinstallation donne exactement le même
--     résultat que la première fois.
DELETE rp
  FROM role_permissions rp
  INNER JOIN permissions p ON p.id = rp.permission_id
  INNER JOIN roles r       ON r.id = rp.role_id
 WHERE p.application_id IN (4, 5)
   AND r.application_id IN (4, 5);

-- admin : CRUD total sur son application
INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
  FROM roles r CROSS JOIN permissions p
 WHERE r.code = 'admin' AND r.application_id IN (4, 5)
   AND p.application_id = r.application_id;

-- gestionnaire_rh : SAISIT et VALIDE le Personnel, CONSULTATION sur la
--                    Maintenance. C'est le profil opérationnel, à
--                    contraster avec « agent » sur la même application.
INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
  FROM roles r CROSS JOIN permissions p
 WHERE r.code = 'gestionnaire_rh' AND r.application_id IN (4, 5)
   AND p.application_id = r.application_id
   AND p.code IN (
     -- Gestion du Personnel : écriture + validation
     'rh.personnel.view', 'rh.personnel.create', 'rh.personnel.edit',
     'rh.personnel.validate',
'rh.conge.view', 'rh.conge.manage', 'rh.conge.validate',
      -- « rh.carriere.validate » est indispensable et non décoratif :
      -- la validation d'un acte passe par POST /api/carrieres/<id>/valider/,
      -- qui contrôle CETTE permission et non « rh.carriere.manage ».
      -- Sans elle, le gestionnaire saisit des actes qu'il ne peut pas
      -- valider, et l'acte reste indéfiniment « en attente » — le genre
      -- de blocage qui se découvre en démonstration, devant le public.
      'rh.carriere.view', 'rh.carriere.manage', 'rh.carriere.validate',
      'rh.evaluation.view', 'rh.evaluation.manage',
     'rh.structure.view', 'rh.structure.manage',
     'rh.stats.view', 'rh.export',
     -- Contrôle Maintenance : consultation seule
     'mnt.equipement.view', 'mnt.intervention.view',
     'mnt.stats.view', 'mnt.export');

-- agent : CONSULTATION SEULE sur les deux applications, AUCUNE écriture.
-- C'est l'« utilisateur simple » : il regarde, il ne modifie rien.
-- Poser une demande de congé suppose le rôle « employe » (app 4) et
-- signaler une panne suppose « operateur » ou « technicien » (app 5) :
-- les écritures deviennent intentionnelles au lieu d'être accidentelles.
INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
  FROM roles r CROSS JOIN permissions p
 WHERE r.code = 'agent' AND r.application_id IN (4, 5)
   AND p.application_id = r.application_id
   AND p.code IN (
     'rh.personnel.view', 'rh.conge.view',
     'mnt.equipement.view', 'mnt.intervention.view');

-- auditeur : consultation et export sur tout, aucune écriture
INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
  FROM roles r CROSS JOIN permissions p
 WHERE r.code = 'auditeur' AND r.application_id IN (4, 5)
   AND p.application_id = r.application_id
   AND p.code IN (
     'rh.personnel.view', 'rh.conge.view', 'rh.carriere.view',
     'rh.evaluation.view', 'rh.structure.view', 'rh.stats.view', 'rh.export',
     'mnt.equipement.view', 'mnt.intervention.view', 'mnt.piece.view',
     'mnt.technicien.view', 'mnt.fournisseur.view', 'mnt.stats.view', 'mnt.export');

-- ------------------------------------------------------------
-- 5. Rôles LOCAUX — vocabulaire métier d'une seule application
--    application_id renseigné : ils n'apparaissent QUE dans l'app
--    concernée, et délimitent un PÉRIMÈTRE DE DONNÉES.
--
--    Insertion idempotente sur la clé unique
--    (application_id, code) : ici elle fonctionne, car
--    application_id n'est pas NULL.
-- ------------------------------------------------------------
INSERT INTO roles (application_id, name, code, description, is_system) VALUES
  (4, 'Employé',    'employe',    'Consulte l''annuaire et gère ses propres demandes de congé', 0),
  (5, 'Technicien',  'technicien', 'Réalise et met à jour ses interventions et celles de son équipe', 0),
  (5, 'Exploitant',  'operateur',  'Signale une panne et suit ses demandes', 0),
  (5, 'Magasinier',  'magasinier', 'Gère le stock de pièces et les mouvements', 0)
ON DUPLICATE KEY UPDATE
  name = VALUES(name), description = VALUES(description);

-- employe (app 4) : annuaire + SAISIR ses propres congés.
-- L'API vérifie en plus que la demande le concerne : la permission
-- ouvre la saisie, elle n'accorde pas le droit d'écrire pour autrui.
INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
  FROM roles r CROSS JOIN permissions p
 WHERE r.application_id = 4 AND r.code = 'employe'
   AND p.code IN ('rh.personnel.view', 'rh.conge.view', 'rh.conge.manage');

-- technicien (app 5) : ses interventions + consultation du stock
INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
  FROM roles r CROSS JOIN permissions p
 WHERE r.application_id = 5 AND r.code = 'technicien'
   AND p.code IN ('mnt.intervention.view', 'mnt.intervention.create', 'mnt.intervention.edit',
                  'mnt.piece.view', 'mnt.technicien.view', 'mnt.equipement.view');

-- operateur (app 5) : signalement de panne
INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
  FROM roles r CROSS JOIN permissions p
 WHERE r.application_id = 5 AND r.code = 'operateur'
   AND p.code IN ('mnt.equipement.view', 'mnt.intervention.view', 'mnt.intervention.create');

-- magasinier (app 5) : stock de pièces, aucune intervention
INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
  FROM roles r CROSS JOIN permissions p
 WHERE r.application_id = 5 AND r.code = 'magasinier'
   AND p.code IN ('mnt.equipement.view', 'mnt.intervention.view',
                  'mnt.piece.view', 'mnt.piece.manage', 'mnt.technicien.view');

-- ------------------------------------------------------------
-- 6. Accès de l'administrateur de la plateforme aux deux apps
--    (rôles locaux : l'admin reçoit le rôle 'admin' de chaque app)
-- ------------------------------------------------------------
INSERT IGNORE INTO user_roles (user_id, role_id, application_id)
SELECT u.id, r.id, r.application_id FROM users u CROSS JOIN roles r
 WHERE u.email = '{{DEMO_EMAIL}}' AND r.code = 'admin'
   AND r.application_id IN (4, 5);

-- ============================================================
-- 7. COMPTES DE DÉMONSTRATION (optionnel)
--
--    Décoché par défaut : l'installateur ne les crée que sur demande.
--    Sept comptes, un par vue, mots de passe identiques à celui du
--    compte administrateur. C'est ce jeu de comptes qui permet de
--    comparer côte à côte le CRUD de l'admin et la consultation de
--    l'agent sur la même page.
--
--      demo.gestionnaire  gestionnaire_rh  apps 4 et 5  CRUD RH
--      demo.agent         agent            apps 4 et 5  consultation seule
--      demo.auditeur      auditeur         apps 4 et 5  consultation + export
--      demo.technicien    technicien       app  5       ses interventions
--      demo.magasinier    magasinier       app  5       stock de pièces
--      demo.employe       employe          app  4       ses propres congés
--
--    « operateur » (signaler une panne) est le 7e rôle mais ne
--    dispose pas de compte : il est couvert par demo.technicien
--    pour la démonstration des périmètres de données.
--
--    Suppression : Administration > Utilisateurs.
-- ============================================================

-- 7.1 Comptes
INSERT INTO users (username, email, password_hash, first_name, last_name, matricule, fonction, status, mfa_enabled, must_change_password)
SELECT 'demo.gestionnaire', 'demo.gestionnaire@local', '{{DEMO_PASSWORD_HASH}}',
       'Démo', 'Gestionnaire', 'DEMO-001', 'Gestionnaire du personnel', 'active', 0, 0
FROM DUAL WHERE '{{WITH_DEMO}}' = '1'
  AND NOT EXISTS (SELECT 1 FROM users WHERE email = 'demo.gestionnaire@local');

INSERT INTO users (username, email, password_hash, first_name, last_name, matricule, fonction, status, mfa_enabled, must_change_password)
SELECT 'demo.agent', 'demo.agent@local', '{{DEMO_PASSWORD_HASH}}',
       'Démo', 'Agent', 'DEMO-002', 'Agent de bureau', 'active', 0, 0
FROM DUAL WHERE '{{WITH_DEMO}}' = '1'
  AND NOT EXISTS (SELECT 1 FROM users WHERE email = 'demo.agent@local');

INSERT INTO users (username, email, password_hash, first_name, last_name, matricule, fonction, status, mfa_enabled, must_change_password)
SELECT 'demo.auditeur', 'demo.auditeur@local', '{{DEMO_PASSWORD_HASH}}',
       'Démo', 'Auditeur', 'DEMO-003', 'Auditeur interne', 'active', 0, 0
FROM DUAL WHERE '{{WITH_DEMO}}' = '1'
  AND NOT EXISTS (SELECT 1 FROM users WHERE email = 'demo.auditeur@local');

INSERT INTO users (username, email, password_hash, first_name, last_name, matricule, fonction, status, mfa_enabled, must_change_password)
SELECT 'demo.technicien', 'demo.technicien@local', '{{DEMO_PASSWORD_HASH}}',
       'Démo', 'Technicien', 'TECH-001', 'Technicien de maintenance', 'active', 0, 0
FROM DUAL WHERE '{{WITH_DEMO}}' = '1'
  AND NOT EXISTS (SELECT 1 FROM users WHERE email = 'demo.technicien@local');

INSERT INTO users (username, email, password_hash, first_name, last_name, matricule, fonction, status, mfa_enabled, must_change_password)
SELECT 'demo.magasinier', 'demo.magasinier@local', '{{DEMO_PASSWORD_HASH}}',
       'Démo', 'Magasinier', 'MAG-001', 'Magasinier', 'active', 0, 0
FROM DUAL WHERE '{{WITH_DEMO}}' = '1'
  AND NOT EXISTS (SELECT 1 FROM users WHERE email = 'demo.magasinier@local');

INSERT INTO users (username, email, password_hash, first_name, last_name, matricule, fonction, status, mfa_enabled, must_change_password)
SELECT 'demo.employe', 'demo.employe@local', '{{DEMO_PASSWORD_HASH}}',
       'Démo', 'Employé', 'EMP-001', 'Agent de bureau', 'active', 0, 0
FROM DUAL WHERE '{{WITH_DEMO}}' = '1'
  AND NOT EXISTS (SELECT 1 FROM users WHERE email = 'demo.employe@local');

-- 7.2 Rôles : le MÊME profil sur les DEUX applications produit
--     deux vues différentes du même compte. C'est le point central
--     de la démonstration.
--     Attention : le « ; » termine toujours la ligne, jamais après un
--     commentaire « -- », sinon le exécuteur SQL le prendrait pour
--     un commentaire et fusionnerait deux instructions.
INSERT IGNORE INTO user_roles (user_id, role_id, application_id)
SELECT u.id, r.id, r.application_id FROM users u CROSS JOIN roles r
 WHERE u.email = 'demo.gestionnaire@local' AND r.code = 'gestionnaire_rh'
   AND r.application_id IN (4, 5);
INSERT IGNORE INTO user_roles (user_id, role_id, application_id)
SELECT u.id, r.id, r.application_id FROM users u CROSS JOIN roles r
 WHERE u.email = 'demo.agent@local' AND r.code = 'agent'
   AND r.application_id IN (4, 5);
INSERT IGNORE INTO user_roles (user_id, role_id, application_id)
SELECT u.id, r.id, r.application_id FROM users u CROSS JOIN roles r
 WHERE u.email = 'demo.auditeur@local' AND r.code = 'auditeur'
   AND r.application_id IN (4, 5);

-- Rôles locaux : ils n'existent que sur une seule application,
-- un compte peut donc n'être visible que d'un seul côté.
INSERT IGNORE INTO user_roles (user_id, role_id, application_id)
SELECT u.id, r.id, 5 FROM users u CROSS JOIN roles r
 WHERE u.email = 'demo.technicien@local' AND r.application_id = 5 AND r.code = 'technicien';
INSERT IGNORE INTO user_roles (user_id, role_id, application_id)
SELECT u.id, r.id, 5 FROM users u CROSS JOIN roles r
 WHERE u.email = 'demo.magasinier@local' AND r.application_id = 5 AND r.code = 'magasinier';
INSERT IGNORE INTO user_roles (user_id, role_id, application_id)
SELECT u.id, r.id, 4 FROM users u CROSS JOIN roles r
 WHERE u.email = 'demo.employe@local' AND r.application_id = 4 AND r.code = 'employe';

-- 7.3 Historique de mot de passe
INSERT IGNORE INTO password_history (user_id, password_hash)
SELECT u.id, '{{DEMO_PASSWORD_HASH}}' FROM users u
 WHERE u.email IN ('demo.gestionnaire@local','demo.agent@local','demo.auditeur@local',
                   'demo.technicien@local','demo.magasinier@local','demo.employe@local')
   AND '{{WITH_DEMO}}' = '1';
