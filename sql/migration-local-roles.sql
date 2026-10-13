-- ============================================================
--  IAM-LOCAL — MIGRATION : SUPPRESSION DES RÔLES GLOBAUX
--  Les 4 profils globaux (application_id NULL) deviennent des
--  rôles PROPRES À CHAQUE APPLICATION : le même jeu de permissions
--  est répliqué sur les 5 applications.
--
--  1. Les permissions de chaque profil sont transférées aux rôles
--     locaux (le code du rôle reste la clé logique).
--  2. Les attributions (user_roles) existantes sont re-pointées :
--     un utilisateur qui avait le profil sur l'app X garde le rôle
--     local 'X' sur l'app X ; la ligne (role global, app NULL→X)
--     de user_roles est réécrite vers le rôle local de l'app X.
--  3. Les 4 rôles globaux sont supprimés.
--
--  Idempotent : rejouable sans dupliquer ni perdre d'attributions.
--  Ne supprime PAS le rôle 'admin' : il devient local à l'application
--  IAM et continue de porter l'administration de la plateforme.
-- ============================================================

USE iam_local;

-- ------------------------------------------------------------
-- 0. Sécurité : le rôle global 'admin' doit exister avant conversion
-- ------------------------------------------------------------
INSERT INTO roles (name, code, description, is_system, application_id)
SELECT 'Administrateur', 'admin', 'Accès complet : CRUD sur toutes les applications et administration de l''IAM', 1, NULL
FROM DUAL WHERE NOT EXISTS (SELECT 1 FROM roles WHERE code = 'admin' AND application_id IS NULL);

-- ------------------------------------------------------------
-- 1. Pour chaque application : créer les 4 rôles locaux s'ils
--    manquent (admin, gestionnaire_rh, agent, auditeur).
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
WHERE a.active = 1
  AND NOT EXISTS (SELECT 1 FROM roles r WHERE r.code = t.code AND r.application_id = a.id);

-- ------------------------------------------------------------
-- 2. Transférer les permissions : chaque rôle local d'une app
--    reçoit exactement les permissions que le rôle global portait
--    ET qui appartiennent à cette application.
-- ------------------------------------------------------------
INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT localr.id, rp.permission_id
  FROM roles gr
  JOIN role_permissions rp ON rp.role_id = gr.id
  JOIN permissions p ON p.id = rp.permission_id
  JOIN roles localr ON localr.code = gr.code AND localr.application_id = p.application_id
 WHERE gr.application_id IS NULL
   AND gr.code IN ('admin', 'gestionnaire_rh', 'agent', 'auditeur');

-- ------------------------------------------------------------
-- 3. Re-pointer les attributions : (user, rôle global, app X)
--    devient (user, rôle local de X, app X).
-- ------------------------------------------------------------
INSERT IGNORE INTO user_roles (user_id, role_id, application_id)
SELECT ur.user_id, localr.id, ur.application_id
  FROM user_roles ur
  JOIN roles gr ON gr.id = ur.role_id AND gr.application_id IS NULL
  JOIN roles localr ON localr.code = gr.code AND localr.application_id = ur.application_id
 WHERE gr.code IN ('admin', 'gestionnaire_rh', 'agent', 'auditeur');

DELETE ur FROM user_roles ur
  JOIN roles gr ON gr.id = ur.role_id
 WHERE gr.application_id IS NULL
   AND gr.code IN ('admin', 'gestionnaire_rh', 'agent', 'auditeur');

-- ------------------------------------------------------------
-- 4. Droits hérités à nettoyer avant suppression des globaux :
--    les rôles locaux 'agent'/'auditeur' perdent leurs permissions
--    hors de leur application (recopiées par d'anciens scripts),
--    puis les 4 rôles globaux sont supprimés.
-- ------------------------------------------------------------
DELETE rp FROM role_permissions rp
  JOIN roles r ON r.id = rp.role_id
  JOIN permissions p ON p.id = rp.permission_id
 WHERE r.code IN ('agent', 'auditeur') AND r.application_id IS NOT NULL
   AND p.application_id <> r.application_id;

DELETE rp FROM role_permissions rp
  JOIN roles r ON r.id = rp.role_id
 WHERE r.application_id IS NULL
   AND r.code IN ('admin', 'gestionnaire_rh', 'agent', 'auditeur');

DELETE FROM roles
 WHERE application_id IS NULL
   AND code IN ('admin', 'gestionnaire_rh', 'agent', 'auditeur');

-- ------------------------------------------------------------
-- 5. Filet : si une application n'a pas reçu ses 4 rôles
--    (créée après coup, désactivée au passage 1...), les créer
--    et lui transférer les permissions qui lui appartiennent.
--    Idempotent : ne fait rien si tout est déjà en place.
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

INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT localr.id, p.id
  FROM applications a
  JOIN permissions p ON p.application_id = a.id
  JOIN roles localr ON localr.application_id = a.id
 WHERE localr.code = 'admin';

INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT localr.id, p.id
  FROM applications a
  JOIN permissions p ON p.application_id = a.id
  JOIN roles localr ON localr.application_id = a.id
 WHERE localr.code = 'gestionnaire_rh'
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

INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT localr.id, p.id
  FROM applications a
  JOIN permissions p ON p.application_id = a.id
  JOIN roles localr ON localr.application_id = a.id
 WHERE localr.code = 'agent'
   AND p.code IN ('presence.view', 'salary.view', 'rh.personnel.view', 'rh.conge.view',
                  'mnt.equipement.view', 'mnt.intervention.view');

INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT localr.id, p.id
  FROM applications a
  JOIN permissions p ON p.application_id = a.id
  JOIN roles localr ON localr.application_id = a.id
 WHERE localr.code = 'auditeur'
   AND p.code IN (
     'personnel.view', 'presence.view', 'salary.view', 'audit.view',
     'rh.personnel.view', 'rh.conge.view', 'rh.carriere.view',
     'rh.evaluation.view', 'rh.structure.view', 'rh.stats.view', 'rh.export',
     'mnt.equipement.view', 'mnt.intervention.view', 'mnt.piece.view',
     'mnt.technicien.view', 'mnt.fournisseur.view', 'mnt.stats.view', 'mnt.export');
